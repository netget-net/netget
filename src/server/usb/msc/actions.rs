//! USB Mass Storage Class protocol actions implementation

#[cfg(all(unix, feature = "libusb"))]
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
#[cfg(all(unix, feature = "libusb"))]
use crate::protocol::log_template::LogTemplate;
#[cfg(all(unix, feature = "libusb"))]
use crate::protocol::EventType;
#[cfg(all(unix, feature = "libusb"))]
use crate::server::connection::ConnectionId;
#[cfg(all(unix, feature = "libusb"))]
use crate::state::app_state::AppState;
#[cfg(all(unix, feature = "libusb"))]
use anyhow::{Context, Result};
#[cfg(all(unix, feature = "libusb"))]
use serde_json::json;
#[cfg(all(unix, feature = "libusb"))]
use std::collections::HashMap;
#[cfg(all(unix, feature = "libusb"))]
use std::sync::{Arc, LazyLock};

// Event type definitions (static for efficient reuse)
#[cfg(all(unix, feature = "libusb"))]
pub static USB_MSC_ATTACHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_msc_attached",
        "A USB/IP host attached to this virtual mass-storage device and can now read and write \
         sectors. The drive starts empty: answer with serve_files to say what it contains, and \
         netget lays those files out as a FAT16 volume the host can read. wait_for_more leaves \
         it empty.",
        json!({
            "type": "serve_files",
            "files": [{"name": "hello.txt", "content": "world"}]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Connection ID of the USB/IP session".to_string(),
            required: true,
        },
        Parameter {
            name: "total_sectors".to_string(),
            type_hint: "number".to_string(),
            description: "Total number of 512-byte sectors".to_string(),
            required: true,
        },
        Parameter {
            name: "capacity_mb".to_string(),
            type_hint: "number".to_string(),
            description: "Total capacity in megabytes".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        serve_files_action(),
        mount_disk_action(),
        eject_disk_action(),
        set_write_protect_action(),
        wait_for_more_action(),
    ])
});

#[cfg(all(unix, feature = "libusb"))]
pub static USB_MSC_DETACHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_msc_detached",
        "The host detached from this virtual mass-storage device. Purely informational - the \
         USB/IP session is gone, so there is nothing left to mount, eject or write-protect.",
        json!({"type": "show_message", "message": "USB mass storage host detached"}),
    )
    .with_parameters(vec![Parameter {
        name: "connection_id".to_string(),
        type_hint: "string".to_string(),
        description: "Connection ID of the USB/IP session".to_string(),
        required: true,
    }])
    .with_no_actions()
});

#[cfg(all(unix, feature = "libusb"))]
pub static USB_MSC_READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_msc_read",
        "The host read sectors from the mass-storage device. Informational: the read has \
         already been served from the current volume, so this is a notification and not a \
         request. Answer wait_for_more unless you want to replace the contents with \
         serve_files or change write protection in response.",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Connection ID".to_string(),
            required: true,
        },
        Parameter {
            name: "lba".to_string(),
            type_hint: "number".to_string(),
            description: "Logical Block Address (starting sector)".to_string(),
            required: true,
        },
        Parameter {
            name: "sector_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of sectors read".to_string(),
            required: true,
        },
        Parameter {
            name: "bytes_read".to_string(),
            type_hint: "number".to_string(),
            description: "Total bytes read".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        serve_files_action(),
        mount_disk_action(),
        eject_disk_action(),
        set_write_protect_action(),
        wait_for_more_action(),
    ])
});

#[cfg(all(unix, feature = "libusb"))]
pub static USB_MSC_WRITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "usb_msc_write",
        "The host wrote sectors to the mass-storage device. Informational: the write has \
         already been applied to the current volume, so this is a notification and not a \
         request. Answer wait_for_more unless you want to replace the contents with \
         serve_files or write-protect it in response.",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "connection_id".to_string(),
            type_hint: "string".to_string(),
            description: "Connection ID".to_string(),
            required: true,
        },
        Parameter {
            name: "lba".to_string(),
            type_hint: "number".to_string(),
            description: "Logical Block Address (starting sector)".to_string(),
            required: true,
        },
        Parameter {
            name: "sector_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of sectors written".to_string(),
            required: true,
        },
        Parameter {
            name: "bytes_written".to_string(),
            type_hint: "number".to_string(),
            description: "Total bytes written".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        serve_files_action(),
        mount_disk_action(),
        eject_disk_action(),
        set_write_protect_action(),
        wait_for_more_action(),
    ])
});

/// The per-connection MSC handlers, keyed by connection.
///
/// A `std::sync::Mutex` rather than a tokio one because `usbip` requires
/// `Arc<Mutex<Box<dyn UsbInterfaceHandler + Send>>>` from `std`, and because `execute_action`
/// is synchronous — it runs on a tokio worker, where the `Handle::current().block_on(...)`
/// this registry used to need would panic outright. The guard is never held across an
/// `.await`.
#[cfg(all(unix, feature = "libusb"))]
type SharedHandler = Arc<std::sync::Mutex<Box<dyn usbip::UsbInterfaceHandler + Send>>>;

/// USB Mass Storage Class protocol action handler
#[cfg(all(unix, feature = "libusb"))]
pub struct UsbMscProtocol {
    handlers: Arc<std::sync::Mutex<HashMap<ConnectionId, SharedHandler>>>,
    /// The directory `mount_disk` images must live in. `None` on the registry's instance,
    /// which only describes the protocol; a spawned server always carries one.
    image_dir: Option<super::image_dir::ImageDir>,
}

#[cfg(all(unix, feature = "libusb"))]
impl Default for UsbMscProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(unix, feature = "libusb"))]
impl UsbMscProtocol {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            image_dir: None,
        }
    }

    /// The instance a spawned server executes actions on, bound to its image directory.
    pub fn with_image_dir(image_dir: super::image_dir::ImageDir) -> Self {
        Self {
            handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            image_dir: Some(image_dir),
        }
    }

    /// The boundary a `disk_image` is checked against: the server's, or the default
    /// directory for an instance that was never spawned.
    fn image_dir(&self) -> Result<super::image_dir::ImageDir> {
        match &self.image_dir {
            Some(dir) => Ok(dir.clone()),
            None => super::image_dir::ImageDir::new(None),
        }
    }

    /// Register the handler that drives one attached device.
    pub fn set_handler(&self, connection_id: ConnectionId, handler: SharedHandler) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.insert(connection_id, handler);
        }
    }

    /// Drop the handler for a device whose host has detached, so a later action cannot reach
    /// a device that is gone.
    pub fn remove_handler(&self, connection_id: ConnectionId) {
        if let Ok(mut handlers) = self.handlers.lock() {
            handlers.remove(&connection_id);
        }
    }

    /// Resolve which attached device an action refers to.
    ///
    /// An explicit `connection_id` wins. Otherwise the single attached device is used — and if
    /// there is not exactly one, this is an error rather than a guess: ejecting the wrong disk
    /// is indistinguishable from ejecting the right one from the model's side.
    fn resolve_handler(&self, action: &serde_json::Value) -> Result<SharedHandler> {
        let handlers = self
            .handlers
            .lock()
            .map_err(|_| anyhow::anyhow!("USB MSC handler registry poisoned"))?;

        // All three forms a model can produce: the number, the number as a string, and the
        // `conn-N` form the events themselves carry. That last one matters — every event
        // reports `connection_id.to_string()`, which is `"conn-2"`, not `2`, so a model quoting
        // the event's own field back would otherwise never match.
        let requested = action["connection_id"].as_u64().or_else(|| {
            action["connection_id"].as_str().and_then(|s| {
                let s = s.trim();
                s.strip_prefix("conn-").unwrap_or(s).parse::<u64>().ok()
            })
        });

        if let Some(id) = requested {
            let Ok(id) = u32::try_from(id) else {
                anyhow::bail!("connection_id {id} is not a valid connection number");
            };
            let connection_id = ConnectionId::new(id);
            return handlers.get(&connection_id).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "No USB mass storage device attached on connection {}",
                    connection_id
                )
            });
        }

        match handlers.len() {
            0 => Err(anyhow::anyhow!(
                "No USB mass storage host is attached, so there is no device to act on"
            )),
            1 => Ok(handlers.values().next().cloned().expect("len checked")),
            _ => {
                let mut ids: Vec<u32> = handlers.keys().map(|c| c.as_u32()).collect();
                ids.sort_unstable();
                Err(anyhow::anyhow!(
                    "{} USB mass storage hosts are attached ({:?}); the action must name one \
                     with 'connection_id'",
                    ids.len(),
                    ids
                ))
            }
        }
    }

    /// Take the medium away because the model could not be reached.
    ///
    /// A drive whose contents the model never got to supply must not look like a working drive:
    /// an empty, correctly-formatted FAT16 volume is indistinguishable from one the model
    /// deliberately left empty. `eject_disk` is the existing mechanism for "there is no medium",
    /// so every command that needs one fails CHECK CONDITION with NOT READY / MEDIUM NOT
    /// PRESENT (02/3A/00) until a later `serve_files` or `mount_disk` puts one back.
    ///
    /// Returns whether a handler was found; the session may already have ended.
    pub fn fail_closed_eject(&self, connection_id: ConnectionId) -> bool {
        let handler = match self.handlers.lock() {
            Ok(handlers) => handlers.get(&connection_id).cloned(),
            Err(_) => None,
        };
        let Some(handler) = handler else {
            return false;
        };
        let Ok(mut guard) = handler.lock() else {
            return false;
        };
        match guard
            .as_any()
            .downcast_mut::<super::handler::UsbMscHandler>()
        {
            Some(msc) => {
                msc.eject_disk();
                true
            }
            None => false,
        }
    }

    /// Run `f` against the MSC handler an action refers to.
    fn with_msc_handler<T>(
        &self,
        action: &serde_json::Value,
        f: impl FnOnce(&mut super::handler::UsbMscHandler) -> T,
    ) -> Result<T> {
        let handler = self.resolve_handler(action)?;
        let mut guard = handler
            .lock()
            .map_err(|_| anyhow::anyhow!("USB MSC handler mutex poisoned"))?;
        let msc = guard
            .as_any()
            .downcast_mut::<super::handler::UsbMscHandler>()
            .context("Handler is not a USB mass storage handler")?;
        Ok(f(msc))
    }
}

// Implement Protocol trait
#[cfg(all(unix, feature = "libusb"))]
impl Protocol for UsbMscProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "disk_image".to_string(),
                type_hint: "string".to_string(),
                description: "OPTIONAL disk image file to serve instead of an LLM-supplied \
                              volume, under image_dir (a relative path is resolved against it). \
                              Leave it out for the normal case: the device then starts with an \
                              empty in-memory FAT16 volume and the model fills it with \
                              serve_files. Naming a file here is host state you are choosing to \
                              expose; it is created if it does not exist."
                    .to_string(),
                required: false,
                example: serde_json::json!("prepared.img"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: super::image_dir::IMAGE_DIR_PARAM.to_string(),
                type_hint: "string".to_string(),
                description: "Directory the startup disk_image and every mount_disk image must \
                              live in; nothing outside it is opened. The USB/IP peer reads a \
                              mounted image as sectors and, with write protection off, writes \
                              it in place, so this is the boundary on what a peer-influenced \
                              model can expose. Defaults to NetGet's own usb-images directory \
                              under the platform's local-data dir."
                    .to_string(),
                required: false,
                example: serde_json::json!("/var/lib/netget/usb-images"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a peer that has only connected may send no USB/IP message \
                              at all before the server closes it. Default 30. USB/IP is \
                              client-speaks-first and nothing here answers a peer that has not \
                              asked - `usbip attach` and `usbip list -r` both write their \
                              request as soon as the socket is up - so a short bound is the \
                              honest one. Raise it only if your host is reached over a link \
                              where a handshake can take that long."
                    .to_string(),
                required: false,
                example: serde_json::json!(30),
                default: Some(serde_json::json!(
                    crate::server::usb::guard::DEFAULT_FIRST_MESSAGE_TIMEOUT.as_secs()
                )),
            },
            crate::llm::actions::ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds an attached host may go without sending a further USB/IP \
                              message before the server closes the session. Default 1800. \
                              USB/IP has no keepalive and nothing obliges an attached host to \
                              speak - a drive a host has imported and has not mounted issues no \
                              URB at all - so this is deliberately long and exists to reap a \
                              peer that is gone rather than to police one that is here. Lower \
                              it if you are exporting to strangers."
                    .to_string(),
                required: false,
                example: serde_json::json!(1800),
                default: Some(serde_json::json!(
                    crate::server::usb::guard::DEFAULT_IDLE_TIMEOUT.as_secs()
                )),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            serve_files_action(),
            mount_disk_action(),
            eject_disk_action(),
            set_write_protect_action(),
            wait_for_more_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "USB-MassStorage"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            USB_MSC_ATTACHED_EVENT.clone(),
            USB_MSC_DETACHED_EVENT.clone(),
            USB_MSC_READ_EVENT.clone(),
            USB_MSC_WRITE_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "USB>MSC>SCSI"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["usb", "storage", "disk", "msc", "scsi", "flash"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        crate::protocol::metadata::ProtocolMetadataV2::builder()
            .state(crate::protocol::metadata::DevelopmentState::Experimental)
            .implementation(
                "Virtual USB mass storage over USB/IP: BOT plus a SCSI-2 subset (INQUIRY, \
                 TEST UNIT READY, READ CAPACITY(10), READ(10), WRITE(10), REQUEST SENSE, \
                 MODE SENSE(6), PREVENT/ALLOW MEDIUM REMOVAL, READ FORMAT CAPACITIES) served \
                 synchronously. The protocol owns the transport, the SCSI layer and the FAT16 \
                 layout; the LLM owns the contents. usbip::handler runs on the accepted \
                 socket, so the listen port is whatever the caller asks for.",
            )
            .llm_control(
                "serve_files is the main one: the model names files and their text, and netget \
                 lays them out as a FAT16 volume in memory that the host reads back through \
                 READ(10). mount_disk serves a host file instead (opt-in), eject_disk makes \
                 every medium command report NOT READY, set_write_protect toggles DATA PROTECT \
                 on WRITE(10). All four events fire: usb_msc_attached on connect, \
                 usb_msc_read / usb_msc_write after sector transfers (coalesced - a mount does \
                 hundreds), usb_msc_detached when the USB/IP session ends.",
            )
            .e2e_testing(
                "E2E drives a real USB/IP client over TCP (OP_REQ_IMPORT, then CBW/CSW over \
                 the bulk endpoints). The headline test has the *model* supply the files, then \
                 walks the volume the way a host does - parse the BPB from sector 0, find the \
                 directory entry, follow it to its cluster - and asserts the content that \
                 arrives is what the model asked for. No usbip kernel module or root.",
            )
            .privilege_requirement(crate::protocol::metadata::PrivilegeRequirement::None)
            .notes(
                "The default medium is an empty in-memory FAT16 volume the model fills with \
                 serve_files; nothing is written to the filesystem. It used to memory-map \
                 ./tmp/netget_msc_disk.img by default, which made the protocol implement \
                 storage - the sectors a host read came from a file netget created rather than \
                 from the model. A file is used only when the caller names one in \
                 startup_params.disk_image or in mount_disk. serve_files takes text, not \
                 base64, so a binary payload cannot be expressed; names must be FAT 8.3 and \
                 are rejected rather than truncated. Attaching from a real host still needs \
                 vhci-hcd and root on the client side and is untested - the E2E harness proves \
                 the device side, not that an OS mounts the filesystem. Single LUN only.",
            )
            // The USB/IP screen in `src/server/usb/guard.rs` refuses a `USBIP_CMD_SUBMIT`
            // declaring more than this, before the crate allocates from the number.
            .max_inbound_bytes(crate::server::usb::guard::MAX_TRANSFER_BUFFER_BYTES)
            .build()
    }

    fn description(&self) -> &'static str {
        "Virtual USB Mass Storage device (flash drive/disk)"
    }

    fn example_prompt(&self) -> &'static str {
        "Create a USB mass storage device with a 100MB disk image"
    }

    fn group_name(&self) -> &'static str {
        "USB Devices"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: the model decides what is on the drive. No disk_image, because the
            // point is that the contents come from the model rather than from a file.
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "USB-MassStorage",
                "instruction": "Be a USB drive holding a README and a config file"
            }),
            // Script mode: deterministic contents, no LLM round trip.
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "USB-MassStorage",
                "event_handlers": [{
                    "event_pattern": "usb_msc_attached",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "actions = [{'type': 'serve_files', 'files': [{'name': 'readme.txt', 'content': 'generated by netget'}]}]"
                    }
                }]
            }),
            // Static mode: a fixed set of files.
            json!({
                "type": "open_server",
                "port": 3240,
                "base_stack": "USB-MassStorage",
                "event_handlers": [{
                    "event_pattern": "usb_msc_attached",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "serve_files",
                            "files": [{"name": "hello.txt", "content": "world"}]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait
#[cfg(all(unix, feature = "libusb"))]
impl Server for UsbMscProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            let image_dir = super::image_dir::ImageDir::new(
                ctx.startup_params
                    .as_ref()
                    .map(|p| p.get_optional_string(super::image_dir::IMAGE_DIR_PARAM))
                    .transpose()?
                    .flatten()
                    .as_deref(),
            )?;
            // Confined like a `mount_disk` image: the parameter is model-settable through
            // `open_server` and the peer reads (and may write) whatever it names.
            let disk_image = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("disk_image"))
                .transpose()?
                .flatten()
                .map(|raw| image_dir.resolve(&raw, "the `disk_image` startup parameter"))
                .transpose()?;

            // Read here rather than through a shared helper so the parameter names appear
            // in this protocol's own source: `tests/startup_param_drift_test.rs` proves a
            // declared knob is wired by finding its name outside the declaration, and a read
            // one directory up is invisible to it — and to the next person reading this file.
            // The numbers and the argument for them are in `src/server/usb/guard.rs`.
            let secs = |name: &str| -> anyhow::Result<Option<u64>> {
                Ok(ctx
                    .startup_params
                    .as_ref()
                    .map(|p| p.get_optional_u64(name))
                    .transpose()?
                    .flatten())
            };
            let first_byte_timeout_secs = secs("first_byte_timeout_secs")?;
            let idle_timeout_secs = secs("idle_timeout_secs")?;

            crate::server::usb::msc::UsbMscServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                image_dir,
                disk_image,
                first_byte_timeout_secs,
                idle_timeout_secs,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action["type"]
            .as_str()
            .context("Action must have 'type' field")?;

        match action_type {
            // The LLM-driven path: the model says what files the drive holds, and the protocol
            // lays them out as a FAT16 volume in memory. This is the action that makes the
            // sectors a host reads *the model's* data rather than a file netget put on disk.
            "serve_files" => {
                let files = action["files"]
                    .as_array()
                    .context("serve_files requires a 'files' array")?;
                if files.is_empty() {
                    anyhow::bail!(
                        "serve_files needs at least one file; use eject_disk to present an \
                         empty drive"
                    );
                }

                let specs: Vec<super::fat16::FileSpec> = files
                    .iter()
                    .enumerate()
                    .map(|(i, f)| {
                        let name = f["name"]
                            .as_str()
                            .with_context(|| format!("files[{}] needs a 'name'", i))?
                            .to_string();
                        let content = f["content"].as_str().unwrap_or("").to_string();
                        Ok(super::fat16::FileSpec { name, content })
                    })
                    .collect::<Result<Vec<_>>>()?;

                // `encode_label` already strips anything that is not ASCII graphic or space
                // before the bytes reach the boot sector, so the *volume* is safe. The log
                // line is not: it prints the model's raw string, and a label containing a
                // newline forges a record of its own. Sanitise what is logged, and keep the
                // raw value for the encoder, which has its own stricter filter.
                let label = action["volume_label"].as_str().unwrap_or("NETGET");
                let label_for_log = crate::utils::sanitize::line_field(label);
                let total_sectors = super::fat16::DEFAULT_TOTAL_SECTORS;

                // Build before touching the device: an unusable file name must not leave the
                // handler holding half a volume.
                let image = super::fat16::build_volume(&specs, total_sectors, label)?;
                let disk = super::disk::DiskImage::in_memory(image)?;
                let sectors = disk.total_sectors();
                let disk = std::sync::Arc::new(std::sync::Mutex::new(disk));

                // A drive whose contents the model just declared is read-only unless it says
                // otherwise: a host that writes would be editing the model's answer.
                let write_protect = action["write_protect"].as_bool().unwrap_or(true);

                self.with_msc_handler(&action, |msc| {
                    msc.mount_disk(disk);
                    msc.set_write_protect(write_protect);
                })?;

                tracing::info!(
                    "USB MSC: serving {} LLM-supplied file(s) as a {} sector FAT16 volume \
                     '{}' (write_protect={})",
                    specs.len(),
                    sectors,
                    label_for_log,
                    write_protect
                );
                Ok(ActionResult::NoAction)
            }
            "mount_disk" => {
                let disk_image_path = action["disk_image"]
                    .as_str()
                    .context("mount_disk requires 'disk_image' field")?;
                // Write protection defaults to *on*, matching how a device starts up. A model
                // that wants the host to be able to write has to say so.
                let write_protect = action["write_protect"].as_bool().unwrap_or(true);
                // Bounded, not just fitted into 32 bits. `u32::try_from` alone accepted
                // 4294967295 MB, i.e. a 4 PiB `set_len` on a sparse file whose sector count
                // then had to be truncated to be representable. `MAX_DISK_MB` is the largest
                // image a 32-bit LBA can address at 512 bytes per sector.
                let size_mb = action["size_mb"].as_u64().unwrap_or(10);
                if !(1..=MAX_DISK_MB).contains(&size_mb) {
                    anyhow::bail!(
                        "size_mb is {size_mb}; a virtual drive must be between 1 and \
                         {MAX_DISK_MB} MB (a 32-bit LBA addresses no more)"
                    );
                }
                let size_mb = size_mb as u32;

                // Confined first: the model that chose this path is driven by the peer that
                // will read the file as sectors. See `image_dir`. Then open the image before
                // touching the device: a bad path must not leave the handler half-remounted.
                let path = self
                    .image_dir()?
                    .resolve(disk_image_path, "the mount_disk 'disk_image'")?;
                // The device is looked up before the image is opened, so an action with no
                // device to mount on creates no image file.
                self.resolve_handler(&action)?;
                let disk = super::disk::DiskImage::open_or_create(&path, size_mb)
                    .with_context(|| format!("Failed to open disk image '{}'", path.display()))?;
                let sectors = disk.total_sectors();
                let disk = std::sync::Arc::new(std::sync::Mutex::new(disk));

                self.with_msc_handler(&action, |msc| {
                    msc.mount_disk(disk);
                    msc.set_write_protect(write_protect);
                })?;

                tracing::info!(
                    "USB MSC: Mounted disk '{}' ({} sectors, write_protect={})",
                    crate::utils::sanitize::line_field(disk_image_path),
                    sectors,
                    write_protect
                );
                Ok(ActionResult::NoAction)
            }
            "eject_disk" => {
                self.with_msc_handler(&action, |msc| msc.eject_disk())?;
                tracing::info!("USB MSC: Disk ejected");
                Ok(ActionResult::NoAction)
            }
            "set_write_protect" => {
                let enabled = action["enabled"]
                    .as_bool()
                    .context("set_write_protect requires 'enabled' boolean field")?;
                self.with_msc_handler(&action, |msc| msc.set_write_protect(enabled))?;
                tracing::info!(
                    "USB MSC: Write protection {}",
                    if enabled { "enabled" } else { "disabled" }
                );
                Ok(ActionResult::NoAction)
            }
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!("Unknown action type: {}", action_type)),
        }
    }
}

/// Largest virtual drive `mount_disk` will create, in megabytes.
///
/// SCSI READ(10) carries a 32-bit LBA and the sector size is fixed at 512, so 2 TiB is the
/// most this device can address. Anything past it has to be truncated somewhere, and a device
/// that advertises a capacity it cannot reach is worse than one that refuses to be that big.
#[cfg(all(unix, feature = "libusb"))]
const MAX_DISK_MB: u64 = (u32::MAX as u64) * 512 / (1024 * 1024);

// Action definitions

/// Optional device selector shared by every action.
///
/// It is optional on purpose. A virtual drive normally has exactly one host attached, and
/// asking a model to copy an id back is a reliable source of wrong answers. When exactly one
/// host is attached the action needs no id; when several are, an omitted id is an error naming
/// the candidates rather than a guess.
#[cfg(all(unix, feature = "libusb"))]
fn connection_id_parameter() -> Parameter {
    Parameter {
        name: "connection_id".to_string(),
        type_hint: "string".to_string(),
        description: "Which attached device to act on. Omit it when only one host is attached; \
            required (copy it from the event) when there are several."
            .to_string(),
        required: false,
    }
}

/// Declare what the drive contains. The LLM-driven path, and the one to reach for first.
#[cfg(all(unix, feature = "libusb"))]
fn serve_files_action() -> ActionDefinition {
    ActionDefinition {
        name: "serve_files".to_string(),
        description: "Put files on the virtual drive. netget lays them out as a FAT16 volume in \
                      memory and serves the sectors; nothing is written to disk. Names must be \
                      FAT 8.3 (at most 8 characters, a dot, at most 3 more) and content is \
                      text. This is how the drive gets its contents - prefer it over mount_disk."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "files".to_string(),
                type_hint: "array".to_string(),
                description: "Array of {\"name\": \"hello.txt\", \"content\": \"world\"} \
                              objects placed in the root directory"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "volume_label".to_string(),
                type_hint: "string".to_string(),
                description: "Volume label a host shows for the drive (default NETGET)".to_string(),
                required: false,
            },
            Parameter {
                name: "write_protect".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether the host may write to the drive. Defaults to true: the \
                              contents are your answer, and a host write would edit it."
                    .to_string(),
                required: false,
            },
            connection_id_parameter(),
        ],
        example: serde_json::json!({
            "type": "serve_files",
            "files": [{"name": "hello.txt", "content": "world"}]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB MSC serve files")
                .with_debug("USB-MSC serve_files: label={volume_label}"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn mount_disk_action() -> ActionDefinition {
    ActionDefinition {
        name: "mount_disk".to_string(),
        description: "Mount a disk image file as the virtual mass storage device. An image that \
            already exists is served as-is at its own size; a missing one is created empty."
            .to_string(),
        parameters: vec![
            connection_id_parameter(),
            Parameter {
                name: "disk_image".to_string(),
                type_hint: "string".to_string(),
                description: "Disk image file under the server's image_dir directory; a relative \
                    path is resolved against it, and nothing outside it is opened"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "write_protect".to_string(),
                type_hint: "boolean".to_string(),
                description: "Enable write protection (default: true)".to_string(),
                required: false,
            },
            Parameter {
                name: "size_mb".to_string(),
                type_hint: "number".to_string(),
                description: "Size in megabytes, used only when creating a new image \
                    (default: 10). Ignored for an image that already exists."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "mount_disk",
            "disk_image": "prepared.img",
            "write_protect": true
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB MSC mount disk '{disk_image}'")
                .with_debug("USB-MSC mount_disk: path={disk_image} write_protect={write_protect}"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn eject_disk_action() -> ActionDefinition {
    ActionDefinition {
        name: "eject_disk".to_string(),
        description: "Eject the currently mounted disk image. Every command that needs the \
            medium then fails with NOT READY until mount_disk supplies a new image."
            .to_string(),
        parameters: vec![connection_id_parameter()],
        example: json!({
            "type": "eject_disk"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB MSC eject disk")
                .with_debug("USB-MSC eject_disk: connection_id={connection_id}"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn set_write_protect_action() -> ActionDefinition {
    ActionDefinition {
        name: "set_write_protect".to_string(),
        description: "Enable or disable write protection on the virtual disk".to_string(),
        parameters: vec![
            connection_id_parameter(),
            Parameter {
                name: "enabled".to_string(),
                type_hint: "boolean".to_string(),
                description: "true to enable write protection, false to disable".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "set_write_protect",
            "enabled": true
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB MSC write protect {enabled}")
                .with_debug("USB-MSC set_write_protect: enabled={enabled}"),
        ),
    }
}

#[cfg(all(unix, feature = "libusb"))]
fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Wait for more data or events before taking action".to_string(),
        parameters: vec![],
        example: json!({
            "type": "wait_for_more"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> USB MSC wait for more")
                .with_debug("USB-MSC wait_for_more"),
        ),
    }
}
