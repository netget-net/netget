//! A slave's SDO server: which objects Rust answers from the device description, which it asks
//! the model about, and the segmented-transfer bookkeeping in between.
//!
//! Rust answers the objects that describe the device and its process data, because they must
//! agree with the SII and the SyncManagers a master has just configured: 0x1000 device type,
//! 0x1008/0x1009/0x100A names, 0x1018 identity, 0x1600/0x1A00 PDO mapping, 0x1C00 SyncManager
//! types, 0x1C12/0x1C13 PDO assignment, and the process data objects 0x6000 (inputs) and
//! 0x7000 (outputs). They are read-only. The objects the device description declares are the
//! model's; anything else does not exist.
use super::coe::{self, abort, SdoRequest};
use super::device::{Access, DataType, DeviceSpec, Object};
use serde_json::{json, Value};

/// What to do with one SDO request.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Reply with this CoE data now.
    Reply(Vec<u8>),
    /// The model answers a read of this object.
    AskRead(Object),
    /// The model decides a write of this value.
    AskWrite(Object, Value, Option<bool>),
    /// Nothing to send (an abort from the master).
    Nothing,
}

#[derive(Debug, Default)]
pub struct SdoServer {
    /// Upload segments still to send: (next toggle, the octets).
    upload: Option<(bool, Vec<u8>)>,
    /// A segmented download being received: index, subindex, declared size, octets, toggle.
    download: Option<(u16, u8, usize, Vec<u8>, bool)>,
}

fn abort_reply(index: u16, subindex: u8, code: u32) -> Outcome {
    Outcome::Reply(coe::abort_response(index, subindex, code))
}

/// The value of a Rust-answered object, `Err(abort)` when it has no such subindex, `None` when
/// the index is not one of them.
pub fn structural(
    dev: &DeviceSpec,
    index: u16,
    sub: u8,
    inputs: &[u8],
    outputs: &[u8],
) -> Option<Result<Vec<u8>, u32>> {
    let u8v = |v: u8| Ok(vec![v]);
    let u16v = |v: u16| Ok(v.to_le_bytes().to_vec());
    let u32v = |v: u32| Ok(v.to_le_bytes().to_vec());
    let mapping = |img: &super::device::Image, obj: u16| -> Result<Vec<u8>, u32> {
        if img.is_empty() {
            return Err(abort::NO_OBJECT);
        }
        match sub {
            0 => Ok(vec![img.entries.len() as u8]),
            s if (s as usize) <= img.entries.len() => {
                let e = &img.entries[s as usize - 1];
                let v = (obj as u32) << 16 | (s as u32) << 8 | e.ty.bits() as u32;
                Ok(v.to_le_bytes().to_vec())
            }
            _ => Err(abort::NO_SUBINDEX),
        }
    };
    let data = |img: &super::device::Image, buf: &[u8]| -> Result<Vec<u8>, u32> {
        if img.is_empty() {
            return Err(abort::NO_OBJECT);
        }
        match sub {
            0 => Ok(vec![img.entries.len() as u8]),
            s if (s as usize) <= img.entries.len() => {
                let e = &img.entries[s as usize - 1];
                Ok(super::device::get_bits(buf, e.bit_offset, e.ty.bits()))
            }
            _ => Err(abort::NO_SUBINDEX),
        }
    };
    let only0 = |r: Result<Vec<u8>, u32>| if sub == 0 { r } else { Err(abort::NO_SUBINDEX) };
    Some(match index {
        0x1000 => only0(u32v(dev.device_type)),
        0x1008 => only0(Ok(dev.name.as_bytes().to_vec())),
        0x1009 => match &dev.hardware_version {
            Some(v) => only0(Ok(v.as_bytes().to_vec())),
            None => Err(abort::NO_OBJECT),
        },
        0x100A => match &dev.software_version {
            Some(v) => only0(Ok(v.as_bytes().to_vec())),
            None => Err(abort::NO_OBJECT),
        },
        0x1018 => match sub {
            0 => u8v(4),
            1 => u32v(dev.vendor_id),
            2 => u32v(dev.product_code),
            3 => u32v(dev.revision),
            4 => u32v(dev.serial),
            _ => Err(abort::NO_SUBINDEX),
        },
        coe::RXPDO_MAPPING => mapping(&dev.outputs, coe::OUTPUT_OBJECT),
        coe::TXPDO_MAPPING => mapping(&dev.inputs, coe::INPUT_OBJECT),
        0x1C00 => match sub {
            0 => u8v(4),
            1..=4 => u8v(sub),
            _ => Err(abort::NO_SUBINDEX),
        },
        0x1C12 => match sub {
            0 => u8v(!dev.outputs.is_empty() as u8),
            1 if !dev.outputs.is_empty() => u16v(coe::RXPDO_MAPPING),
            _ => Err(abort::NO_SUBINDEX),
        },
        0x1C13 => match sub {
            0 => u8v(!dev.inputs.is_empty() as u8),
            1 if !dev.inputs.is_empty() => u16v(coe::TXPDO_MAPPING),
            _ => Err(abort::NO_SUBINDEX),
        },
        coe::INPUT_OBJECT => data(&dev.inputs, inputs),
        coe::OUTPUT_OBJECT => data(&dev.outputs, outputs),
        _ => return None,
    })
}

/// A declared object, or the abort that says why there is none.
fn declared(dev: &DeviceSpec, index: u16, sub: u8) -> Result<Object, u32> {
    if let Some(o) = dev
        .objects
        .iter()
        .find(|o| o.index == index && o.subindex == sub)
    {
        return Ok(o.clone());
    }
    if dev.objects.iter().any(|o| o.index == index) {
        return Err(abort::NO_SUBINDEX);
    }
    Err(abort::NO_OBJECT)
}

/// The highest declared subindex of an index whose subindex 0 was not declared itself (a
/// record's "number of entries").
fn implicit_count(dev: &DeviceSpec, index: u16) -> Option<u8> {
    let subs: Vec<u8> = dev
        .objects
        .iter()
        .filter(|o| o.index == index)
        .map(|o| o.subindex)
        .collect();
    (!subs.is_empty() && !subs.contains(&0)).then(|| subs.into_iter().max().unwrap_or(0))
}

impl SdoServer {
    pub fn reset(&mut self) {
        self.upload = None;
        self.download = None;
    }

    /// Answer what Rust can; say what the model must.
    pub fn handle(
        &mut self,
        dev: &DeviceSpec,
        req: SdoRequest,
        mailbox: usize,
        inputs: &[u8],
        outputs: &[u8],
    ) -> Outcome {
        match req {
            SdoRequest::Abort { .. } => {
                self.reset();
                Outcome::Nothing
            }
            SdoRequest::Upload {
                index,
                subindex,
                complete_access,
            } => {
                self.reset();
                if complete_access {
                    return abort_reply(index, subindex, abort::UNSUPPORTED_ACCESS);
                }
                if let Some(r) = structural(dev, index, subindex, inputs, outputs) {
                    return match r {
                        Ok(v) => self.upload_reply(index, subindex, &v, mailbox),
                        Err(code) => abort_reply(index, subindex, code),
                    };
                }
                if subindex == 0 {
                    if let Some(n) = implicit_count(dev, index) {
                        return self.upload_reply(index, 0, &[n], mailbox);
                    }
                }
                match declared(dev, index, subindex) {
                    Ok(o) if o.access == Access::WriteOnly => {
                        abort_reply(index, subindex, abort::WRITE_ONLY)
                    }
                    Ok(o) => Outcome::AskRead(o),
                    Err(code) => abort_reply(index, subindex, code),
                }
            }
            SdoRequest::UploadSegment { toggle } => match self.upload.take() {
                Some((want, rest)) if want == toggle => {
                    let (data, rest) = coe::upload_segment(toggle, &rest, mailbox);
                    if !rest.is_empty() {
                        self.upload = Some((!toggle, rest));
                    }
                    Outcome::Reply(data)
                }
                Some(_) => abort_reply(0, 0, abort::TOGGLE),
                None => abort_reply(0, 0, abort::COMMAND),
            },
            SdoRequest::Download {
                index,
                subindex,
                complete_access,
                size,
                data,
            } => {
                self.reset();
                if complete_access {
                    return abort_reply(index, subindex, abort::UNSUPPORTED_ACCESS);
                }
                if size > coe::MAX_SDO_BYTES {
                    return abort_reply(index, subindex, abort::TOO_LONG);
                }
                if let Some(r) = structural(dev, index, subindex, inputs, outputs) {
                    return abort_reply(
                        index,
                        subindex,
                        if r.is_ok() {
                            abort::READ_ONLY
                        } else {
                            r.err().unwrap_or(abort::READ_ONLY)
                        },
                    );
                }
                let object = match declared(dev, index, subindex) {
                    Ok(o) if o.access == Access::ReadOnly => {
                        return abort_reply(index, subindex, abort::READ_ONLY)
                    }
                    Ok(o) => o,
                    Err(code) => return abort_reply(index, subindex, code),
                };
                if data.len() < size {
                    self.download = Some((index, subindex, size, data, false));
                    return Outcome::Reply(coe::download_response(index, subindex));
                }
                self.write_outcome(object, &data)
            }
            SdoRequest::DownloadSegment { toggle, last, data } => {
                let Some((index, sub, size, mut got, want)) = self.download.take() else {
                    return abort_reply(0, 0, abort::COMMAND);
                };
                if toggle != want {
                    return abort_reply(index, sub, abort::TOGGLE);
                }
                got.extend_from_slice(&data);
                if got.len() > size {
                    return abort_reply(index, sub, abort::TOO_LONG);
                }
                if !last {
                    self.download = Some((index, sub, size, got, !toggle));
                    return Outcome::Reply(coe::download_segment_response(toggle));
                }
                if got.len() != size {
                    return abort_reply(index, sub, abort::TOO_SHORT);
                }
                match declared(dev, index, sub) {
                    Ok(o) => match self.write_outcome(o, &got) {
                        Outcome::AskWrite(o, v, _) => Outcome::AskWrite(o, v, Some(toggle)),
                        other => other,
                    },
                    Err(code) => abort_reply(index, sub, code),
                }
            }
        }
    }

    fn write_outcome(&mut self, object: Object, data: &[u8]) -> Outcome {
        let value = if object.ty == DataType::String {
            object.ty.decode(data)
        } else {
            let want = object.ty.bits().div_ceil(8);
            // An expedited request without a size indicator always carries four octets.
            let d = if data.len() == 4 && want < 4 {
                &data[..want]
            } else {
                data
            };
            object.ty.decode(d)
        };
        match value {
            Some(v) => Outcome::AskWrite(object, v, None),
            None => abort_reply(object.index, object.subindex, abort::TYPE_LENGTH),
        }
    }

    /// The upload reply for `value`, keeping what does not fit for segments.
    pub fn upload_reply(&mut self, index: u16, sub: u8, value: &[u8], mailbox: usize) -> Outcome {
        let (data, rest) = coe::upload_response(index, sub, value, mailbox);
        self.upload = (!rest.is_empty()).then_some((false, rest));
        Outcome::Reply(data)
    }

    /// Whether a download segment reply is due for an answered write (the master sent
    /// segments, so the final reply is a segment reply).
    pub fn finish_write_reply(index: u16, sub: u8, segmented: Option<bool>) -> Vec<u8> {
        match segmented {
            Some(toggle) => coe::download_segment_response(toggle),
            None => coe::download_response(index, sub),
        }
    }
}

/// The JSON describing an object for the model.
pub fn object_json(o: &Object) -> Value {
    json!({
        "index": format!("{:#06x}", o.index),
        "subindex": o.subindex,
        "name": o.name,
        "type": o.ty.name(),
        "access": o.access.name(),
    })
}
