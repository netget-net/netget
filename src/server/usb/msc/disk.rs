//! Sector storage behind the virtual USB mass storage device.
//!
//! Two backings, and which one is the **default** is the whole point:
//!
//! * [`Backing::Memory`] — a `Vec<u8>` that never touches the filesystem. This is the default,
//!   and it is what an LLM-supplied file map is laid out into
//!   (`super::fat16::build_volume`). Nothing persists, nothing is created in the working
//!   directory, and the only data on the wire is data the model supplied.
//! * [`Backing::Mapped`] — a memory-mapped file, reached only when the caller **names a path**
//!   in `startup_params.disk_image` or in a `mount_disk` action.
//!
//! It used to be file-only, and the default path was `./tmp/netget_msc_disk.img` relative to
//! the process's working directory. That made the protocol *implement storage*, which the
//! project rule forbids: the sectors a host read came from a file on disk, not from the model,
//! and the read/write events were decorative notifications about data nobody had been asked
//! for. A path the caller names is host state the model refers to — the same shape as `proxy`'s
//! `ca_export_path` — and it is opt-in now rather than the default.

#[cfg(all(unix, feature = "libusb"))]
use anyhow::{Context, Result};
#[cfg(all(unix, feature = "libusb"))]
use memmap2::MmapMut;
#[cfg(all(unix, feature = "libusb"))]
use std::fs::OpenOptions;
#[cfg(all(unix, feature = "libusb"))]
use std::path::Path;
#[cfg(all(unix, feature = "libusb"))]
use tracing::{debug, info, trace};

/// Where a `DiskImage`'s sectors actually live.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug)]
enum Backing {
    /// In-process bytes. Nothing is written to the filesystem and nothing outlives the server.
    Memory(Vec<u8>),
    /// A memory-mapped file the caller named.
    Mapped(MmapMut),
}

#[cfg(all(unix, feature = "libusb"))]
impl Backing {
    fn as_slice(&self) -> &[u8] {
        match self {
            Backing::Memory(bytes) => bytes,
            Backing::Mapped(mmap) => mmap,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Backing::Memory(bytes) => bytes,
            Backing::Mapped(mmap) => mmap,
        }
    }

    /// Push writes through to the file, if there is one.
    fn flush(&self) -> Result<()> {
        match self {
            Backing::Memory(_) => Ok(()),
            Backing::Mapped(mmap) => mmap.flush().context("Failed to flush disk writes"),
        }
    }
}

/// Virtual disk: a flat array of sectors, in memory or memory-mapped from a file.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug)]
pub struct DiskImage {
    backing: Backing,
    /// Total number of sectors
    total_sectors: u32,
    /// Bytes per sector (typically 512)
    bytes_per_sector: u32,
}

#[cfg(all(unix, feature = "libusb"))]
impl DiskImage {
    /// Open existing disk image or create new one
    ///
    /// An image that already exists keeps its own size: `default_size_mb` only decides how
    /// large a *newly created* image is. Resizing to a fixed default would silently truncate
    /// or pad a filesystem image the caller supplied, which is exactly the case that matters
    /// (`startup_params.disk_image` pointing at a prepared FAT volume).
    ///
    /// # Arguments
    /// * `path` - Path to disk image file
    /// * `default_size_mb` - Size in megabytes, used only when creating a new image
    ///
    /// # Returns
    /// DiskImage instance with memory-mapped file
    /// A disk whose sectors are held in memory and never written anywhere.
    ///
    /// This is how an LLM-supplied file map becomes a device: `super::fat16::build_volume`
    /// produces the bytes, and this wraps them. `bytes` is rounded up to a whole sector so a
    /// partial trailing sector cannot make `read_sectors` slice past the end.
    pub fn in_memory(mut bytes: Vec<u8>) -> Result<Self> {
        let bytes_per_sector: u32 = 512;

        let rounded = bytes.len().div_ceil(bytes_per_sector as usize) * bytes_per_sector as usize;
        bytes.resize(rounded, 0);

        let total_sectors = u32::try_from(rounded / bytes_per_sector as usize)
            .context("in-memory disk is too large to address in 32-bit sectors")?;
        if total_sectors == 0 {
            anyhow::bail!("in-memory disk is smaller than one 512-byte sector");
        }

        debug!("Created in-memory disk ({} sectors)", total_sectors);

        Ok(Self {
            backing: Backing::Memory(bytes),
            total_sectors,
            bytes_per_sector,
        })
    }

    pub fn open_or_create(path: &Path, default_size_mb: u32) -> Result<Self> {
        let bytes_per_sector: u32 = 512;

        // Open or create file
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            // Explicit: this opens an existing disk image or creates a new one.
            // Truncating would destroy the image's contents, and leaving it
            // unstated is what clippy's suspicious_open_options flags.
            .truncate(false);
        // A symlink planted at the image path must not redirect the mapping outside
        // `image_dir`; `ImageDir::resolve` refuses one it can see, this refuses the race.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(path)
            .context("Failed to open/create disk image file")?;

        let current_size = file.metadata()?.len();
        let size_bytes = if current_size == 0 {
            // Brand-new (or empty) image: use the requested default size.
            let size_bytes = (default_size_mb as u64) * 1024 * 1024;
            file.set_len(size_bytes)
                .context("Failed to set disk image size")?;
            info!(
                "Created disk image {} ({} MB)",
                path.display(),
                default_size_mb
            );
            size_bytes
        } else {
            // Existing image: keep its contents, but round the mapping up to a whole
            // sector so a partial trailing sector cannot make read_sectors slice past
            // the end of the mapping.
            let rounded = current_size.div_ceil(bytes_per_sector as u64) * bytes_per_sector as u64;
            if rounded != current_size {
                file.set_len(rounded)
                    .context("Failed to pad disk image to a sector boundary")?;
            }
            debug!(
                "Opened existing disk image {} ({} bytes)",
                path.display(),
                rounded
            );
            rounded
        };

        // `as u32` truncated: a 4 TiB request produced a sector count that wrapped to a small
        // number, so the device advertised a capacity bearing no relation to the mapping behind
        // it. SCSI READ(10) addresses 32 bits of sectors and nothing larger is representable,
        // so refuse rather than round.
        let total_sectors =
            u32::try_from(size_bytes / bytes_per_sector as u64).with_context(|| {
                format!(
                    "Disk image {} is {} bytes, more than the {} sectors a 32-bit LBA can \
                     address",
                    path.display(),
                    size_bytes,
                    u32::MAX
                )
            })?;
        if total_sectors == 0 {
            anyhow::bail!(
                "Disk image {} is smaller than one 512-byte sector",
                path.display()
            );
        }

        // Memory-map the file
        let mmap =
            unsafe { MmapMut::map_mut(&file).context("Failed to memory-map disk image file")? };

        Ok(Self {
            backing: Backing::Mapped(mmap),
            total_sectors,
            bytes_per_sector,
        })
    }

    /// Get total number of sectors
    pub fn total_sectors(&self) -> u32 {
        self.total_sectors
    }

    /// Get bytes per sector
    pub fn bytes_per_sector(&self) -> u32 {
        self.bytes_per_sector
    }

    /// Read sectors from disk image
    ///
    /// # Arguments
    /// * `lba` - Logical Block Address (sector number)
    /// * `count` - Number of sectors to read
    ///
    /// # Returns
    /// Vector containing sector data
    pub fn read_sectors(&self, lba: u32, count: u32) -> Result<Vec<u8>> {
        // `lba + count` is host-controlled, so it must not be allowed to wrap: a wrapped sum
        // would compare small and then slice out of bounds.
        let end = lba
            .checked_add(count)
            .context("Read beyond disk bounds: LBA + count overflows")?;
        if end > self.total_sectors {
            anyhow::bail!(
                "Read beyond disk bounds: LBA {} + {} > {}",
                lba,
                count,
                self.total_sectors
            );
        }

        // In `usize`, not `u32`. `lba * 512` overflows 32 bits at 4 GiB, which is well inside
        // what `mount_disk` accepts -- a debug or test build panicked on the multiply and a
        // release build wrapped to a small offset and served the wrong sectors. Nothing here
        // is bounded by 32 bits except the LBA itself, which SCSI READ(10) defines that way.
        let offset = lba as usize * self.bytes_per_sector as usize;
        let length = count as usize * self.bytes_per_sector as usize;

        trace!(
            "Reading {} sectors from LBA {} (offset {}, length {})",
            count,
            lba,
            offset,
            length
        );

        Ok(self.backing.as_slice()[offset..offset + length].to_vec())
    }

    /// Write sectors to disk image
    ///
    /// # Arguments
    /// * `lba` - Logical Block Address (sector number)
    /// * `data` - Data to write (will be padded to sector boundary if needed)
    ///
    /// # Returns
    /// Number of sectors written
    pub fn write_sectors(&mut self, lba: u32, data: &[u8]) -> Result<u32> {
        let count = u32::try_from(data.len().div_ceil(self.bytes_per_sector as usize))
            .context("Write payload is too large to address in sectors")?;

        let end = lba
            .checked_add(count)
            .context("Write beyond disk bounds: LBA + count overflows")?;
        if end > self.total_sectors {
            anyhow::bail!(
                "Write beyond disk bounds: LBA {} + {} > {}",
                lba,
                count,
                self.total_sectors
            );
        }

        let offset = lba as usize * self.bytes_per_sector as usize;
        let length = data.len();

        trace!(
            "Writing {} bytes ({} sectors) to LBA {} (offset {})",
            length,
            count,
            lba,
            offset
        );

        self.backing.as_mut_slice()[offset..offset + length].copy_from_slice(data);

        // Push through to the file, if this disk has one.
        self.backing.flush()?;

        Ok(count)
    }

    /// Zero out a range of sectors
    ///
    /// # Arguments
    /// * `lba` - Starting sector
    /// * `count` - Number of sectors to zero
    #[allow(dead_code)]
    pub fn zero_sectors(&mut self, lba: u32, count: u32) -> Result<()> {
        let end = lba
            .checked_add(count)
            .context("Zero beyond disk bounds: LBA + count overflows")?;
        if end > self.total_sectors {
            anyhow::bail!(
                "Zero beyond disk bounds: LBA {} + {} > {}",
                lba,
                count,
                self.total_sectors
            );
        }

        let offset = lba as usize * self.bytes_per_sector as usize;
        let length = count as usize * self.bytes_per_sector as usize;

        debug!("Zeroing {} sectors from LBA {}", count, lba);

        self.backing.as_mut_slice()[offset..offset + length].fill(0);
        self.backing.flush()?;

        Ok(())
    }
}
