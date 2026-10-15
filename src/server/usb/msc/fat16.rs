//! Lay out an LLM-supplied file map as a FAT16 volume, in memory.
//!
//! # Why this exists
//!
//! `usb-msc` used to violate the project's no-storage rule outright: `DiskImage::open_or_create`
//! memory-mapped a real file, defaulting to `./tmp/netget_msc_disk.img` in the process's working
//! directory. The protocol *was* the storage — the model named a path and the filesystem did the
//! rest — and the `usb_msc_read` / `usb_msc_write` events were decorative, because the sectors
//! had already been served from the file before the model was told anything.
//!
//! This is the shape the rule asks for instead: **the protocol owns BOT/SCSI/geometry, the model
//! owns the content.** The model answers `usb_msc_attached` with
//!
//! ```json
//! {"type": "serve_files", "files": [{"name": "hello.txt", "content": "world"}]}
//! ```
//!
//! and this module turns that into the bytes a host reads. Nothing is written to disk, nothing
//! outlives the server, and the only data on the wire is data the model supplied. Structured
//! fields, not base64: names and text, which a model can produce reliably.
//!
//! # Layout
//!
//! 512-byte sectors, one sector per cluster:
//!
//! | LBA | Contents |
//! |---|---|
//! | 0 | Boot sector / BPB |
//! | 1..1+F | FAT #1 |
//! | 1+F..1+2F | FAT #2 |
//! | .. | Root directory (512 entries, 32 sectors) |
//! | .. | Data region; cluster *n* is `data_start + n - 2` |
//!
//! The volume is sized so the **cluster count** lands inside FAT16's 4085..65525 window. That
//! window is the definition of FAT16 — below it a host is required to read the FAT with 12-bit
//! entries, above it with 32-bit ones — so a volume that misses it is not "a small FAT16", it is
//! a volume the host decodes with the wrong entry width.

#[cfg(all(unix, feature = "libusb"))]
use anyhow::{bail, Result};

/// Bytes per sector. Fixed: `READ CAPACITY(10)` reports it and the BPB repeats it.
#[cfg(all(unix, feature = "libusb"))]
pub const BYTES_PER_SECTOR: usize = 512;

#[cfg(all(unix, feature = "libusb"))]
const SECTORS_PER_CLUSTER: u8 = 1;
#[cfg(all(unix, feature = "libusb"))]
const RESERVED_SECTORS: u16 = 1;
#[cfg(all(unix, feature = "libusb"))]
const NUM_FATS: u8 = 2;
#[cfg(all(unix, feature = "libusb"))]
const ROOT_ENTRIES: u16 = 512;
#[cfg(all(unix, feature = "libusb"))]
const FAT_SECTORS: u16 = 32;

/// Default volume size in sectors: 8192 * 512 = 4 MiB, which gives 8095 data clusters.
#[cfg(all(unix, feature = "libusb"))]
pub const DEFAULT_TOTAL_SECTORS: u16 = 8192;

/// Root directory occupies 512 entries of 32 bytes.
#[cfg(all(unix, feature = "libusb"))]
const ROOT_DIR_SECTORS: u32 = (ROOT_ENTRIES as u32 * 32).div_ceil(BYTES_PER_SECTOR as u32);

#[cfg(all(unix, feature = "libusb"))]
const ROOT_DIR_LBA: u32 = RESERVED_SECTORS as u32 + (NUM_FATS as u32 * FAT_SECTORS as u32);

#[cfg(all(unix, feature = "libusb"))]
const DATA_START_LBA: u32 = ROOT_DIR_LBA + ROOT_DIR_SECTORS;

/// One file the model asked for.
#[cfg(all(unix, feature = "libusb"))]
#[derive(Debug, Clone)]
pub struct FileSpec {
    /// 8.3 name. Case is normalised to upper, as FAT stores it.
    pub name: String,
    /// File contents as text. There is no binary form on purpose: a model cannot reliably
    /// produce or read base64, and the project rule forbids putting raw bytes in an action.
    pub content: String,
}

/// Where a cluster's data lives.
#[cfg(all(unix, feature = "libusb"))]
pub fn cluster_lba(cluster: u16) -> u32 {
    DATA_START_LBA + (cluster as u32 - 2) * SECTORS_PER_CLUSTER as u32
}

/// Build a FAT16 volume containing `files` in the root directory.
///
/// `total_sectors` sizes the volume; `volume_label` is the 11-character label a host shows.
/// Files are allocated consecutive clusters from cluster 2, in the order given.
#[cfg(all(unix, feature = "libusb"))]
pub fn build_volume(files: &[FileSpec], total_sectors: u16, volume_label: &str) -> Result<Vec<u8>> {
    if files.len() > ROOT_ENTRIES as usize {
        bail!(
            "{} files do not fit in a {}-entry root directory",
            files.len(),
            ROOT_ENTRIES
        );
    }

    let total = total_sectors as usize;
    if (total as u32) <= DATA_START_LBA {
        bail!(
            "{} sectors is smaller than the {} sectors of metadata a FAT16 volume needs",
            total,
            DATA_START_LBA
        );
    }

    let data_clusters = total as u32 - DATA_START_LBA;
    if !(4085..65525).contains(&data_clusters) {
        bail!(
            "{} sectors gives {} data clusters, outside the FAT16 range 4085..65525; a host \
             would read the FAT with the wrong entry width",
            total,
            data_clusters
        );
    }

    let mut image = vec![0u8; total * BYTES_PER_SECTOR];
    write_boot_sector(&mut image, total_sectors, volume_label);

    // FAT entries 0 and 1 are reserved: the media descriptor and the end-of-chain marker.
    let mut fat = vec![0u16; (FAT_SECTORS as usize * BYTES_PER_SECTOR) / 2];
    fat[0] = 0xFFF8;
    fat[1] = 0xFFFF;

    let mut next_cluster: u16 = 2;
    for (index, file) in files.iter().enumerate() {
        let name = encode_8_3(&file.name)?;
        let data = file.content.as_bytes();

        let clusters_needed = if data.is_empty() {
            0u32
        } else {
            (data.len() as u32).div_ceil(BYTES_PER_SECTOR as u32 * SECTORS_PER_CLUSTER as u32)
        };
        if clusters_needed as u64 + next_cluster as u64 > data_clusters as u64 + 2 {
            bail!(
                "'{}' does not fit in the remaining {} clusters",
                file.name,
                data_clusters as u64 + 2 - next_cluster as u64
            );
        }

        // A zero-length file has no cluster at all; FAT stores first-cluster 0 for it.
        let first_cluster = if clusters_needed == 0 {
            0
        } else {
            next_cluster
        };

        for n in 0..clusters_needed {
            let cluster = next_cluster;
            let offset = cluster_lba(cluster) as usize * BYTES_PER_SECTOR;
            let start = (n as usize) * BYTES_PER_SECTOR * SECTORS_PER_CLUSTER as usize;
            let end = (start + BYTES_PER_SECTOR * SECTORS_PER_CLUSTER as usize).min(data.len());
            let chunk = &data[start..end];
            image
                .get_mut(offset..offset + chunk.len())
                .ok_or_else(|| anyhow::anyhow!("'{}' runs past the end of the volume", file.name))?
                .copy_from_slice(chunk);

            *fat.get_mut(cluster as usize)
                .ok_or_else(|| anyhow::anyhow!("cluster {} is outside the FAT", cluster))? =
                if n + 1 == clusters_needed {
                    0xFFFF // end of chain
                } else {
                    cluster + 1
                };
            next_cluster += 1;
        }

        // Root directory entry.
        let entry_offset = ROOT_DIR_LBA as usize * BYTES_PER_SECTOR + index * 32;
        let entry = image
            .get_mut(entry_offset..entry_offset + 32)
            .ok_or_else(|| anyhow::anyhow!("root directory entry is outside the volume"))?;
        entry[0..11].copy_from_slice(&name);
        entry[11] = 0x20; // archive
        entry[22..24].copy_from_slice(&0u16.to_le_bytes()); // write time 00:00:00
        entry[24..26].copy_from_slice(&0x5821u16.to_le_bytes()); // write date 2024-01-01
        entry[26..28].copy_from_slice(&first_cluster.to_le_bytes());
        entry[28..32].copy_from_slice(&(data.len() as u32).to_le_bytes());
    }

    // Both FAT copies. A host that reads only FAT #2 (they exist to be redundant) must see the
    // same chains.
    let fat_bytes: Vec<u8> = fat.iter().flat_map(|e| e.to_le_bytes()).collect();
    for copy in 0..NUM_FATS as usize {
        let offset = (RESERVED_SECTORS as usize + copy * FAT_SECTORS as usize) * BYTES_PER_SECTOR;
        image
            .get_mut(offset..offset + fat_bytes.len())
            .ok_or_else(|| anyhow::anyhow!("FAT does not fit in the volume"))?
            .copy_from_slice(&fat_bytes);
    }

    Ok(image)
}

#[cfg(all(unix, feature = "libusb"))]
fn write_boot_sector(image: &mut [u8], total_sectors: u16, volume_label: &str) {
    let bs = &mut image[..BYTES_PER_SECTOR];

    bs[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]); // jmp short / nop
    bs[3..11].copy_from_slice(b"MSWIN4.1"); // OEM name

    // BIOS Parameter Block
    bs[11..13].copy_from_slice(&(BYTES_PER_SECTOR as u16).to_le_bytes());
    bs[13] = SECTORS_PER_CLUSTER;
    bs[14..16].copy_from_slice(&RESERVED_SECTORS.to_le_bytes());
    bs[16] = NUM_FATS;
    bs[17..19].copy_from_slice(&ROOT_ENTRIES.to_le_bytes());
    bs[19..21].copy_from_slice(&total_sectors.to_le_bytes());
    bs[21] = 0xF8; // media descriptor: fixed disk
    bs[22..24].copy_from_slice(&FAT_SECTORS.to_le_bytes());
    bs[24..26].copy_from_slice(&32u16.to_le_bytes()); // sectors per track
    bs[26..28].copy_from_slice(&2u16.to_le_bytes()); // heads
    bs[28..32].copy_from_slice(&0u32.to_le_bytes()); // hidden sectors
    bs[32..36].copy_from_slice(&0u32.to_le_bytes()); // total sectors (32-bit), unused

    // Extended BPB
    bs[36] = 0x80; // drive number
    bs[37] = 0x00; // reserved
    bs[38] = 0x29; // extended boot signature
    bs[39..43].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // volume id, fixed on purpose
    bs[43..54].copy_from_slice(&encode_label(volume_label));
    bs[54..62].copy_from_slice(b"FAT16   "); // fs type (advisory)

    bs[510] = 0x55;
    bs[511] = 0xAA;
}

/// An 11-byte, space-padded, upper-case volume label.
#[cfg(all(unix, feature = "libusb"))]
fn encode_label(label: &str) -> [u8; 11] {
    let mut out = [b' '; 11];
    for (slot, byte) in out.iter_mut().zip(
        label
            .to_ascii_uppercase()
            .bytes()
            .filter(|b| b.is_ascii_graphic() || *b == b' '),
    ) {
        *slot = byte;
    }
    out
}

/// Encode a name as an 11-byte 8.3 directory entry name.
///
/// Rejects rather than truncates. A model that asks for `configuration.json` and silently gets
/// `CONFIGUR.JSO` has been lied to, and the file it then tells the user about does not exist.
#[cfg(all(unix, feature = "libusb"))]
fn encode_8_3(name: &str) -> Result<[u8; 11]> {
    let upper = name.trim().to_ascii_uppercase();
    let (base, ext) = match upper.rsplit_once('.') {
        Some((b, e)) => (b, e),
        None => (upper.as_str(), ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        bail!(
            "'{}' is not a valid FAT 8.3 name: at most 8 characters, a dot, and at most 3 more",
            name
        );
    }
    if !base
        .bytes()
        .chain(ext.bytes())
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || b"$%'-_@~`!(){}^#&".contains(&c))
    {
        bail!(
            "'{}' contains characters a FAT 8.3 name cannot hold (letters, digits and \
             $%'-_@~`!(){{}}^#& only)",
            name
        );
    }

    let mut out = [b' '; 11];
    out[..base.len()].copy_from_slice(base.as_bytes());
    out[8..8 + ext.len()].copy_from_slice(ext.as_bytes());
    Ok(out)
}
