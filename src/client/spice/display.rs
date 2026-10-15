//! The display channel as the model sees it: the primary surface, rebuilt from the draw
//! commands this client can apply exactly, plus a count of every command and image the server
//! sent — so a reading is honest about what it could not show.
//!
//! Applied exactly: SURFACE_CREATE/DESTROY of the primary surface, DRAW_FILL with a solid
//! brush, DRAW_COPY of an uncompressed bitmap (32-bit, RGBA, 24-bit; scaled nearest-neighbour
//! when the source and destination differ) or of an image from the pixmap cache, BLACKNESS,
//! WHITENESS, INVERS and COPY_BITS, each through its clip rectangles. Everything else —
//! compressed images (QUIC, LZ, GLZ, JPEG, LZ4), patterns, masks, raster operations other than
//! PUT, streams, text and strokes — is counted, and a reading that includes any of it says
//! `exact: false`. The client asks the server for uncompressed images
//! (`SPICE_MSGC_DISPLAY_PREFERRED_COMPRESSION` OFF) where it offers the choice, which spice-server
//! honours.
//!
//! Every size the server declares is checked before anything is allocated for it: a surface or
//! image above [`MAX_SIDE`] a side or [`MAX_PIXELS`] in all is refused, a bitmap must fit in the
//! message that carries it, and the pixmap cache holds at most [`MAX_CACHE_BYTES`].
use crate::server::spice::wire::{self, image_type, msg, Cursor};
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use tokio::time::Instant;

/// The largest surface or image side accepted.
pub const MAX_SIDE: u32 = 4096;
/// The largest surface or image accepted, in pixels (4 bytes each).
pub const MAX_PIXELS: u64 = 4096 * 2160;
/// The pixmap cache's ceiling, and (in pixels) what DISPLAY_INIT announces to the server.
pub const MAX_CACHE_BYTES: usize = 64 << 20;
/// Clip rectangles accepted on one draw.
pub const MAX_CLIP_RECTS: u32 = 1024;
/// Monitors accepted in one MONITORS_CONFIG.
pub const MAX_MONITORS: u16 = 16;

/// What a display message changed that the model should hear about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    SurfaceCreated {
        width: u32,
        height: u32,
        format: u32,
    },
}

/// An image decoded to BGRX.
#[derive(Clone)]
struct Image {
    width: u32,
    height: u32,
    bgrx: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct Rect {
    top: i64,
    left: i64,
    bottom: i64,
    right: i64,
}

impl Rect {
    fn read(c: &mut Cursor) -> Result<Self> {
        Ok(Rect {
            top: c.i32("rect top")? as i64,
            left: c.i32("rect left")? as i64,
            bottom: c.i32("rect bottom")? as i64,
            right: c.i32("rect right")? as i64,
        })
    }
    fn width(&self) -> i64 {
        self.right - self.left
    }
    fn height(&self) -> i64 {
        self.bottom - self.top
    }
    fn intersect(&self, o: &Rect) -> Rect {
        Rect {
            top: self.top.max(o.top),
            left: self.left.max(o.left),
            bottom: self.bottom.min(o.bottom),
            right: self.right.min(o.right),
        }
    }
    fn is_empty(&self) -> bool {
        self.width() <= 0 || self.height() <= 0
    }
}

struct Surface {
    id: u32,
    width: u32,
    height: u32,
    format: u32,
    bgrx: Vec<u8>,
}

/// The pixmap cache: images the server flagged CACHE_ME, by id, oldest evicted first.
#[derive(Default)]
struct Cache {
    images: HashMap<u64, Image>,
    order: VecDeque<u64>,
    bytes: usize,
}

impl Cache {
    fn insert(&mut self, id: u64, image: Image) {
        let size = image.bgrx.len();
        if size > MAX_CACHE_BYTES {
            return;
        }
        if let Some(old) = self.images.remove(&id) {
            self.bytes -= old.bgrx.len();
            self.order.retain(|i| *i != id);
        }
        while self.bytes + size > MAX_CACHE_BYTES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.images.remove(&oldest) {
                self.bytes -= old.bgrx.len();
            }
        }
        self.bytes += size;
        self.order.push_back(id);
        self.images.insert(id, image);
    }
    fn remove(&mut self, id: u64) {
        if let Some(old) = self.images.remove(&id) {
            self.bytes -= old.bgrx.len();
            self.order.retain(|i| *i != id);
        }
    }
    fn clear(&mut self) {
        *self = Cache::default();
    }
}

pub struct DisplayModel {
    primary: Option<Surface>,
    other_surfaces: u32,
    ops: BTreeMap<&'static str, u64>,
    images: BTreeMap<&'static str, u64>,
    undecoded: u64,
    updates: u64,
    marked: bool,
    monitors: Vec<Value>,
    cache: Cache,
    pub last_update: Instant,
}

impl Default for DisplayModel {
    fn default() -> Self {
        Self {
            primary: None,
            other_surfaces: 0,
            ops: BTreeMap::new(),
            images: BTreeMap::new(),
            undecoded: 0,
            updates: 0,
            marked: false,
            monitors: Vec::new(),
            cache: Cache::default(),
            last_update: Instant::now(),
        }
    }
}

fn op_name(t: u16) -> &'static str {
    match t {
        msg::DISPLAY_MODE => "mode",
        msg::DISPLAY_MARK => "mark",
        msg::DISPLAY_RESET => "reset",
        msg::DISPLAY_COPY_BITS => "copy_bits",
        msg::DISPLAY_INVAL_LIST => "inval_list",
        msg::DISPLAY_INVAL_ALL_PIXMAPS => "inval_all_pixmaps",
        msg::DISPLAY_INVAL_PALETTE => "inval_palette",
        msg::DISPLAY_INVAL_ALL_PALETTES => "inval_all_palettes",
        msg::DISPLAY_STREAM_CREATE => "stream_create",
        msg::DISPLAY_STREAM_DATA => "stream_data",
        msg::DISPLAY_STREAM_CLIP => "stream_clip",
        msg::DISPLAY_STREAM_DESTROY => "stream_destroy",
        msg::DISPLAY_STREAM_DESTROY_ALL => "stream_destroy_all",
        msg::DISPLAY_DRAW_FILL => "fill",
        msg::DISPLAY_DRAW_OPAQUE => "opaque",
        msg::DISPLAY_DRAW_COPY => "copy",
        msg::DISPLAY_DRAW_BLEND => "blend",
        msg::DISPLAY_DRAW_BLACKNESS => "blackness",
        msg::DISPLAY_DRAW_WHITENESS => "whiteness",
        msg::DISPLAY_DRAW_INVERS => "invers",
        msg::DISPLAY_DRAW_ROP3 => "rop3",
        msg::DISPLAY_DRAW_STROKE => "stroke",
        msg::DISPLAY_DRAW_TEXT => "text",
        msg::DISPLAY_DRAW_TRANSPARENT => "transparent",
        msg::DISPLAY_DRAW_ALPHA_BLEND => "alpha_blend",
        msg::DISPLAY_SURFACE_CREATE => "surface_create",
        msg::DISPLAY_SURFACE_DESTROY => "surface_destroy",
        msg::DISPLAY_STREAM_DATA_SIZED => "stream_data_sized",
        msg::DISPLAY_MONITORS_CONFIG => "monitors_config",
        msg::DISPLAY_DRAW_COMPOSITE => "composite",
        _ => "other",
    }
}

fn check_size(what: &str, width: u32, height: u32) -> Result<()> {
    ensure!(
        (1..=MAX_SIDE).contains(&width) && (1..=MAX_SIDE).contains(&height),
        "{what} of {width}x{height}: this client accepts 1 to {MAX_SIDE} pixels a side"
    );
    ensure!(
        u64::from(width) * u64::from(height) <= MAX_PIXELS,
        "{what} of {width}x{height} is above the {MAX_PIXELS} pixel limit"
    );
    Ok(())
}

impl DisplayModel {
    /// Apply one display-channel message. An error means the server declared something this
    /// client refuses to allocate, and ends the channel.
    pub fn handle(&mut self, msg_type: u16, body: &[u8]) -> Result<Option<Change>> {
        let name = op_name(msg_type);
        if name == "other" {
            return Ok(None);
        }
        *self.ops.entry(name).or_default() += 1;
        let mut c = Cursor::new(body);
        match msg_type {
            msg::DISPLAY_SURFACE_CREATE => {
                let id = c.u32("surface id")?;
                let width = c.u32("surface width")?;
                let height = c.u32("surface height")?;
                let format = c.u32("surface format")?;
                let flags = c.u32("surface flags")?;
                if flags & wire::SURFACE_FLAGS_PRIMARY == 0 {
                    self.other_surfaces += 1;
                    return Ok(None);
                }
                check_size("a primary surface", width, height)?;
                self.primary = Some(Surface {
                    id,
                    width,
                    height,
                    format,
                    bgrx: vec![0; width as usize * height as usize * 4],
                });
                self.touch();
                return Ok(Some(Change::SurfaceCreated {
                    width,
                    height,
                    format,
                }));
            }
            msg::DISPLAY_SURFACE_DESTROY => {
                let id = c.u32("surface id")?;
                if self.primary.as_ref().is_some_and(|s| s.id == id) {
                    self.primary = None;
                    self.marked = false;
                } else {
                    self.other_surfaces = self.other_surfaces.saturating_sub(1);
                }
            }
            msg::DISPLAY_MARK => self.marked = true,
            msg::DISPLAY_RESET => {
                self.primary = None;
                self.marked = false;
            }
            msg::DISPLAY_INVAL_ALL_PIXMAPS => self.cache.clear(),
            msg::DISPLAY_INVAL_LIST => {
                let n = c.u16("resource count")?;
                for _ in 0..n {
                    let _kind = c.u8("resource type")?;
                    let id = c.u64("resource id")?;
                    self.cache.remove(id);
                }
            }
            msg::DISPLAY_MONITORS_CONFIG => {
                let n = c.u16("monitor count")?;
                let _max = c.u16("max monitors")?;
                ensure!(n <= MAX_MONITORS, "{n} monitors; at most {MAX_MONITORS}");
                self.monitors.clear();
                for _ in 0..n {
                    let head = json!({
                        "id": c.u32("head id")?,
                        "surface_id": c.u32("head surface")?,
                        "width": c.u32("head width")?,
                        "height": c.u32("head height")?,
                        "x": c.u32("head x")?,
                        "y": c.u32("head y")?,
                    });
                    let _flags = c.u32("head flags")?;
                    self.monitors.push(head);
                }
            }
            msg::DISPLAY_DRAW_FILL
            | msg::DISPLAY_DRAW_COPY
            | msg::DISPLAY_DRAW_BLACKNESS
            | msg::DISPLAY_DRAW_WHITENESS
            | msg::DISPLAY_DRAW_INVERS
            | msg::DISPLAY_COPY_BITS
            | msg::DISPLAY_DRAW_OPAQUE
            | msg::DISPLAY_DRAW_BLEND
            | msg::DISPLAY_DRAW_ROP3
            | msg::DISPLAY_DRAW_STROKE
            | msg::DISPLAY_DRAW_TEXT
            | msg::DISPLAY_DRAW_TRANSPARENT
            | msg::DISPLAY_DRAW_ALPHA_BLEND
            | msg::DISPLAY_DRAW_COMPOSITE => {
                self.touch();
                let applied = self.draw(msg_type, body)?;
                if !applied {
                    self.undecoded += 1;
                }
            }
            msg::DISPLAY_STREAM_DATA | msg::DISPLAY_STREAM_DATA_SIZED => {
                self.touch();
                self.undecoded += 1;
            }
            _ => {}
        }
        Ok(None)
    }

    fn touch(&mut self) {
        self.updates += 1;
        self.last_update = Instant::now();
    }

    /// Apply a draw command to the primary surface. Ok(false) when it cannot be applied
    /// exactly; Ok(true) also for a draw on a surface this client does not keep.
    fn draw(&mut self, msg_type: u16, body: &[u8]) -> Result<bool> {
        let mut c = Cursor::new(body);
        let surface_id = c.u32("surface id")?;
        let bbox = Rect::read(&mut c)?;
        let clip_type = c.u8("clip type")?;
        let clips = if clip_type == 1 {
            let n = c.u32("clip rect count")?;
            ensure!(
                n <= MAX_CLIP_RECTS,
                "{n} clip rects; at most {MAX_CLIP_RECTS}"
            );
            ensure!(
                (n as usize) * 16 <= c.remaining(),
                "{n} clip rects do not fit in the message"
            );
            (0..n)
                .map(|_| Rect::read(&mut c))
                .collect::<Result<Vec<_>>>()?
        } else {
            vec![bbox]
        };
        let Some(primary) = self.primary.as_ref() else {
            return Ok(false);
        };
        if primary.id != surface_id {
            // Off-screen surfaces are not kept; what is copied from them is what counts.
            return Ok(true);
        }
        if primary.format != wire::SURFACE_FMT_32_XRGB && primary.format != 96 {
            return Ok(false);
        }
        let bounds = Rect {
            top: 0,
            left: 0,
            bottom: primary.height as i64,
            right: primary.width as i64,
        };
        let regions: Vec<Rect> = clips
            .iter()
            .map(|r| r.intersect(&bbox).intersect(&bounds))
            .filter(|r| !r.is_empty())
            .collect();
        match msg_type {
            msg::DISPLAY_DRAW_FILL => {
                let brush = c.u8("brush type")?;
                if brush != 1 {
                    return Ok(false);
                }
                let color = c.u32("brush color")?;
                let rop = c.u16("rop")?;
                let mask = Self::read_mask(&mut c)?;
                if rop != wire::ROPD_OP_PUT || mask {
                    return Ok(false);
                }
                let px = [color as u8, (color >> 8) as u8, (color >> 16) as u8, 0];
                self.fill(&regions, |_| px);
                Ok(true)
            }
            msg::DISPLAY_DRAW_BLACKNESS | msg::DISPLAY_DRAW_WHITENESS => {
                if Self::read_mask(&mut c)? {
                    return Ok(false);
                }
                let v = if msg_type == msg::DISPLAY_DRAW_BLACKNESS {
                    0
                } else {
                    255
                };
                self.fill(&regions, |_| [v, v, v, 0]);
                Ok(true)
            }
            msg::DISPLAY_DRAW_INVERS => {
                if Self::read_mask(&mut c)? {
                    return Ok(false);
                }
                self.fill(&regions, |p| [!p[0], !p[1], !p[2], 0]);
                Ok(true)
            }
            msg::DISPLAY_COPY_BITS => {
                let sx = c.i32("source x")? as i64;
                let sy = c.i32("source y")? as i64;
                let snapshot = self.primary.as_ref().map(|s| s.bgrx.clone());
                let Some(src) = snapshot else {
                    return Ok(false);
                };
                let (w, h) = (bounds.right, bounds.bottom);
                self.copy(&regions, |x, y| {
                    let (u, v) = (sx + (x - bbox.left), sy + (y - bbox.top));
                    if u < 0 || v < 0 || u >= w || v >= h {
                        return None;
                    }
                    let i = ((v * w + u) * 4) as usize;
                    Some([src[i], src[i + 1], src[i + 2], 0])
                });
                Ok(true)
            }
            msg::DISPLAY_DRAW_COPY => {
                let image_at = c.u32("image offset")?;
                let src = Rect::read(&mut c)?;
                let rop = c.u16("rop")?;
                let _scale = c.u8("scale mode")?;
                let mask = Self::read_mask(&mut c)?;
                let image = self.image(body, image_at)?;
                let Some(image) = image else {
                    return Ok(false);
                };
                if rop != wire::ROPD_OP_PUT || mask || src.is_empty() || bbox.is_empty() {
                    return Ok(false);
                }
                let (sw, sh) = (src.width(), src.height());
                let (bw, bh) = (bbox.width(), bbox.height());
                let (iw, ih) = (image.width as i64, image.height as i64);
                self.copy(&regions, |x, y| {
                    let u = src.left + (x - bbox.left) * sw / bw;
                    let v = src.top + (y - bbox.top) * sh / bh;
                    if u < 0 || v < 0 || u >= iw || v >= ih {
                        return None;
                    }
                    let i = ((v * iw + u) * 4) as usize;
                    Some([image.bgrx[i], image.bgrx[i + 1], image.bgrx[i + 2], 0])
                });
                Ok(true)
            }
            _ => {
                // Opaque, blend, rop3, transparent, alpha blend and composite carry an image
                // as their first field; it is counted (and cached) even though the draw is not
                // applied.
                if matches!(
                    msg_type,
                    msg::DISPLAY_DRAW_OPAQUE
                        | msg::DISPLAY_DRAW_BLEND
                        | msg::DISPLAY_DRAW_ROP3
                        | msg::DISPLAY_DRAW_TRANSPARENT
                ) {
                    let at = c.u32("image offset")?;
                    let _ = self.image(body, at)?;
                }
                Ok(false)
            }
        }
    }

    /// A QMask: flags, position, image offset. True when a mask image is present.
    fn read_mask(c: &mut Cursor) -> Result<bool> {
        let _flags = c.u8("mask flags")?;
        let _x = c.i32("mask x")?;
        let _y = c.i32("mask y")?;
        Ok(c.u32("mask image")? != 0)
    }

    fn fill(&mut self, regions: &[Rect], f: impl Fn([u8; 4]) -> [u8; 4]) {
        let Some(s) = self.primary.as_mut() else {
            return;
        };
        let w = s.width as i64;
        for r in regions {
            for y in r.top..r.bottom {
                for x in r.left..r.right {
                    let i = ((y * w + x) * 4) as usize;
                    let old = [s.bgrx[i], s.bgrx[i + 1], s.bgrx[i + 2], s.bgrx[i + 3]];
                    s.bgrx[i..i + 4].copy_from_slice(&f(old));
                }
            }
        }
    }

    fn copy(&mut self, regions: &[Rect], src: impl Fn(i64, i64) -> Option<[u8; 4]>) {
        let Some(s) = self.primary.as_mut() else {
            return;
        };
        let w = s.width as i64;
        for r in regions {
            for y in r.top..r.bottom {
                for x in r.left..r.right {
                    if let Some(px) = src(x, y) {
                        let i = ((y * w + x) * 4) as usize;
                        s.bgrx[i..i + 4].copy_from_slice(&px);
                    }
                }
            }
        }
    }

    /// Decode the image at `offset` within `body`, counting its type; `None` when it is a
    /// kind this client does not decode, or a cache miss.
    fn image(&mut self, body: &[u8], offset: u32) -> Result<Option<Image>> {
        if offset == 0 {
            return Ok(None);
        }
        let mut c = Cursor::at(body, offset as usize);
        let id = c.u64("image id")?;
        let kind = c.u8("image type")?;
        let flags = c.u8("image flags")?;
        let width = c.u32("image width")?;
        let height = c.u32("image height")?;
        *self.images.entry(image_type::name(kind)).or_default() += 1;
        let image = match kind {
            image_type::BITMAP => {
                check_size("an image", width, height)?;
                let format = c.u8("bitmap format")?;
                let bflags = c.u8("bitmap flags")?;
                let x = c.u32("bitmap width")?;
                let y = c.u32("bitmap height")?;
                let stride = c.u32("bitmap stride")?;
                if bflags & wire::BITMAP_FLAGS_PAL_FROM_CACHE != 0 {
                    c.u64("palette id")?;
                } else {
                    c.u32("palette offset")?;
                }
                let bpp = match format {
                    wire::BITMAP_FMT_32BIT | wire::BITMAP_FMT_RGBA => 4,
                    wire::BITMAP_FMT_24BIT => 3,
                    _ => return Ok(None),
                };
                ensure!(
                    x == width && y == height,
                    "a {x}x{y} bitmap in a {width}x{height} image"
                );
                ensure!(
                    u64::from(stride) >= u64::from(x) * bpp as u64,
                    "a bitmap stride of {stride} for {x} pixels of {bpp} bytes"
                );
                let size = u64::from(stride) * u64::from(y);
                ensure!(
                    size <= c.remaining() as u64,
                    "a bitmap of {size} bytes in a message with {} left",
                    c.remaining()
                );
                let data = c.bytes(size as usize, "bitmap data")?;
                let top_down = bflags & wire::BITMAP_FLAGS_TOP_DOWN != 0;
                let mut bgrx = Vec::with_capacity(x as usize * y as usize * 4);
                for row in 0..y as usize {
                    let r = if top_down { row } else { y as usize - 1 - row };
                    let line = &data[r * stride as usize..];
                    for px in 0..x as usize {
                        let p = &line[px * bpp..px * bpp + bpp];
                        bgrx.extend_from_slice(&[p[0], p[1], p[2], 0]);
                    }
                }
                Some(Image {
                    width,
                    height,
                    bgrx,
                })
            }
            image_type::FROM_CACHE | image_type::FROM_CACHE_LOSSLESS => {
                self.cache.images.get(&id).cloned()
            }
            _ => None,
        };
        if let Some(img) = &image {
            if flags & wire::IMAGE_FLAGS_CACHE_ME != 0 {
                self.cache.insert(id, img.clone());
            }
        }
        Ok(image)
    }

    pub fn primary_size(&self) -> Option<(u32, u32)> {
        self.primary.as_ref().map(|s| (s.width, s.height))
    }

    /// The reading the model gets: size, colours, a checksum, and what was and was not drawn.
    pub fn describe(&self, grid: usize) -> Value {
        let mut out = match &self.primary {
            Some(s) => describe_bgrx(&s.bgrx, s.width as usize, s.height as usize, grid),
            None => json!({"width": 0, "height": 0}),
        };
        out["surface"] = json!(self.primary.is_some());
        out["marked"] = json!(self.marked);
        out["updates"] = json!(self.updates);
        out["draw_ops"] = json!(self.ops);
        out["images"] = json!(self.images);
        out["undecoded"] = json!(self.undecoded);
        out["exact"] = json!(self.undecoded == 0);
        out["offscreen_surfaces"] = json!(self.other_surfaces);
        out["monitors"] = json!(self.monitors);
        out
    }
}

fn hex([r, g, b]: [u8; 3]) -> String {
    format!("#{r:02x}{g:02x}{b:02x}")
}

/// Size, most common colour and its share, a grid of each cell's most common colour, and an
/// FNV-1a checksum of the RGB bytes. A cell's most common colour, not its average, so a
/// background reads exactly and an edge does not blend two colours into a third.
pub fn describe_bgrx(bgrx: &[u8], width: usize, height: usize, grid: usize) -> Value {
    let grid = grid.clamp(1, width.max(1)).clamp(1, height.max(1));
    let mut counts: HashMap<[u8; 3], u64> = HashMap::new();
    let mut cells: Vec<HashMap<[u8; 3], u64>> = vec![HashMap::new(); grid * grid];
    let mut checksum: u64 = 0xcbf2_9ce4_8422_2325;
    for y in 0..height {
        let gy = y * grid / height;
        for x in 0..width {
            let i = (y * width + x) * 4;
            let px = [bgrx[i + 2], bgrx[i + 1], bgrx[i]];
            for b in px {
                checksum ^= u64::from(b);
                checksum = checksum.wrapping_mul(0x0100_0000_01b3);
            }
            *counts.entry(px).or_default() += 1;
            *cells[gy * grid + x * grid / width].entry(px).or_default() += 1;
        }
    }
    let (dominant, n) = most_common(&counts);
    let rows: Vec<Vec<String>> = cells
        .chunks(grid)
        .map(|row| row.iter().map(|c| hex(most_common(c).0)).collect())
        .collect();
    json!({
        "width": width,
        "height": height,
        "dominant_color": hex(dominant),
        "dominant_share": ((n as f64 / (width * height).max(1) as f64) * 1000.0).round() / 1000.0,
        "distinct_colors": counts.len(),
        "grid": rows,
        "checksum": format!("{checksum:016x}"),
    })
}

fn most_common(counts: &HashMap<[u8; 3], u64>) -> ([u8; 3], u64) {
    counts
        .iter()
        .max_by_key(|&(px, n)| (*n, std::cmp::Reverse(*px)))
        .map(|(px, n)| (*px, *n))
        .unwrap_or(([0, 0, 0], 0))
}

/// The pixel at (x, y) as #rrggbb, for tests and the model's spot checks.
pub fn pixel_hex(model: &DisplayModel, x: u32, y: u32) -> Option<String> {
    let s = model.primary.as_ref()?;
    if x >= s.width || y >= s.height {
        return None;
    }
    let i = ((y * s.width + x) * 4) as usize;
    Some(hex([s.bgrx[i + 2], s.bgrx[i + 1], s.bgrx[i]]))
}
