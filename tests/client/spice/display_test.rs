//! The client's display decoder against hand-built display messages, laid out as
//! `spice.proto` lays them out: what it applies exactly (solid fills through clip rectangles,
//! bitmaps top-down and bottom-up, 24- and 32-bit, scaled copies, the pixmap cache, copy-bits)
//! and what it counts without pretending to show (compressed images, raster operations it
//! does not implement).
use netget::client::spice::display::{pixel_hex, DisplayModel};
use netget::server::spice::wire::{self, image_type, msg};

fn rect(v: &mut Vec<u8>, top: i32, left: i32, bottom: i32, right: i32) {
    for x in [top, left, bottom, right] {
        v.extend_from_slice(&x.to_le_bytes());
    }
}

fn with_surface(w: u32, h: u32) -> DisplayModel {
    let mut m = DisplayModel::default();
    let change = m
        .handle(
            msg::DISPLAY_SURFACE_CREATE,
            &wire::surface_create(
                0,
                w,
                h,
                wire::SURFACE_FMT_32_XRGB,
                wire::SURFACE_FLAGS_PRIMARY,
            ),
        )
        .unwrap();
    assert!(change.is_some());
    m
}

/// DRAW_FILL with a solid brush, PUT, no mask, through `clips` (none means the box).
fn fill(bbox: (i32, i32, i32, i32), clips: &[(i32, i32, i32, i32)], color: u32) -> Vec<u8> {
    let mut v = 0u32.to_le_bytes().to_vec();
    rect(&mut v, bbox.0, bbox.1, bbox.2, bbox.3);
    if clips.is_empty() {
        v.push(0);
    } else {
        v.push(1);
        v.extend_from_slice(&(clips.len() as u32).to_le_bytes());
        for c in clips {
            rect(&mut v, c.0, c.1, c.2, c.3);
        }
    }
    v.push(1); // solid brush
    v.extend_from_slice(&color.to_le_bytes());
    v.extend_from_slice(&wire::ROPD_OP_PUT.to_le_bytes());
    v.push(0);
    v.extend_from_slice(&[0; 12]);
    v
}

#[test]
fn a_solid_fill_lands_inside_its_clip_rectangles_only() {
    let mut m = with_surface(32, 32);
    m.handle(
        msg::DISPLAY_DRAW_FILL,
        &fill(
            (0, 0, 32, 32),
            &[(0, 0, 8, 8), (24, 24, 32, 32)],
            0x00ff_8000,
        ),
    )
    .unwrap();
    assert_eq!(pixel_hex(&m, 4, 4).as_deref(), Some("#ff8000"));
    assert_eq!(pixel_hex(&m, 28, 28).as_deref(), Some("#ff8000"));
    assert_eq!(pixel_hex(&m, 16, 16).as_deref(), Some("#000000"));
    assert_eq!(m.describe(1)["exact"], true);
}

/// A DRAW_COPY of a `width` x `height` bitmap image of `format` with `rows` already laid out
/// `stride` bytes apart, into `bbox`, from `src`.
#[allow(clippy::too_many_arguments)]
fn copy(
    bbox: (i32, i32, i32, i32),
    src: (i32, i32, i32, i32),
    format: u8,
    flags: u8,
    width: u32,
    height: u32,
    stride: u32,
    rows: &[u8],
    image_flags: u8,
    image_id: u64,
) -> Vec<u8> {
    let mut v = 0u32.to_le_bytes().to_vec();
    rect(&mut v, bbox.0, bbox.1, bbox.2, bbox.3);
    v.push(0);
    v.extend_from_slice(&wire::DRAW_COPY_IMAGE_OFFSET.to_le_bytes());
    rect(&mut v, src.0, src.1, src.2, src.3);
    v.extend_from_slice(&wire::ROPD_OP_PUT.to_le_bytes());
    v.push(wire::SCALE_MODE_NEAREST);
    v.push(0);
    v.extend_from_slice(&[0; 12]);
    v.extend_from_slice(&image_id.to_le_bytes());
    v.push(image_type::BITMAP);
    v.push(image_flags);
    v.extend_from_slice(&width.to_le_bytes());
    v.extend_from_slice(&height.to_le_bytes());
    v.push(format);
    v.push(flags);
    v.extend_from_slice(&width.to_le_bytes());
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&stride.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(rows);
    v
}

#[test]
fn a_bottom_up_24_bit_bitmap_is_placed_right_way_up() {
    let mut m = with_surface(8, 8);
    // 2x2, rows bottom-up, BGR, stride padded to 8: bottom row blue, top row red.
    let rows = [
        0xff, 0, 0, 0xff, 0, 0, 0, 0, // bottom row: blue, blue
        0, 0, 0xff, 0, 0, 0xff, 0, 0, // top row: red, red
    ];
    m.handle(
        msg::DISPLAY_DRAW_COPY,
        &copy(
            (2, 2, 4, 4),
            (0, 0, 2, 2),
            wire::BITMAP_FMT_24BIT,
            0,
            2,
            2,
            8,
            &rows,
            0,
            9,
        ),
    )
    .unwrap();
    assert_eq!(pixel_hex(&m, 2, 2).as_deref(), Some("#ff0000"));
    assert_eq!(pixel_hex(&m, 3, 3).as_deref(), Some("#0000ff"));
    assert_eq!(pixel_hex(&m, 4, 4).as_deref(), Some("#000000"));
}

#[test]
fn a_cached_scaled_bitmap_is_drawn_from_the_cache() {
    let mut m = with_surface(16, 16);
    // A 1x1 green 32-bit bitmap, cached, copied to 1x1, then drawn again from the cache
    // stretched to 4x4.
    let green = [0, 0xff, 0, 0];
    m.handle(
        msg::DISPLAY_DRAW_COPY,
        &copy(
            (0, 0, 1, 1),
            (0, 0, 1, 1),
            wire::BITMAP_FMT_32BIT,
            wire::BITMAP_FLAGS_TOP_DOWN,
            1,
            1,
            4,
            &green,
            wire::IMAGE_FLAGS_CACHE_ME,
            77,
        ),
    )
    .unwrap();
    let mut from_cache = 0u32.to_le_bytes().to_vec();
    rect(&mut from_cache, 8, 8, 12, 12);
    from_cache.push(0);
    from_cache.extend_from_slice(&wire::DRAW_COPY_IMAGE_OFFSET.to_le_bytes());
    rect(&mut from_cache, 0, 0, 1, 1);
    from_cache.extend_from_slice(&wire::ROPD_OP_PUT.to_le_bytes());
    from_cache.push(wire::SCALE_MODE_NEAREST);
    from_cache.push(0);
    from_cache.extend_from_slice(&[0; 12]);
    from_cache.extend_from_slice(&77u64.to_le_bytes());
    from_cache.push(image_type::FROM_CACHE);
    from_cache.push(0);
    from_cache.extend_from_slice(&1u32.to_le_bytes());
    from_cache.extend_from_slice(&1u32.to_le_bytes());
    m.handle(msg::DISPLAY_DRAW_COPY, &from_cache).unwrap();
    for (x, y) in [(8, 8), (11, 11)] {
        assert_eq!(pixel_hex(&m, x, y).as_deref(), Some("#00ff00"), "({x},{y})");
    }
    assert_eq!(pixel_hex(&m, 12, 12).as_deref(), Some("#000000"));
    let r = m.describe(1);
    assert_eq!(r["images"]["from_cache"], 1);
    assert_eq!(r["exact"], true);
}

#[test]
fn copy_bits_moves_pixels_within_the_surface() {
    let mut m = with_surface(16, 16);
    m.handle(
        msg::DISPLAY_DRAW_FILL,
        &fill((0, 0, 2, 2), &[], 0x0000_00ff),
    )
    .unwrap();
    let mut bits = 0u32.to_le_bytes().to_vec();
    rect(&mut bits, 10, 10, 12, 12);
    bits.push(0);
    bits.extend_from_slice(&0i32.to_le_bytes());
    bits.extend_from_slice(&0i32.to_le_bytes());
    m.handle(msg::DISPLAY_COPY_BITS, &bits).unwrap();
    assert_eq!(pixel_hex(&m, 11, 11).as_deref(), Some("#0000ff"));
    assert_eq!(pixel_hex(&m, 1, 1).as_deref(), Some("#0000ff"));
}

#[test]
fn what_cannot_be_decoded_is_counted_and_makes_the_reading_inexact() {
    let mut m = with_surface(16, 16);
    // An LZ_RGB image: counted by type, not drawn.
    let mut lz = copy((0, 0, 4, 4), (0, 0, 4, 4), 0, 0, 4, 4, 16, &[], 0, 5);
    let at = wire::DRAW_COPY_IMAGE_OFFSET as usize + 8;
    lz[at] = image_type::LZ_RGB;
    lz.truncate(at + 10);
    lz.extend_from_slice(&[0; 32]);
    m.handle(msg::DISPLAY_DRAW_COPY, &lz).unwrap();
    // A fill with an XOR raster operation.
    let mut xor = fill((0, 0, 4, 4), &[], 0x00ff_ffff);
    let rop_at = xor.len() - 15;
    xor[rop_at..rop_at + 2].copy_from_slice(&(1u16 << 6).to_le_bytes());
    m.handle(msg::DISPLAY_DRAW_FILL, &xor).unwrap();
    let r = m.describe(2);
    assert_eq!(r["images"]["lz_rgb"], 1, "{r}");
    assert_eq!(r["undecoded"], 2, "{r}");
    assert_eq!(r["exact"], false, "{r}");
    assert_eq!(pixel_hex(&m, 1, 1).as_deref(), Some("#000000"));
}
