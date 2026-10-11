//! The framebuffer as the model sees it: its size, its most common colour, and a grid of
//! each cell's most common colour. Pixels never reach the model.
use ironrdp_session::image::DecodedImage;
use serde_json::{json, Value};
use std::collections::HashMap;

fn hex([r, g, b]: [u8; 3]) -> String {
    format!("#{r:02x}{g:02x}{b:02x}")
}

/// Describe an RGBA framebuffer `width` x `height` pixels, `stride` bytes per row.
pub fn describe_rgba(
    data: &[u8],
    width: usize,
    height: usize,
    stride: usize,
    grid: usize,
) -> Value {
    let grid = grid.clamp(1, width.max(1)).clamp(1, height.max(1));
    let mut counts: HashMap<[u8; 3], u64> = HashMap::new();
    let mut cells: Vec<HashMap<[u8; 3], u64>> = vec![HashMap::new(); grid * grid];
    for y in 0..height {
        let row = &data[y * stride..y * stride + width * 4];
        let gy = y * grid / height;
        for x in 0..width {
            let px = [row[x * 4], row[x * 4 + 1], row[x * 4 + 2]];
            *counts.entry(px).or_default() += 1;
            *cells[gy * grid + x * grid / width].entry(px).or_default() += 1;
        }
    }
    let (dominant, n) = most_common(&counts);
    let total = (width * height).max(1) as f64;
    let rows: Vec<Vec<String>> = cells
        .chunks(grid)
        .map(|row| row.iter().map(|c| hex(most_common(c).0)).collect())
        .collect();
    json!({
        "width": width,
        "height": height,
        "dominant_color": hex(dominant),
        "dominant_share": ((n as f64 / total) * 1000.0).round() / 1000.0,
        "grid": rows,
    })
}

/// The most common colour and its count; ties go to the lowest colour, so the answer does
/// not depend on hash order.
fn most_common(counts: &HashMap<[u8; 3], u64>) -> ([u8; 3], u64) {
    counts
        .iter()
        .max_by_key(|&(px, n)| (*n, std::cmp::Reverse(*px)))
        .map(|(px, n)| (*px, *n))
        .unwrap_or(([0, 0, 0], 0))
}

pub fn describe(image: &DecodedImage, grid: usize) -> Value {
    describe_rgba(
        image.data(),
        usize::from(image.width()),
        usize::from(image.height()),
        image.stride(),
        grid,
    )
}
