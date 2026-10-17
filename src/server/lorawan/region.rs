//! EU868 regional parameters (LoRaWAN Regional Parameters RP002-1.0.x, §2.4): data rates,
//! payload limits, the RX1 data-rate offset, RX2 and the band. The only region implemented;
//! a region is a table, so adding one is adding a table, not code.
use anyhow::{bail, ensure, Result};

pub const REGION: &str = "EU868";

/// LoRa data rates DR0..DR6 as `(spreading factor, bandwidth kHz)`. DR7 is FSK, which
/// NetGet does not carry.
const DATA_RATES: [(u8, u32); 7] = [
    (12, 125),
    (11, 125),
    (10, 125),
    (9, 125),
    (8, 125),
    (7, 125),
    (7, 250),
];

/// Maximum MACPayload size M per data rate (no repeater).
const MAX_MAC_PAYLOAD: [usize; 7] = [59, 59, 59, 123, 250, 250, 250];

/// The band EU868 devices may use, in Hz.
pub const BAND_MIN_HZ: u64 = 863_000_000;
pub const BAND_MAX_HZ: u64 = 870_000_000;

/// RX2 defaults: 869.525 MHz at DR0.
pub const RX2_FREQUENCY_HZ: u64 = 869_525_000;
pub const RX2_DATA_RATE: u8 = 0;
/// RX1 opens RECEIVE_DELAY1 after the uplink; RX2 a second later. Join Accepts use 5 s / 6 s.
pub const RECEIVE_DELAY1_US: u32 = 1_000_000;
pub const RECEIVE_DELAY2_US: u32 = 2_000_000;
pub const JOIN_ACCEPT_DELAY1_US: u32 = 5_000_000;
pub const JOIN_ACCEPT_DELAY2_US: u32 = 6_000_000;
/// The default join channels a device starts on.
pub const DEFAULT_CHANNELS_HZ: [u64; 3] = [868_100_000, 868_300_000, 868_500_000];
/// Downlink EIRP NetGet asks a gateway for, dBm (the band's 14 dBm limit, 27 dBm on RX2's
/// sub-band is not used).
pub const DOWNLINK_POWER_DBM: i32 = 14;
pub const MAX_TX_POWER_DBM: i32 = 27;

pub fn check_region(name: &str) -> Result<()> {
    ensure!(
        name.eq_ignore_ascii_case(REGION),
        "region {name:?} is not implemented: only EU868 is"
    );
    Ok(())
}

/// `"SF7BW125"` → DR5.
pub fn data_rate_index(datr: &str) -> Result<u8> {
    let upper = datr.to_ascii_uppercase();
    let Some(rest) = upper.strip_prefix("SF") else {
        bail!("data rate {datr:?} is not a LoRa SFxBWy");
    };
    let Some((sf, bw)) = rest.split_once("BW") else {
        bail!("data rate {datr:?} is not a LoRa SFxBWy");
    };
    let (Ok(sf), Ok(bw)) = (sf.parse::<u8>(), bw.parse::<u32>()) else {
        bail!("data rate {datr:?} is not a LoRa SFxBWy");
    };
    match DATA_RATES.iter().position(|&(s, b)| s == sf && b == bw) {
        Some(i) => Ok(i as u8),
        None => bail!("{datr} is not an EU868 data rate"),
    }
}

pub fn data_rate_name(dr: u8) -> Result<String> {
    match DATA_RATES.get(dr as usize) {
        Some((sf, bw)) => Ok(format!("SF{sf}BW{bw}")),
        None => bail!("DR{dr} is not an EU868 LoRa data rate (DR0..DR6)"),
    }
}

pub fn spreading_factor(dr: u8) -> u8 {
    DATA_RATES.get(dr as usize).map(|d| d.0).unwrap_or(12)
}

/// The largest MACPayload at this data rate.
pub fn max_mac_payload(dr: u8) -> usize {
    MAX_MAC_PAYLOAD.get(dr as usize).copied().unwrap_or(59)
}

/// The largest PHYPayload at this data rate (MHDR + MACPayload + MIC).
pub fn max_phy_payload(dr: u8) -> usize {
    max_mac_payload(dr) + 5
}

/// The largest FRMPayload at this data rate when FOpts carries `fopts` bytes
/// (MACPayload = FHDR (7 + FOpts) + FPort (1) + FRMPayload).
pub fn max_frm_payload(dr: u8, fopts: usize) -> usize {
    max_mac_payload(dr).saturating_sub(8 + fopts)
}

/// RX1's data rate for an uplink at `uplink_dr` (EU868: DR − offset, floored at DR0).
pub fn rx1_data_rate(uplink_dr: u8, offset: u8) -> u8 {
    uplink_dr.saturating_sub(offset.min(5))
}

pub fn in_band(freq_hz: u64) -> bool {
    (BAND_MIN_HZ..=BAND_MAX_HZ).contains(&freq_hz)
}

/// The demodulation floor of each spreading factor, in tenths of a dB, for LinkCheckAns.
pub fn required_snr_tenths(dr: u8) -> i32 {
    match spreading_factor(dr) {
        7 => -75,
        8 => -100,
        9 => -125,
        10 => -150,
        11 => -175,
        _ => -200,
    }
}

/// LinkCheckAns margin: how far above the floor the uplink was received, 0..=254 dB.
pub fn link_margin_db(dr: u8, snr_db: f64) -> u8 {
    let margin = (snr_db * 10.0).round() as i32 - required_snr_tenths(dr);
    (margin / 10).clamp(0, 254) as u8
}

pub fn mhz(freq_hz: u64) -> f64 {
    freq_hz as f64 / 1_000_000.0
}

pub fn hz(mhz: f64) -> Result<u64> {
    ensure!(
        mhz.is_finite() && mhz > 0.0 && mhz < 10_000.0,
        "frequency {mhz} MHz is not a frequency"
    );
    Ok((mhz * 1_000_000.0).round() as u64)
}
