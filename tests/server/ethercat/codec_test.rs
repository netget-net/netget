//! The EtherCAT codec and the emulated ESC against literal frames and the rules of
//! ETG.1000.4/6: datagram layout, working counters for every command, addressing, SyncManager
//! access rules, FMMU bit mapping, the SII through the EEPROM registers, the AL state machine,
//! CoE SDO transfers, and every declared bound. No network, no model.
use netget::server::ethercat::coe::{self, abort, SdoRequest, SdoResponse};
use netget::server::ethercat::device::{self, DataType, DeviceSpec, Image};
use netget::server::ethercat::esc::{self, al_code, state, Esc, EscEvent};
use netget::server::ethercat::frame::{self, cmd, Datagram, FrameError};
use netget::server::ethercat::sdo::{Outcome, SdoServer};
use netget::server::ethercat::sii;
use serde_json::json;

fn dev() -> DeviceSpec {
    DeviceSpec::parse(&super::support::slave_params()["slaves"][0], 0).unwrap()
}

fn chain(n: usize) -> Vec<Esc> {
    (0..n).map(|i| Esc::new(i, n, dev(), 128)).collect()
}

/// Run datagrams through the chain; return them as they came back.
fn run(chain: &mut [Esc], dgs: Vec<Datagram>) -> Vec<Datagram> {
    let mut p = frame::encode(&dgs).unwrap();
    esc::process_frame(chain, &mut p).unwrap();
    frame::decode(&p).unwrap()
}

fn one(chain: &mut [Esc], d: Datagram) -> Datagram {
    run(chain, vec![d]).remove(0)
}

fn fpwr(chain: &mut [Esc], station: u16, ado: u16, data: Vec<u8>) -> u16 {
    one(chain, Datagram::physical(cmd::FPWR, station, ado, data)).wkc
}

fn fprd(chain: &mut [Esc], station: u16, ado: u16, len: usize) -> Datagram {
    one(
        chain,
        Datagram::physical(cmd::FPRD, station, ado, vec![0; len]),
    )
}

/// Give slave `i` station address 0x1001 + i.
fn address(chain: &mut [Esc]) {
    for i in 0..chain.len() {
        let adp = 0u16.wrapping_sub(i as u16);
        let d = one(
            chain,
            Datagram::physical(
                cmd::APWR,
                adp,
                0x0010,
                (0x1001 + i as u16).to_le_bytes().to_vec(),
            ),
        );
        assert_eq!(d.wkc, 1);
    }
}

fn sm_bytes(start: u16, len: u16, control: u8, enable: bool) -> Vec<u8> {
    let mut b = start.to_le_bytes().to_vec();
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(&[control, 0, enable as u8, 0]);
    b
}

/// Program the mailbox SyncManagers as the SII says and go to PRE-OP (accepting).
fn to_preop(chain: &mut [Esc], station: u16) {
    let l = chain[0].layout;
    let mut sms = sm_bytes(l.sm[0].start, l.sm[0].length, l.sm[0].control, true);
    sms.extend(sm_bytes(
        l.sm[1].start,
        l.sm[1].length,
        l.sm[1].control,
        true,
    ));
    assert_eq!(fpwr(chain, station, 0x0800, sms), 1);
    assert_eq!(fpwr(chain, station, 0x0120, vec![state::PREOP, 0]), 1);
    let i = (station - 0x1001) as usize;
    let ev = chain[i].take_events();
    assert!(
        ev.contains(&EscEvent::StateRequest {
            from: state::INIT,
            to: state::PREOP
        }),
        "{ev:?}"
    );
    assert!(chain[i].resolve_transition(state::PREOP, Ok(())));
    assert_eq!(chain[i].al_state(), state::PREOP);
}

#[test]
fn a_datagram_has_the_iec_61158_layout() {
    let p = frame::encode(&[Datagram::physical(cmd::BRD, 0, 0x0000, vec![0, 0])]).unwrap();
    assert_eq!(
        p,
        vec![
            0x0E, 0x10, // 14 octets of datagrams, type 1
            0x07, 0x00, // BRD, index 0
            0x00, 0x00, 0x00, 0x00, // ADP 0, ADO 0
            0x02, 0x00, // length 2, last
            0x00, 0x00, // IRQ
            0x00, 0x00, // data
            0x00, 0x00, // working counter
        ]
    );
    let two = frame::encode(&[
        Datagram::physical(cmd::FPRD, 0x1001, 0x0130, vec![0; 2]),
        Datagram::logical(cmd::LRW, 0x0001_0000, vec![0; 3]),
    ])
    .unwrap();
    let ds = frame::parse(&two).unwrap();
    assert_eq!(ds.len(), 2);
    assert_eq!(
        two[8..10],
        [0x02, 0x80],
        "the first datagram says another follows"
    );
    assert_eq!(ds[0].adp(&two), 0x1001);
    assert_eq!(ds[0].ado(&two), 0x0130);
    assert_eq!(ds[1].logical(&two), 0x0001_0000);
}

#[test]
fn frames_outside_the_bounds_are_refused() {
    // 65 empty datagrams: legal octets, more than MAX_DATAGRAMS.
    let many: Vec<Datagram> = (0..65)
        .map(|_| Datagram::physical(cmd::NOP, 0, 0, vec![]))
        .collect();
    assert_eq!(frame::encode(&many), Err(FrameError::TooManyDatagrams));
    let mut p = frame::encode(&many[..64]).unwrap();
    // Chain a 65th by hand.
    let more_at = p.len() - 12 + 6;
    p[more_at + 1] |= 0x80;
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let len = (p.len() - 2) as u16 | 0x1000;
    p[..2].copy_from_slice(&len.to_le_bytes());
    assert_eq!(frame::parse(&p), Err(FrameError::TooManyDatagrams));

    let ok = frame::encode(&[Datagram::physical(cmd::BRD, 0, 0, vec![0; 4])]).unwrap();
    let mut lie = ok.clone();
    lie[0] = 0xFF; // declares more than is there
    assert!(matches!(
        frame::parse(&lie),
        Err(FrameError::LengthBeyondPayload { .. })
    ));
    let mut long = ok.clone();
    long[8] = 0xFF; // the datagram claims 255 octets of data
    assert!(matches!(
        frame::parse(&long),
        Err(FrameError::DatagramBeyondFrame { .. })
    ));
    let mut mailbox_type = ok.clone();
    mailbox_type[1] = 0x50; // type 5: mailbox gateway, not commands
    assert_eq!(frame::parse(&mailbox_type), Err(FrameError::NotCommands(5)));
    let big = vec![0u8; frame::MAX_DATAGRAM_DATA + 1];
    assert!(frame::encode(&[Datagram::physical(cmd::BWR, 0, 0, big)]).is_err());
    assert!(frame::encode(&[Datagram::physical(
        cmd::BWR,
        0,
        0,
        vec![0; frame::MAX_DATAGRAM_DATA]
    )])
    .is_ok());
}

#[test]
fn broadcast_reads_count_every_slave_and_or_their_data() {
    let mut c = chain(3);
    let d = one(&mut c, Datagram::physical(cmd::BRD, 0, 0x0000, vec![0; 1]));
    assert_eq!(d.wkc, 3, "one per slave: this is how a master counts them");
    assert_eq!(d.data, vec![0x04]);
    let w = one(&mut c, Datagram::physical(cmd::BWR, 0, 0x0138, vec![1]));
    assert_eq!(w.wkc, 3);
    let rw = one(&mut c, Datagram::physical(cmd::BRW, 0, 0x0138, vec![0]));
    assert_eq!(rw.wkc, 9, "read +1 and write +2 at each of three slaves");
    assert_eq!(rw.data, vec![1], "read data ORed, before the write");
}

#[test]
fn position_and_station_addressing_reach_exactly_one_slave() {
    let mut c = chain(3);
    address(&mut c);
    for i in 0..3u16 {
        let d = one(
            &mut c,
            Datagram::physical(cmd::APRD, 0u16.wrapping_sub(i), 0x0010, vec![0; 2]),
        );
        assert_eq!(d.wkc, 1);
        assert_eq!(d.data, (0x1001 + i).to_le_bytes());
        // Every slave incremented the position on the way.
        assert_eq!(d.address & 0xFFFF, (3u16.wrapping_sub(i)) as u32);
    }
    assert_eq!(fprd(&mut c, 0x1002, 0x0010, 2).wkc, 1);
    assert_eq!(fprd(&mut c, 0x2000, 0x0010, 2).wkc, 0, "nobody has 0x2000");
    let rw = one(
        &mut c,
        Datagram::physical(cmd::FPRW, 0x1003, 0x0138, vec![0x01]),
    );
    assert_eq!(rw.wkc, 3, "read-write: 1 for the read, 2 for the write");
    // ARMW: the addressed slave reads, every other slave writes what it read.
    let armw = one(&mut c, Datagram::physical(cmd::ARMW, 0, 0x0010, vec![0; 2]));
    assert_eq!(armw.wkc, 3);
    assert_eq!(armw.data, 0x1001u16.to_le_bytes());
    // The alias answers only when DL control enables it.
    let alias = c[1].station_address();
    let _ = alias;
    assert_eq!(fprd(&mut c, 0, 0x0010, 2).wkc, 0);
}

#[test]
fn read_only_registers_ignore_a_write_and_still_count_it() {
    let mut c = chain(1);
    address(&mut c);
    assert_eq!(fpwr(&mut c, 0x1001, 0x0000, vec![0x55]), 1);
    assert_eq!(fprd(&mut c, 0x1001, 0x0000, 1).data, vec![0x04]);
    // AL status is not writable by the master.
    assert_eq!(fpwr(&mut c, 0x1001, 0x0130, vec![0x08, 0]), 1);
    assert_eq!(fprd(&mut c, 0x1001, 0x0130, 1).data, vec![state::INIT]);
}

#[test]
fn the_sii_reads_back_through_the_eeprom_registers() {
    let mut c = chain(1);
    address(&mut c);
    let ctl = fprd(&mut c, 0x1001, 0x0502, 2).data;
    assert_eq!(ctl[0] & 0x40, 0x40, "8-octet reads");
    // Read command (0x0100) and word address 8 in one write, as SOEM and ethercrab send it.
    assert_eq!(
        fpwr(&mut c, 0x1001, 0x0502, vec![0x00, 0x01, 8, 0, 0, 0]),
        1
    );
    let st = fprd(&mut c, 0x1001, 0x0502, 2).data;
    assert_eq!(st[1] & 0x80, 0, "never busy");
    let data = fprd(&mut c, 0x1001, 0x0508, 8).data;
    assert_eq!(&data[..4], &0x0000_0ABCu32.to_le_bytes(), "vendor ID");
    assert_eq!(&data[4..], &0x0001_2345u32.to_le_bytes(), "product code");
    // A write command is refused: the SII is read-only.
    fpwr(&mut c, 0x1001, 0x0502, vec![0x01, 0x02, 8, 0, 0, 0]);
    let st = fprd(&mut c, 0x1001, 0x0502, 2).data;
    assert_ne!(u16::from_le_bytes([st[0], st[1]]) & 0x2000, 0);

    let image = c[0].sii().to_vec();
    let info = sii::parse(&image).unwrap();
    assert!(info.checksum_ok);
    assert_eq!(info.vendor_id, 0xABC);
    assert_eq!(info.product_code, 0x12345);
    assert_eq!(info.revision, 7);
    assert_eq!(info.serial, 99);
    assert_eq!(info.name.as_deref(), Some("NetGet Test Slave"));
    assert!(info.has_coe());
    assert_eq!(info.rx_mailbox, (0x1000, 128));
    assert_eq!(info.tx_mailbox, (0x1080, 128));
    assert_eq!(info.sync_managers.len(), 4);
    assert_eq!(info.sync_managers[2].length, 3, "1 + 16 bits of outputs");
    assert_eq!(info.sync_managers[3].length, 3, "16 + 1 bits of inputs");
    assert_eq!(info.fmmu_usage[..3], [1, 2, 3]);
    let inputs = sii::image_of(&info.txpdos);
    assert_eq!(
        inputs.describe(),
        json!([{"name": "count", "type": "u16"}, {"name": "ready", "type": "bool"}])
    );
    let outputs = sii::image_of(&info.rxpdos);
    assert_eq!(
        outputs.entries[1].bit_offset, 1,
        "setpoint follows the 1-bit bool"
    );
    // The configuration area's CRC covers words 0-6; a changed alias must change it.
    let mut d2 = dev();
    d2.alias = 5;
    let other = Esc::new(0, 1, d2, 128);
    assert_ne!(other.sii()[14], image[14]);
}

#[test]
fn a_category_chain_that_does_not_end_is_bounded() {
    let mut img = vec![0u8; 128];
    for _ in 0..70 {
        img.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // type 1, length 0
    }
    img.extend_from_slice(&[0xFF, 0xFF]);
    assert!(sii::chain_end(&img).is_err(), "more than 64 categories");
    let mut huge = vec![0u8; 128];
    huge.extend_from_slice(&[0x0A, 0x00, 0xFF, 0x7F]); // a 64 KiB strings category
    assert!(sii::chain_end(&huge).is_err(), "runs past 8 KiB");
}

#[test]
fn the_al_state_machine_checks_before_it_asks() {
    let mut c = chain(1);
    address(&mut c);
    // Skipping a state.
    fpwr(&mut c, 0x1001, 0x0120, vec![state::SAFEOP, 0]);
    assert_eq!(c[0].al_error(), Some(al_code::INVALID_STATE_CHANGE));
    let st = fprd(&mut c, 0x1001, 0x0130, 6).data;
    assert_eq!(st[0], state::INIT | state::ERROR);
    assert_eq!(u16::from_le_bytes([st[4], st[5]]), 0x0011);
    // Without acknowledging the error nothing happens.
    fpwr(&mut c, 0x1001, 0x0120, vec![state::PREOP, 0]);
    assert!(c[0]
        .take_events()
        .iter()
        .all(|e| !matches!(e, EscEvent::StateRequest { .. })));
    // Acknowledged, but the mailbox SyncManagers are not programmed.
    fpwr(&mut c, 0x1001, 0x0120, vec![state::PREOP | 0x10, 0]);
    assert_eq!(c[0].al_error(), Some(al_code::INVALID_MAILBOX_CONFIG));
    // Bootstrap is not offered.
    fpwr(&mut c, 0x1001, 0x0120, vec![state::BOOT | 0x10, 0]);
    assert_eq!(c[0].al_error(), Some(al_code::BOOTSTRAP_NOT_SUPPORTED));
    fpwr(&mut c, 0x1001, 0x0120, vec![state::INIT | 0x10, 0]);
    assert_eq!(c[0].al_error(), None);
    to_preop(&mut c, 0x1001);
    // PRE-OP → SAFE-OP with the process data SyncManagers right, the model accepting, and no
    // inputs ever set: the slave refuses rather than report zeros nobody chose.
    let l = c[0].layout;
    fpwr(
        &mut c,
        0x1001,
        0x0810,
        sm_bytes(l.sm[2].start, 3, 0x64, true),
    );
    fpwr(
        &mut c,
        0x1001,
        0x0818,
        sm_bytes(l.sm[3].start, 3, 0x20, true),
    );
    fpwr(&mut c, 0x1001, 0x0120, vec![state::SAFEOP, 0]);
    assert!(c[0].take_events().contains(&EscEvent::StateRequest {
        from: state::PREOP,
        to: state::SAFEOP
    }));
    assert!(c[0].resolve_transition(state::SAFEOP, Ok(())));
    assert_eq!(c[0].al_state(), state::PREOP);
    assert_eq!(c[0].al_error(), Some(al_code::NO_VALID_INPUTS));
    // A refusal the model chose carries its code.
    fpwr(&mut c, 0x1001, 0x0120, vec![state::SAFEOP | 0x10, 0]);
    c[0].take_events();
    assert!(c[0].resolve_transition(state::SAFEOP, Err(0x001E)));
    assert_eq!(c[0].al_error(), Some(0x001E));
    // A late answer for a request the master replaced is ignored.
    fpwr(&mut c, 0x1001, 0x0120, vec![state::PREOP | 0x10, 0]);
    assert!(!c[0].resolve_transition(state::SAFEOP, Ok(())));
    // A wrong output SyncManager length is caught before the model is asked.
    fpwr(
        &mut c,
        0x1001,
        0x0810,
        sm_bytes(l.sm[2].start, 2, 0x64, true),
    );
    fpwr(&mut c, 0x1001, 0x0120, vec![state::SAFEOP, 0]);
    assert_eq!(c[0].al_error(), Some(al_code::INVALID_OUTPUT_CONFIG));
}

#[test]
fn process_data_maps_through_fmmus_with_exact_working_counters() {
    let mut c = chain(1);
    address(&mut c);
    to_preop(&mut c, 0x1001);
    let l = c[0].layout;
    fpwr(
        &mut c,
        0x1001,
        0x0810,
        sm_bytes(l.sm[2].start, 3, 0x64, true),
    );
    fpwr(
        &mut c,
        0x1001,
        0x0818,
        sm_bytes(l.sm[3].start, 3, 0x20, true),
    );
    // FMMU0: logical 0..3 → outputs (write); FMMU1: logical 3..6 → inputs (read).
    let fmmu = |log: u32, phys: u16, ty: u8| {
        let mut b = log.to_le_bytes().to_vec();
        b.extend_from_slice(&3u16.to_le_bytes());
        b.extend_from_slice(&[0, 7]);
        b.extend_from_slice(&phys.to_le_bytes());
        b.extend_from_slice(&[0, ty, 1, 0, 0, 0]);
        b
    };
    fpwr(&mut c, 0x1001, 0x0600, fmmu(0, l.sm[2].start, 2));
    fpwr(&mut c, 0x1001, 0x0610, fmmu(3, l.sm[3].start, 1));
    // PRE-OP: the process data SyncManagers are deactivated by the slave, so nothing counts.
    let d = one(&mut c, Datagram::logical(cmd::LRW, 0, vec![0; 6]));
    assert_eq!(d.wkc, 0);
    let mut img = vec![0u8; 3];
    c[0].device
        .inputs
        .encode_into(
            json!({"count": 42, "ready": true}).as_object().unwrap(),
            &mut img,
        )
        .unwrap();
    assert_eq!(img, vec![42, 0, 1], "u16 then a bool at bit 16");
    c[0].set_inputs(&img);
    fpwr(&mut c, 0x1001, 0x0120, vec![state::SAFEOP, 0]);
    c[0].take_events();
    assert!(c[0].resolve_transition(state::SAFEOP, Ok(())));
    assert_eq!(c[0].al_state(), state::SAFEOP);
    // motor_on (bit 0) and setpoint 300 (bits 1-16): 1 | 300 << 1 = 601.
    let out = [0x59, 0x02, 0x00];
    let mut data = out.to_vec();
    data.extend_from_slice(&[0, 0, 0]);
    let d = one(&mut c, Datagram::logical(cmd::LRW, 0, data));
    assert_eq!(d.wkc, 3, "outputs written (+2), inputs read (+1)");
    assert_eq!(&d.data[3..], &[42, 0, 1]);
    let outputs: Vec<_> = c[0]
        .take_events()
        .into_iter()
        .filter_map(|e| match e {
            EscEvent::Outputs(o) => Some(o),
            _ => None,
        })
        .collect();
    assert_eq!(outputs.len(), 1);
    let decoded = c[0].device.outputs.decode(&outputs[0][..3]);
    assert_eq!(decoded["motor_on"], json!(true));
    assert_eq!(decoded["setpoint"], json!(300));
    assert_eq!(
        one(&mut c, Datagram::logical(cmd::LRD, 3, vec![0; 3])).wkc,
        1
    );
    assert_eq!(
        one(&mut c, Datagram::logical(cmd::LWR, 0, out.to_vec())).wkc,
        1
    );
    // A datagram outside every FMMU touches nothing.
    assert_eq!(
        one(&mut c, Datagram::logical(cmd::LRW, 100, vec![0; 4])).wkc,
        0
    );
    // Outputs have arrived in SAFE-OP, so OP may be asked for.
    fpwr(&mut c, 0x1001, 0x0120, vec![state::OP, 0]);
    assert!(c[0].take_events().contains(&EscEvent::StateRequest {
        from: state::SAFEOP,
        to: state::OP
    }));
}

#[test]
fn bit_granular_fmmus_map_single_bits() {
    let mut c = chain(1);
    address(&mut c);
    to_preop(&mut c, 0x1001);
    let l = c[0].layout;
    fpwr(
        &mut c,
        0x1001,
        0x0818,
        sm_bytes(l.sm[3].start, 3, 0x20, true),
    );
    fpwr(
        &mut c,
        0x1001,
        0x0810,
        sm_bytes(l.sm[2].start, 3, 0x64, true),
    );
    // Map only the `ready` bit (physical bit 16) to logical bit 5 of octet 0.
    let mut f = 0u32.to_le_bytes().to_vec();
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&[5, 5]);
    f.extend_from_slice(&(l.sm[3].start + 2).to_le_bytes());
    f.extend_from_slice(&[0, 1, 1, 0, 0, 0]);
    fpwr(&mut c, 0x1001, 0x0600, f);
    c[0].set_inputs(&[0xFF, 0xFF, 0x01]);
    fpwr(&mut c, 0x1001, 0x0120, vec![state::SAFEOP, 0]);
    c[0].take_events();
    c[0].resolve_transition(state::SAFEOP, Ok(()));
    let d = one(&mut c, Datagram::logical(cmd::LRD, 0, vec![0]));
    assert_eq!(d.wkc, 1);
    assert_eq!(d.data, vec![0x20], "only bit 5 set");
}

#[test]
fn mailbox_syncmanagers_refuse_what_their_state_forbids() {
    let mut c = chain(1);
    address(&mut c);
    to_preop(&mut c, 0x1001);
    // Nothing to read yet.
    assert_eq!(fprd(&mut c, 0x1001, 0x1080, 128).wkc, 0);
    let req = coe::coe_mailbox(1, coe::upload_request(0x1018, 1)).encode(128);
    assert_eq!(fpwr(&mut c, 0x1001, 0x1000, req.clone()), 1);
    let ev = c[0].take_events();
    assert!(matches!(ev.as_slice(), [EscEvent::Mailbox(_)]));
    // Until the slave has read it, the receive mailbox is full.
    assert_eq!(fpwr(&mut c, 0x1001, 0x1000, req.clone()), 0);
    let st = fprd(&mut c, 0x1001, 0x0805, 1).data;
    assert_eq!(st[0] & 0x08, 0x08);
    c[0].mailbox_consumed();
    c[0].post_mailbox(coe::coe_mailbox(1, coe::download_response(0x1018, 1)).encode(128));
    assert_eq!(fprd(&mut c, 0x1001, 0x080D, 1).data[0] & 0x08, 0x08);
    let back = fprd(&mut c, 0x1001, 0x1080, 128);
    assert_eq!(back.wkc, 1);
    assert_eq!(
        fprd(&mut c, 0x1001, 0x1080, 128).wkc,
        0,
        "emptied by the read"
    );
    // The repeat request hands the last reply back.
    let act = fprd(&mut c, 0x1001, 0x080E, 1).data[0];
    fpwr(&mut c, 0x1001, 0x080E, vec![act ^ 0x02]);
    assert_eq!(fprd(&mut c, 0x1001, 0x1080, 128).data, back.data);
    assert_eq!(
        fprd(&mut c, 0x1001, 0x080F, 1).data[0] & 0x02,
        (act ^ 0x02) & 0x02
    );
    // Replies beyond the queue are dropped, and counted.
    for _ in 0..(esc::MAILBOX_QUEUE + 3) {
        c[0].post_mailbox(vec![0; 128]);
    }
    assert!(c[0].mailbox_dropped > 0);
    // A send mailbox the master moved past the end of the memory takes nothing (and the
    // slave survives putting a reply there).
    let before = c[0].mailbox_dropped;
    fpwr(&mut c, 0x1001, 0x0808, sm_bytes(0x2FC0, 0x0100, 0x22, false));
    fpwr(&mut c, 0x1001, 0x0808, sm_bytes(0x2FC0, 0x0100, 0x22, true));
    c[0].post_mailbox(vec![0; 256]);
    assert!(c[0].mailbox_dropped > before);
}

#[test]
fn a_mailbox_header_may_not_claim_more_than_its_syncmanager() {
    let mut area = vec![0u8; 64];
    area[0] = 200;
    assert!(coe::Mailbox::parse(&area).is_err());
    area[0] = 58;
    assert!(coe::Mailbox::parse(&area).is_ok());
}

#[test]
fn sdo_frames_have_the_etg_1000_6_layout() {
    // An expedited upload answer of 0x1018:1 = 0x00000ABC.
    let (d, rest) = coe::upload_response(0x1018, 1, &0xABCu32.to_le_bytes(), 128);
    assert!(rest.is_empty());
    assert_eq!(
        d,
        vec![0x00, 0x30, 0x43, 0x18, 0x10, 0x01, 0xBC, 0x0A, 0x00, 0x00]
    );
    // A one-octet answer says how many of the four are unused.
    let (d, _) = coe::upload_response(0x1C12, 0, &[1], 128);
    assert_eq!(d[2], 0x4F);
    // An expedited two-octet download request.
    let (d, rest) = coe::download_request(0x8000, 1, &1200u16.to_le_bytes(), 128);
    assert!(rest.is_empty());
    assert_eq!(
        d,
        vec![0x00, 0x20, 0x2B, 0x00, 0x80, 0x01, 0xB0, 0x04, 0x00, 0x00]
    );
    assert_eq!(
        coe::abort_response(0x8000, 1, abort::VALUE_HIGH),
        vec![0x00, 0x20, 0x80, 0x00, 0x80, 0x01, 0x31, 0x00, 0x09, 0x06]
    );
    // A mailbox header: length, address, channel/priority, type 3 with counter 2.
    let m = coe::coe_mailbox(2, d).encode(64);
    assert_eq!(&m[..6], &[10, 0, 0, 0, 0, 0x23]);
    assert_eq!(m.len(), 64);
}

#[test]
fn the_sdo_server_answers_the_structure_and_asks_about_the_rest() {
    let d = dev();
    let mut s = SdoServer::default();
    let up = |s: &mut SdoServer, index: u16, sub: u8| {
        s.handle(
            &d,
            SdoRequest::Upload {
                index,
                subindex: sub,
                complete_access: false,
            },
            128,
            &[42, 0, 1],
            &[0x59, 2, 0],
        )
    };
    let value = |o: Outcome| match o {
        Outcome::Reply(r) => coe::parse_response(&r).unwrap(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        value(up(&mut s, 0x1018, 2)),
        SdoResponse::Upload {
            size: 4,
            data: 0x12345u32.to_le_bytes().to_vec()
        }
    );
    assert_eq!(
        value(up(&mut s, 0x1C12, 1)),
        SdoResponse::Upload {
            size: 2,
            data: 0x1600u16.to_le_bytes().to_vec()
        }
    );
    // RxPDO entry 2: 0x7000:02, 16 bits.
    assert_eq!(
        value(up(&mut s, 0x1600, 2)),
        SdoResponse::Upload {
            size: 4,
            data: 0x7000_0210u32.to_le_bytes().to_vec()
        }
    );
    // The process data objects read the image.
    assert_eq!(
        value(up(&mut s, 0x6000, 1)),
        SdoResponse::Upload {
            size: 2,
            data: vec![42, 0]
        }
    );
    assert_eq!(
        value(up(&mut s, 0x7000, 2)),
        SdoResponse::Upload {
            size: 2,
            data: 300i16.to_le_bytes().to_vec()
        }
    );
    assert_eq!(
        value(up(&mut s, 0x1018, 9)),
        SdoResponse::Abort {
            code: abort::NO_SUBINDEX
        }
    );
    assert_eq!(
        value(up(&mut s, 0x3000, 0)),
        SdoResponse::Abort {
            code: abort::NO_OBJECT
        }
    );
    assert!(matches!(up(&mut s, 0x8000, 1), Outcome::AskRead(o) if o.ty == DataType::U16));
    // A record's subindex 0 counts its declared subindices.
    assert_eq!(
        value(up(&mut s, 0x8000, 0)),
        SdoResponse::Upload {
            size: 1,
            data: vec![1]
        }
    );
    let ca = s.handle(
        &d,
        SdoRequest::Upload {
            index: 0x1C12,
            subindex: 0,
            complete_access: true,
        },
        128,
        &[],
        &[],
    );
    assert_eq!(
        value(ca),
        SdoResponse::Abort {
            code: abort::UNSUPPORTED_ACCESS
        }
    );
    let down = |s: &mut SdoServer, index: u16, sub: u8, data: Vec<u8>| {
        s.handle(
            &d,
            SdoRequest::Download {
                index,
                subindex: sub,
                complete_access: false,
                size: data.len(),
                data,
            },
            128,
            &[],
            &[],
        )
    };
    assert_eq!(
        value(down(&mut s, 0x1C12, 1, vec![0, 0x16])),
        SdoResponse::Abort {
            code: abort::READ_ONLY
        }
    );
    assert_eq!(
        value(down(&mut s, 0x2001, 0, b"x".to_vec())),
        SdoResponse::Abort {
            code: abort::READ_ONLY
        }
    );
    assert_eq!(
        value(down(&mut s, 0x8000, 1, vec![1, 2, 3])),
        SdoResponse::Abort {
            code: abort::TYPE_LENGTH
        }
    );
    assert!(matches!(
        down(&mut s, 0x8000, 1, 1200u16.to_le_bytes().to_vec()),
        Outcome::AskWrite(_, v, None) if v == json!(1200)
    ));
}

#[test]
fn long_values_travel_in_segments_both_ways() {
    let text = "NetGet EtherCAT slave, serial text that needs SDO segments";
    let mut s = SdoServer::default();
    let Outcome::Reply(first) = s.upload_reply(0x2001, 0, text.as_bytes(), 40) else {
        panic!()
    };
    let SdoResponse::Upload { size, mut data } = coe::parse_response(&first).unwrap() else {
        panic!()
    };
    assert_eq!(size, text.len());
    assert!(data.len() < size);
    let d = DeviceSpec::parse(&super::support::slave_params()["slaves"][0], 0).unwrap();
    let mut toggle = false;
    while data.len() < size {
        let Outcome::Reply(seg) = s.handle(&d, SdoRequest::UploadSegment { toggle }, 40, &[], &[])
        else {
            panic!()
        };
        match coe::parse_response(&seg).unwrap() {
            SdoResponse::UploadSegment { data: more, .. } => data.extend(more),
            other => panic!("{other:?}"),
        }
        toggle = !toggle;
    }
    assert_eq!(data, text.as_bytes());
    // A segment out of turn is an abort.
    s.upload_reply(0x2001, 0, text.as_bytes(), 40);
    let Outcome::Reply(bad) =
        s.handle(&d, SdoRequest::UploadSegment { toggle: true }, 40, &[], &[])
    else {
        panic!()
    };
    assert_eq!(
        coe::parse_response(&bad).unwrap(),
        SdoResponse::Abort {
            code: abort::TOGGLE
        }
    );
    // The master side splits a download the same way, and the request parser reassembles it.
    let (first, mut rest) = coe::download_request(0x8000, 1, text.as_bytes(), 40);
    let SdoRequest::Download { size, mut data, .. } = coe::parse_request(&first).unwrap() else {
        panic!()
    };
    let mut t = false;
    while !rest.is_empty() {
        let (seg, r) = coe::download_segment_request(t, &rest, 40);
        rest = r;
        let SdoRequest::DownloadSegment { data: more, .. } = coe::parse_request(&seg).unwrap()
        else {
            panic!()
        };
        data.extend(more);
        t = !t;
    }
    assert_eq!(size, text.len());
    assert_eq!(data, text.as_bytes());
    // A declared size over the bound is refused at the first frame.
    let mut huge = coe::download_request(0x8000, 1, &[0; 8], 40).0;
    huge[6..10].copy_from_slice(&((coe::MAX_SDO_BYTES as u32) + 1).to_le_bytes());
    assert!(coe::parse_request(&huge).is_err());
}

#[test]
fn device_descriptions_are_bounded() {
    let many: Vec<_> = (0..33)
        .map(|i| json!({"name": format!("e{i}"), "type": "u8"}))
        .collect();
    assert!(Image::parse(Some(&json!(many)), "inputs").is_err());
    let wide: Vec<_> = (0..17)
        .map(|i| json!({"name": format!("e{i}"), "type": "u64"}))
        .collect();
    assert!(
        Image::parse(Some(&json!(wide)), "inputs").is_err(),
        "136 octets, over 128"
    );
    assert!(
        Image::parse(Some(&json!(wide[..16])), "inputs").is_ok(),
        "128 octets fit"
    );
    let nine: Vec<_> = (0..9).map(|_| json!({})).collect();
    assert!(device::segment_from_params(Some(&json!(nine))).is_err());
    assert!(
        DeviceSpec::parse(&json!({"objects": [{"index": "0x1000", "type": "u8"}]}), 0).is_err()
    );
    assert!(
        DeviceSpec::parse(&json!({"objects": [{"index": "0x6000", "type": "u8"}]}), 0).is_err()
    );
    assert!(DeviceSpec::parse(&json!({"objects": [{"index": "0x2000", "type": "u8"}]}), 0).is_ok());
    assert!(DeviceSpec::parse(&json!({"colour": "red"}), 0).is_err());
    assert!(DataType::U8.encode(&json!(256)).is_err());
    assert!(DataType::I16.encode(&json!(-32768)).is_ok());
}
