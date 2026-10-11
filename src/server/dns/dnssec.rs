//! DNSSEC (RFC 4033-4035) for one zone: NetGet signs what the model answers.
//!
//! The model never sees a key, a signature or an NSEC record. It answers as it always does,
//! and when the operator names a zone with the `dnssec_zone` startup parameter the server signs
//! every answer under that zone for a client that sets the DO bit, and every zone transfer of
//! it. The key is generated at startup — one ECDSA P-256 key (algorithm 13) acting as both KSK
//! and ZSK, flags 257 — and lives only as long as the server; a validator is given it as a trust
//! anchor by querying the zone's DNSKEY, which the server answers itself.
//!
//! Denial of existence:
//!
//! - **In an answer**, compact denial ("black lies", RFC 9824 without the NXNAME type): a name
//!   the model says does not exist is answered NOERROR with one NSEC at the queried name whose
//!   next name is `\000.<qname>` and whose bitmap holds only RRSIG and NSEC. It proves no type
//!   exists there, needs no knowledge of the rest of the zone (the model has none to give), and
//!   cannot be walked. A validator accepts it as NODATA; NXDOMAIN is not reported as such,
//!   which is the documented cost of the technique.
//! - **In a zone transfer**, a real NSEC chain over every owner name in the zone, because a
//!   transferred zone is a zone file and a verifier checks the whole chain.
//!
//! Signatures are valid from an hour before signing to seven days after.

use anyhow::{bail, Context, Result};
use hickory_proto::rr::dnssec::rdata::{DNSSECRData, DNSKEY, NSEC, RRSIG};
use hickory_proto::rr::dnssec::{tbs, Algorithm, KeyFormat, KeyPair, Private};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::collections::{BTreeMap, BTreeSet};

/// The one algorithm: ECDSA P-256 with SHA-256 (13), the algorithm RFC 8624 recommends.
pub const ALGORITHM: Algorithm = Algorithm::ECDSAP256SHA256;

/// TTL of the DNSKEY RRset and of a synthesized SOA.
pub const KEY_TTL: u32 = 3600;

/// Signatures start this long before signing, for clock skew.
pub const INCEPTION_SKEW_SECS: u32 = 3600;

/// And end this long after.
pub const VALIDITY_SECS: u32 = 7 * 24 * 3600;

/// The zone's signing key and what is derived from it.
pub struct ZoneSigner {
    zone: Name,
    key: KeyPair<Private>,
    dnskey: DNSKEY,
    key_tag: u16,
    /// The SOA used when the model's answer carries none and a negative answer needs one.
    soa: SOA,
}

impl ZoneSigner {
    /// Generate a key for `zone`.
    pub fn generate(zone: Name, now: u32) -> Result<ZoneSigner> {
        let mut zone = zone;
        zone.set_fqdn(true);
        let pkcs8 = KeyPair::<Private>::generate_pkcs8(ALGORITHM)
            .map_err(|e| anyhow::anyhow!("cannot generate a DNSSEC key: {e}"))?;
        let key = KeyFormat::Pkcs8
            .decode_key(&pkcs8, None, ALGORITHM)
            .map_err(|e| anyhow::anyhow!("cannot load the generated DNSSEC key: {e}"))?;
        let public = key
            .to_public_bytes()
            .map_err(|e| anyhow::anyhow!("cannot derive the DNSSEC public key: {e}"))?;
        // Zone key, secure entry point: one key signing everything, flags 257.
        let dnskey = DNSKEY::new(true, true, false, ALGORITHM, public);
        let key_tag = dnskey
            .calculate_key_tag()
            .map_err(|e| anyhow::anyhow!("cannot compute the key tag: {e}"))?;
        let host = |label: &str| -> Result<Name> {
            Name::from_str_relaxed(label)?
                .append_domain(&zone)
                .context("zone name too long")
        };
        let soa = SOA::new(
            host("ns1")?,
            host("hostmaster")?,
            now,
            3600,
            600,
            604_800,
            300,
        );
        Ok(ZoneSigner {
            zone,
            key,
            dnskey,
            key_tag,
            soa,
        })
    }

    pub fn zone(&self) -> &Name {
        &self.zone
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// True when `name` is the zone or below it.
    pub fn covers(&self, name: &Name) -> bool {
        self.zone.zone_of(name)
    }

    pub fn dnskey_record(&self) -> Record {
        let mut r = Record::with(self.zone.clone(), RecordType::DNSKEY, KEY_TTL);
        r.set_data(Some(RData::DNSSEC(DNSSECRData::DNSKEY(
            self.dnskey.clone(),
        ))));
        r
    }

    /// The SOA a negative answer carries when the model gave none.
    pub fn soa_record(&self) -> Record {
        let mut r = Record::with(self.zone.clone(), RecordType::SOA, KEY_TTL);
        r.set_data(Some(RData::SOA(self.soa.clone())));
        r
    }

    /// The RRSIG over one RRset. Every record must share owner, class and type; their TTLs are
    /// made equal (the smallest), since an RRset's TTL is signed as one value.
    pub fn sign_rrset(&self, rrset: &mut [Record], now: u32) -> Result<Record> {
        let first = rrset.first().context("cannot sign an empty RRset")?;
        let name = first.name().clone();
        let rtype = first.record_type();
        let class = first.dns_class();
        if rrset
            .iter()
            .any(|r| r.name() != &name || r.record_type() != rtype || r.dns_class() != class)
        {
            bail!("an RRset must share owner, class and type");
        }
        let ttl = rrset.iter().map(|r| r.ttl()).min().unwrap_or(KEY_TTL);
        for r in rrset.iter_mut() {
            r.set_ttl(ttl);
        }
        let inception = now.saturating_sub(INCEPTION_SKEW_SECS);
        let expiration = now.saturating_add(VALIDITY_SECS);
        let labels = name.num_labels();
        let to_sign = tbs::rrset_tbs(
            &name,
            class,
            labels,
            rtype,
            ALGORITHM,
            ttl,
            expiration,
            inception,
            self.key_tag,
            &self.zone,
            rrset,
        )
        .map_err(|e| anyhow::anyhow!("cannot serialise {name} {rtype} for signing: {e}"))?;
        let signature = self
            .key
            .sign(ALGORITHM, &to_sign)
            .map_err(|e| anyhow::anyhow!("cannot sign {name} {rtype}: {e}"))?;
        let sig = RRSIG::new(
            rtype,
            ALGORITHM,
            labels,
            ttl,
            expiration,
            inception,
            self.key_tag,
            self.zone.clone(),
            signature,
        );
        let mut r = Record::with(name, RecordType::RRSIG, ttl);
        r.set_dns_class(class);
        r.set_data(Some(RData::DNSSEC(DNSSECRData::RRSIG(sig))));
        Ok(r)
    }

    /// RRSIGs for every in-zone RRset in `records`, which are left in place (TTLs equalised).
    /// RRSIGs already present are not signed again.
    pub fn signatures_for(&self, records: &mut [Record], now: u32) -> Result<Vec<Record>> {
        let mut sets: BTreeMap<(Name, u16), Vec<usize>> = BTreeMap::new();
        for (i, r) in records.iter().enumerate() {
            if r.record_type() == RecordType::RRSIG
                || r.record_type() == RecordType::OPT
                || !self.covers(r.name())
            {
                continue;
            }
            sets.entry((r.name().clone(), u16::from(r.record_type())))
                .or_default()
                .push(i);
        }
        let mut sigs = Vec::new();
        for indexes in sets.values() {
            let mut rrset: Vec<Record> = indexes.iter().map(|i| records[*i].clone()).collect();
            sigs.push(self.sign_rrset(&mut rrset, now)?);
            for (i, signed) in indexes.iter().zip(rrset) {
                records[*i] = signed;
            }
        }
        Ok(sigs)
    }

    /// The compact-denial NSEC for `qname`: next name `\000.<qname>`, types RRSIG and NSEC.
    pub fn compact_denial(&self, qname: &Name, ttl: u32) -> Result<Record> {
        let next = Name::from_labels(std::iter::once(&[0u8][..]).chain(qname.iter()))
            .map_err(|e| anyhow::anyhow!("cannot build the NSEC next name for {qname}: {e}"))?;
        let mut next = next;
        next.set_fqdn(true);
        let mut r = Record::with(qname.clone(), RecordType::NSEC, ttl);
        r.set_data(Some(RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
            next,
            vec![RecordType::RRSIG, RecordType::NSEC],
        )))));
        Ok(r)
    }

    /// The full NSEC chain over `zone_records` (which must all be in the zone), in canonical
    /// order, closing back to the apex. Each name's bitmap lists its types plus RRSIG and NSEC.
    pub fn nsec_chain(&self, zone_records: &[Record], ttl: u32) -> Result<Vec<Record>> {
        let mut types: BTreeMap<Name, BTreeSet<u16>> = BTreeMap::new();
        types.entry(self.zone.clone()).or_default();
        for r in zone_records {
            if r.record_type() == RecordType::RRSIG || r.record_type() == RecordType::NSEC {
                continue;
            }
            types
                .entry(r.name().to_lowercase())
                .or_default()
                .insert(u16::from(r.record_type()));
        }
        let names: Vec<Name> = types.keys().cloned().collect();
        let mut chain = Vec::with_capacity(names.len());
        for (i, name) in names.iter().enumerate() {
            let next = names.get(i + 1).unwrap_or(&names[0]).clone();
            let mut bitmap: Vec<RecordType> =
                types[name].iter().map(|t| RecordType::from(*t)).collect();
            bitmap.push(RecordType::RRSIG);
            bitmap.push(RecordType::NSEC);
            bitmap.sort_by_key(|t| u16::from(*t));
            bitmap.dedup();
            let mut r = Record::with(name.clone(), RecordType::NSEC, ttl);
            r.set_data(Some(RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                next, bitmap,
            )))));
            chain.push(r);
        }
        Ok(chain)
    }
}

/// The negative-caching TTL a zone's SOA gives (RFC 9077: the smaller of its TTL and MINIMUM).
pub fn negative_ttl(soa: &Record) -> u32 {
    match soa.data() {
        Some(RData::SOA(s)) => soa.ttl().min(s.minimum()),
        _ => soa.ttl(),
    }
}

/// The class every record here uses.
pub const CLASS: DNSClass = DNSClass::IN;
