//! 128-NEA1/NIA1 (SNOW 3G: 128-EEA1/EIA1, i.e. UEA2/UIA2) and 128-NEA3/NIA3 (ZUC: 128-EEA3/EIA3)
//! against every published test set, and through `NasContext` end to end.
//!
//! Sources, all ETSI/SAGE unless named otherwise:
//! - "UEA2 & UIA2, Document 3: Implementors' Test Data" v1.1 (25 October 2012): SNOW 3G sets 1-4,
//!   UEA2 sets 1-5, UIA2 sets 1-6.
//! - "UEA2 & UIA2, Document 4: Design Conformance Test Data" v1.0: UEA2 sets 1-6, UIA2 sets 1-7.
//! - 3GPP TS 33.401 V19.2.0 Annex C.4: 128-EIA1 sets 1-7. (Annex C.3 publishes no 128-EEA1 data:
//!   UEA2's applies unchanged, BEARER and DIRECTION mapping one to one, so the UEA2 sets above are
//!   the 128-EEA1 vectors.)
//! - "128-EEA3 & 128-EIA3, Document 3: Implementor's Test Data" v1.1 (4 January 2011, the version
//!   that matches ZUC v1.5+/EIA3 v1.5+): ZUC sets 1-4, 128-EEA3 sets 1-5, 128-EIA3 sets 1-5.
//!
//! The values were read out of the documents' text, not retyped; each carries its source and set
//! number. Lengths are in bits, as the documents give them; where a length is not a whole number
//! of octets the documents print the last octet with the unused low bits zero, and so do these.
//! UIA2 takes FRESH, which 128-EIA1 replaces with BEARER || 0^27, so the UIA2 sets exercise
//! `uia2_bits` and the TS 33.401 sets exercise `eia1_bits`.
use super::support::unhex;
use netget::server::ngap::security;
use netget::server::ngap::{snow3g, zuc};

struct KeystreamVector {
    source: &'static str,
    key: &'static str,
    iv: &'static str,
    /// (t, z_t): the t-th keystream word, counted from 1 as the documents do.
    words: &'static [(u32, u32)],
}

struct CipherVector {
    source: &'static str,
    key: &'static str,
    count: u32,
    bearer: u8,
    direction: u8,
    length_bits: u64,
    plaintext: &'static str,
    ciphertext: &'static str,
}

struct MacVector {
    source: &'static str,
    key: &'static str,
    count: u32,
    bearer: u8,
    direction: u8,
    length_bits: u64,
    message: &'static str,
    mac: &'static str,
}

struct Uia2Vector {
    source: &'static str,
    key: &'static str,
    count: u32,
    fresh: u32,
    direction: u8,
    length_bits: u64,
    message: &'static str,
    mac: &'static str,
}

type CipherFn = fn(&[u8; 16], u32, u8, u8, &mut [u8], u64);
type MacFn = fn(&[u8; 16], u32, u8, u8, &[u8], u64) -> [u8; 4];

fn key(s: &str) -> [u8; 16] {
    unhex(s).try_into().expect("128-bit key")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const SNOW3G_KEYSTREAM: &[KeystreamVector] = &[
    // SAGE UEA2&UIA2 Document 3 v1.1, section 3.3, SNOW 3G Test Set 1
    KeystreamVector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 3.3, SNOW 3G Test Set 1",
        key: "2bd6459f82c5b300952c49104881ff48",
        iv: "ea024714ad5c4d84df1f9b251c0bf45f",
        words: &[(1, 0xabee9704), (2, 0x7ac31373)],
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 3.4, SNOW 3G Test Set 2
    KeystreamVector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 3.4, SNOW 3G Test Set 2",
        key: "8ce33e2cc3c0b5fc1f3de8a6dc66b1f3",
        iv: "d3c5d592327fb11cde551988ceb2f9b7",
        words: &[(1, 0xeff8a342), (2, 0xf751480f)],
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 3.5, SNOW 3G Test Set 3
    KeystreamVector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 3.5, SNOW 3G Test Set 3",
        key: "4035c6680af8c6d1a8ff8667b1714013",
        iv: "62a540981ba6f9b74592b0e78690f71b",
        words: &[(1, 0xa8c874a9), (2, 0x7ae7c4f8)],
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 3.6, SNOW 3G Test Set 4
    KeystreamVector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 3.6, SNOW 3G Test Set 4",
        key: "0ded7263109cf92e3352255a140e0f76",
        iv: "6b68079a41a7c4c91befd79f7fdcc233",
        words: &[
            (1, 0xd712c05c),
            (2, 0xa937c2a6),
            (3, 0xeb7eaae3),
            (2500, 0x9c0db3aa),
        ],
    },
];

const UEA2_DOC3: &[CipherVector] = &[
    // SAGE UEA2&UIA2 Document 3 v1.1, section 4.3, UEA2 Test Set 1
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 4.3, UEA2 Test Set 1",
        key: "2bd6459f82c5b300952c49104881ff48",
        count: 0x72a4f20f,
        bearer: 0x0c,
        direction: 1,
        length_bits: 798,
        plaintext: "7ec61272 743bf161 4726446a 6c38ced1 66f6ca76 eb543004 4286346c ef130f92 \
         922b0345 0d3a9975 e5bd2ea0 eb55ad8e 1b199e3e c4316020 e9a1b285 e7627953 \
         59b7bdfd 39bef4b2 484583d5 afe082ae e638bf5f d5a60619 3901a08f 4ab41aab \
         9b134880",
        ciphertext: "8ceba629 43dced3a 0990b06e a1b0a2c4 fb3cedc7 1b369f42 ba64c1eb 6665e72a \
         a1c9bb0d eaa20fe8 6058b8ba ee2c2e7f 0becce48 b52932a5 3c9d5f93 1a3a7c53 \
         2259af43 25e2a65e 3084ad5f 6a513b7b ddc1b65f 0aa0d97a 053db55a 88c4c4f9 \
         605e4140",
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 4.4, UEA2 Test Set 2
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 4.4, UEA2 Test Set 2",
        key: "efa8b2229e720c2a7c36ea55e9605695",
        count: 0xe28bcf7b,
        bearer: 0x18,
        direction: 0,
        length_bits: 510,
        plaintext: "10111231 e060253a 43fd3f57 e37607ab 2827b599 b6b1bbda 37a8abcc 5a8c550d \
         1bfb2f49 4624fb50 367fa36c e3bc68f1 1cf93b15 10376b02 130f812a 9fa169d8",
        ciphertext: "e0da15ca 8e2554f5 e56c9468 dc6c7c12 9c568aa5 032317e0 4e072964 6cabefa6 \
         89864c41 0f24f919 e61e3dfd fad77e56 0db0a9cd 36c34ae4 181490b2 9f5fa2fc",
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 4.5, UEA2 Test Set 3
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 4.5, UEA2 Test Set 3",
        key: "5acb1d644c0d51204ea5f1451010d852",
        count: 0xfa556b26,
        bearer: 0x03,
        direction: 1,
        length_bits: 120,
        plaintext: "ad9c441f 890b38c4 57a49d42 1407e8",
        ciphertext: "ba0f3130 0334c56b 52a7497c bac046",
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 4.6, UEA2 Test Set 4
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 4.6, UEA2 Test Set 4",
        key: "d3c5d592327fb11c4035c6680af8c6d1",
        count: 0x398a59b4,
        bearer: 0x05,
        direction: 1,
        length_bits: 253,
        plaintext: "981ba682 4c1bfb1a b4854720 29b71d80 8ce33e2c c3c0b5fc 1f3de8a6 dc66b1f0",
        ciphertext: "989b719c dc33ceb7 cf276a52 827cef94 a56c40c0 ab9d81f7 a2a9bac6 0e11c4b0",
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 4.7, UEA2 Test Set 5
    // The document prints plaintext word 19 as "60876A0" (seven digits); its own keystream
    // and enc/dec columns for that word (AE56E26E ^ A85E94CE) give 060876A0, and SAGE
    // Document 4 Test Set 6 prints the same plaintext with the leading zero.
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 4.7, UEA2 Test Set 5",
        key: "6090eae04c83706eecbf652be8e36566",
        count: 0x72a4f20f,
        bearer: 0x09,
        direction: 0,
        length_bits: 837,
        plaintext: "40981ba6 824c1bfb 4286b299 783daf44 2c099f7a b0f58d5c 8e46b104 f08f01b4 \
         1ab48547 2029b71d 36bd1a3d 90dc3a41 b46d5167 2ac4c966 3a2be063 da4bc8d2 \
         808ce33e 2cccbfc6 34e1b259 060876a0 fbb5a437 ebcc8d31 c19e4454 318745e3 \
         98764598 7a986f2c b0",
        ciphertext: "5892bba8 8bbbcaae ae769aa0 6b683d3a 17cc04a3 69881697 435e44fe d5ff9af5 \
         7b9e890d 4d5c6470 9885d48a e40690ec 043baae9 705796e4 a9ff5a4b 8d8b36d7 \
         f3fe57cc 6cfd6cd0 05cd3852 a85e94ce 6bcd90d0 d07839ce 09733544 ca8e3508 \
         43248550 922ac128 18",
    },
];

const UEA2_DOC4: &[CipherVector] = &[
    // SAGE UEA2&UIA2 Document 4 v1.0, section 3.3, UEA2 Test Set 1
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 3.3, UEA2 Test Set 1",
        key: "d3c5d592327fb11c4035c6680af8c6d1",
        count: 0x398a59b4,
        bearer: 0x15,
        direction: 1,
        length_bits: 253,
        plaintext: "981ba682 4c1bfb1a b4854720 29b71d80 8ce33e2c c3c0b5fc 1f3de8a6 dc66b1f0",
        ciphertext: "5d5bfe75 eb04f68c e0a12377 ea00b37d 47c6a0ba 06309155 086a859c 4341b378",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 3.4, UEA2 Test Set 2
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 3.4, UEA2 Test Set 2",
        key: "2bd6459f82c440e0952c49104805ff48",
        count: 0xc675a64b,
        bearer: 0x0c,
        direction: 1,
        length_bits: 798,
        plaintext: "7ec61272 743bf161 4726446a 6c38ced1 66f6ca76 eb543004 4286346c ef130f92 \
         922b0345 0d3a9975 e5bd2ea0 eb55ad8e 1b199e3e c4316020 e9a1b285 e7627953 \
         59b7bdfd 39bef4b2 484583d5 afe082ae e638bf5f d5a60619 3901a08f 4ab41aab \
         9b134880",
        ciphertext: "3f678507 14b8da69 efb727ed 7a6c0c50 714ad736 c4f56000 06e3525b e807c467 \
         c677ff86 4af45fba 09c27cde 38f87a1f 84d59ab2 55408f2c 7b82f9ea d41a1fe6 \
         5eabebfb c1f3a4c5 6c9a26fc f7b3d66d 0220ee47 75bc5817 0a2b12f3 431d11b3 \
         44d6e36c",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 3.5, UEA2 Test Set 3
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 3.5, UEA2 Test Set 3",
        key: "0a8b6bd8d9b08b08d64e32d1817777fb",
        count: 0x544d49cd,
        bearer: 0x04,
        direction: 0,
        length_bits: 310,
        plaintext: "fd40a41d 370a1f65 74509568 7d47ba1d 36d2349e 23f64439 2c8ea9c4 9d40c132 \
         71aff264 d0f248",
        ciphertext: "48148e54 52a210c0 5f46bc80 dc6f7349 5b02048c 1b958b02 6102ca97 280279a4 \
         c18d2ee3 08921c",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 3.6, UEA2 Test Set 4
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 3.6, UEA2 Test Set 4",
        key: "aa1f95aea533bcb32eb63bf52d8f831a",
        count: 0x72d8c671,
        bearer: 0x10,
        direction: 1,
        length_bits: 1022,
        plaintext: "fb1b96c5 c8badfb2 e8e8edfd e78e57f2 ad81e741 03fc430a 534dcc37 afcec70e \
         1517bb06 f27219da e49022dd c47a068d e4c9496a 951a6b09 edbdc864 c7adbd74 \
         0ac50c02 2f3082ba fd22d781 97c5d508 b977bca1 3f32e652 e74ba728 576077ce \
         628c535e 87dc6077 ba07d290 68590c8c b5f1088e 082cfa0e c961302d 69cf3d44",
        ciphertext: "ffcfc2fe ad6c094e 96c589d0 f6779b67 84246c3c 4d1cea20 3db3901f 40ad4fd7 \
         138bc6d7 7e8320cb 102f497f dd44a269 a96ecb28 617700e3 32eb2f73 6b34f4f2 \
         693094e2 2ff94f9b e4723da4 0c40dfd3 931cc1ac 9723f6b4 a9913e96 b6db7abc \
         ace41517 7c1d0115 c5f09b5f dea0b3ad b8f9da6e 9f9a04c5 43397b9d 43f87330",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 3.7, UEA2 Test Set 5
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 3.7, UEA2 Test Set 5",
        key: "9618ae46891f86578eebe90ef7a1202e",
        count: 0xc675a64b,
        bearer: 0x0c,
        direction: 1,
        length_bits: 1245,
        plaintext: "8daa17b1 ae050529 c6827f28 c0ef6a12 42e93f8b 314fb18a 77f790ae 049fedd6 \
         12267fec aefc4501 74d76d9f 9aa7755a 30cd90a9 a5874bf4 8eaf70ee a3a62a25 \
         0a8b6bd8 d9b08b08 d64e32d1 817777fb 544d49cd 49720e21 9dbf8bbe d33904e1 \
         fd40a41d 370a1f65 74509568 7d47ba1d 36d2349e 23f64439 2c8ea9c4 9d40c132 \
         71aff264 d0f24841 d6465f09 96ff84e6 5fc517c5 3efc3363 c38492a8",
        ciphertext: "6cdb18a7 ca8218e8 6e4b4b71 6a4d0437 1fbec262 fc5ad0b3 819b187b 97e55b1a \
         4d7c19ee 24c8b4d7 723cfedf 045b8aca e4869517 d80e5061 5d9035d5 d9c5a40a \
         f602280b 542597b0 cb18619e eb359257 59d195e1 00e8e4aa 0c38a3c2 abe0f3d8 \
         ff04f3c3 3c295069 c23694b5 bbeacdd5 42e28e8a 94edb911 9f412d05 4be1fa72 \
         72b5ffb2 b2570f4f 7ceaf383 a8a9d935 72f04d6e 3a6e2937 26ec62c8",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 3.8, UEA2 Test Set 6
    CipherVector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 3.8, UEA2 Test Set 6",
        key: "54f4e2e04c83786eec8fb5abe8e36566",
        count: 0xaca4f50f,
        bearer: 0x0b,
        direction: 0,
        length_bits: 3861,
        plaintext: "40981ba6 824c1bfb 4286b299 783daf44 2c099f7a b0f58d5c 8e46b104 f08f01b4 \
         1ab48547 2029b71d 36bd1a3d 90dc3a41 b46d5167 2ac4c966 3a2be063 da4bc8d2 \
         808ce33e 2cccbfc6 34e1b259 060876a0 fbb5a437 ebcc8d31 c19e4454 318745e3 \
         fa16bb11 adae2488 79fe52db 2543e53c f445d3d8 28ce0bf5 c560593d 97278a59 \
         762dd0c2 c9cd68d4 496a7925 08614014 b13b6aa5 1128c18c d6a90b87 978c2ff1 \
         cabe7d9f 898a411b fdb84f68 f6727b14 99cdd30d f0443ab4 a6665333 0bcba110 \
         5e4cec03 4c73e605 b4310eaa adcfd5b0 ca27ffd8 9d144df4 79275942 7c9cc1f8 \
         cd8c8720 2364b8a6 87954cb0 5a8d4e2d 99e73db1 60deb180 ad0841e9 6741a5d5 \
         9fe4189f 15420026 fe4cd121 04932fb3 8f735340 438aaf7e ca6fd5cf d3a195ce \
         5abe6527 2af607ad a1be65a6 b4c9c069 3234092c 4d018f17 56c6db9d c8a6d80b \
         88813861 6b681262 f954d0e7 71174878 0d92291d 86299972 db741cfa 4f37b8b5 \
         6cdb18a7 ca8218e8 6e4b4b71 6a4d0437 1fbec262 fc5ad0b3 819b187b 97e55b1a \
         4d7c19ee 24c8b4d7 723cfedf 045b8aca e4869517 d80e5061 5d9035d5 d9c5a40a \
         f602280b 542597b0 cb18619e eb359257 59d195e1 00e8e4aa 0c38a3c2 abe0f3d8 \
         ff04f3c3 3c295069 c23694b5 bbeacdd5 42e28e8a 94edb911 9f412d05 4be1fa72 \
         b09550",
        ciphertext: "351e30d4 d910c5dd 5ad7834c 426e6c0c ab6486da 7b0fda4c d83af1b9 647137f1 \
         ac43b434 223b19be 07bd89d1 cc306944 d3361ea1 a2f8cdbd 32165597 6350d00b \
         80dd8381 20a7755c 6dea2ab2 b0c99a91 3f47dae2 b8deb9a8 29e5469f f2e18777 \
         6f6fd081 e3871d11 9a76e24c 917ea626 48e02e90 367564de 72ae7e4f 0a4249a9 \
         a5b0e465 a2d6d9dc 87843b1b 875cc9a3 be93d8da 8f56ecaf 5981fe93 c284318b \
         0dec7a3b a108e2cb 1a61e966 fa7afa7a c7f67f65 bc4a2df0 70d4e434 845f109a \
         b2b68ade 3dc316ca 6332a628 93e0a7ec 0b4fc251 91bf2ff1 b9f9815e 4ba8a99c \
         643b5218 04f7d585 0dde3952 206ec6cc f340f9b3 220b3023 bdd06395 6ea83339 \
         20fde99e 0675410e 49ef3b4d 3fb3df51 92f99ca8 3d3b0032 de08c220 776a5865 \
         b0e4b3b0 c75defe7 762dff01 8ea7f5be 2b2f972b 2a8ba597 0e43bd6f dd63dae6 \
         29784ec4 8d610054 ee4e4b5d bbf1fc2f a0b830e9 4dcbb701 4e8ab429 ab100fc4 \
         8f83171d 99fc258b 7c2ba7c1 76eaeaad 37f860d5 97a31ce7 9b594733 c7141df7 \
         9151fca9 0c08478a 5c6c2cc4 81d51ffe ce3cd7d2 58134882 7a71f091 428ebe38 \
         c95a3f5c 63e056df b7cc45a9 b7c07d83 4e7b20b9 9ed20242 9c14bb85 ffa43b7c \
         b68495cd 75ab66d9 64d4cafe 64dd9404 dae2dc51 10617f19 4fc3c184 f583cd0d \
         ef6d00",
    },
];

const UIA2_DOC3: &[Uia2Vector] = &[
    // SAGE UEA2&UIA2 Document 3 v1.1, section 5.3, UIA2 Test Set 1
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 5.3, UIA2 Test Set 1",
        key: "2bd6459f82c5b300952c49104881ff48",
        count: 0x38a6f056,
        fresh: 0x05d2ec49,
        direction: 0,
        length_bits: 189,
        message: "6b227737 296f393c 8079353e dc87e2e8 05d2ec49 a4f2d8e0",
        mac: "2bce1820",
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 5.4, UIA2 Test Set 2
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 5.4, UIA2 Test Set 2",
        key: "d42f682428201cafcd9f97945e6de7b7",
        count: 0x3edc87e2,
        fresh: 0xa4f2d8e2,
        direction: 1,
        length_bits: 254,
        message: "b5924384 328a4ae0 0b737109 f8b6c8dd 2b4db63d d533981c eb19aad5 2a5b2bc0",
        mac: "fc7b18bd",
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 5.5, UIA2 Test Set 3
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 5.5, UIA2 Test Set 3",
        key: "fdb9cfdf28936cc483a31869d81b8fab",
        count: 0x36af6144,
        fresh: 0x9838f03a,
        direction: 1,
        length_bits: 319,
        message: "5932bc0a ce2b0aba 33d8ac18 8ac54f34 6fad10bf 9dee2920 b43bd0c5 3a915cb7 \
         df6caa72 053abff2",
        mac: "02f1faaf",
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 5.6, UIA2 Test Set 4
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 5.6, UIA2 Test Set 4",
        key: "c736c6aab22bfff91e2698d2e22ad57e",
        count: 0x14793e41,
        fresh: 0x0397e8fd,
        direction: 1,
        length_bits: 384,
        message: "d0a7d463 df9fb2b2 78833fa0 2e235aa1 72bd970c 1473e129 07fb648b 6599aaa0 \
         b24a0386 65422b20 a499276a 50427009",
        mac: "38b554c0",
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 5.7, UIA2 Test Set 5
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 5.7, UIA2 Test Set 5",
        key: "f4ebec69e73eaf2eb2cf6af4b3120ffd",
        count: 0x296f393c,
        fresh: 0x6b227737,
        direction: 1,
        length_bits: 1000,
        message: "10bfff83 9e0c7165 8dbb2d17 07e14572 4f41c16f 48bf403c 3b18e38f d5d1663b \
         6f6d9001 93e3cea8 bb4f1b4f 5be82203 2232a78d 7d75238d 5e6daecd 3b4322cf \
         59bc7ea8 4ab18811 b5bfb7bc 553f4fe4 4478ce28 7a148799 90d18d12 ca79d2c8 \
         55149021 cd5ce8ca 0371ca04 fcce143e 3d7cfee9 4585b588 5cac4606 8b",
        mac: "061745ae",
    },
    // SAGE UEA2&UIA2 Document 3 v1.1, section 5.8, UIA2 Test Set 6
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 3 v1.1, section 5.8, UIA2 Test Set 6",
        key: "b3120ffdb2cf6af4e73eaf2ef4ebec69",
        count: 0x296f393c,
        fresh: 0x6b227737,
        direction: 1,
        length_bits: 16448,
        message: "00000000 00000000 01010101 01010101 e0958045 f3a0bba4 e3968346 f0a3b8a7 \
         c02a018a e6407652 26b987c9 13e6cbf0 83570016 cf83efbc 61c08251 3e21561a \
         427c009d 28c298ef ace78ed6 d56c2d45 05ad032e 9c04dc60 e73a8169 6da665c6 \
         c48603a5 7b45ab33 221585e6 8ee31691 87fb0239 528632dd 656c807e a3248b7b \
         46d002b2 b5c7458e b85b9ce9 5879e034 0859055e 3b0abbc3 eace8719 caa80265 \
         c97205d5 dc4bcc90 2fe18396 29ed7132 8a0f0449 f588557e 6898860e 042aecd8 \
         4b2404c2 12c9222d a5bf8a89 ef679787 0cf50771 a60f66a2 ee628536 57addf04 \
         cdde07fa 414e11f1 2b4d81b9 b4e8ac53 8ea30666 688d881f 6c348421 992f31b9 \
         4f8806ed 8fccff4c 9123b896 42527ad6 13b109bf 75167485 f1268bf8 84b4cd23 \
         d29a0934 925703d6 34098f77 67f1be74 91e708a8 bb949a38 73708aef 4a36239e \
         50cc0823 5cd5ed6b be578668 a17b58c1 171d0b90 e813a9e4 f58a89d7 19b11042 \
         d6360b1b 0f52deb7 30a58d58 faf46315 954b0a87 26914759 77dc88c0 d733feff \
         54600a0c c1d0300a aaeb9457 2c6e95b0 1ae90de0 4f1dce47 f87e8fa7 bebf77e1 \
         dbc20d6b a85cb914 3d518b28 5dfa04b6 98bf0cf7 819f20fa 7a288eb0 703d995c \
         59940c7c 66de57a9 b70f8237 9b70e203 1e450fcf d2181326 fcd28d88 23baaa80 \
         df6e0f44 35596475 39fd8907 c0ffd9d7 9c130ed8 1c9afd9b 7e848c9f ed38443d \
         5d380e53 fbdb8ac8 c3d3f068 76054f12 2461107d e92fea09 c6f6923a 188d53af \
         e54a10f6 0e6e9d5a 03d996b5 fbc820f8 a637116a 27ad04b4 44a0932d d60fbd12 \
         671c11e1 c0ec73e7 89879faa 3d42c64d 20cd1252 742a3768 c25a9015 85888ece \
         e1e612d9 936b403b 0775949a 66cdfd99 a29b1345 baa8d9d5 400c9102 4b0a6073 \
         63b013ce 5de9ae86 9d3b8d95 b0570b3c 2d391422 d32450cb cfae9665 2286e96d \
         ec1214a9 34652798 0a8192ea c1c39a3a af6f1535 1da6be76 4df89772 ec0407d0 \
         6e4415be fae7c925 80df9bf5 07497c8f 2995160d 4e218daa cb02944a bf83340c \
         e8be1686 a960faf9 0e2d90c5 5cc6475b abc3171a 80a36317 4954955d 7101dab1 \
         6ae81791 67e21444 b443a9ea aa7c91de 36d118c3 9d389f8d d4469a84 6c9a262b \
         f7fa1848 7a79e8de 11699e0b 8fdf557c b48719d4 53ba7130 56109b93 a218c896 \
         75ac195f b4fb0663 9b379714 4955b3c9 327d1aec 003d42ec d0ea98ab f19ffb4a \
         f3561a67 e77c35bf 15c59c24 12da881d b02b1bfb cebfac51 52bc99bc 3f1d15f7 \
         71001b70 29fedb02 8f8b852b c4407eb8 3f891c9c a733254f dd1e9edb 56919ce9 \
         fea21c17 4072521c 18319a54 b5d4efbe bddf1d8b 69b1cbf2 5f489fcc 98137254 \
         7cf41d00 8ef0bca1 926f934b 735e090b 3b251eb3 3a36f82e d9b29cf4 cb944188 \
         fa0e1e38 dd778f7d 1c9d987b 28d132df b9731fa4 f4b41693 5be49de3 0516af35 \
         78581f2f 13f561c0 66336194 1eab249a 4bc123f8 d15cd711 a956a1bf 20fe6eb7 \
         8aea2373 361da042 6c79a530 c3bb1de0 c99722ef 1fde39ac 2b00a0a8 ee7c800a \
         08bc2264 f89f4eff e627ac2f 0531fb55 4f6d21d7 4c590a70 adfaa390 bdfbb3d6 \
         8e46215c ab187d23 68d5a71f 5ebec081 cd3b20c0 82dbe4cd 2faca287 73795d6b \
         0c10204b 659a939e f29bbe10 88243624 429927a7 eb576dd3 a00ea5e0 1af5d475 \
         83b2272c 0c161a80 6521a16f f9b0a722 c0cf26b0 25d5836e 2258a4f7 d4773ac8 \
         01e4263b c294f43d ef7fa870 3f3a4197 46352588 7652b0b2 a4a2a7cf 87f00914 \
         871e2503 9113c7e1 618da340 64b57a43 c463249f b8d05e0f 26f4a6d8 4972e7a9 \
         05482414 5f91295c dbe39a6f 920facc6 59712b46 a54ba295 bbe6a901 54e91b33 \
         985a2bcd 420ad5c6 7ec9ad8e b7ac6864 db272a51 6bc94c28 39b0a816 9a6bf58e \
         1a0c2ada 8c883b7b f497a491 71268ed1 5ddd2969 384e7ff4 bf4aab2e c9ecc652 \
         9cf629e2 df0f08a7 7a65afa1 2aa9b505 df8b287e f6cc9149 3d1caa39 076e28ef \
         1ea028f5 118de61a e02bb6ae fc3343a0 50292f19 9f401857 b2bead5e 6ee2a1f1 \
         91022f92 78016f04 7791a9d1 8da7d2a6 d27f2e0e 51c2f6ea 30e8ac49 a0604f4c \
         13542e85 b68381b9 fdcfa0ce 4b2d3413 54852d36 0245c536 b612af71 f3e77c90 \
         95ae2dbd e504b265 733dabfe 10a20fc7 d6d32c21 ccc72b8b 3444ae66 3d65922d \
         17f82caa 2b865cd8 8913d291 a6589902 6ea13284 39723c19 8c36b0c3 c8d085bf \
         af8a320f de334b4a 4919b44c 2b95f6e8 ecf73393 f7f0d2a4 0e60b1d4 06526b02 \
         2ddc3318 10b1a5f7 c347bd53 ed1f105d 6a0d30ab a477e178 889ab2ec 55d558de \
         ab263020 4336962b 4db5b663 b6902b89 e85b31bc 6af50fc5 0accb3fb 9b57b663 \
         29703137 8db47896 d7fbaf6c 600add2c 67f936db 037986db 856eb49c f2db3f7d \
         a6d23650 e438f188 4041b013 119e4c2a e5af37cc cdfb6866 0738b58b 3c59d1c0 \
         24843747 2aba1f35 ca1fb90c d714aa9f 635534f4 9e7c5bba 81c2b6b3 6fdee21c \
         a27e347f 793d2ce9 44edb23c 8c9b914b e10335e3 50feb507 0394b7a4 a15c0ca1 \
         20283568 b7bfc254 fe838b13 7a2147ce 7c113a3a 4d65499d 9e86b87d bcc7f03b \
         bd3a3ab1 aa243ece 5ba9bcf2 5f82836c fe473b2d 83e7a720 1cd0b96a 72451e86 \
         3f6c3ba6 64a6d073 d1f7b5ed 990865d9 78bd3815 d06094fc 9a2aba52 21c22d5a \
         b996389e 3721e3af 5f05bedd c2875e0d faeb3902 1ee27a41 187cbb45 ef40c3e7 \
         3bc03989 f9a30d12 c54ba7d2 141da8a8 75493e65 776ef35f 97debc22 86cc4af9 \
         b4623eee 902f840c 52f1b8ad 658939ae f71f3f72 b9ec1de2 1588bd35 484ea444 \
         36343ff9 5ead6ab1 d8afb1b2 a303df1b 71e53c4a ea6b2e3e 9372be0d 1bc99798 \
         b0ce3cc1 0d2a596d 565dba82 f88ce4cf f3b33d5d 24e9c083 1124bf1a d54b7925 \
         32983dd6 c3a8b7d0",
        mac: "179f2fa6",
    },
];

const UIA2_DOC4: &[Uia2Vector] = &[
    // SAGE UEA2&UIA2 Document 4 v1.0, section 4.2, UIA2 Test Set 1
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 4.2, UIA2 Test Set 1",
        key: "2bd6459f82c5b300952c49104881ff48",
        count: 0x38a6f056,
        fresh: 0xb8aefda9,
        direction: 0,
        length_bits: 88,
        message: "33323462 63393861 373479",
        mac: "ee419e0d",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 4.3, UIA2 Test Set 2
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 4.3, UIA2 Test Set 2",
        key: "7e5e94431e11d73828d739cc6ced4573",
        count: 0x36af6144,
        fresh: 0x9838f03a,
        direction: 1,
        length_bits: 254,
        message: "b3d3c917 0a4e1632 f60f8610 13d22d84 b726b6a2 78d802d1 eeaf1321 ba5929dc",
        mac: "92f2a453",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 4.4, UIA2 Test Set 3
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 4.4, UIA2 Test Set 3",
        key: "d3419be821087acd02123a9248033359",
        count: 0xc7590ea9,
        fresh: 0x57d5df7d,
        direction: 0,
        length_bits: 511,
        message: "bbb05703 8809496b cff86d6f bc8ce5b1 35a06b16 6054f2d5 65be8ace 75dc851e \
         0bcdd8f0 7141c495 872fb5d8 c0c66a8b 6da55666 3e4e4612 05d84580 bee5bc7e",
        mac: "ad8c69f9",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 4.5, UIA2 Test Set 4
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 4.5, UIA2 Test Set 4",
        key: "83fd23a244a74cf358da3019f1722635",
        count: 0x36af6144,
        fresh: 0x4f302ad2,
        direction: 1,
        length_bits: 768,
        message: "35c68716 633c66fb 750c2668 65d53c11 ea05b1e9 fa49c839 8d48e1ef a5909d39 \
         47902837 f5ae96d5 a05bc8d6 1ca8dbef 1b13a4b4 abfe4fb1 006045b6 74bb5472 \
         9304c382 be53a5af 05556176 f6eaa2ef 1d05e4b0 83181ee6 74cda5a4 85f74d7a",
        mac: "7306d607",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 4.6, UIA2 Test Set 5
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 4.6, UIA2 Test Set 5",
        key: "6832a65cff4473621ebdd4ba26a921fe",
        count: 0x36af6144,
        fresh: 0x9838f03a,
        direction: 0,
        length_bits: 383,
        message: "d3c53839 62682071 77656676 20323837 63624098 1ba6824c 1bfb1ab4 85472029 \
         b71d808c e33e2cc3 c0b5fc1f 3de8a6dc",
        mac: "e3d36ef1",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 4.7, UIA2 Test Set 6
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 4.7, UIA2 Test Set 6",
        key: "5d0a80d8134ae19677824b671e838af4",
        count: 0x7827fab2,
        fresh: 0xa56c6ca2,
        direction: 1,
        length_bits: 2558,
        message: "70dedf2d c42c5cbd 3a96f8a0 b11418b3 608d5733 604a2cd3 6aabc70c e3193bb5 \
         153be2d3 c06dfdb2 d16e9c35 7158be6a 41d6b861 e491db3f bfeb518e fcf048d7 \
         d5895373 0ff30c9e c470ffcd 663dc342 01c36add c0111c35 b38afee7 cfdb582e \
         3731f8b4 baa8d1a8 9c06e811 99a97162 27be344e fcb436dd d0f096c0 64c3b5e2 \
         c399993f c77394f9 e09720a8 11850ef2 3b2ee05d 9e617360 9d86e1c0 c18ea51a \
         012a00bb 413b9cb8 188a703c d6bae31c c67b34b1 b00019e6 a2b2a690 f02671fe \
         7c9ef8de c0094e53 3763478d 58d2c5f5 b827a014 8c5948a9 6931acf8 4f465a64 \
         e62ce740 07e991e3 7ea823fa 0fb21923 b79905b7 33b631e6 c7d6860a 3831ac35 \
         1a9c730c 52ff72d9 d308eedb ab21fde1 43a0ea17 e23edc1f 74cbb363 8a2033aa \
         a15464ea a733385d bbeb6fd7 3509b857 e6a419dc a1d8907a f977fbac 4dfa35ec",
        mac: "c058d244",
    },
    // SAGE UEA2&UIA2 Document 4 v1.0, section 4.8, UIA2 Test Set 7
    Uia2Vector {
        source: "SAGE UEA2&UIA2 Document 4 v1.0, section 4.8, UIA2 Test Set 7",
        key: "b3120ffdb2cf6af4e73eaf2ef4ebec69",
        count: 0x296f393c,
        fresh: 0x6b227737,
        direction: 1,
        length_bits: 16448,
        message: "00000000 00000000 01010101 01010101 e0958045 f3a0bba4 e3968346 f0a3b8a7 \
         c02a018a e6407652 26b987c9 13e6cbf0 83570016 cf83efbc 61c08251 3e21561a \
         427c009d 28c298ef ace78ed6 d56c2d45 05ad032e 9c04dc60 e73a8169 6da665c6 \
         c48603a5 7b45ab33 221585e6 8ee31691 87fb0239 528632dd 656c807e a3248b7b \
         46d002b2 b5c7458e b85b9ce9 5879e034 0859055e 3b0abbc3 eace8719 caa80265 \
         c97205d5 dc4bcc90 2fe18396 29ed7132 8a0f0449 f588557e 6898860e 042aecd8 \
         4b2404c2 12c9222d a5bf8a89 ef679787 0cf50771 a60f66a2 ee628536 57addf04 \
         cdde07fa 414e11f1 2b4d81b9 b4e8ac53 8ea30666 688d881f 6c348421 992f31b9 \
         4f8806ed 8fccff4c 9123b896 42527ad6 13b109bf 75167485 f1268bf8 84b4cd23 \
         d29a0934 925703d6 34098f77 67f1be74 91e708a8 bb949a38 73708aef 4a36239e \
         50cc0823 5cd5ed6b be578668 a17b58c1 171d0b90 e813a9e4 f58a89d7 19b11042 \
         d6360b1b 0f52deb7 30a58d58 faf46315 954b0a87 26914759 77dc88c0 d733feff \
         54600a0c c1d0300a aaeb9457 2c6e95b0 1ae90de0 4f1dce47 f87e8fa7 bebf77e1 \
         dbc20d6b a85cb914 3d518b28 5dfa04b6 98bf0cf7 819f20fa 7a288eb0 703d995c \
         59940c7c 66de57a9 b70f8237 9b70e203 1e450fcf d2181326 fcd28d88 23baaa80 \
         df6e0f44 35596475 39fd8907 c0ffd9d7 9c130ed8 1c9afd9b 7e848c9f ed38443d \
         5d380e53 fbdb8ac8 c3d3f068 76054f12 2461107d e92fea09 c6f6923a 188d53af \
         e54a10f6 0e6e9d5a 03d996b5 fbc820f8 a637116a 27ad04b4 44a0932d d60fbd12 \
         671c11e1 c0ec73e7 89879faa 3d42c64d 20cd1252 742a3768 c25a9015 85888ece \
         e1e612d9 936b403b 0775949a 66cdfd99 a29b1345 baa8d9d5 400c9102 4b0a6073 \
         63b013ce 5de9ae86 9d3b8d95 b0570b3c 2d391422 d32450cb cfae9665 2286e96d \
         ec1214a9 34652798 0a8192ea c1c39a3a af6f1535 1da6be76 4df89772 ec0407d0 \
         6e4415be fae7c925 80df9bf5 07497c8f 2995160d 4e218daa cb02944a bf83340c \
         e8be1686 a960faf9 0e2d90c5 5cc6475b abc3171a 80a36317 4954955d 7101dab1 \
         6ae81791 67e21444 b443a9ea aa7c91de 36d118c3 9d389f8d d4469a84 6c9a262b \
         f7fa1848 7a79e8de 11699e0b 8fdf557c b48719d4 53ba7130 56109b93 a218c896 \
         75ac195f b4fb0663 9b379714 4955b3c9 327d1aec 003d42ec d0ea98ab f19ffb4a \
         f3561a67 e77c35bf 15c59c24 12da881d b02b1bfb cebfac51 52bc99bc 3f1d15f7 \
         71001b70 29fedb02 8f8b852b c4407eb8 3f891c9c a733254f dd1e9edb 56919ce9 \
         fea21c17 4072521c 18319a54 b5d4efbe bddf1d8b 69b1cbf2 5f489fcc 98137254 \
         7cf41d00 8ef0bca1 926f934b 735e090b 3b251eb3 3a36f82e d9b29cf4 cb944188 \
         fa0e1e38 dd778f7d 1c9d987b 28d132df b9731fa4 f4b41693 5be49de3 0516af35 \
         78581f2f 13f561c0 66336194 1eab249a 4bc123f8 d15cd711 a956a1bf 20fe6eb7 \
         8aea2373 361da042 6c79a530 c3bb1de0 c99722ef 1fde39ac 2b00a0a8 ee7c800a \
         08bc2264 f89f4eff e627ac2f 0531fb55 4f6d21d7 4c590a70 adfaa390 bdfbb3d6 \
         8e46215c ab187d23 68d5a71f 5ebec081 cd3b20c0 82dbe4cd 2faca287 73795d6b \
         0c10204b 659a939e f29bbe10 88243624 429927a7 eb576dd3 a00ea5e0 1af5d475 \
         83b2272c 0c161a80 6521a16f f9b0a722 c0cf26b0 25d5836e 2258a4f7 d4773ac8 \
         01e4263b c294f43d ef7fa870 3f3a4197 46352588 7652b0b2 a4a2a7cf 87f00914 \
         871e2503 9113c7e1 618da340 64b57a43 c463249f b8d05e0f 26f4a6d8 4972e7a9 \
         05482414 5f91295c dbe39a6f 920facc6 59712b46 a54ba295 bbe6a901 54e91b33 \
         985a2bcd 420ad5c6 7ec9ad8e b7ac6864 db272a51 6bc94c28 39b0a816 9a6bf58e \
         1a0c2ada 8c883b7b f497a491 71268ed1 5ddd2969 384e7ff4 bf4aab2e c9ecc652 \
         9cf629e2 df0f08a7 7a65afa1 2aa9b505 df8b287e f6cc9149 3d1caa39 076e28ef \
         1ea028f5 118de61a e02bb6ae fc3343a0 50292f19 9f401857 b2bead5e 6ee2a1f1 \
         91022f92 78016f04 7791a9d1 8da7d2a6 d27f2e0e 51c2f6ea 30e8ac49 a0604f4c \
         13542e85 b68381b9 fdcfa0ce 4b2d3413 54852d36 0245c536 b612af71 f3e77c90 \
         95ae2dbd e504b265 733dabfe 10a20fc7 d6d32c21 ccc72b8b 3444ae66 3d65922d \
         17f82caa 2b865cd8 8913d291 a6589902 6ea13284 39723c19 8c36b0c3 c8d085bf \
         af8a320f de334b4a 4919b44c 2b95f6e8 ecf73393 f7f0d2a4 0e60b1d4 06526b02 \
         2ddc3318 10b1a5f7 c347bd53 ed1f105d 6a0d30ab a477e178 889ab2ec 55d558de \
         ab263020 4336962b 4db5b663 b6902b89 e85b31bc 6af50fc5 0accb3fb 9b57b663 \
         29703137 8db47896 d7fbaf6c 600add2c 67f936db 037986db 856eb49c f2db3f7d \
         a6d23650 e438f188 4041b013 119e4c2a e5af37cc cdfb6866 0738b58b 3c59d1c0 \
         24843747 2aba1f35 ca1fb90c d714aa9f 635534f4 9e7c5bba 81c2b6b3 6fdee21c \
         a27e347f 793d2ce9 44edb23c 8c9b914b e10335e3 50feb507 0394b7a4 a15c0ca1 \
         20283568 b7bfc254 fe838b13 7a2147ce 7c113a3a 4d65499d 9e86b87d bcc7f03b \
         bd3a3ab1 aa243ece 5ba9bcf2 5f82836c fe473b2d 83e7a720 1cd0b96a 72451e86 \
         3f6c3ba6 64a6d073 d1f7b5ed 990865d9 78bd3815 d06094fc 9a2aba52 21c22d5a \
         b996389e 3721e3af 5f05bedd c2875e0d faeb3902 1ee27a41 187cbb45 ef40c3e7 \
         3bc03989 f9a30d12 c54ba7d2 141da8a8 75493e65 776ef35f 97debc22 86cc4af9 \
         b4623eee 902f840c 52f1b8ad 658939ae f71f3f72 b9ec1de2 1588bd35 484ea444 \
         36343ff9 5ead6ab1 d8afb1b2 a303df1b 71e53c4a ea6b2e3e 9372be0d 1bc99798 \
         b0ce3cc1 0d2a596d 565dba82 f88ce4cf f3b33d5d 24e9c083 1124bf1a d54b7925 \
         32983dd6 c3a8b7d0",
        mac: "179f2fa6",
    },
];

const EIA1_TS33401: &[MacVector] = &[
    // TS 33.401 V19.2.0 Annex C.4.1, 128-EIA1 Test Set 1
    MacVector {
        source: "TS 33.401 V19.2.0 Annex C.4.1, 128-EIA1 Test Set 1",
        key: "2bd6459f82c5b300952c49104881ff48",
        count: 0x38a6f056,
        bearer: 0x1f,
        direction: 0,
        length_bits: 88,
        message: "33323462 63393861 373479",
        mac: "731f1165",
    },
    // TS 33.401 V19.2.0 Annex C.4.2, 128-EIA1 Test Set 2
    MacVector {
        source: "TS 33.401 V19.2.0 Annex C.4.2, 128-EIA1 Test Set 2",
        key: "7e5e94431e11d73828d739cc6ced4573",
        count: 0x36af6144,
        bearer: 0x18,
        direction: 1,
        length_bits: 254,
        message: "b3d3c917 0a4e1632 f60f8610 13d22d84 b726b6a2 78d802d1 eeaf1321 ba5929dc",
        mac: "e3259f6f",
    },
    // TS 33.401 V19.2.0 Annex C.4.3, 128-EIA1 Test Set 3
    MacVector {
        source: "TS 33.401 V19.2.0 Annex C.4.3, 128-EIA1 Test Set 3",
        key: "d3419be821087acd02123a9248033359",
        count: 0xc7590ea9,
        bearer: 0x17,
        direction: 0,
        length_bits: 511,
        message: "bbb05703 8809496b cff86d6f bc8ce5b1 35a06b16 6054f2d5 65be8ace 75dc851e \
         0bcdd8f0 7141c495 872fb5d8 c0c66a8b 6da55666 3e4e4612 05d84580 bee5bc7e",
        mac: "9a16c77d",
    },
    // TS 33.401 V19.2.0 Annex C.4.4, 128-EIA1 Test Set 4
    MacVector {
        source: "TS 33.401 V19.2.0 Annex C.4.4, 128-EIA1 Test Set 4",
        key: "83fd23a244a74cf358da3019f1722635",
        count: 0x36af6144,
        bearer: 0x0f,
        direction: 1,
        length_bits: 768,
        message: "35c68716 633c66fb 750c2668 65d53c11 ea05b1e9 fa49c839 8d48e1ef a5909d39 \
         47902837 f5ae96d5 a05bc8d6 1ca8dbef 1b13a4b4 abfe4fb1 006045b6 74bb5472 \
         9304c382 be53a5af 05556176 f6eaa2ef 1d05e4b0 83181ee6 74cda5a4 85f74d7a",
        mac: "bba74492",
    },
    // TS 33.401 V19.2.0 Annex C.4.5, 128-EIA1 Test Set 5
    MacVector {
        source: "TS 33.401 V19.2.0 Annex C.4.5, 128-EIA1 Test Set 5",
        key: "6832a65cff4473621ebdd4ba26a921fe",
        count: 0x36af6144,
        bearer: 0x18,
        direction: 0,
        length_bits: 383,
        message: "d3c53839 62682071 77656676 20323837 63624098 1ba6824c 1bfb1ab4 85472029 \
         b71d808c e33e2cc3 c0b5fc1f 3de8a6dc",
        mac: "4145e4b0",
    },
    // TS 33.401 V19.2.0 Annex C.4.6, 128-EIA1 Test Set 6
    MacVector {
        source: "TS 33.401 V19.2.0 Annex C.4.6, 128-EIA1 Test Set 6",
        key: "5d0a80d8134ae19677824b671e838af4",
        count: 0x7827fab2,
        bearer: 0x05,
        direction: 1,
        length_bits: 2558,
        message: "70dedf2d c42c5cbd 3a96f8a0 b11418b3 608d5733 604a2cd3 6aabc70c e3193bb5 \
         153be2d3 c06dfdb2 d16e9c35 7158be6a 41d6b861 e491db3f bfeb518e fcf048d7 \
         d5895373 0ff30c9e c470ffcd 663dc342 01c36add c0111c35 b38afee7 cfdb582e \
         3731f8b4 baa8d1a8 9c06e811 99a97162 27be344e fcb436dd d0f096c0 64c3b5e2 \
         c399993f c77394f9 e09720a8 11850ef2 3b2ee05d 9e617360 9d86e1c0 c18ea51a \
         012a00bb 413b9cb8 188a703c d6bae31c c67b34b1 b00019e6 a2b2a690 f02671fe \
         7c9ef8de c0094e53 3763478d 58d2c5f5 b827a014 8c5948a9 6931acf8 4f465a64 \
         e62ce740 07e991e3 7ea823fa 0fb21923 b79905b7 33b631e6 c7d6860a 3831ac35 \
         1a9c730c 52ff72d9 d308eedb ab21fde1 43a0ea17 e23edc1f 74cbb363 8a2033aa \
         a15464ea a733385d bbeb6fd7 3509b857 e6a419dc a1d8907a f977fbac 4dfa35ec",
        mac: "0fa2b1ee",
    },
    // TS 33.401 V19.2.0 Annex C.4.7, 128-EIA1 Test Set 7
    MacVector {
        source: "TS 33.401 V19.2.0 Annex C.4.7, 128-EIA1 Test Set 7",
        key: "b3120ffdb2cf6af4e73eaf2ef4ebec69",
        count: 0x296f393c,
        bearer: 0x0b,
        direction: 1,
        length_bits: 16448,
        message: "00000000 00000000 01010101 01010101 e0958045 f3a0bba4 e3968346 f0a3b8a7 \
         c02a018a e6407652 26b987c9 13e6cbf0 83570016 cf83efbc 61c08251 3e21561a \
         427c009d 28c298ef ace78ed6 d56c2d45 05ad032e 9c04dc60 e73a8169 6da665c6 \
         c48603a5 7b45ab33 221585e6 8ee31691 87fb0239 528632dd 656c807e a3248b7b \
         46d002b2 b5c7458e b85b9ce9 5879e034 0859055e 3b0abbc3 eace8719 caa80265 \
         c97205d5 dc4bcc90 2fe18396 29ed7132 8a0f0449 f588557e 6898860e 042aecd8 \
         4b2404c2 12c9222d a5bf8a89 ef679787 0cf50771 a60f66a2 ee628536 57addf04 \
         cdde07fa 414e11f1 2b4d81b9 b4e8ac53 8ea30666 688d881f 6c348421 992f31b9 \
         4f8806ed 8fccff4c 9123b896 42527ad6 13b109bf 75167485 f1268bf8 84b4cd23 \
         d29a0934 925703d6 34098f77 67f1be74 91e708a8 bb949a38 73708aef 4a36239e \
         50cc0823 5cd5ed6b be578668 a17b58c1 171d0b90 e813a9e4 f58a89d7 19b11042 \
         d6360b1b 0f52deb7 30a58d58 faf46315 954b0a87 26914759 77dc88c0 d733feff \
         54600a0c c1d0300a aaeb9457 2c6e95b0 1ae90de0 4f1dce47 f87e8fa7 bebf77e1 \
         dbc20d6b a85cb914 3d518b28 5dfa04b6 98bf0cf7 819f20fa 7a288eb0 703d995c \
         59940c7c 66de57a9 b70f8237 9b70e203 1e450fcf d2181326 fcd28d88 23baaa80 \
         df6e0f44 35596475 39fd8907 c0ffd9d7 9c130ed8 1c9afd9b 7e848c9f ed38443d \
         5d380e53 fbdb8ac8 c3d3f068 76054f12 2461107d e92fea09 c6f6923a 188d53af \
         e54a10f6 0e6e9d5a 03d996b5 fbc820f8 a637116a 27ad04b4 44a0932d d60fbd12 \
         671c11e1 c0ec73e7 89879faa 3d42c64d 20cd1252 742a3768 c25a9015 85888ece \
         e1e612d9 936b403b 0775949a 66cdfd99 a29b1345 baa8d9d5 400c9102 4b0a6073 \
         63b013ce 5de9ae86 9d3b8d95 b0570b3c 2d391422 d32450cb cfae9665 2286e96d \
         ec1214a9 34652798 0a8192ea c1c39a3a af6f1535 1da6be76 4df89772 ec0407d0 \
         6e4415be fae7c925 80df9bf5 07497c8f 2995160d 4e218daa cb02944a bf83340c \
         e8be1686 a960faf9 0e2d90c5 5cc6475b abc3171a 80a36317 4954955d 7101dab1 \
         6ae81791 67e21444 b443a9ea aa7c91de 36d118c3 9d389f8d d4469a84 6c9a262b \
         f7fa1848 7a79e8de 11699e0b 8fdf557c b48719d4 53ba7130 56109b93 a218c896 \
         75ac195f b4fb0663 9b379714 4955b3c9 327d1aec 003d42ec d0ea98ab f19ffb4a \
         f3561a67 e77c35bf 15c59c24 12da881d b02b1bfb cebfac51 52bc99bc 3f1d15f7 \
         71001b70 29fedb02 8f8b852b c4407eb8 3f891c9c a733254f dd1e9edb 56919ce9 \
         fea21c17 4072521c 18319a54 b5d4efbe bddf1d8b 69b1cbf2 5f489fcc 98137254 \
         7cf41d00 8ef0bca1 926f934b 735e090b 3b251eb3 3a36f82e d9b29cf4 cb944188 \
         fa0e1e38 dd778f7d 1c9d987b 28d132df b9731fa4 f4b41693 5be49de3 0516af35 \
         78581f2f 13f561c0 66336194 1eab249a 4bc123f8 d15cd711 a956a1bf 20fe6eb7 \
         8aea2373 361da042 6c79a530 c3bb1de0 c99722ef 1fde39ac 2b00a0a8 ee7c800a \
         08bc2264 f89f4eff e627ac2f 0531fb55 4f6d21d7 4c590a70 adfaa390 bdfbb3d6 \
         8e46215c ab187d23 68d5a71f 5ebec081 cd3b20c0 82dbe4cd 2faca287 73795d6b \
         0c10204b 659a939e f29bbe10 88243624 429927a7 eb576dd3 a00ea5e0 1af5d475 \
         83b2272c 0c161a80 6521a16f f9b0a722 c0cf26b0 25d5836e 2258a4f7 d4773ac8 \
         01e4263b c294f43d ef7fa870 3f3a4197 46352588 7652b0b2 a4a2a7cf 87f00914 \
         871e2503 9113c7e1 618da340 64b57a43 c463249f b8d05e0f 26f4a6d8 4972e7a9 \
         05482414 5f91295c dbe39a6f 920facc6 59712b46 a54ba295 bbe6a901 54e91b33 \
         985a2bcd 420ad5c6 7ec9ad8e b7ac6864 db272a51 6bc94c28 39b0a816 9a6bf58e \
         1a0c2ada 8c883b7b f497a491 71268ed1 5ddd2969 384e7ff4 bf4aab2e c9ecc652 \
         9cf629e2 df0f08a7 7a65afa1 2aa9b505 df8b287e f6cc9149 3d1caa39 076e28ef \
         1ea028f5 118de61a e02bb6ae fc3343a0 50292f19 9f401857 b2bead5e 6ee2a1f1 \
         91022f92 78016f04 7791a9d1 8da7d2a6 d27f2e0e 51c2f6ea 30e8ac49 a0604f4c \
         13542e85 b68381b9 fdcfa0ce 4b2d3413 54852d36 0245c536 b612af71 f3e77c90 \
         95ae2dbd e504b265 733dabfe 10a20fc7 d6d32c21 ccc72b8b 3444ae66 3d65922d \
         17f82caa 2b865cd8 8913d291 a6589902 6ea13284 39723c19 8c36b0c3 c8d085bf \
         af8a320f de334b4a 4919b44c 2b95f6e8 ecf73393 f7f0d2a4 0e60b1d4 06526b02 \
         2ddc3318 10b1a5f7 c347bd53 ed1f105d 6a0d30ab a477e178 889ab2ec 55d558de \
         ab263020 4336962b 4db5b663 b6902b89 e85b31bc 6af50fc5 0accb3fb 9b57b663 \
         29703137 8db47896 d7fbaf6c 600add2c 67f936db 037986db 856eb49c f2db3f7d \
         a6d23650 e438f188 4041b013 119e4c2a e5af37cc cdfb6866 0738b58b 3c59d1c0 \
         24843747 2aba1f35 ca1fb90c d714aa9f 635534f4 9e7c5bba 81c2b6b3 6fdee21c \
         a27e347f 793d2ce9 44edb23c 8c9b914b e10335e3 50feb507 0394b7a4 a15c0ca1 \
         20283568 b7bfc254 fe838b13 7a2147ce 7c113a3a 4d65499d 9e86b87d bcc7f03b \
         bd3a3ab1 aa243ece 5ba9bcf2 5f82836c fe473b2d 83e7a720 1cd0b96a 72451e86 \
         3f6c3ba6 64a6d073 d1f7b5ed 990865d9 78bd3815 d06094fc 9a2aba52 21c22d5a \
         b996389e 3721e3af 5f05bedd c2875e0d faeb3902 1ee27a41 187cbb45 ef40c3e7 \
         3bc03989 f9a30d12 c54ba7d2 141da8a8 75493e65 776ef35f 97debc22 86cc4af9 \
         b4623eee 902f840c 52f1b8ad 658939ae f71f3f72 b9ec1de2 1588bd35 484ea444 \
         36343ff9 5ead6ab1 d8afb1b2 a303df1b 71e53c4a ea6b2e3e 9372be0d 1bc99798 \
         b0ce3cc1 0d2a596d 565dba82 f88ce4cf f3b33d5d 24e9c083 1124bf1a d54b7925 \
         32983dd6 c3a8b7d0",
        mac: "abf3e651",
    },
];

const ZUC_KEYSTREAM: &[KeystreamVector] = &[
    // SAGE EEA3&EIA3 Document 3 v1.1, section 3.3, ZUC Test Set 1
    KeystreamVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 3.3, ZUC Test Set 1",
        key: "00000000000000000000000000000000",
        iv: "00000000000000000000000000000000",
        words: &[(1, 0x27bede74), (2, 0x018082da)],
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 3.4, ZUC Test Set 2
    KeystreamVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 3.4, ZUC Test Set 2",
        key: "ffffffffffffffffffffffffffffffff",
        iv: "ffffffffffffffffffffffffffffffff",
        words: &[(1, 0x0657cfa0), (2, 0x7096398b)],
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 3.5, ZUC Test Set 3
    KeystreamVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 3.5, ZUC Test Set 3",
        key: "3d4c4be96a82fdaeb58f641db17b455b",
        iv: "84319aa8de6915ca1f6bda6bfbd8c766",
        words: &[(1, 0x14f1c272), (2, 0x3279c419)],
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 3.6, ZUC Test Set 4
    KeystreamVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 3.6, ZUC Test Set 4",
        key: "4d320bfad4c285bfd6b8bd00f39d8b41",
        iv: "52959daba0bf176ece2dc315049eb574",
        words: &[(1, 0xed4400e7), (2, 0x0633e5c5), (2000, 0x7a574cdb)],
    },
];

const EEA3_DOC3: &[CipherVector] = &[
    // SAGE EEA3&EIA3 Document 3 v1.1, section 4.3, 128-EEA3 Test Set 1
    CipherVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 4.3, 128-EEA3 Test Set 1",
        key: "173d14ba5003731d7a60049470f00a29",
        count: 0x66035492,
        bearer: 0x0f,
        direction: 0,
        length_bits: 193,
        plaintext: "6cf65340 735552ab 0c9752fa 6f9025fe 0bd675d9 005875b2 00",
        ciphertext: "a6c85fc6 6afb8533 aafc2518 dfe78494 0ee1e4b0 30238cc8 00",
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 4.4, 128-EEA3 Test Set 2
    CipherVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 4.4, 128-EEA3 Test Set 2",
        key: "e5bd3ea0eb55ade866c6ac58bd54302a",
        count: 0x00056823,
        bearer: 0x18,
        direction: 1,
        length_bits: 800,
        plaintext: "14a8ef69 3d678507 bbe7270a 7f67ff50 06c3525b 9807e467 c4e56000 ba338f5d \
         42955903 67518222 46c80d3b 38f07f4b e2d8ff58 05f51322 29bde93b bbdcaf38 \
         2bf1ee97 2fbf9977 bada8945 847a2a6c 9ad34a66 7554e04d 1f7fa2c3 3241bd8f \
         01ba220d",
        ciphertext: "131d43e0 dea1be5c 5a1bfd97 1d852cbf 712d7b4f 57961fea 3208afa8 bca433f4 \
         56ad09c7 417e58bc 69cf8866 d1353f74 865e8078 1d202dfb 3ecff7fc bc3b190f \
         e82a204e d0e350fc 0f6f2613 b2f2bca6 df5a473a 57a4a00d 985ebad8 80d6f238 \
         64a07b01",
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 4.5, 128-EEA3 Test Set 3
    CipherVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 4.5, 128-EEA3 Test Set 3",
        key: "d4552a8fd6e61cc81a2009141a29c10b",
        count: 0x76452ec1,
        bearer: 0x02,
        direction: 1,
        length_bits: 1570,
        plaintext: "38f07f4b e2d8ff58 05f51322 29bde93b bbdcaf38 2bf1ee97 2fbf9977 bada8945 \
         847a2a6c 9ad34a66 7554e04d 1f7fa2c3 3241bd8f 01ba220d 3ca4ec41 e074595f \
         54ae2b45 4fd97143 20436019 65cca85c 2417ed6c bec3bada 84fc8a57 9aea7837 \
         b0271177 242a64dc 0a9de71a 8edee86c a3d47d03 3d6bf539 804eca86 c584a905 \
         2de46ad3 fced6554 3bd90207 372b27af b79234f5 ff43ea87 0820e2c2 b78a8aae \
         61cce52a 0515e348 d196664a 3456b182 a07c406e 4a207912 71cfeda1 65d535ec \
         5ea2d4df 40",
        ciphertext: "8383b022 9fcc0b9d 2295ec41 c977e9c2 bb72e220 378141f9 c8318f3a 270dfbcd \
         ee6411c2 b3044f17 6dc6e00f 8960f97a facd131a d6a3b49b 16b7babc f2a509eb \
         b16a75dc ab14ff27 5dbeeea1 a2b155f9 d52c2645 2d0187c3 10a4ee55 beaa78ab \
         4024615b a9f5d5ad c7728f73 560671f0 13e5e550 085d3291 df7d5fec edded559 \
         641b6c2f 585233bc 71e9602b d2305855 bbd25ffa 7f17ecbc 042daae3 8c1f57ad \
         8e8ebd37 346f71be fdbb7432 e0e0bb2c fc09bcd9 6570cb0c 0c39df5e 29294e82 \
         703a637f 80",
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 4.6, 128-EEA3 Test Set 4
    CipherVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 4.6, 128-EEA3 Test Set 4",
        key: "db84b4fbccda563b66227bfe456f0f77",
        count: 0xe4850fe1,
        bearer: 0x10,
        direction: 1,
        length_bits: 2798,
        plaintext: "e539f3b8 973240da 03f2b8aa 05ee0a00 dbafc0e1 82055dfe 3d7383d9 2cef40e9 \
         2928605d 52d05f4f 9018a1f1 89ae3997 ce19155f b1221db8 bb0951a8 53ad852c \
         e16cff07 382c93a1 57de00dd b125c753 9fd85045 e4ee07e0 c43f9e9d 6f414fc4 \
         d1c62917 813f74c0 0fc83f3e 2ed7c45b a5835264 b43e0b20 afda6b30 53bfb642 \
         3b7fce25 479ff5f1 39dd9b5b 995558e2 a56be18d d581cd01 7c735e6f 0d0d97c4 \
         ddc1d1da 70c6db4a 12cc9277 8e2fbbd6 f3ba52af 91c9c6b6 4e8da4f7 a2c266d0 \
         2d001753 df089603 93c5d568 88bf49eb 5c16d9a8 0427a416 bcb597df 5bfe6f13 \
         890a07ee 1340e647 6b0d9aa8 f822ab0f d1ab0d20 4f40b7ce 6f2e136e b67485e5 \
         07804d50 4588ad37 ffd81656 8b2dc403 11dfb654 cdead47e 2385c343 6203dd83 \
         6f9c64d9 7462ad5d fa63b5cf e08acb95 32866f5c a787566f ca93e6b1 693ee15c \
         f6f7a2d6 89d97417 98dc1c23 8e1be650 733b18fb 34ff880e 16bbd21b 47ac",
        ciphertext: "4bbfa91b a25d47db 9a9f190d 962a19ab 323926b3 51fbd39e 351e05da 8b8925e3 \
         0b1cce0d 12211010 95815cc7 cb631950 9ec0d679 40491987 e13f0aff ac332aa6 \
         aa64626d 3e9a1917 519e0b97 b655c6a1 65e44ca9 feac0790 d2a321ad 3d86b79c \
         5138739f a38d887e c7def449 ce8abdd3 e7f8dc4c a9e7b733 14ad310f 9025e619 \
         46b3a56d c649ec0d a0d63943 dff592cf 962a7efb 2c8524e3 5a2a6e78 79d62604 \
         ef268695 fa400302 7e22e608 30775220 64bd4a5b 906b5f53 1274f235 ed506cff \
         0154c754 928a0ce5 476f2cb1 020a1222 d32c1455 ecaef1e3 68fb344d 1735bfbe \
         deb71d0a 33a2a54b 1da5a294 e679144d df11eb1a 3de8cf0c c0619179 74f35c1d \
         9ca0ac81 807f8fcc e6199a6c 7712da86 5021b04c e0439516 f1a526cc da9fd9ab \
         bd53c3a6 84f9ae1e 7ee6b11d a138ea82 6c5516b5 aadf1abb e36fa7ff f92e3a11 \
         76064e8d 95f2e488 2b5500b9 3228b219 4a475c1a 27f63f9f fd264989 a1bc",
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 4.7, 128-EEA3 Test Set 5
    CipherVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 4.7, 128-EEA3 Test Set 5",
        key: "e13fed21b46e4e7ec31253b2bb17b3e0",
        count: 0x2738cdaa,
        bearer: 0x1a,
        direction: 0,
        length_bits: 4019,
        plaintext: "8d74e20d 54894e06 d3cb13cb 3933065e 8674be62 adb1c72b 3a646965 ab63cb7b \
         7854dfdc 27e84929 f49c64b8 72a490b1 3f957b64 827e71f4 1fbd4269 a42c97f8 \
         24537027 f86e9f4a d82d1df4 51690fdd 98b6d03f 3a0ebe3a 312d6b84 0ba5a182 \
         0b2a2c97 09c090d2 45ed267c f845ae41 fa975d33 33ac3009 fd40eba9 eb5b8857 \
         14b768b6 97138baf 21380eca 49f644d4 8689e421 5760b906 739f0d2b 3f091133 \
         ca15d981 cbe401ba f72d05ac e05cccb2 d297f4ef 6a5f58d9 1246cfa7 7215b892 \
         ab441d52 78452795 ccb7f5d7 9057a1c4 f77f80d4 6db2033c b79bedf8 e60551ce \
         10c667f6 2a97abaf abbcd677 2018df96 a282ea73 7ce2cb33 1211f60d 5354ce78 \
         f9918d9c 206ca042 c9b62387 dd709604 a50af16d 8d35a890 6be484cf 2e74a928 \
         99403643 53249b27 b4c9ae29 eddfc7da 6418791a 4e7baa06 60fa6451 1f2d685c \
         c3a5ff70 e0d2b742 92e3b8a0 cd6b04b1 c790b8ea d2703708 540dea2f c09c3da7 \
         70f65449 e84d817a 4f551055 e19ab850 18a0028b 71a144d9 6791e9a3 57793350 \
         4eee0060 340c69d2 74e1bf9d 805dcbcc 1a6faa97 6800b6ff 2b671dc4 63652fa8 \
         a33ee509 74c1c21b e01eabb2 16743026 9d72ee51 1c9dde30 797c9a25 d86ce74f \
         5b961be5 fdfb6807 814039e7 137636bd 1d7fa9e0 9efd2007 505906a5 ac45dfde \
         ed7757bb ee745749 c2963335 0bee0ea6 f409df45 801600",
        ciphertext: "94eaa4aa 30a57137 ddf09b97 b25618a2 0a13e2f1 0fa5bf81 61a879cc 2ae797a6 \
         b4cf2d9d f31debb9 905ccfec 97de605d 21c61ab8 531b7f3c 9da5f039 31f8a064 \
         2de48211 f5f52ffe a10f392a 04766998 5da454a2 8f080961 a6c2b62d aa17f33c \
         d60a4971 f48d2d90 9394a55f 48117ace 43d708e6 b77d3dc4 6d8bc017 d4d1abb7 \
         7b7428c0 42b06f2f 99d8d07c 9879d996 00127a31 985f1099 bbd7d6c1 519ede8f \
         5eeb4a61 0b349ac0 1ea23506 91756bd1 05c974a5 3eddb35d 1d4100b0 12e522ab \
         41f4c5f2 fde76b59 cb8b96d8 85cfe408 0d1328a0 d636cc0e dc05800b 76acca8f \
         ef672084 d1f52a8b bd8e0993 320992c7 ffbae17c 408441e0 ee883fc8 a8b05e22 \
         f5ff7f8d 1b48c74c 468c467a 028f09fd 7ce91109 a570a2d5 c4d5f4fa 18c5dd3e \
         4562afe2 4ef77190 1f59af64 5898acef 088abae0 7e92d52e b2de5504 5bb1b7c4 \
         164ef2d7 a6cac15e eb926d7e a2f08b66 e1f759f3 aee44614 725aa3c7 482b3084 \
         4c143ff8 5b53f1e5 83c50125 7dddd096 b81268da a303f172 34c23335 41f0bb8e \
         190648c5 807c866d 71932286 09adb948 686f7de2 94a802cc 38f7fe52 08f5ea31 \
         96d0167b 9bdd02f0 d2a5221c a508f893 af5c4b4b b9f4f520 fd84289b 3dbe7e61 \
         497a7e2a 584037ea 637b6981 127174af 57b471df 4b2768fd 79c1540f b3edf2ea \
         22cb69be c0cf8d93 3d9c6fdd 645e8505 91cca3d6 2c0cc0",
    },
];

const EIA3_DOC3: &[MacVector] = &[
    // SAGE EEA3&EIA3 Document 3 v1.1, section 5.2, 128-EIA3 Test Set 1
    MacVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 5.2, 128-EIA3 Test Set 1",
        key: "00000000000000000000000000000000",
        count: 0x00000000,
        bearer: 0x00,
        direction: 0,
        length_bits: 1,
        message: "00",
        mac: "c8a9595e",
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 5.3, 128-EIA3 Test Set 2
    MacVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 5.3, 128-EIA3 Test Set 2",
        key: "47054125561eb2dda94059da05097850",
        count: 0x561eb2dd,
        bearer: 0x14,
        direction: 0,
        length_bits: 90,
        message: "00000000 00000000 00000000",
        mac: "6719a088",
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 5.4, 128-EIA3 Test Set 3
    MacVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 5.4, 128-EIA3 Test Set 3",
        key: "c9e6cec4607c72db000aefa88385ab0a",
        count: 0xa94059da,
        bearer: 0x0a,
        direction: 1,
        length_bits: 577,
        message: "983b41d4 7d780c9e 1ad11d7e b70391b1 de0b35da 2dc62f83 e7b78d63 06ca0ea0 \
         7e941b7b e91348f9 fcb170e2 217fecd9 7f9f68ad b16e5d7d 21e569d2 80ed775c \
         ebde3f40 93c53881 00",
        mac: "fae8ff0b",
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 5.5, 128-EIA3 Test Set 4
    MacVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 5.5, 128-EIA3 Test Set 4",
        key: "c8a48262d0c2e2bac4b96ef77e80ca59",
        count: 0x05097850,
        bearer: 0x10,
        direction: 1,
        length_bits: 2079,
        message: "b546430b f87b4f1e e834704c d6951c36 e26f108c f731788f 48dc34f1 678c0522 \
         1c8fa7ff 2f39f477 e7e49ef6 0a4ec2c3 de24312a 96aa26e1 cfba5756 3838b297 \
         f47e8510 c779fd66 54b14338 6fa639d3 1edbd6c0 6e47d159 d94362f2 6aeeedee \
         0e4f49d9 bf841299 5415bfad 56ee82d1 ca7463ab f085b082 b09904d6 d990d43c \
         f2e062f4 0839d932 48b1eb92 cdfed530 0bc14828 0430b6d0 caa094b6 ec8911ab \
         7dc36824 b824dc0a f6682b09 35fde7b4 92a14dc2 f4364803 8da2cf79 170d2d50 \
         133fd494 16cb6e33 bea90b8b f4559b03 732a01ea 290e6d07 4f79bb83 c10e5800 \
         15cc1a85 b36b5501 046e9c4b dcae5135 690b8666 bd54b7a7 03ea7b6f 220a5469 \
         a568027e",
        mac: "004ac4d6",
    },
    // SAGE EEA3&EIA3 Document 3 v1.1, section 5.6, 128-EIA3 Test Set 5
    MacVector {
        source: "SAGE EEA3&EIA3 Document 3 v1.1, section 5.6, 128-EIA3 Test Set 5",
        key: "6b8b08ee79e0b5982d6d128ea9f220cb",
        count: 0x561eb2dd,
        bearer: 0x1c,
        direction: 0,
        length_bits: 5670,
        message: "5bad7247 10ba1c56 d5a315f8 d40f6e09 3780be8e 8de07b69 92432018 e08ed96a \
         5734af8b ad8a575d 3a1f162f 85045cc7 70925571 d9f5b94e 454a77c1 6e72936b \
         f016ae15 7499f054 3b5d52ca a6dbeab6 97d2bb73 e41b8075 dce79b4b 86044f66 \
         1d4485a5 43dd7860 6e0419e8 059859d3 cb2b67ce 0977603f 81ff839e 33185954 \
         4cfbc8d0 0fef1a4c 8510fb54 7d6b06c6 11ef44f1 bce107cf a45a06aa b360152b \
         28dc1ebe 6f7fe09b 0516f9a5 b02a1bd8 4bb0181e 2e89e19b d8125930 d178682f \
         3862dc51 b636f04e 720c47c3 ce51ad70 d94b9b22 55fbae90 6549f499 f8c6d399 \
         47ed5e5d f8e2def1 13253e7b 08d0a76b 6bfc68c8 12f375c7 9b8fe5fd 85976aa6 \
         d46b4a23 39d8ae51 47f680fb e70f978b 38effd7b 2f7866a2 2554e193 a94e98a6 \
         8b74bd25 bb2b3f5f b0a5fd59 887f9ab6 8159b717 8d5b7b67 7cb546bf 41eadca2 \
         16fc1085 0128f8bd ef5c8d89 f96afa4f a8b54885 565ed838 a950fee5 f1c3b0a4 \
         f6fb71e5 4dfd169e 82cecc72 66c850e6 7c5ef0ba 960f5214 060e71eb 172a75fc \
         1486835c bea65344 65b055c9 6a72e410 52241823 25d83041 4b40214d aa8091d2 \
         e0fb010a e15c6de9 0850973b df1e423b e148a237 b87a0c9f 34d4b476 05b803d7 \
         43a86a90 399a4af3 96d3a120 0a62f3d9 507962e8 e5bee6d3 da2bb3f7 237664ac \
         7a292823 900bc635 03b29e80 d63f6067 bf8e1716 ac25beba 350deb62 a99fe031 \
         85eb4f69 937ecd38 7941fda5 44ba67db 09117749 38b01827 bcc69c92 b3f772a9 \
         d2859ef0 03398b1f 6bbad7b5 74f7989a 1d10b2df 798e0dbf 30d65874 64d24878 \
         cd00c0ea ee8a1a0c c753a279 79e11b41 db1de3d5 038afaf4 9f5c682c 3748d8a3 \
         a9ec54e6 a371275f 1683510f 8e4f9093 8f9ab6e1 34c2cfdf 4841cba8 8e0cff2b \
         0bcc8e6a dcb71109 b5198fec f1bb7e5c 531aca50 a56a8a3b 6de59862 d41fa113 \
         d9cd9578 08f08571 d9a4bb79 2af271f6 cc6dbb8d c7ec36e3 6be1ed30 8164c31c \
         7c0afc54 1c",
        mac: "0ca12792",
    },
];

fn check_keystream(
    vectors: &[KeystreamVector],
    mut next: impl FnMut(&[u8; 16], &[u8; 16]) -> Box<dyn FnMut() -> u32>,
) {
    for v in vectors {
        let mut gen = next(&key(v.key), &key(v.iv));
        let mut t = 0u32;
        for &(want_t, want) in v.words {
            let mut z = 0;
            while t < want_t {
                z = gen();
                t += 1;
            }
            assert_eq!(z, want, "{}: z{want_t}", v.source);
        }
    }
}

fn check_cipher(vectors: &[CipherVector], f: CipherFn) -> usize {
    for v in vectors {
        let plain = unhex(v.plaintext);
        let cipher = unhex(v.ciphertext);
        let mut data = plain.clone();
        f(
            &key(v.key),
            v.count,
            v.bearer,
            v.direction,
            &mut data,
            v.length_bits,
        );
        assert_eq!(hex(&data), hex(&cipher), "{}", v.source);
        f(
            &key(v.key),
            v.count,
            v.bearer,
            v.direction,
            &mut data,
            v.length_bits,
        );
        assert_eq!(hex(&data), hex(&plain), "{}: its own inverse", v.source);
    }
    vectors.len()
}

fn check_mac(vectors: &[MacVector], f: MacFn) -> usize {
    for v in vectors {
        let msg = unhex(v.message);
        let mac = f(
            &key(v.key),
            v.count,
            v.bearer,
            v.direction,
            &msg,
            v.length_bits,
        );
        assert_eq!(hex(&mac), v.mac, "{}", v.source);
    }
    vectors.len()
}

#[test]
fn snow3g_keystream_matches_uea2_document_3() {
    check_keystream(SNOW3G_KEYSTREAM, |k, iv| {
        let mut g = snow3g::Snow3g::from_bytes(k, iv);
        Box::new(move || g.next_word())
    });
}

#[test]
fn eea1_matches_uea2_documents_3_and_4() {
    assert_eq!(check_cipher(UEA2_DOC3, snow3g::eea1_bits), 5);
    assert_eq!(check_cipher(UEA2_DOC4, snow3g::eea1_bits), 6);
}

#[test]
fn uia2_matches_documents_3_and_4() {
    for v in UIA2_DOC3.iter().chain(UIA2_DOC4) {
        let msg = unhex(v.message);
        let mac = snow3g::uia2_bits(
            &key(v.key),
            v.count,
            v.fresh,
            v.direction,
            &msg,
            v.length_bits,
        );
        assert_eq!(hex(&mac), v.mac, "{}", v.source);
    }
    assert_eq!(UIA2_DOC3.len() + UIA2_DOC4.len(), 13);
}

#[test]
fn eia1_matches_ts_33_401_annex_c4() {
    assert_eq!(check_mac(EIA1_TS33401, snow3g::eia1_bits), 7);
}

#[test]
fn zuc_keystream_matches_eea3_document_3() {
    check_keystream(ZUC_KEYSTREAM, |k, iv| {
        let mut g = zuc::Zuc::new(k, iv);
        Box::new(move || g.next_word())
    });
}

#[test]
fn eea3_matches_document_3() {
    assert_eq!(check_cipher(EEA3_DOC3, zuc::eea3_bits), 5);
}

#[test]
fn eia3_matches_document_3() {
    assert_eq!(check_mac(EIA3_DOC3, zuc::eia3_bits), 5);
}

/// The octet functions the NAS layer calls are the bit functions at 8 × the length: checked on
/// every published set whose length is a whole number of octets.
#[test]
fn octet_functions_match_the_byte_aligned_sets() {
    let mut seen = 0;
    for (vectors, nea) in [
        (
            UEA2_DOC3,
            snow3g::nea1 as fn(&[u8; 16], u32, u8, u8, &mut [u8]),
        ),
        (UEA2_DOC4, snow3g::nea1),
        (EEA3_DOC3, zuc::nea3),
    ] {
        for v in vectors.iter().filter(|v| v.length_bits % 8 == 0) {
            let mut data = unhex(v.plaintext);
            nea(&key(v.key), v.count, v.bearer, v.direction, &mut data);
            assert_eq!(hex(&data), hex(&unhex(v.ciphertext)), "{}", v.source);
            seen += 1;
        }
    }
    for (vectors, nia) in [
        (
            EIA1_TS33401,
            snow3g::nia1 as fn(&[u8; 16], u32, u8, u8, &[u8]) -> [u8; 4],
        ),
        (EIA3_DOC3, zuc::nia3),
    ] {
        for v in vectors.iter().filter(|v| v.length_bits % 8 == 0) {
            let mac = nia(
                &key(v.key),
                v.count,
                v.bearer,
                v.direction,
                &unhex(v.message),
            );
            assert_eq!(hex(&mac), v.mac, "{}", v.source);
            seen += 1;
        }
    }
    // UEA2 Document 3 set 3 (120 bits), EEA3 set 2 (800), EIA1 sets 1, 4 and 7 (88, 768, 16448).
    assert_eq!(seen, 5, "byte-aligned sets checked");
}

/// Bits of the last octet beyond LENGTH are not part of the message: ciphering leaves them as
/// they were, and the MAC does not depend on them.
#[test]
fn bits_beyond_length_are_outside_the_message() {
    for (vectors, f) in [
        (UEA2_DOC3, snow3g::eea1_bits as CipherFn),
        (EEA3_DOC3, zuc::eea3_bits),
    ] {
        for v in vectors.iter().filter(|v| v.length_bits % 8 != 0) {
            let unused = 8 - (v.length_bits % 8) as u32;
            let mask = ((1u16 << unused) - 1) as u8;
            let mut data = unhex(v.plaintext);
            *data.last_mut().unwrap() |= mask;
            f(
                &key(v.key),
                v.count,
                v.bearer,
                v.direction,
                &mut data,
                v.length_bits,
            );
            let mut want = unhex(v.ciphertext);
            *want.last_mut().unwrap() |= mask;
            assert_eq!(hex(&data), hex(&want), "{}", v.source);
        }
    }
    for (vectors, f) in [
        (EIA1_TS33401, snow3g::eia1_bits as MacFn),
        (EIA3_DOC3, zuc::eia3_bits),
    ] {
        for v in vectors.iter().filter(|v| v.length_bits % 8 != 0) {
            let mut msg = unhex(v.message);
            *msg.last_mut().unwrap() |= 0x01;
            let mac = f(
                &key(v.key),
                v.count,
                v.bearer,
                v.direction,
                &msg,
                v.length_bits,
            );
            assert_eq!(hex(&mac), v.mac, "{}", v.source);
        }
    }
}

/// No length panics: empty input, a LENGTH beyond the buffer (clamped to it), and LENGTH 0.
#[test]
fn degenerate_lengths_do_not_panic() {
    let k = [7u8; 16];
    for len in [0usize, 1, 3, 4, 5, 7, 8, 9, 63, 64, 65] {
        let msg = vec![0xA5u8; len];
        let mut d1 = msg.clone();
        snow3g::nea1(&k, 1, 1, 0, &mut d1);
        let mut d3 = msg.clone();
        zuc::nea3(&k, 1, 1, 0, &mut d3);
        assert_eq!(d1.len(), len);
        assert_eq!(d3.len(), len);
        let _ = snow3g::nia1(&k, 1, 1, 0, &msg);
        let _ = zuc::nia3(&k, 1, 1, 0, &msg);
        // A LENGTH past the end of the buffer is the whole buffer.
        let mut over = msg.clone();
        snow3g::eea1_bits(&k, 1, 1, 0, &mut over, u64::MAX);
        assert_eq!(over, d1);
        let mut over = msg.clone();
        zuc::eea3_bits(&k, 1, 1, 0, &mut over, u64::MAX);
        assert_eq!(over, d3);
        assert_eq!(
            snow3g::eia1_bits(&k, 1, 1, 0, &msg, u64::MAX),
            snow3g::nia1(&k, 1, 1, 0, &msg)
        );
        assert_eq!(
            zuc::eia3_bits(&k, 1, 1, 0, &msg, u64::MAX),
            zuc::nia3(&k, 1, 1, 0, &msg)
        );
        // LENGTH 0 ciphers nothing.
        let mut zero = msg.clone();
        snow3g::eea1_bits(&k, 1, 1, 0, &mut zero, 0);
        zuc::eea3_bits(&k, 1, 1, 0, &mut zero, 0);
        assert_eq!(zero, msg);
    }
}

// ---- NasContext round trips ----

/// The AMF protects downlink with NIA1/NEA1 and NIA3/NEA3, a UE context derived from the same
/// K_AMF reads it, and the other way round; the wire carries exactly what the algorithm
/// functions compute under the derived NAS keys, and a flipped MAC bit is refused.
#[test]
fn nas_context_round_trips_with_snow3g_and_zuc() {
    let k_amf = [0x5Au8; 32];
    for (ia, ea) in [
        (security::NIA1, security::NEA1),
        (security::NIA3, security::NEA3),
    ] {
        let (k_enc, k_int) = security::nas_keys(&k_amf, ea, ia);
        let mut amf = security::NasContext::new(1, k_amf, ia, ea, security::DOWNLINK);
        let mut ue = security::NasContext::new(1, k_amf, ia, ea, security::UPLINK);

        let plain = [
            0x7e, 0x00, 0x42, 0x01, 0x01, 0x77, 0x00, 0x0b, 0xf2, 0x00, 0xf1, 0x10,
        ];
        let wire = amf.protect(&plain, security::SHT_INTEGRITY_CIPHERED);
        assert_ne!(&wire[7..], &plain, "ia={ia} ea={ea}: the body is ciphered");
        let mut expected_body = plain.to_vec();
        let expected_mac = if ia == security::NIA1 {
            snow3g::nea1(
                &k_enc,
                0,
                security::BEARER_3GPP,
                security::DOWNLINK,
                &mut expected_body,
            );
            let mut covered = vec![0u8];
            covered.extend_from_slice(&expected_body);
            snow3g::nia1(
                &k_int,
                0,
                security::BEARER_3GPP,
                security::DOWNLINK,
                &covered,
            )
        } else {
            zuc::nea3(
                &k_enc,
                0,
                security::BEARER_3GPP,
                security::DOWNLINK,
                &mut expected_body,
            );
            let mut covered = vec![0u8];
            covered.extend_from_slice(&expected_body);
            zuc::nia3(
                &k_int,
                0,
                security::BEARER_3GPP,
                security::DOWNLINK,
                &covered,
            )
        };
        assert_eq!(&wire[7..], expected_body.as_slice(), "ia={ia} ea={ea}");
        assert_eq!(&wire[2..6], &expected_mac, "ia={ia} ea={ea}");

        let (got, count, sht) = ue.unprotect(&wire).expect("UE accepts the AMF's message");
        assert_eq!((got.as_slice(), count, sht), (&plain[..], 0, 2));

        // Uplink, the other direction's keystream and MAC.
        let complete = [0x7e, 0x00, 0x5e, 0x77, 0x00, 0x09];
        let up = ue.protect(&complete, security::SHT_INTEGRITY_CIPHERED);
        assert_ne!(&up[7..], &complete);
        assert_eq!(amf.unprotect(&up).unwrap().0, complete);

        // One flipped MAC bit is refused, and the genuine message still verifies after it.
        let next = amf.protect(&[0x7e, 0x00, 0x54], security::SHT_INTEGRITY_CIPHERED);
        let mut forged = next.clone();
        forged[2] ^= 0x01;
        assert!(
            matches!(
                ue.unprotect(&forged),
                Err(security::UnprotectError::Mac { count: 1 })
            ),
            "ia={ia} ea={ea}"
        );
        assert_eq!(ue.unprotect(&next).unwrap().0, vec![0x7e, 0x00, 0x54]);
    }
}
