#![no_main]

use libfuzzer_sys::fuzz_target;
use satspath_core::bip321::parse_bip321;
use satspath_core::bip353::{validated_bitcoin_record, DnsTxtRecord};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(n) = satspath_core::bip353::parse_bip353_name(s) {
            assert!(n.dns_name.len() <= 253);
        }

        // Fuzz single chunked record
        let strings: Vec<String> = s.split('\n').map(|chunk| chunk.to_string()).collect();
        let record = DnsTxtRecord {
            strings: strings.clone(),
            dnssec_validated: true,
            ttl_seconds: Some(300),
        };
        let expected = record.reconstruct();
        if let Ok((_, uri)) = validated_bitcoin_record(&[record]) {
            assert_eq!(uri, expected);
            assert!(parse_bip321(&uri).is_ok());
        }

        // Fuzz multiple records
        let records: Vec<DnsTxtRecord> = strings
            .into_iter()
            .map(|chunk| DnsTxtRecord {
                strings: vec![chunk],
                dnssec_validated: true,
                ttl_seconds: Some(300),
            })
            .collect();
        if let Ok((_, uri)) = validated_bitcoin_record(&records) {
            assert!(uri.starts_with("bitcoin:"));
            assert!(parse_bip321(&uri).is_ok());
        }
    }
});
