#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(parsed) = satspath_core::bip321::parse_bip321(s) {
            let _ = serde_json::to_string(&parsed);
            assert_eq!(parsed.raw, s);
            assert!(parsed.instructions.iter().all(|instruction| {
                !matches!(
                    instruction,
                    satspath_core::bip321::Bip321Instruction::Unknown { required: true, .. }
                )
            }));
            assert!(s.len() <= satspath_core::bip321::MAX_BIP321_URI_BYTES);
        }
    }
});
