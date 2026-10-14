#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// Return whether a JSON value contains a number outside its integer variants.
///
/// Recurses through arrays and objects to gate the integer-only idempotency check.
fn has_float(v: &Value) -> bool {
    match v {
        Value::Number(n) => !n.is_i64() && !n.is_u64(),
        Value::Array(a) => a.iter().any(has_float),
        Value::Object(o) => o.values().any(has_float),
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<Value>(data) {
        if let Ok(canonical1) = canonical_json::to_string(&value) {
            let value2 = serde_json::from_str::<Value>(&canonical1)
                .expect("canonical_json produced invalid JSON");
            if !has_float(&value) {
                if let Ok(canonical2) = canonical_json::to_string(&value2) {
                    assert_eq!(
                        canonical1, canonical2,
                        "canonical_json idempotency violation"
                    );
                }
            }
        }
    }
});
