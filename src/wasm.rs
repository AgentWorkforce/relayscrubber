//! Thin wasm-bindgen transport. Recognition lives in the native engine.
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = manifestJson)]
pub fn manifest_json() -> String {
    serde_json::to_string(&crate::manifest()).expect("manifest serialization")
}
#[wasm_bindgen(js_name = scrubText)]
pub fn scrub_text(input: &str) -> String {
    crate::scrub_text(input)
}
#[wasm_bindgen(js_name = scrubLong)]
pub fn scrub_long(input: &str) -> String {
    crate::scrub_long(input)
}
#[wasm_bindgen(js_name = scrubJson)]
pub fn scrub_json(input: &str) -> Result<String, JsValue> {
    let (value, count) =
        crate::scrub_json_text(input).ok_or_else(|| JsValue::from_str("invalid_json"))?;
    let json_text =
        serde_json::to_string(&value).map_err(|_| JsValue::from_str("serialization_error"))?;
    serde_json::to_string(
        &serde_json::json!({ "value": value, "jsonText":json_text, "redactionCount": count }),
    )
    .map_err(|_| JsValue::from_str("serialization_error"))
}
#[wasm_bindgen(js_name = scrubRecords)]
pub fn scrub_records(input: &[u8]) -> Result<String, JsValue> {
    let result = crate::scrub_records(input)
        .map_err(|e| JsValue::from_str(&serde_json::to_string(&e).expect("error serialization")))?;
    let text = String::from_utf8(result.bytes).expect("JSON output is UTF-8");
    serde_json::to_string(&serde_json::json!({ "text": text, "recordCount": result.record_count, "redactionCount": result.redaction_count })).map_err(|_| JsValue::from_str("serialization_error"))
}
