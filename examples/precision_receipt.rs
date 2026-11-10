//! Replay invented ruleset 10.1 cases across the three native APIs.
use relayscrubber::*;
use serde_json::{json, Value};
fn main() {
    let cases: Value = serde_json::from_str(&include_str!("../eval/precision_10_1_cases.json").replace("OPENAI_PREFIX_", "sk-")).unwrap();
    let rows: Vec<_> = cases.as_array().unwrap().iter().enumerate().map(|(id,c)| {
        let input = c["input"].as_str().unwrap();
        let v = json!({"text":input});
        let records = scrub_records(v.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
        let outputs = [scrub_text_checked(input).unwrap(),scrub_json(&v).0["text"].as_str().unwrap().to_owned(),parsed["text"].as_str().unwrap().to_owned()];
        let valid: Vec<_> = outputs.iter().map(|out| if let Some(expected)=c["expected"].as_str(){out==expected}else{!out.contains(c["secret"].as_str().unwrap())&&out.contains(REDACTION_TOKEN)}).collect();
        let repeat: Vec<_> = outputs.iter().map(|out| scrub_text(out)!=*out).collect();
        json!({"id":id,"family":c["family"],"reaudit3":c["reaudit3"],"input":input,"outputsTextJsonRecords":outputs,"validTextJsonRecords":valid,"secondPassChanges":repeat})
    }).collect();
    println!("{}",json!({"manifest":manifest(),"rows":rows}));
}
