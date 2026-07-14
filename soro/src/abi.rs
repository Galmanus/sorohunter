//! Parse a Soroban contract spec (`stellar contract info interface --output
//! json`) into a probe plan. A faithful port of the Python `abi.py`.
//!
//! The spec is an array of SCSpecEntry. We keep `function_v0` entries. Each
//! input's `type_` is either a bare string (primitive) or a one-key object
//! (composite). We can synthesize test args for primitives, address, and fixed
//! bytes; anything else is flagged so the function is skipped with a stated
//! reason rather than probed with a bogus arg.

use serde_json::Value;

/// Primitives for which the fork-sim harness has a default `Val`.
const PRIMITIVES: &[&str] = &[
    "address", "u32", "u64", "u128", "i32", "i64", "i128", "bool", "symbol", "string", "bytes", "void",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FnPlan {
    pub name: String,
    pub inputs: Vec<String>,
    pub synthesizable: bool,
    pub skip_reason: Option<String>,
}

/// Canonical label for a type: `address`, `bytes_n:32`, `udt:Name`, `vec<...>`.
pub fn type_name(t: &Value) -> String {
    match t {
        Value::String(s) => s.clone(),
        Value::Object(m) => match m.iter().next() {
            Some((key, body)) => match key.as_str() {
                "bytes_n" => format!(
                    "bytes_n:{}",
                    body.get("n").and_then(Value::as_u64).map(|n| n.to_string()).unwrap_or_default()
                ),
                "udt" => format!("udt:{}", body.get("name").and_then(Value::as_str).unwrap_or("")),
                "vec" => match body.get("element_type") {
                    Some(inner) => format!("vec<{}>", type_name(inner)),
                    None => "vec".into(),
                },
                other => other.to_string(),
            },
            None => "unknown".into(),
        },
        _ => "unknown".into(),
    }
}

/// Whether we can build a default test value for this type.
pub fn synthesizable(t: &Value) -> bool {
    match t {
        Value::String(s) => PRIMITIVES.contains(&s.as_str()),
        Value::Object(m) => m.keys().next().map(|k| k == "bytes_n").unwrap_or(false),
        _ => false,
    }
}

/// Return the probe plan: one entry per exported function.
pub fn parse_spec(entries: &[Value]) -> Vec<FnPlan> {
    let mut plan = Vec::new();
    for entry in entries {
        let f = match entry.get("function_v0") {
            Some(f) => f,
            None => continue,
        };
        let name = match f.get("name").and_then(Value::as_str) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let raw: Vec<&Value> = f
            .get("inputs")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|inp| inp.get("type_")).collect())
            .unwrap_or_default();
        let inputs: Vec<String> = raw.iter().map(|t| type_name(t)).collect();
        let unsynth: Vec<String> = raw.iter().filter(|t| !synthesizable(t)).map(|t| type_name(t)).collect();
        let synthesizable = unsynth.is_empty();
        plan.push(FnPlan {
            name,
            inputs,
            synthesizable,
            skip_reason: if synthesizable {
                None
            } else {
                Some(format!("unsynthesizable args: {}", unsynth.join(", ")))
            },
        });
    }
    plan
}

// ---- native spec-from-wasm (no stellar-CLI shell-out) ----

use soroban_sdk::xdr::{ScSpecEntry, ScSpecTypeDef};
use std::cell::RefCell;
use std::collections::HashMap;

/// A user-defined type's shape, in string labels the engine's synth understands.
/// This is the ABI-driven answer to "unsynthesizable udt:Signer": we read the
/// contractspec's UDT definitions and build a matching Val recursively, instead
/// of skipping the function. (SorobanArbitrary does this from the compiled Rust
/// type at dev-time; here we do it from the deployed wasm's spec, black-box.)
#[derive(Clone, Debug)]
pub enum UdtDef {
    /// (field_name, type_label). Empty field_name => positional/tuple struct.
    Struct(Vec<(String, String)>),
    /// (variant_name, type_labels_of_the_variant_payload).
    Union(Vec<(String, Vec<String>)>),
    /// integer enum; the first case's discriminant value.
    Enum(u32),
}

thread_local! {
    /// UDT name -> shape, populated per `plan_from_wasm`. Read by the engine's synth.
    pub static UDT_REGISTRY: RefCell<HashMap<String, UdtDef>> = RefCell::new(HashMap::new());
}

fn label_of(t: &ScSpecTypeDef) -> String {
    typedef_name(t)
}

/// Can we build a Val for this label, recursing through the UDT registry?
pub fn label_synthesizable(label: &str, reg: &HashMap<String, UdtDef>, depth: u32) -> bool {
    if depth > 6 {
        return false;
    }
    if PRIMITIVES.contains(&label) || label.starts_with("bytes_n:") {
        return true;
    }
    if label.starts_with("vec<") || label.starts_with("option<") || label == "map" || label == "void" {
        return true; // empty vec / None / empty map are always valid
    }
    if let Some(name) = label.strip_prefix("udt:") {
        return match reg.get(name) {
            Some(UdtDef::Enum(_)) => true,
            Some(UdtDef::Struct(fields)) => fields.iter().all(|(_, t)| label_synthesizable(t, reg, depth + 1)),
            Some(UdtDef::Union(variants)) => variants
                .first()
                .map(|(_, ts)| ts.iter().all(|t| label_synthesizable(t, reg, depth + 1)))
                .unwrap_or(true),
            None => false,
        };
    }
    false
}

/// Build the UDT registry from all spec entries (structs, unions, enums).
fn build_registry(entries: &[ScSpecEntry]) -> HashMap<String, UdtDef> {
    let mut reg = HashMap::new();
    for e in entries {
        match e {
            ScSpecEntry::UdtStructV0(s) => {
                let fields = s
                    .fields
                    .iter()
                    .map(|f| {
                        let n = f.name.to_string();
                        // soroban tuple-structs name fields "0","1",...; treat as positional.
                        let name = if n.chars().all(|c| c.is_ascii_digit()) { String::new() } else { n };
                        (name, label_of(&f.type_))
                    })
                    .collect();
                reg.insert(s.name.to_string(), UdtDef::Struct(fields));
            }
            ScSpecEntry::UdtUnionV0(u) => {
                use soroban_sdk::xdr::ScSpecUdtUnionCaseV0 as C;
                let variants = u
                    .cases
                    .iter()
                    .map(|c| match c {
                        C::VoidV0(v) => (v.name.to_string(), Vec::new()),
                        C::TupleV0(t) => (t.name.to_string(), t.type_.iter().map(label_of).collect()),
                    })
                    .collect();
                reg.insert(u.name.to_string(), UdtDef::Union(variants));
            }
            ScSpecEntry::UdtEnumV0(en) => {
                let first = en.cases.first().map(|c| c.value).unwrap_or(0);
                reg.insert(en.name.to_string(), UdtDef::Enum(first));
            }
            _ => {}
        }
    }
    reg
}

/// Canonical type label from an XDR `ScSpecTypeDef` — the native mirror of
/// `type_name` (which works on the CLI's JSON).
pub fn typedef_name(t: &ScSpecTypeDef) -> String {
    use ScSpecTypeDef as T;
    match t {
        T::Address => "address".into(),
        T::MuxedAddress => "muxed_address".into(),
        T::Bool => "bool".into(),
        T::Void => "void".into(),
        T::U32 => "u32".into(),
        T::I32 => "i32".into(),
        T::U64 => "u64".into(),
        T::I64 => "i64".into(),
        T::U128 => "u128".into(),
        T::I128 => "i128".into(),
        T::U256 => "u256".into(),
        T::I256 => "i256".into(),
        T::Bytes => "bytes".into(),
        T::String => "string".into(),
        T::Symbol => "symbol".into(),
        T::BytesN(b) => format!("bytes_n:{}", b.n),
        T::Udt(u) => format!("udt:{}", u.name.to_string()),
        T::Vec(v) => format!("vec<{}>", typedef_name(&v.element_type)),
        T::Option(o) => format!("option<{}>", typedef_name(&o.value_type)),
        T::Map(_) => "map".into(),
        T::Tuple(_) => "tuple".into(),
        T::Result(_) => "result".into(),
        _ => "unknown".into(),
    }
}

fn typedef_synthesizable(t: &ScSpecTypeDef) -> bool {
    use ScSpecTypeDef as T;
    matches!(
        t,
        T::Address | T::Bool | T::Void | T::U32 | T::I32 | T::U64 | T::I64 | T::U128 | T::I128 | T::Bytes | T::String | T::Symbol
    ) || matches!(t, T::BytesN(_))
}

/// Parse the contract spec directly from the WASM custom section into a probe
/// plan — the native replacement for `stellar contract info interface`.
pub fn plan_from_wasm(wasm: &[u8]) -> Vec<FnPlan> {
    let entries = match soroban_spec::read::from_wasm(wasm) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    // ABI-driven UDT synthesis: register every struct/union/enum so the engine can
    // build their Vals instead of skipping the function (P0 coverage upgrade).
    let reg = build_registry(&entries);
    UDT_REGISTRY.with(|r| *r.borrow_mut() = reg.clone());
    let mut plan = Vec::new();
    for e in entries {
        if let ScSpecEntry::FunctionV0(f) = e {
            let name = f.name.to_string();
            let inputs: Vec<String> = f.inputs.iter().map(|i| typedef_name(&i.type_)).collect();
            let unsynth: Vec<String> =
                inputs.iter().filter(|l| !label_synthesizable(l, &reg, 0)).cloned().collect();
            let synthesizable = unsynth.is_empty();
            let _ = typedef_synthesizable; // legacy primitive check retained for reference
            plan.push(FnPlan {
                name,
                inputs,
                synthesizable,
                skip_reason: if synthesizable {
                    None
                } else {
                    Some(format!("unsynthesizable args: {}", unsynth.join(", ")))
                },
            });
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn primitive_type_names() {
        assert_eq!(type_name(&json!("address")), "address");
        assert_eq!(type_name(&json!("i128")), "i128");
    }

    #[test]
    fn composite_type_names() {
        assert_eq!(type_name(&json!({"bytes_n": {"n": 32}})), "bytes_n:32");
        assert_eq!(type_name(&json!({"udt": {"name": "Mandate"}})), "udt:Mandate");
        assert_eq!(type_name(&json!({"vec": {"element_type": "address"}})), "vec<address>");
    }

    #[test]
    fn synthesizable_rules() {
        assert!(synthesizable(&json!("address")));
        assert!(synthesizable(&json!({"bytes_n": {"n": 32}})));
        assert!(!synthesizable(&json!({"udt": {"name": "X"}})));
        assert!(!synthesizable(&json!({"vec": {"element_type": "u32"}})));
        assert!(!synthesizable(&json!("muxed_address")));
    }

    #[test]
    fn parse_plan_flags_unsynthesizable() {
        let entries = vec![
            json!({"function_v0": {"name": "withdraw", "inputs": [{"type_": "address"}, {"type_": "i128"}]}}),
            json!({"function_v0": {"name": "swap", "inputs": [{"type_": {"udt": {"name": "Order"}}}]}}),
            json!({"other_v0": {"name": "ignored"}}),
        ];
        let plan = parse_spec(&entries);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].name, "withdraw");
        assert!(plan[0].synthesizable);
        assert_eq!(plan[0].inputs, vec!["address".to_string(), "i128".to_string()]);
        assert_eq!(plan[1].name, "swap");
        assert!(!plan[1].synthesizable);
        assert!(plan[1].skip_reason.as_ref().unwrap().contains("udt:Order"));
    }

    #[test]
    fn udt_synthesizable_via_registry() {
        // ABI-driven UDT synthesis (P0): a struct of buildable fields is
        // synthesizable, recursion works, and unknown/unbuildable leaves fail.
        let mut reg = HashMap::new();
        reg.insert("Signer".to_string(), UdtDef::Struct(vec![("pk".into(), "bytes_n:32".into())]));
        reg.insert("Deep".to_string(), UdtDef::Struct(vec![("s".into(), "udt:Signer".into())]));
        reg.insert("Kind".to_string(), UdtDef::Union(vec![("Ed".into(), vec!["bytes_n:32".into()])]));
        reg.insert("Bad".to_string(), UdtDef::Struct(vec![("x".into(), "muxed_address".into())]));
        assert!(label_synthesizable("udt:Signer", &reg, 0));
        assert!(label_synthesizable("udt:Deep", &reg, 0)); // recurses into Signer
        assert!(label_synthesizable("udt:Kind", &reg, 0)); // union first variant
        assert!(label_synthesizable("vec<udt:Signer>", &reg, 0)); // empty vec is valid
        assert!(!label_synthesizable("udt:Bad", &reg, 0)); // muxed_address not buildable
        assert!(!label_synthesizable("udt:Unknown", &reg, 0)); // not in registry
    }

    #[test]
    fn no_inputs_is_synthesizable() {
        let entries = vec![json!({"function_v0": {"name": "pot"}})];
        let plan = parse_spec(&entries);
        assert_eq!(plan.len(), 1);
        assert!(plan[0].synthesizable);
        assert!(plan[0].inputs.is_empty());
    }
}
