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
    fn no_inputs_is_synthesizable() {
        let entries = vec![json!({"function_v0": {"name": "pot"}})];
        let plan = parse_spec(&entries);
        assert_eq!(plan.len(), 1);
        assert!(plan[0].synthesizable);
        assert!(plan[0].inputs.is_empty());
    }
}
