"""The ABI parser turns `stellar contract info interface --output json` into a
probe plan: for each exported function, the ordered arg types and whether v1 can
synthesize a test value for each. UDT/collection args are not v1-synthesizable
and must be flagged, not silently dropped."""
import json
import os

from sorohunter.abi import type_name, synthesizable, parse_spec

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "skernel_registry_abi.json")


def test_type_name_primitive_is_the_bare_string():
    assert type_name("address") == "address"
    assert type_name("i128") == "i128"
    assert type_name("bool") == "bool"


def test_type_name_bytes_n_carries_length():
    assert type_name({"bytes_n": {"n": 32}}) == "bytes_n:32"


def test_type_name_udt_carries_name():
    assert type_name({"udt": {"name": "VerifierKind"}}) == "udt:VerifierKind"


def test_type_name_vec_is_labeled():
    assert type_name({"vec": {"element_type": "u32"}}).startswith("vec")


def test_synthesizable_primitives_and_bytesn_and_address():
    for t in ["address", "u32", "u64", "i128", "u128", "bool", "symbol", "string", "bytes"]:
        assert synthesizable(t), t
    assert synthesizable({"bytes_n": {"n": 32}})


def test_not_synthesizable_udt_and_collections():
    assert not synthesizable({"udt": {"name": "VerifierKind"}})
    assert not synthesizable({"vec": {"element_type": "u32"}})
    assert not synthesizable({"map": {}})
    assert not synthesizable({"tuple": {}})


def test_parse_real_registry_abi():
    entries = json.load(open(FIX))
    plan = parse_spec(entries)
    names = {p["name"] for p in plan}
    assert names == {"head", "is_registered", "register_genesis", "append_generation"}
    reg = next(p for p in plan if p["name"] == "register_genesis")
    assert reg["inputs"] == ["address", "bytes_n:32"]
    assert reg["synthesizable"] is True
    assert reg["skip_reason"] is None


def test_parse_flags_unsynthesizable_function():
    entries = [{
        "function_v0": {
            "name": "configure",
            "inputs": [
                {"name": "who", "type_": "address"},
                {"name": "kind", "type_": {"udt": {"name": "VerifierKind"}}},
            ],
            "outputs": [],
        }
    }]
    plan = parse_spec(entries)
    assert len(plan) == 1
    assert plan[0]["synthesizable"] is False
    assert "udt:VerifierKind" in plan[0]["skip_reason"]


def test_parse_ignores_non_function_entries():
    entries = json.load(open(FIX))
    # the fixture has enums/structs/events too; only functions become probes
    assert len(parse_spec(entries)) == 4
