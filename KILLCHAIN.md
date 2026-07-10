# The Soroban Kill Chain — a traversal of the matrix

The canonical catalog is [`SOROBAN_ATTACK.md`](SOROBAN_ATTACK.md) (the Soroban
ATT&CK, tactics × techniques). A *kill chain* is one **path** through that
matrix — the ordered steps of a single realized attack — the way a threat-actor
profile is a path through MITRE ATT&CK.

sorohunter's job is to find and **execute** these paths in a local fork, so a
finding is a run, not a narrative.

## Worked example: the privilege chain (SK-C01 / TE-01)

```
TA-02  unprotected admin setter        set_admin(attacker)      under empty auth
  │                                     (foothold: state mutated, no signature)
  ▼
TE-01  admin capture → privileged path  withdraw()               now as "admin"
  │                                     (the legit gate now passes for the attacker)
  ▼
OBJ-DRAIN  funds leave the contract      balance delta < 0        realized in fork
```

An isolated missing-auth probe (TA-01) sees the `set_admin` foothold but not the
drain it unlocks. The value of the chain is that both steps run **in one fork**,
and the PoC is the executed sequence + the balance delta — immune to the
false-positive tax, because it either drains the forked contract or it does not.

## The invariant (unchanged)

Every step executes only in a local `Env` fork against public WASM. Recon is
read-only. Nothing is ever sent to a live network. Defensive research, executed
proof, manual disclosure.

See [`SOROBAN_ATTACK.md`](SOROBAN_ATTACK.md) for the full technique catalog and
shipped-vs-roadmap status.
