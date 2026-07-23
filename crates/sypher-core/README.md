# sypher-core

The hardware-independent half of Sypherstore. No TPM, FIDO2, DBus or GUI
dependencies, so everything here is unit-testable on any machine.

## Reading order

Start at `vault/session.rs`. It composes everything else and is the only path
from ciphertext to plaintext; the rest of the crate is components it uses.

| Module | Responsibility |
| --- | --- |
| `secure` | `SecureBuf`: mlocked, zeroize-on-drop, redacted-`Debug` byte buffer. Every plaintext byte lives in one. |
| `crypto::keys` | Key hierarchy (`outer_kek`, random `inner_kek` wrapped per enrolled key, per-secret subkeys) and the two hardware provider traits. |
| `crypto::envelope` | The double-encryption envelope: format, seal, open, metadata seal, inner-key wrap, verification blob. |
| `model` | `SecretMeta` (searchable, now also sealed) and `SecretPayload` (encrypted). The split is a safety property, not organization. |
| `vault::db` | SQLite storage. Never decrypts; each row is two opaque sealed blobs plus two random UUIDs. |
| `vault::paths` | Vault location resolution and owner-only atomic writes. |
| `vault::session` | Lock state machine, CRUD, and authenticator enrollment. Enforces "both keys or no plaintext". Enrollment passes the already-enrolled credential ids to `InnerKeyProvider::provision_excluding`, so a hardware provider can direct the new registration at a key that is not yet enrolled. |
| `search::domain` | Hostname normalization and PSL-based domain matching. |
| `search::fuzzy` | Ranking for the popup. Metadata only. |
| `config` | Non-secret JSON configuration. |
| `mock_hw` | File-backed fake providers, behind the `mock-hw` feature. **No security.** |

## The envelope

```
blob := header || n2 || c2

header := "SYPH" | version:u8 | cipher:u8 | uuid:16        (22 bytes)
c1     := XChaCha20Poly1305(k_inner, n1, aad = header) [ CBOR payload ]
c2     := XChaCha20Poly1305(k_outer, n2, aad = header) [ n1 || c1 ]
```

Both layers authenticate the same header, which contains the secret's UUID.
Since the per-secret subkeys are themselves derived from that UUID, a blob
cannot be moved from one row to another: the target row's keys will not open
it, and rewriting the header's UUID to compensate invalidates the AEAD tag.
Both cases have tests.

The version and cipher bytes are authenticated too, so an attacker cannot
downgrade a blob to a weaker future cipher without breaking the tag.

## Key hierarchy

```
TPM ──seal──> outer_kek ──HKDF-Expand(uuid)──> k_outer_i ──┐
                                                            ├─> one secret
FIDO2 hmac-secret ──HKDF-Extract(salt)──> inner_kek         │
                   ──HKDF-Expand(uuid)──> k_inner_i ────────┘
```

No per-row DEK is stored: subkeys are derived on demand from the UUID. A nonce
reuse in one row therefore cannot compromise another.

## Lock state machine

```
Locked { outer_kek }
   │  unlock(assertion) ──> verify blob ──┐
   │                                      ▼
   │                        Unlocked { inner_kek, deadline }
   │                                      │  use() extends the deadline
   └────────── zeroize <── tick() past deadline
```

The outer key is deliberately not part of the lock state: it is recovered once
at cold start and held for the process lifetime, because a per-operation TPM
unseal would add latency for no security gain.

## Feature flags

- `mock-hw` — file-backed stand-ins for both hardware layers. Development and
  CI only; every mock file carries a `SYPHERSTORE-MOCK-KEY-NO-SECURITY` banner.

## Testing

```sh
cargo test -p sypher-core --features mock-hw
```

The suite covers the attack shapes the design exists to stop: wrong key,
tampered ciphertext, swapped blobs, rewritten headers, truncated input,
downgraded versions, suffix-lookalike domains, and a vault copied to another
machine.
