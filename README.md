# Receipt verifier

Local ESM package for browsers and Node 22. Uses WebCrypto; no dependencies.
Licensed under Apache-2.0. NOTICE preserves the upstream MIT attribution.

```js
import { verifyReceipt } from './index.js';
const result = await verifyReceipt(receipt, publishedKeys);
```

`verifyReceipt` accepts `syderial.action-receipt.v1` and audit-chain events
(including answer events). Action receipts contain the canonical draft, an
`at` timestamp, `receipt_digest`, and an Ed25519 `signature` with `key_id`,
`public_key_ref` and base64 `value`. Audit events contain `event_id`, `claim_id`,
`operation`, `recorded_at`, `previous_event_hash`, `payload`, `event_hash`,
`signature` and `signer_key_id`.

Canonical JSON recursively sorts keys, then uses JSON.stringify, including its
integer-key ordering. SHA-256 produces lowercase hexadecimal. Ed25519 signs
the UTF-8 hexadecimal digest, not the raw digest bytes. Action draft validation
and normalization come from packages/audit-chain. Published key sets use
`syderial.signing-keys.v1`, key fingerprints, aliases, and half-open
`[valid_from, valid_until)` windows. Missing legacy IDs resolve only to the
published legacy key. Fetch keys from a trusted HTTPS origin independently of
the receipt. A signature from a retired key proves the key signed it, not when,
because the old key was exposed.

`verifyAnswerReceipt` refuses runtime retrieval receipts: they have no signed
timestamp for enforcing key windows. The demo also strips their canonical
payload. No private data is needed to verify a complete signed receipt, but
missing canonical content cannot be reconstructed from its digest.

Source: Syderial origin/main c24e9238c (audit-chain action normalization and
receipt-verifier WebCrypto checks). Fixture receipt.json and keys.json are the
upstream recorded signed test fixture, not a production customer receipt.

Run `npm test` on Node 22. Tests cover that signed fixture, tampering, a retired
key inside and outside its window, and canonical integer keys and Unicode.
No remote is configured. This package hasn't been published.
