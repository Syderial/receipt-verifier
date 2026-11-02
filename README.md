# Syderial receipt verifier

Check a Syderial receipt without asking Syderial.

When an agent asks Syderial's record something, or asks to act, Syderial signs a receipt: what was provided, who asked, when, and the rule as applied. This package checks that signature offline, in a browser or in Node 22, against Syderial's published signing keys. No account, no network call beyond fetching the keys, no dependencies. Apache-2.0.

If the receipt verifies, Syderial's key signed exactly this receipt, the key was valid at the receipt's time, and nothing in it has changed since. If one byte changed, it fails.

## Try it in a minute

```sh
git clone https://github.com/Syderial/receipt-verifier
cd receipt-verifier
npm test
```

The tests sign nothing; they check a recorded signed receipt, a tampered copy, a retired key inside and outside its validity window, and canonical JSON edge cases (integer keys, Unicode).

Then verify the two examples and break one:

```sh
node --input-type=module <<'JS'
import { readFile } from 'node:fs/promises';
import { verifyReceipt } from './index.js';
const keys = JSON.parse(await readFile('examples/keys.json', 'utf8'));
for (const name of ['refused-raise', 'allowed-shut-in']) {
  const receipt = JSON.parse(await readFile(`examples/${name}.json`, 'utf8'));
  console.log(name, await verifyReceipt(receipt, keys));
}
const tampered = JSON.parse(await readFile('examples/allowed-shut-in.json', 'utf8'));
tampered.action.name = 'raise';
console.log('tampered', await verifyReceipt(tampered, keys));
JS
```

Expected: the two examples print `{ verified: true, key_id: '2b32220c9552a7d5', issues: [] }` and the tampered copy prints `{ verified: false, issues: [ 'Canonical hash mismatch' ] }`.

## What the examples are, and what they aren't

`examples/refused-raise.json` is a refused action: the record didn't entail it, so the gate said no. `examples/allowed-shut-in.json` is an allowed one. Both are Ed25519 signatures made by a local signer whose private key was generated for the run and never saved. `examples/keys.json` is the key set for those two files only.

They aren't receipts from a running Syderial. Receipts from the public walkthrough at [demo.syderial.ai](https://demo.syderial.ai) (Northwind Energy, Well 47) are next: when they land, this README will show how to take one from the walkthrough and verify it against the live key set below, the same way.

## The live key set

Syderial publishes its signing keys at

```
https://api.syderial.ai/.well-known/syderial-signing-keys.json
```

in the `syderial.signing-keys.v1` format: `current_key_id`, `legacy_key_id`, and for each key its `key_id`, `public_key_pem`, `aliases` and half-open `[valid_from, valid_until)` window. Fetch the keys from that HTTPS origin yourself, never from inside the receipt. A signature from a retired key proves that key signed the receipt, not when it did, because the retired key may have been exposed.

## What a receipt contains

An action receipt (`syderial.action-receipt.v1`):

| field | what it is |
|---|---|
| `receipt_id` | the receipt's id |
| `action` | the operation the agent asked to perform |
| `principal` | who asked |
| `boundary_labels` | the labels the request and the record were checked against |
| `authority` | the decision (`allow`, `deny` or `approval_required`) and the policy it applied |
| `at` | when the gate decided |
| `source` | where the receipt came from |
| `receipt_digest` | SHA-256 of the canonical receipt, lowercase hex |
| `signature` | `key_id`, `public_key_ref` and the base64 Ed25519 `value` |

An audit-chain event (`event_id`, `claim_id`, `operation`, `recorded_at`, `previous_event_hash`, `payload`, `event_hash`, `signature`, `signer_key_id`) verifies the same way, and `previous_event_hash` ties each event to the one before it, so a removed or reordered event breaks the chain.

## How verification works

1. Canonical JSON: keys sorted recursively, then `JSON.stringify`, which keeps its integer-key ordering.
2. SHA-256 of the canonical bytes, as lowercase hexadecimal. That is `receipt_digest`.
3. Ed25519 over the UTF-8 bytes of that hexadecimal string, not over the raw digest bytes.
4. The key named by `key_id` must be in the key set and valid at `at` (or `recorded_at`).

`verifyReceipt(receipt, keySet)` returns `{ verified, key_id, issues }`. It accepts action receipts and audit-chain events, including answer events. Missing legacy ids resolve only to the published legacy key.

`verifyAnswerReceipt` refuses the runtime's retrieval receipts on purpose: they have no signed timestamp, so a key window can't be enforced, and the walkthrough strips their canonical payload. A complete signed receipt needs no private data to verify; a receipt whose canonical content was stripped can't be rebuilt from its digest.

## API

It isn't on npm. Install it from GitHub with `npm install github:Syderial/receipt-verifier`, or import `./index.js` from a clone.

```js
import { verifyReceipt, canonicalJson, hashCanonical, signingKeyId } from '@syderial/receipt-verifier';

const result = await verifyReceipt(receipt, keySet);   // { verified, key_id, issues }
canonicalJson(value);                                   // the canonical string
await hashCanonical(value);                             // lowercase hex SHA-256
await signingKeyId(publicKeyPem);                       // the key id for a PEM public key
```

`buildUnsignedActionReceipt` and `receiptRoute` build the unsigned receipt and label how the action reached Syderial: through the proxy or an enforcing hook (`enforced`), or observed after the fact (`observed_only`, with the notice that Syderial couldn't have blocked it).

## Source

The verification code and the action normalization come from Syderial's `audit-chain` package (origin/main `c24e9238c`). `test/fixtures/receipt.json` and `keys.json` are the upstream recorded signed test fixture, not a receipt from any deployment. `NOTICE` keeps the upstream MIT attribution.

## Syderial

Syderial is the system of record for intelligence: the context and the policy of record every business agent acts on, for humans and agents, under whatever harness, model or provider you run. The receipt is how an agent's action is shown to have been within the record and the rules. [syderial.ai](https://syderial.ai) · [demo.syderial.ai](https://demo.syderial.ai) · [hello@syderial.ai](mailto:hello@syderial.ai)
