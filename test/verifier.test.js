import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyReceipt, canonicalJson } from '../index.js';
const receipt = JSON.parse(readFileSync(new URL('./fixtures/receipt.json', import.meta.url)));
const keys = JSON.parse(readFileSync(new URL('./fixtures/keys.json', import.meta.url)));
test('recorded audit-chain signed action fixture verifies; changed content fails', async () => {
  assert.equal((await verifyReceipt(receipt, keys)).verified, true);
  assert.equal((await verifyReceipt({...receipt, source:'tampered'}, keys)).verified, false);
});
test('retired key verifies inside its window and fails at its exclusive end', async () => {
  const { publicKey } = await import('node:crypto').then(c => c.generateKeyPairSync('ed25519'));
  const { signingKeyId } = await import('../index.js');
  const pem = publicKey.export({type:'spki',format:'pem'}).toString();
  const id = await signingKeyId(pem);
  const rotated = {...keys, current_key_id:id, keys:[{...keys.keys[0],valid_until:'2026-10-25T00:00:00Z'}, {key_id:id,public_key_pem:pem,valid_from:'2026-10-25T00:00:00Z',valid_until:null}]};
  assert.equal((await verifyReceipt(receipt, rotated)).verified,true);
  rotated.keys[0].valid_until=receipt.at;
  assert.deepEqual((await verifyReceipt(receipt, rotated)).issues,['Signature outside key validity window']);
});
test('canonical JSON preserves producer integer-key ordering and Unicode', () => {
  assert.equal(canonicalJson({'10':'é','2':2,z:{b:1,a:null}}),'{"2":2,"10":"é","z":{"a":null,"b":1}}');
});
test('retrieval answers fail closed without canonical payload and signed time', async () => {
  const { verifyAnswerReceipt } = await import('../index.js');
  assert.equal((await verifyAnswerReceipt({schema_version:'syderial.runtime.retrieval-receipt.v1'},keys)).verified,false);
  assert.match((await verifyAnswerReceipt({schema_version:'syderial.runtime.retrieval-receipt.v1',recall:{},candidates:[]},keys)).issues[0],/signed timestamp/);
});
test('both local signed examples verify with their published example key', async () => {
  const exampleKeys = JSON.parse(readFileSync(new URL('../examples/keys.json', import.meta.url)));
  for (const name of ['refused-raise', 'allowed-shut-in']) {
    const example = JSON.parse(readFileSync(new URL(`../examples/${name}.json`, import.meta.url)));
    assert.equal((await verifyReceipt(example, exampleKeys)).verified, true, name);
  }
});
