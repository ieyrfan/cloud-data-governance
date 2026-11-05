const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');

const source = fs.readFileSync('frontend/static/customer-crypto.js', 'utf8');
const scope = vm.createContext({crypto:webcrypto, Blob, File, TextEncoder, TextDecoder, btoa: value => Buffer.from(value, 'binary').toString('base64'), atob: value => Buffer.from(value, 'base64').toString('binary')});
vm.runInContext(source, scope);

test('customer crypto round trips bytes and metadata', async () => {
  const original = new File([Buffer.from('private test bytes')], 'result.pdf', {type:'application/pdf'});
  const encrypted = await scope.encryptCustomerFile(original);
  const decrypted = await scope.decryptCustomerFile(encrypted.encrypted, encrypted.key);
  assert.equal(decrypted.name, 'result.pdf');
  assert.equal(decrypted.type, 'application/pdf');
  assert.equal(Buffer.from(await decrypted.arrayBuffer()).toString(), 'private test bytes');
});

test('wrong key and changed ciphertext fail without a recovery path', async () => {
  const original = new File([Buffer.from('secret')], 'secret.txt', {type:'text/plain'});
  const encrypted = await scope.encryptCustomerFile(original);
  const wrong = await scope.encryptCustomerFile(new File([Buffer.from('other')], 'other.txt'));
  await assert.rejects(scope.decryptCustomerFile(encrypted.encrypted, wrong.key), /does not match/);
  const bytes = new Uint8Array(await encrypted.encrypted.arrayBuffer());
  bytes[bytes.length - 1] ^= 1;
  await assert.rejects(scope.decryptCustomerFile(new Blob([bytes]), encrypted.key), /does not match|incorrect/);
});

test('crypto source has no network or browser persistence calls', () => {
  assert.doesNotMatch(source, /fetch\s*\(|XMLHttpRequest|localStorage|sessionStorage|indexedDB/);
});
