/* Customer-side encryption helpers. No network calls, storage, or server key path. */
const DS_MAGIC = new TextEncoder().encode('DSENC01');
const DS_HEADER_BYTES = DS_MAGIC.length + 1 + 12 + 4;

function toBase64Url(bytes) {
  let binary = '';
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function joinBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  parts.forEach(part => { output.set(part, offset); offset += part.length; });
  return output;
}

async function digest(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function encryptCustomerFile(file) {
  const plaintext = new Uint8Array(await file.arrayBuffer());
  const key = await crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, true, ['encrypt', 'decrypt']);
  const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const metadata = new TextEncoder().encode(JSON.stringify({name: file.name, type: file.type || 'application/octet-stream'}));
  if (metadata.length > 0xffff) throw new Error('File metadata is too large.');
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, metadata.length);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, plaintext));
  const envelope = joinBytes(DS_MAGIC, new Uint8Array([1]), iv, length, metadata, ciphertext);
  const keyFile = {
    format: 'DataSentinel customer key',
    version: 1,
    algorithm: 'AES-256-GCM',
    key: toBase64Url(rawKey),
    encrypted_sha256: toBase64Url(await digest(envelope)),
  };
  return {
    encrypted: new Blob([envelope], {type: 'application/octet-stream'}),
    key: new Blob([JSON.stringify(keyFile, null, 2)], {type: 'application/json'}),
    encryptedName: `${file.name}.dsenc`,
    keyName: 'datasentinel-key.json',
  };
}

async function decryptCustomerFile(encryptedFile, keyFile) {
  const envelope = new Uint8Array(await encryptedFile.arrayBuffer());
  if (envelope.length < DS_HEADER_BYTES || !DS_MAGIC.every((value, index) => envelope[index] === value)) {
    throw new Error('This is not a DataSentinel encrypted file.');
  }
  if (envelope[DS_MAGIC.length] !== 1) throw new Error('Unsupported encrypted file version.');
  const ivStart = DS_MAGIC.length + 1;
  const iv = envelope.slice(ivStart, ivStart + 12);
  const metadataLength = new DataView(envelope.buffer, envelope.byteOffset + ivStart + 12, 4).getUint32(0);
  const metadataStart = DS_HEADER_BYTES;
  const ciphertextStart = metadataStart + metadataLength;
  if (ciphertextStart >= envelope.length) throw new Error('Encrypted file is incomplete.');
  let parsed;
  try { parsed = JSON.parse(await keyFile.text()); } catch (_) { throw new Error('Key file is not valid JSON.'); }
  if (parsed?.format !== 'DataSentinel customer key' || parsed?.version !== 1 || parsed?.algorithm !== 'AES-256-GCM') throw new Error('Key file format is not supported.');
  let rawKey;
  try { rawKey = fromBase64Url(parsed.key); } catch (_) { throw new Error('Key file is incomplete.'); }
  if (rawKey.length !== 32) throw new Error('Key file contains an invalid key.');
  if (parsed.encrypted_sha256 && toBase64Url(await digest(envelope)) !== parsed.encrypted_sha256) throw new Error('The key does not match this encrypted file.');
  let metadata;
  try { metadata = JSON.parse(new TextDecoder().decode(envelope.slice(metadataStart, ciphertextStart))); } catch (_) { throw new Error('Encrypted file metadata is corrupt.'); }
  const key = await crypto.subtle.importKey('raw', rawKey, {name: 'AES-GCM'}, false, ['decrypt']);
  let plaintext;
  try { plaintext = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, key, envelope.slice(ciphertextStart)); } catch (_) { throw new Error('The key or encrypted file is incorrect.'); }
  return new File([plaintext], metadata.name || 'decrypted-file', {type: metadata.type || 'application/octet-stream'});
}

function downloadCustomerBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename; anchor.rel = 'noopener';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function downloadCustomerFiles(files) {
  for (const [index, file] of files.entries()) {
    downloadCustomerBlob(file.blob, file.filename);
    if (index < files.length - 1) await new Promise(resolve => setTimeout(resolve, 350));
  }
}
