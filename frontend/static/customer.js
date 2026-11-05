const fileInput = document.querySelector('#customer-file');
const fileLabel = document.querySelector('#customer-file-label');
const statusNode = document.querySelector('#customer-status');
const result = document.querySelector('#download-result');
const downloadAgain = document.querySelector('#download-again');
const canvas = document.querySelector('#redaction-canvas');
const editor = document.querySelector('#image-editor');
const context = canvas.getContext('2d');
const allowed = new Set(['.pdf','.jpg','.jpeg','.png','.txt','.csv','.json','.md','.log','.html','.htm','.xml','.yaml','.yml','.ini','.cfg']);
const mime = {pdf:'application/pdf',jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',txt:'text/plain',csv:'text/csv',json:'application/json',md:'text/markdown',log:'text/plain',html:'text/html',htm:'text/html',xml:'application/xml',yaml:'application/yaml',yml:'application/yaml',ini:'text/plain',cfg:'text/plain'};
const maxBytes = 3 * 1024 * 1024;
const documentTypes = {PASSPORT:'Passport / travel document',IDENTITY:'Identity document',RESUME:'Resume / CV',PAYSLIP:'Payslip / payroll',ACADEMIC_RESULT:'Academic result',FORM:'Form / application',INVOICE:'Invoice / financial',CERTIFICATE:'Certificate',CONTRACT:'Contract / agreement',REPORT:'Report',OTHER:'Other document'};
const classifications = {RESTRICTED:'Restricted',CONFIDENTIAL:'Confidential',REVIEW_REQUIRED:'Requires review'};
const categoryLabels = {my_ic:'Malaysian identity number',credit_card:'Payment card',government_id:'Government or passport ID',passport_number:'Passport number',financial_account:'Financial account',aws_access_key:'Access key',secret:'Secret or token',private_key:'Private key',patient_id:'Patient ID',email:'Email address',my_phone:'Phone number',name:'Name',address:'Address',matric_number:'Student ID',employee_id:'Employee ID',date_of_birth:'Date of birth',ip_address:'IP address',mac_address:'Device address',gps_coordinates:'Location',customer_id:'Customer ID',user_identifier:'User ID'};
let bitmap = null;
let masks = [];
let start = null;
let busy = false;
let downloadUrl = null;
let fileGeneration = 0;
const extension = name => name.includes('.') ? name.slice(name.lastIndexOf('.')).toLowerCase() : '';
const say = message => { statusNode.textContent = message; };
function csrfHeaders(extra = {}) {
  const headers = new Headers(extra);
  const cookie = document.cookie.split('; ').find(item => item.startsWith('ds_csrf='));
  if (cookie) headers.set('X-CSRF-Token', decodeURIComponent(cookie.split('=').slice(1).join('=')));
  return headers;
}
function clearDownload() {
  if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  downloadUrl = null;
  result.hidden = true;
  downloadAgain.removeAttribute('href');
}
function renderSummary(headers) {
  const type = headers.get('X-Document-Type');
  const classification = headers.get('X-Suggested-Classification');
  const categories = (headers.get('X-Detected-Categories') || '').split(',').filter(Boolean);
  const redacted = (headers.get('X-Redacted-Categories') || '').split(',').filter(Boolean);
  const kept = (headers.get('X-Kept-Categories') || '').split(',').filter(Boolean);
  const hits = headers.get('X-Redaction-Hits');
  document.querySelector('#summary-type').textContent = documentTypes[type] || 'Other document · review type';
  document.querySelector('#summary-classification').textContent = classifications[classification] || 'Requires review';
  document.querySelector('#summary-categories').textContent = categories.length
    ? categories.map(category => categoryLabels[category] || 'Other protected field').join(', ')
    : 'No verified category reported';
  document.querySelector('#summary-redacted').textContent = redacted.length
    ? redacted.map(category => categoryLabels[category] || 'Other protected field').join(', ')
    : 'Not reported';
  document.querySelector('#summary-kept').textContent = kept.length
    ? kept.map(category => categoryLabels[category] || 'Other field').join(', ')
    : 'None';
  document.querySelector('#summary-hits').textContent = /^\d+$/.test(hits || '') ? hits : 'Not reported';
  document.querySelector('#summary-ocr').textContent = headers.get('X-OCR-Used') === 'true' ? 'Yes' : 'No';
  document.querySelector('#summary-check').textContent = headers.get('X-Output-Verified') === 'true'
    ? 'Passed checks for detected values' : 'Not reported';
  const elapsed = headers.get('X-Processing-Ms') || '';
  document.querySelector('#summary-time').textContent = /^\d{1,7}$/.test(elapsed) ? `${elapsed} ms` : 'Not reported';
  const reference = headers.get('X-Correlation-ID') || '';
  document.querySelector('#summary-reference').textContent = /^[a-f0-9]{32}$/.test(reference) ? reference : 'Not reported';
  const policyNote = document.querySelector('#summary-policy');
  policyNote.hidden = kept.length === 0;
  policyNote.textContent = kept.length
    ? 'Your selected policy kept some detected categories visible. This output is not PII-free. Check it before sharing.'
    : '';
}
function drawImage() {
  if (!bitmap) return;
  context.drawImage(bitmap, 0, 0);
  context.fillStyle = '#000';
  for (const box of masks) context.fillRect(...box);
  document.querySelector('#mask-status').textContent = `${masks.length} additional areas covered.`;
}
function point(event) {
  const bounds = canvas.getBoundingClientRect();
  return [Math.max(0, Math.min(canvas.width, (event.clientX-bounds.left)*canvas.width/bounds.width)), Math.max(0, Math.min(canvas.height, (event.clientY-bounds.top)*canvas.height/bounds.height))];
}
canvas.addEventListener('pointerdown', event => {
  if (busy || !bitmap) return;
  start = point(event);
  canvas.setPointerCapture(event.pointerId);
});
canvas.addEventListener('pointerup', event => {
  if (!start || busy) return;
  const end = point(event);
  const box = [Math.min(start[0],end[0]),Math.min(start[1],end[1]),Math.abs(end[0]-start[0]),Math.abs(end[1]-start[1])];
  start = null;
  if (box[2] >= 2 && box[3] >= 2) masks.push(box);
  drawImage();
});
canvas.addEventListener('pointercancel', () => { start = null; });
document.querySelector('#reset-masks').addEventListener('click', () => { if (!busy) { masks = []; drawImage(); } });
fileInput.addEventListener('change', async () => {
  const generation = ++fileGeneration;
  clearDownload(); masks = []; editor.hidden = true;
  bitmap?.close(); bitmap = null;
  const file = fileInput.files?.[0];
  fileLabel.textContent = file?.name || 'Choose a file';
  if (!file) return say('');
  if (!allowed.has(extension(file.name))) return say('This format is not supported.');
  if (!file.size || file.size > maxBytes) return say('Choose a non-empty file no larger than 3 MB.');
  say('File ready. The protected copy will download after processing.');
  if (!['.jpg','.jpeg','.png'].includes(extension(file.name))) return;
  try {
    const candidate = await createImageBitmap(file);
    if (generation !== fileGeneration) { candidate.close(); return; }
    if (candidate.width * candidate.height > 25000000) { candidate.close(); return say('Image is too large for the manual editor. Choose a smaller image.'); }
    bitmap = candidate; canvas.width = candidate.width; canvas.height = candidate.height;
    editor.hidden = false; drawImage();
  } catch (_) { say('Image preview failed. Choose a valid JPG or PNG.'); }
});
document.querySelector('#customer-upload').addEventListener('submit', async event => {
  event.preventDefault();
  if (busy) return;
  const file = fileInput.files?.[0];
  if (!file || !allowed.has(extension(file.name))) return say('Choose a supported file.');
  if (!file.size || file.size > maxBytes) return say('Choose a non-empty file no larger than 3 MB.');
  if (!window.DataSentinelPolicy) return say('Category choices did not load. Refresh this page before processing.');
  const policy = window.DataSentinelPolicy.selected();
  if (!window.DataSentinelPolicy.confirmKeep()) return say('Processing cancelled.');
  const button = event.currentTarget.querySelector('button[type="submit"]');
  busy = true; button.disabled = true; fileInput.disabled = true; clearDownload();
  say('Reading and protecting the file. Keep this page open…');
  try {
    const contentType = mime[extension(file.name).slice(1)];
    let uploadFile = file;
    if (bitmap && masks.length) {
      drawImage();
      const blob = await new Promise(resolve => canvas.toBlob(resolve, contentType, 0.95));
      if (!blob || blob.size > maxBytes) throw new Error('Edited image exceeds 3 MB. Choose a smaller image.');
      uploadFile = blob;
    }
    const response = await fetch('/api/v1/protect', {
      method:'POST', credentials:'same-origin', signal:AbortSignal.timeout(120000), body:uploadFile,
      headers:csrfHeaders({'Content-Type':contentType,'X-Filename':encodeURIComponent(file.name),'X-Redaction-Policy':JSON.stringify(policy),'X-Policy-Confirmed':String(Object.values(policy).includes('KEEP'))}),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      if (response.status === 429) throw new Error('The free daily limit or request rate was reached. Wait and try again; no file was issued.');
      if ([502,503,504].includes(response.status)) throw new Error('Processing is temporarily unavailable. Try again later with a smaller clear file; no file was issued.');
      throw new Error(typeof body.detail === 'string' ? body.detail : 'Protection failed; no file was issued.');
    }
    const blob = await response.blob();
    if (!blob.size) throw new Error('The protected result was empty. No download was started.');
    renderSummary(response.headers);
    downloadUrl = URL.createObjectURL(blob);
    const filename = 'protected-' + file.name.replace(/[^A-Za-z0-9._-]/g, '-');
    downloadAgain.href = downloadUrl; downloadAgain.download = filename;
    result.hidden = false;
    downloadAgain.click();
    const hits = response.headers.get('X-Redaction-Hits');
    say(`Protected file ready${hits ? ` · ${hits} area(s) covered` : ''}. Download started. If it was blocked, use “Download again”.`);
  } catch (error) {
    if (error.name === 'TimeoutError' || error.name === 'AbortError') {
      say('Processing timed out. No download was started. Try a smaller or clearer file.');
    } else if (error instanceof TypeError) {
      say('Connection interrupted. No download was started. Check your connection and try again.');
    } else {
      say(error.message || 'Protection failed; no file was issued.');
    }
  }
  finally { busy = false; button.disabled = false; fileInput.disabled = false; }
});
document.querySelector('#copy-api-url')?.addEventListener('click', async () => {
  const status = document.querySelector('#copy-api-status');
  try {
    await navigator.clipboard.writeText('https://datasentinel.ifhx.my/api/v1/protect');
    status.textContent = 'API endpoint copied.';
  } catch (_) {
    status.textContent = 'Copy is unavailable here. Select the endpoint above to copy it.';
  }
});
