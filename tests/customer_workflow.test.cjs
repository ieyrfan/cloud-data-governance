const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function harness(status = 200, responseHeaders = {}) {
  const nodes = new Map();
  function node() {
    return {textContent:'',hidden:false,disabled:false,files:[],handlers:{},
      addEventListener(name, handler) { this.handlers[name] = handler; },
      querySelector() { return node(); },
      getContext() { return {}; },
      removeAttribute() {},
      click() { this.clicked = true; }};
  }
  const requests = [];
  const scope = vm.createContext({
    document:{cookie:'',querySelector(selector) { if (!nodes.has(selector)) nodes.set(selector,node()); return nodes.get(selector); }},
    window:{DataSentinelPolicy:{selected:()=>({email:'REDACT'}),confirmKeep:()=>true}},
    URL:{createObjectURL:()=> 'blob:protected',revokeObjectURL:()=>{}},
    fetch:async (path, options)=>{ requests.push({path,options}); return {
      ok:status < 400,status,headers:new Headers({
        'X-Redaction-Hits':'2','X-Document-Type':'PASSPORT',
        'X-Suggested-Classification':'RESTRICTED',
        'X-Detected-Categories':'my_ic,government_id',
        'X-Redacted-Categories':'my_ic,government_id',
        'X-OCR-Used':'true','X-Output-Verified':'true',
        'X-Processing-Ms':'85','X-Correlation-ID':'0123456789abcdef0123456789abcdef',
        ...responseHeaders,
      }),
      blob:async()=>new Blob(['protected']),json:async()=>({detail:'Protection stopped safely'}),
    }; },
    AbortSignal, Headers, Blob, decodeURIComponent, encodeURIComponent,
    createImageBitmap:async()=>{throw new Error('unused');},
  });
  vm.runInContext(fs.readFileSync('frontend/static/customer.js','utf8'),scope);
  return {nodes,requests,scope};
}

test('successful processing downloads the returned bytes automatically', async()=>{
  const h = harness();
  h.nodes.get('#customer-file').files = [{name:'synthetic.txt',size:50}];
  await h.nodes.get('#customer-upload').handlers.submit({preventDefault(){},currentTarget:h.nodes.get('#customer-upload')});
  assert.equal(h.requests[0].path, '/api/v1/protect');
  assert.equal(h.nodes.get('#download-again').clicked, true);
  assert.equal(h.nodes.get('#download-again').href, 'blob:protected');
  assert.equal(h.nodes.get('#download-again').download, 'protected-synthetic.txt');
  assert.equal(h.nodes.get('#download-result').hidden, false);
  assert.equal(h.nodes.get('#summary-type').textContent, 'Passport / travel document');
  assert.equal(h.nodes.get('#summary-classification').textContent, 'Restricted');
  assert.equal(h.nodes.get('#summary-categories').textContent,
    'Malaysian identity number, Government or passport ID');
  assert.equal(h.nodes.get('#summary-hits').textContent, '2');
  assert.equal(h.nodes.get('#summary-ocr').textContent, 'Yes');
  assert.equal(h.nodes.get('#summary-check').textContent, 'Passed checks for detected values');
  assert.equal(h.nodes.get('#summary-time').textContent, '85 ms');
  assert.equal(h.nodes.get('#summary-reference').textContent, '0123456789abcdef0123456789abcdef');
});

test('failed protection never starts a download', async()=>{
  const h = harness(422);
  h.nodes.get('#customer-file').files = [{name:'uncertain.txt',size:50}];
  await h.nodes.get('#customer-upload').handlers.submit({preventDefault(){},currentTarget:h.nodes.get('#customer-upload')});
  assert.equal(h.nodes.get('#download-again').clicked, undefined);
  assert.equal(h.nodes.get('#download-result').hidden, true);
  assert.match(h.nodes.get('#customer-status').textContent,/stopped safely/);
});

test('interrupted upload never starts a download', async()=>{
  const h = harness();
  h.scope.fetch = async()=>{throw new Error('Connection interrupted');};
  h.nodes.get('#customer-file').files = [{name:'synthetic.txt',size:50}];
  await h.nodes.get('#customer-upload').handlers.submit({preventDefault(){},currentTarget:h.nodes.get('#customer-upload')});
  assert.equal(h.nodes.get('#download-again').clicked,undefined);
  assert.equal(h.nodes.get('#download-result').hidden,true);
  assert.match(h.nodes.get('#customer-status').textContent,/Connection interrupted/);
});

test('missing policy choices block processing', async()=>{
  const h = harness();
  h.scope.window.DataSentinelPolicy = undefined;
  h.nodes.get('#customer-file').files = [{name:'synthetic.txt',size:50}];
  await h.nodes.get('#customer-upload').handlers.submit({preventDefault(){},currentTarget:h.nodes.get('#customer-upload')});
  assert.equal(h.requests.length,0);
  assert.match(h.nodes.get('#customer-status').textContent,/Refresh this page/);
});

test('quota response gives retry guidance without a download', async()=>{
  const h = harness(429);
  h.nodes.get('#customer-file').files = [{name:'synthetic.txt',size:50}];
  await h.nodes.get('#customer-upload').handlers.submit({preventDefault(){},currentTarget:h.nodes.get('#customer-upload')});
  assert.equal(h.nodes.get('#download-again').clicked,undefined);
  assert.match(h.nodes.get('#customer-status').textContent,/free daily limit or request rate/);
});

test('retained categories show a sharing warning without personal values', async()=>{
  const h = harness(200, {'X-Kept-Categories':'email'});
  h.nodes.get('#customer-file').files = [{name:'synthetic.txt',size:50}];
  await h.nodes.get('#customer-upload').handlers.submit({preventDefault(){},currentTarget:h.nodes.get('#customer-upload')});
  assert.equal(h.nodes.get('#summary-policy').hidden, false);
  assert.match(h.nodes.get('#summary-policy').textContent,/not PII-free/);
  assert.doesNotMatch(h.nodes.get('#summary-policy').textContent,/@/);
});

test('advanced choices render every supported category and clear loading state',()=>{
  const inputs = [];
  const listeners = {};
  let loadingRemoved = false;
  const options = {
    append(row) { inputs.push(row.input); },
    querySelectorAll() { return inputs; },
  };
  const summary = {innerHTML:''};
  const loading = {remove() { loadingRemoved = true; }};
  const button = () => ({addEventListener(event,handler) { listeners[event] = handler; }});
  const all = button(); const reset = button();
  const document = {
    querySelector(selector) {
      return {'#policy-options':options,'#policy-summary':summary,
        '#policy-loading':loading,'#redact-all':all,'#reset-policy':reset}[selector];
    },
    querySelectorAll() { return inputs; },
    createElement(tag) {
      if (tag === 'label') return {append(input) { this.input = input; }};
      if (tag === 'input') return {dataset:{},checked:false,disabled:false,addEventListener() {}};
      return {innerHTML:''};
    },
  };
  const window = {confirm:()=>true};
  vm.runInNewContext(fs.readFileSync('frontend/static/customer-policy.js','utf8'),{document,window});
  assert.equal(inputs.length,21);
  assert.equal(loadingRemoved,true);
  assert.match(summary.innerHTML,/21 categories will be redacted/);
  assert.equal(window.DataSentinelPolicy.selected().government_id,'REDACT');
  assert.equal(window.DataSentinelPolicy.selected().employee_id,'REDACT');
  assert.equal(inputs.find(input=>input.dataset.category==='government_id').disabled,true);
});
