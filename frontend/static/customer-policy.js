(function () {
  const categories = [['name','Person name'],['my_ic','Malaysian NRIC / national ID'],['government_id','Other government ID'],['passport_number','Passport number'],['address','Postal address'],['email','Email address'],['my_phone','Phone number'],['date_of_birth','Date of birth'],['financial_account','Financial account'],['credit_card','Payment card'],['matric_number','Student / matric number'],['employee_id','Employee ID'],['patient_id','Patient / medical ID'],['customer_id','Customer ID'],['user_identifier','User identifier'],['ip_address','IP address'],['mac_address','MAC address'],['gps_coordinates','GPS coordinates'],['secret','Secret or token'],['private_key','Private key'],['aws_access_key','AWS access key']];
  const nonKeepable = new Set(['my_ic','passport_number','government_id','credit_card','secret','private_key','aws_access_key']);
  const label = key => categories.find(item => item[0] === key)?.[1] || key;
  const selected = () => Object.fromEntries([...document.querySelectorAll('#policy-options input[data-category]')].map(input => [input.dataset.category, input.checked ? 'REDACT' : 'KEEP']));
  const update = () => {
    const node = document.querySelector('#policy-summary'); if (!node) return;
    const policy = selected(); const keep = Object.keys(policy).filter(key => policy[key] === 'KEEP').map(label); const redact = Object.keys(policy).filter(key => policy[key] === 'REDACT');
    node.innerHTML = `<strong>${redact.length} categories will be redacted</strong>${keep.length ? `<strong class="policy-warning">Kept: ${keep.join(', ')}</strong><small>Output may still contain PII. Confirmation is required.</small>` : '<small>Safe default: detected supported categories are redacted.</small>'}`;
  };
  const options = document.querySelector('#policy-options');
  if (options) {
    categories.forEach(([key, name]) => {
      const row = document.createElement('label'); row.className = 'policy-option';
      const input = document.createElement('input'); input.type = 'checkbox'; input.checked = true; input.dataset.category = key; input.disabled = nonKeepable.has(key);
      const copy = document.createElement('span'); copy.innerHTML = `<strong>${name}</strong><small>${input.disabled ? 'Always protected for safety.' : 'Protected by default. Uncheck only if you intend to keep it visible.'}</small>`;
      row.append(input, copy); options.append(row); input.addEventListener('change', update);
    });
    document.querySelector('#redact-all')?.addEventListener('click', () => { options.querySelectorAll('input').forEach(input => { input.checked = true; }); update(); });
    document.querySelector('#reset-policy')?.addEventListener('click', () => { options.querySelectorAll('input').forEach(input => { input.checked = true; }); update(); });
    document.querySelector('#policy-loading')?.remove();
    update();
  }
  window.DataSentinelPolicy = {selected, confirmKeep: () => {
    const policy = selected(); const keep = Object.keys(policy).filter(key => policy[key] === 'KEEP').map(label);
    return !keep.length || window.confirm(`This output will keep: ${keep.join(', ')}. It may still contain PII. Continue?`);
  }};
})();
