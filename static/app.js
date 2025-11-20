document.getElementById('uploadForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const input = document.getElementById('fileInput');
  if (!input.files || input.files.length === 0) return alert('Choose a .py file first');
  const fd = new FormData();
  fd.append('file', input.files[0]);
  const res = await fetch('/upload', { method: 'POST', body: fd });
  if (!res.ok) {
    const t = await res.text();
    return alert('Upload failed: ' + t);
  }
  const data = await res.json();
  document.getElementById('fname').textContent = data.filename;
  const fileArea = document.getElementById('fileArea');
  fileArea.innerHTML = '';
  const lines = data.content.split('\n');
  // group findings by lineno
  const findingsByLine = {};
  for (const f of data.findings) {
    const ln = f.lineno || 0;
    if (!findingsByLine[ln]) findingsByLine[ln] = [];
    findingsByLine[ln].push(f);
  }

  // build summary
  const total = data.findings.length;
  const errorCount = data.findings.filter(f => f.severity === 'ERROR').length;
  const warningCount = data.findings.filter(f => f.severity === 'WARNING').length;
  const infoCount = data.findings.filter(f => f.severity === 'INFO').length;
  const typeCounts = {};
  for (const f of data.findings) {
    typeCounts[f.code] = (typeCounts[f.code] || 0) + 1;
  }
  const uniqueTypes = Object.keys(typeCounts).length;
  const elTotal = document.getElementById('totalCount');
  if (elTotal) elTotal.textContent = total;
  const elErr = document.getElementById('errorCount');
  if (elErr) elErr.textContent = errorCount;
  const elWarn = document.getElementById('warningCount');
  if (elWarn) elWarn.textContent = warningCount;
  const elInfo = document.getElementById('infoCount');
  if (elInfo) elInfo.textContent = infoCount;
  const typeList = document.getElementById('typeList');
  typeList.innerHTML = '';
  // create a master "Toggle All" checkbox
  const allLi = document.createElement('li');
  allLi.style.listStyle = 'none';
  allLi.className = 'all-toggle';
  const allId = 'type_all_toggle';
  const allChk = document.createElement('input');
  allChk.type = 'checkbox';
  allChk.id = allId;
  const allLabel = document.createElement('label');
  allLabel.htmlFor = allId;
  allLabel.style.marginLeft = '6px';
  allLabel.textContent = `All`;
  allLi.appendChild(allChk);
  allLi.appendChild(allLabel);
  typeList.appendChild(allLi);

  function updateMasterCheckbox() {
    const items = Array.from(document.querySelectorAll('#typeList input[type=checkbox].type-item'));
    if (items.length === 0) { allChk.checked = false; allChk.indeterminate = false; return; }
    const allChecked = items.every(i => i.checked);
    const someChecked = items.some(i => i.checked);
    allChk.checked = allChecked;
    allChk.indeterminate = (!allChecked && someChecked);
  }

  // helper: apply highlighting for a given type checkbox
  function applyTypeToggle(checkbox) {
    const codeKey = checkbox.dataset.code;
    const checked = checkbox.checked;
    const allLines = document.querySelectorAll('[data-codes]');
    allLines.forEach(l => {
      const codes = (l.dataset.codes || '').split(',').filter(Boolean);
      if (codes.includes(codeKey)) {
        if (checked) l.classList.add('type-active'); else l.classList.remove('type-active');
      }
    });
  }

  // when master toggled, toggle all individual type checkboxes
  allChk.addEventListener('change', (ev) => {
    const items = Array.from(document.querySelectorAll('#typeList input[type=checkbox].type-item'));
    items.forEach(i => {
      i.checked = ev.target.checked;
      applyTypeToggle(i);
    });
    allChk.indeterminate = false;
  });

  Object.entries(typeCounts).sort((a,b)=>b[1]-a[1]).forEach(([code,count])=>{
    const li = document.createElement('li');
    li.style.listStyle = 'none';
    const id = 'type_' + code.replace(/[^A-Za-z0-9_\-]/g, '_');
    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.className = 'type-item';
    chk.id = id;
    chk.dataset.code = code;
    const label = document.createElement('label');
    label.htmlFor = id;
    label.style.marginLeft = '6px';
    label.textContent = `${code} (${count})`;
    chk.addEventListener('change', (ev) => {
      applyTypeToggle(ev.target);
      updateMasterCheckbox();
    });
    li.appendChild(chk);
    li.appendChild(label);
    typeList.appendChild(li);
  });
  // after creating all type items, apply initial highlighting and update master state
  const items = Array.from(document.querySelectorAll('#typeList input[type=checkbox].type-item'));
  items.forEach(i => { applyTypeToggle(i); });
  // ensure master checkbox reflects the items' state
  updateMasterCheckbox();
  document.getElementById('summary').style.display = 'block';
  for (let i = 0; i < lines.length; i++) {
    const ln = i + 1;
    const div = document.createElement('div');
    div.className = 'line';
    div.id = 'line-' + ln;
    div.dataset.line = ln;
    // annotate codes present on this line for filtering
    const codes = (findingsByLine[ln] || []).map(x => x.code);
    div.dataset.codes = codes.join(',');
    const num = document.createElement('span');
    num.className = 'line-number';
    num.textContent = ln.toString().padStart(4, ' ');
    const content = document.createElement('span');
    content.className = 'line-content';
    // use Prism to syntax-highlight the line if available
    try {
      if (window.Prism && Prism.languages && Prism.languages.python) {
        const highlighted = Prism.highlight(lines[i] + '\n', Prism.languages.python, 'python');
        content.innerHTML = highlighted.replace(/\n$/, '');
      } else {
        content.textContent = lines[i];
      }
    } catch (e) {
      content.textContent = lines[i];
    }
    div.appendChild(num);
    div.appendChild(content);
    if (findingsByLine[ln]) {
      div.classList.add('flagged');
      for (const f of findingsByLine[ln]) {
        const badge = document.createElement('span');
        badge.className = 'flag';
        badge.textContent = `${f.severity}: ${f.code}`;
        badge.title = f.message;
        div.appendChild(badge);
      }
      // tooltip on the line summarizing findings
      const tip = findingsByLine[ln].map(x=>`[${x.severity}] ${x.code}: ${x.message}`).join('\n');
      div.title = tip;
    }
    fileArea.appendChild(div);
  }
  // scroll to first flagged line
  const firstFlag = document.querySelector('.flagged');
  if (firstFlag) firstFlag.scrollIntoView({behavior:'smooth', block:'center'});
    // JSON output
    const jsonOut = document.getElementById('jsonOutput');
    const outData = { filename: data.filename, findings: data.findings };
    jsonOut.textContent = JSON.stringify(outData, null, 2);
    // download button
    const dl = document.getElementById('downloadJson');
    dl.onclick = () => {
      const blob = new Blob([jsonOut.textContent], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = data.filename + '.findings.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    };
    // toggle JSON visibility
    const tog = document.getElementById('toggleJson');
    tog.onclick = () => {
      if (jsonOut.style.display === 'none') jsonOut.style.display = 'block'; else jsonOut.style.display = 'none';
    };

    // render severity chart
    try {
      const ctx = document.getElementById('severityChart');
      if (ctx) {
        // destroy existing chart if any
        if (window._severityChartInstance) {
          window._severityChartInstance.destroy();
        }
        const chart = new Chart(ctx, {
          type: 'bar',
          data: {
            labels: ['ERROR', 'WARNING', 'INFO'],
            datasets: [{
              label: 'Findings',
              data: [errorCount, warningCount, infoCount],
              backgroundColor: ['#c62828', '#ffb300', '#1976d2']
            }]
          },
          options: { responsive: true, maintainAspectRatio: false }
        });
        window._severityChartInstance = chart;
      }
    } catch (e) {
      console.warn('Chart error', e);
    }
});
