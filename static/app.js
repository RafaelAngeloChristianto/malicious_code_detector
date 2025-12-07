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
  
  // Render parse tree visualization if available
  renderParseTraces(data.parse_traces || []);
  
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
  
  // Grammar-based detection statistics
  const grammarFindings = data.findings.filter(f => f.code === 'GRAMMAR_VULN');
  const grammarCount = grammarFindings.length;
  const uniquePatterns = new Set(grammarFindings.map(f => f.pattern).filter(Boolean));
  
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
  
  // Update grammar info section
  if (grammarCount > 0) {
    document.getElementById('grammarInfo').style.display = 'block';
    document.getElementById('grammarCount').textContent = 
      `${grammarCount} vulnerabilities detected via formal grammar parser`;
  } else {
    document.getElementById('grammarInfo').style.display = 'none';
  }
  
  // Build pattern-based type counts for grammar findings
  const patternCounts = {};
  for (const f of data.findings) {
    // For grammar findings, use pattern as the type key
    if (f.code === 'GRAMMAR_VULN' && f.pattern) {
      const patternKey = f.pattern;
      patternCounts[patternKey] = (patternCounts[patternKey] || 0) + 1;
    } else {
      // For non-grammar findings, use code as before
      patternCounts[f.code] = (patternCounts[f.code] || 0) + 1;
    }
  }
  
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

  Object.entries(patternCounts).sort((a,b)=>b[1]-a[1]).forEach(([code,count])=>{
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
    // annotate codes/patterns present on this line for filtering
    const codes = (findingsByLine[ln] || []).map(f => {
      // Use pattern for grammar findings, code for others
      return (f.code === 'GRAMMAR_VULN' && f.pattern) ? f.pattern : f.code;
    });
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
      
      // Add severity-based class to the line for proper highlighting colors
      const severities = findingsByLine[ln].map(f => f.severity.toLowerCase());
      if (severities.includes('error')) {
        div.classList.add('error-line');
      } else if (severities.includes('warning')) {
        div.classList.add('warning-line');
      } else if (severities.includes('info')) {
        div.classList.add('info-line');
      }
      
      for (const f of findingsByLine[ln]) {
        const badge = document.createElement('span');
        badge.className = 'flag';
        
        // Add severity-specific class to badge
        const severityClass = f.severity.toLowerCase();
        badge.classList.add(severityClass);
        
        // Enhanced display for grammar-based detections
        if (f.code === 'GRAMMAR_VULN') {
          badge.textContent = `${f.severity}: ${f.code}`;
          // Add pattern information if available
          if (f.pattern) {
            const patternSpan = document.createElement('span');
            patternSpan.className = 'pattern-info';
            patternSpan.textContent = ` [${f.pattern}]`;
            badge.appendChild(patternSpan);
          }
          // Build detailed tooltip
          let tooltipText = f.message;
          if (f.pattern) tooltipText += `\nPattern: ${f.pattern}`;
          if (f.tokens) tooltipText += `\nTokens: [${f.tokens.join(', ')}]`;
          if (f.parse_stack) tooltipText += `\nParser States: [${f.parse_stack.join(', ')}]`;
          badge.title = tooltipText;
        } else {
          badge.textContent = `${f.severity}: ${f.code}`;
          badge.title = f.message;
        }
        
        div.appendChild(badge);
      }
      // tooltip on the line summarizing findings
      const tip = findingsByLine[ln].map(x => {
        let msg = `[${x.severity}] ${x.code}: ${x.message}`;
        if (x.pattern) msg += `\n  → Pattern: ${x.pattern}`;
        if (x.tokens) msg += `\n  → Tokens: [${x.tokens.join(', ')}]`;
        return msg;
      }).join('\n\n');
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

// ============================================
// PARSE TREE VISUALIZATION FUNCTIONS
// ============================================

function renderParseTraces(parseTraces) {
  const section = document.getElementById('parseTreeSection');
  const container = document.getElementById('parseTreeContainer');
  
  if (!parseTraces || parseTraces.length === 0) {
    section.style.display = 'none';
    return;
  }
  
  section.style.display = 'block';
  container.innerHTML = '';
  
  // Add legend
  const legend = document.createElement('div');
  legend.className = 'parse-tree-legend';
  legend.innerHTML = `
    <div class="legend-item">
      <span class="legend-color" style="background:#e3f2fd;"></span>
      <span>SHIFT: Push state, consume token</span>
    </div>
    <div class="legend-item">
      <span class="legend-color" style="background:#fce4ec;"></span>
      <span>REDUCE: Apply grammar rule</span>
    </div>
    <div class="legend-item">
      <span class="legend-color" style="background:#fff9c4;"></span>
      <span>Tokens: Input sequence</span>
    </div>
  `;
  container.appendChild(legend);
  
  // Render each parse trace
  parseTraces.forEach((trace, idx) => {
    const traceDiv = document.createElement('div');
    traceDiv.className = 'parse-trace-item';
    
    // Header
    const header = document.createElement('div');
    header.className = 'parse-trace-header';
    header.innerHTML = `
      <div class="parse-trace-title">
        Parse Trace #${idx + 1}: ${trace.vulnerability} Detection
      </div>
      <div class="parse-trace-meta">
        Line ${trace.lineno} | ${trace.severity}
      </div>
    `;
    traceDiv.appendChild(header);
    
    // Message and pattern
    const info = document.createElement('div');
    info.style.marginBottom = '8px';
    info.innerHTML = `
      <div style="font-size:13px; color:#333; margin-bottom:4px;">
        <strong>Message:</strong> ${trace.message}
      </div>
      <div style="font-size:12px; color:#666;">
        <strong>Pattern:</strong> <code>${trace.pattern}</code>
      </div>
    `;
    traceDiv.appendChild(info);
    
    // Tokens
    const tokensDiv = document.createElement('div');
    tokensDiv.className = 'parse-trace-tokens';
    tokensDiv.innerHTML = `<strong>Tokens:</strong> [${trace.tokens.map(t => `"${t}"`).join(', ')}]`;
    traceDiv.appendChild(tokensDiv);
    
    // Parse steps table
    if (trace.steps && trace.steps.length > 0) {
      const stepsTitle = document.createElement('div');
      stepsTitle.style.marginTop = '12px';
      stepsTitle.style.marginBottom = '6px';
      stepsTitle.style.fontWeight = 'bold';
      stepsTitle.style.fontSize = '13px';
      stepsTitle.innerHTML = `Parse Steps (LR Parser Trace):`;
      traceDiv.appendChild(stepsTitle);
      
      const tableDiv = document.createElement('div');
      tableDiv.style.overflowX = 'auto';
      
      const table = document.createElement('table');
      table.className = 'parse-steps-table';
      
      // Table header
      const thead = document.createElement('thead');
      thead.innerHTML = `
        <tr>
          <th style="width:40px;">Step</th>
          <th style="width:80px;">Action</th>
          <th style="width:60px;">State</th>
          <th style="width:100px;">Lookahead</th>
          <th style="min-width:150px;">Production / Next State</th>
          <th style="min-width:120px;">Stack</th>
          <th style="min-width:120px;">Symbols</th>
          <th style="min-width:150px;">Remaining Input</th>
        </tr>
      `;
      table.appendChild(thead);
      
      // Table body
      const tbody = document.createElement('tbody');
      trace.steps.forEach(step => {
        const tr = document.createElement('tr');
        
        // Step number
        const tdStep = document.createElement('td');
        tdStep.textContent = step.step;
        tdStep.style.textAlign = 'center';
        tdStep.style.fontWeight = 'bold';
        tr.appendChild(tdStep);
        
        // Action
        const tdAction = document.createElement('td');
        const actionSpan = document.createElement('span');
        actionSpan.className = `parse-step-action ${step.action.toLowerCase()}`;
        actionSpan.textContent = step.action;
        tdAction.appendChild(actionSpan);
        tr.appendChild(tdAction);
        
        // State
        const tdState = document.createElement('td');
        tdState.innerHTML = `<span class="parse-step-stack">${step.state}</span>`;
        tdState.style.textAlign = 'center';
        tr.appendChild(tdState);
        
        // Lookahead (only for SHIFT)
        const tdLookahead = document.createElement('td');
        if (step.action === 'SHIFT' && step.lookahead) {
          tdLookahead.innerHTML = `<code style="background:#fff3e0; padding:2px 4px; border-radius:3px;">${step.lookahead}</code>`;
        } else {
          tdLookahead.textContent = '—';
        }
        tr.appendChild(tdLookahead);
        
        // Production / Next State
        const tdProd = document.createElement('td');
        if (step.action === 'SHIFT') {
          tdProd.innerHTML = `→ State <span class="parse-step-stack">${step.next_state}</span>`;
        } else if (step.action === 'REDUCE') {
          tdProd.innerHTML = `<div class="parse-step-production">${step.production}</div>`;
          if (step.goto_state !== null && step.goto_state !== undefined) {
            const gotoSpan = document.createElement('div');
            gotoSpan.style.marginTop = '4px';
            gotoSpan.style.fontSize = '11px';
            gotoSpan.innerHTML = `GOTO → <span class="parse-step-stack">${step.goto_state}</span>`;
            tdProd.appendChild(gotoSpan);
          }
        }
        tr.appendChild(tdProd);
        
        // Stack
        const tdStack = document.createElement('td');
        if (step.action === 'REDUCE' && step.stack_after) {
          tdStack.innerHTML = `
            <div style="font-size:10px; color:#999;">Before: <span class="parse-step-stack">[${step.stack_before.join(', ')}]</span></div>
            <div style="margin-top:2px;">After: <span class="parse-step-stack">[${step.stack_after.join(', ')}]</span></div>
          `;
        } else {
          tdStack.innerHTML = `<span class="parse-step-stack">[${step.stack_before.join(', ')}]</span>`;
        }
        tr.appendChild(tdStack);
        
        // Symbols
        const tdSymbols = document.createElement('td');
        if (step.action === 'REDUCE' && step.symbols_after) {
          tdSymbols.innerHTML = `
            <div style="font-size:10px; color:#999;">Before: <span class="parse-step-symbols">[${step.symbols_before.join(', ')}]</span></div>
            <div style="margin-top:2px;">After: <span class="parse-step-symbols">[${step.symbols_after.join(', ')}]</span></div>
          `;
        } else {
          const symbolsText = step.symbols_before && step.symbols_before.length > 0 
            ? step.symbols_before.join(', ') 
            : 'ε';
          tdSymbols.innerHTML = `<span class="parse-step-symbols">[${symbolsText}]</span>`;
        }
        tr.appendChild(tdSymbols);
        
        // Remaining input
        const tdInput = document.createElement('td');
        const inputText = step.input_remaining && step.input_remaining.length > 0
          ? step.input_remaining.join(', ')
          : 'ε';
        tdInput.innerHTML = `<span class="parse-step-input">[${inputText}]</span>`;
        tr.appendChild(tdInput);
        
        tbody.appendChild(tr);
      });
      
      table.appendChild(tbody);
      tableDiv.appendChild(table);
      traceDiv.appendChild(tableDiv);
    }
    
    container.appendChild(traceDiv);
  });
  
  // Toggle button functionality
  const toggleBtn = document.getElementById('toggleParseTree');
  if (toggleBtn) {
    toggleBtn.onclick = () => {
      if (container.style.display === 'none') {
        container.style.display = 'block';
        toggleBtn.textContent = 'Toggle Parse Trees';
      } else {
        container.style.display = 'none';
        toggleBtn.textContent = 'Show Parse Trees';
      }
    };
  }
}
