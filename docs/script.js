
(function(){
  const updates = [{"date": "2025-10-28", "kb": "KB5067036", "product": "Windows 11 24H2 / 25H2", "classification": "Preview (Non-security)", "details": "Cumulative non-security preview update; additional fixes including media DRM/EVR improvements and IIS/HTTP.sys related reliability updates.", "known_issues": "Addresses prior issues with protected content playback and IIS/HTTP.sys connectivity noted after September preview and October security updates.", "link": "https://support.microsoft.com/en-us/help/5067036", "severity": "Preview"}, {"date": "2025-10-20", "kb": "KB5070773", "product": "Windows 11 24H2 / 25H2", "classification": "Out-of-band", "details": "Fixes USB devices not working in Windows Recovery Environment after the Oct 14 security update; updates AI component versions; includes cumulative fixes from 10/14.", "known_issues": "Some Blu-ray/DVD/DTV apps may fail to play protected content (EVR/HDCP/DRM); IIS websites might fail to load in some environments (addressed by later preview).", "link": "https://support.microsoft.com/en-us/help/5070773", "severity": "Important (quality)"}, {"date": "2025-10-14", "kb": "KB5066835", "product": "Windows 11 24H2 / 25H2", "classification": "Security Update (Patch Tuesday)", "details": "October 2025 cumulative security update; includes security fixes and quality improvements. Disables File Explorer preview for files from the internet to mitigate a vulnerability.", "known_issues": "See Release notes: includes items like NDI streaming performance prior to Sept fix; other product-specific items may apply. Use MSRC for CVE details.", "link": "https://support.microsoft.com/en-us/help/5066835", "severity": "Security"}, {"date": "2025-10-14", "kb": "KB5066793", "product": "Windows 11 22H2 / 23H2", "classification": "Security Update (Patch Tuesday)", "details": "October 2025 cumulative security update; contains security fixes and quality improvements.", "known_issues": "Microsoft is not currently aware of any issues for this release.", "link": "https://support.microsoft.com/en-us/help/5066793", "severity": "Security"}, {"date": "2025-10-14", "kb": "KB5066791", "product": "Windows 10 21H2 / 22H2 (incl. LTSC 2021)", "classification": "Security Update (Patch Tuesday)", "details": "October 2025 cumulative security update; includes SSU improvements and various fixes (IME, WinRM, certificate chain for Azure validation, etc.).", "known_issues": "Incorrect 'End of support' message may appear on some editions enrolled in ESU or LTSC 2021; mitigations and Group Policy available.", "link": "https://support.microsoft.com/en-us/help/5066791", "severity": "Security"}, {"date": "2025-09-29", "kb": "KB5065789", "product": "Windows 11 25H2 / 24H2", "classification": "Preview (Non-security)", "details": "Non-security preview addressing protected content playback issues and other quality improvements.", "known_issues": "Addresses issues introduced by prior preview/security releases with EVR/DRM playback and HTTP.sys/IIS connectivity.", "link": "https://support.microsoft.com/en-us/help/5065789", "severity": "Preview"}, {"date": "2025-09-23", "kb": "KB5065790", "product": "Windows 11 23H2", "classification": "Preview (Non-security)", "details": "Non-security preview for Windows 11 23H2; quality fixes including SMBv1 connectivity resolution following Sept security update.", "known_issues": "Addresses SMBv1 protocol connectivity problems observed after September's security update.", "link": "https://support.microsoft.com/en-us/help/5065790", "severity": "Preview"}, {"date": "2025-09-22", "kb": "KB5068221", "product": "Windows 11 24H2", "classification": "Out-of-band", "details": "OOB cumulative update with App-V compatibility fix; includes Sept 9 security content; SSU KB5064531 included.", "known_issues": "SMBv1 connectivity problems after Sept 9 security update; later addressed by KB5065789.", "link": "https://support.microsoft.com/en-us/help/5068221", "severity": "Important (quality)"}, {"date": "2025-09-09", "kb": "KB5065426", "product": "Windows 11 24H2", "classification": "Security Update (Patch Tuesday)", "details": "September 2025 cumulative security update; includes security fixes and quality improvements for 24H2.", "known_issues": "See page for any active advisories; general guidance on Secure Boot cert updates.", "link": "https://support.microsoft.com/en-us/help/5065426", "severity": "Security"}, {"date": "2025-09-09", "kb": "KB5065431", "product": "Windows 11 22H2 / 23H2", "classification": "Security Update (Patch Tuesday)", "details": "September 2025 cumulative security update; includes SMB client/server auditing and MSI repair UAC behavior fixes.", "known_issues": "SMBv1 protocol connections over NetBT can fail after installing Sept 2025 update; addressed by KB5065790.", "link": "https://support.microsoft.com/en-us/help/5065431", "severity": "Security"}, {"date": "2025-09-09", "kb": "KB5065429", "product": "Windows 10 21H2 / 22H2 (incl. LTSC 2021)", "classification": "Security Update (Patch Tuesday)", "details": "September 2025 cumulative security update; includes internal OS security improvements.", "known_issues": "Reset & recovery operations may fail (resolved by later updates); NDI streaming and unexpected MSI repair UAC prompts resolved in Sept 9 update.", "link": "https://support.microsoft.com/en-us/help/5065429", "severity": "Security"}, {"date": "2025-08-29", "kb": "KB5064081", "product": "Windows 11 24H2", "classification": "Preview (Non-security)", "details": "Non-security preview for 24H2; quality improvements.", "known_issues": "Introduced issues playing protected content in some media apps (later addressed by Sept preview and Oct preview).", "link": "https://support.microsoft.com/en-us/help/5064081", "severity": "Preview"}, {"date": "2025-08-12", "kb": "KB5063878", "product": "Windows 11 24H2", "classification": "Security Update (Patch Tuesday)", "details": "August 2025 cumulative security update for Windows 11 24H2.", "known_issues": "See page; none widely documented at release.", "link": "https://support.microsoft.com/en-us/help/5063878", "severity": "Security"}, {"date": "2025-08-12", "kb": "KB5063875", "product": "Windows 11 22H2 / 23H2", "classification": "Security Update (Patch Tuesday)", "details": "August 2025 cumulative security update for Windows 11 22H2/23H2.", "known_issues": "See page; none widely documented at release.", "link": "https://support.microsoft.com/en-us/help/5063875", "severity": "Security"}, {"date": "2025-08-12", "kb": "KB5063709", "product": "Windows 10 21H2 / 22H2 (incl. LTSC 2021)", "classification": "Security Update (Patch Tuesday)", "details": "August 2025 cumulative security update; later changelog added notes about reset/recovery, NDI streaming, and MSI repair UAC prompt behavior.", "known_issues": "Reset & recovery may fail; NDI streaming performance issues; unexpected MSI repair UAC prompts (resolved by Sept updates).", "link": "https://support.microsoft.com/en-us/help/5063709", "severity": "Security"}];

  const coverageEl = document.getElementById('coverage');
  const genEl = document.getElementById('generatedAt');
  const today = new Date();
  const start = new Date(today);
  start.setDate(start.getDate() - 90);
  function fmtDate(d){
    return d.toLocaleString(undefined,{month:'short', day:'2-digit', year:'numeric'});
  }
  coverageEl.textContent = `Coverage window: ${fmtDate(start)} → ${fmtDate(today)}`;
  genEl.textContent = `Generated at: ${new Date().toLocaleString()}`;

  const tbody = document.querySelector('#updatesTable tbody');
  function fmtDateISO(iso){
    const d = new Date(iso + 'T00:00:00');
    return d.toLocaleString(undefined, {month:'short', day:'2-digit', year:'numeric'});
  }
  function rowHTML(u){
    return `<tr>
      <td data-col="date">${fmtDateISO(u.date)}</td>
      <td data-col="kb"><a href="${u.link}" target="_blank" rel="noopener">${u.kb}</a></td>
      <td data-col="product">${u.product}</td>
      <td data-col="class">${u.classification}</td>
      <td data-col="details">${u.details}</td>
      <td data-col="issues">${u.known_issues}</td>
      <td data-col="sev"><span class="badge">${u.severity}</span></td>
    </tr>`;
  }
  updates.sort((a,b) => a.date < b.date ? 1 : -1);
  tbody.innerHTML = updates.map(rowHTML).join('');

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const getText = (el) => (el?.textContent || '').trim();

  let osAsc = true;
  function sortByOS(){
    const rows = $$('#updatesTable tbody tr');
    rows.sort((a,b) => {
      const ap = getText(a.querySelector('td[data-col="product"]')).toLowerCase();
      const bp = getText(b.querySelector('td[data-col="product"]')).toLowerCase();
      if (ap < bp) return osAsc ? -1 : 1;
      if (ap > bp) return osAsc ? 1 : -1;
      const ad = Date.parse(getText(a.querySelector('td[data-col="date"]')));
      const bd = Date.parse(getText(b.querySelector('td[data-col="date"]')));
      return bd - ad;
    });
    tbody.innerHTML = '';
    rows.forEach(r => tbody.appendChild(r));
    $('#btnSortOS').textContent = osAsc ? 'Sort by OS (Z→A)' : 'Sort by OS (A→Z)';
    osAsc = !osAsc;
    applyCombinedFilter();
  }

  function resetSort(){
    tbody.innerHTML = updates.map(rowHTML).join('');
    osAsc = true;
    $('#btnSortOS').textContent = 'Sort by OS (A→Z)';
    buildChips();
    applyCombinedFilter();
  }

  const panel = document.createElement('div');
  panel.id = 'filterPanel';
  panel.className = 'filterpanel';
  const chips = document.createElement('div');
  chips.id = 'chips';
  chips.className = 'chips';
  const controls = document.createElement('div');
  controls.style.cssText = 'margin-top:8px; display:flex; gap:8px; align-items:center;';
  const btnAll = document.createElement('button');
  btnAll.className = 'btn'; btnAll.id='btnSelectAll'; btnAll.textContent='Select all';
  const btnClr = document.createElement('button');
  btnClr.className = 'btn'; btnClr.id='btnClear'; btnClr.textContent='Clear';
  const note = document.createElement('span');
  note.className = 'muted'; note.id='activeFilterNote';
  controls.append(btnAll, btnClr, note);
  const header = document.querySelector('header');
  header.append(panel);
  panel.append(chips, controls);

  function uniqueProducts(){
    const set = new Set();
    $$('#updatesTable td[data-col="product"]').forEach(td => set.add(getText(td)));
    return Array.from(set).sort((a,b)=>a.localeCompare(b));
  }

  function buildChips(){
    chips.innerHTML = '';
    uniqueProducts().forEach(p => {
      const id = 'chk_' + p.replace(/[^a-z0-9]+/gi,'_');
      const lab = document.createElement('label');
      lab.className = 'chip';
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = true;
      input.dataset.os = p;
      input.id = id;
      const span = document.createElement('span');
      span.textContent = p;
      lab.appendChild(input);
      lab.appendChild(span);
      chips.appendChild(lab);
      input.addEventListener('change', applyCombinedFilter);
    });
  }

  function activeOSList(){
    return Array.from(chips.querySelectorAll('input[type="checkbox"]'))
      .filter(cb => cb.checked).map(cb => cb.dataset.os);
  }
  function allOSList(){
    return Array.from(chips.querySelectorAll('input[type="checkbox"]')).map(cb => cb.dataset.os);
  }

  const searchInput = document.getElementById('searchInput');
  const matchCount = document.getElementById('matchCount');

  function applyCombinedFilter(){
    const term = (searchInput?.value || '').toLowerCase().trim();
    const active = activeOSList();
    const all = allOSList();
    let shown = 0;

    $$('#updatesTable tbody tr').forEach(tr => {
      const product = getText(tr.querySelector('td[data-col="product"]'));
      const text = tr.innerText.toLowerCase();
      const matchOS = active.length === 0 ? false : active.includes(product);
      const matchSearch = term === '' ? true : text.includes(term);
      const visible = matchOS && matchSearch;
      tr.style.display = visible ? '' : 'none';
      if (visible) shown += 1;
    });

    note.textContent = active.length === all.length || active.length === 0 ? '' : ('Active OS filters: ' + active.join(', '));
    if (term) { matchCount.textContent = shown + ' match' + (shown===1?'':'es'); }
    else { matchCount.textContent = ''; }
  }

  function toEmailSafe(text, maxLen){
    const enc = encodeURIComponent(text);
    return enc.length > maxLen ? enc.slice(0, maxLen) + '%0A%0A%5Btruncated%5D' : enc;
  }
  function draftEmail(){
    const lines = [];
    lines.push('Windows Updates & Patches — Last 90 Days');
    lines.push(`Coverage: ${fmtDate(start)} to ${fmtDate(today)}`);
    lines.push('');
    $$('#updatesTable tbody tr').forEach(tr => {
      if (tr.style.display === 'none') return;
      const date = getText(tr.querySelector('td[data-col="date"]'));
      const kb = getText(tr.querySelector('td[data-col="kb"]'));
      const kbLink = tr.querySelector('td[data-col="kb"] a')?.href || '';
      const product = getText(tr.querySelector('td[data-col="product"]'));
      const cls = getText(tr.querySelector('td[data-col="class"]'));
      const sev = getText(tr.querySelector('td[data-col="sev"]'));
      const issues = getText(tr.querySelector('td[data-col="issues"]'));
      const line = '• ' + date + ' — ' + kb + ' — ' + product + ' — ' + sev + ' — ' + cls + '\n  ' + kbLink + '\n  Issues: ' + issues;
      lines.push(line);
    });
    lines.push('\n(Attach the HTML report if needed)');
    const subject = encodeURIComponent('Windows updates (last 90 days)');
    const body = toEmailSafe(lines.join('\n'), 1800);
    const mailto = 'mailto:?subject=' + subject + '&body=' + body;
    window.location.href = mailto;
  }

  document.getElementById('btnSortOS').addEventListener('click', sortByOS);
  document.getElementById('btnResetSort').addEventListener('click', resetSort);
  document.getElementById('btnFilterOS').addEventListener('click', () => {
    panel.style.display = (panel.style.display === 'none' || panel.style.display === '') ? 'block' : 'none';
  });
  document.getElementById('btnPrint').addEventListener('click', () => window.print());
  document.getElementById('btnEmail').addEventListener('click', draftEmail);

  document.getElementById('btnSearch').addEventListener('click', applyCombinedFilter);
  document.getElementById('btnClearSearch').addEventListener('click', () => { searchInput.value=''; applyCombinedFilter(); });
  searchInput.addEventListener('keyup', (e) => { if (e.key === 'Enter') applyCombinedFilter(); });

  btnAll.addEventListener('click', () => { chips.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = true); applyCombinedFilter(); });
  btnClr.addEventListener('click', () => { chips.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false); applyCombinedFilter(); });

  buildChips();
  applyCombinedFilter();
})();
