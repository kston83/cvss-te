/**
 * CVSS-TE Application
 * Single-page app with dashboard, lookup, and methodology views.
 * Integrates analytics, KEV enrichment, and CSV export.
 */

import { Analytics } from './modules/analytics.js';
import { KevEnricher } from './modules/kevEnricher.js';
import { ExportManager } from './modules/exportManager.js';

// ───────────────── helpers ─────────────────
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => {
  const map = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
  return String(s ?? '').replace(/[&<>"']/g, c => map[c]);
};

/**
 * Get severity CSS class from severity string
 * @param {string} s - Severity string (CRITICAL, HIGH, MEDIUM, LOW)
 * @returns {string} CSS class name
 */
function sevClass(s) {
  if (!s) return 'ghost';
  const v = String(s).toUpperCase();
  if (v === 'CRITICAL') return 'crit';
  if (v === 'HIGH') return 'high';
  if (v === 'MEDIUM') return 'med';
  if (v === 'LOW') return 'low';
  return 'ghost';
}

/**
 * Get CSS color variable for severity
 * @param {string} s - Severity string
 * @returns {string} CSS variable reference
 */
function sevColor(s) {
  const c = sevClass(s);
  return c === 'crit' ? 'var(--crit)' :
         c === 'high' ? 'var(--high)' :
         c === 'med'  ? 'var(--med)'  :
         c === 'low'  ? 'var(--low)'  : 'var(--fg-muted)';
}

/**
 * Parse numeric value safely
 * @param {*} v - Value to parse
 * @returns {number|null} Parsed number or null
 */
function toNum(v) {
  const n = parseFloat(v);
  return isNaN(n) ? null : n;
}

/**
 * Check if CVE is a CISA KEV
 * @param {Object} c - CVE object
 * @returns {boolean}
 */
function isKev(c) {
  return c.cisa_kev === 1 || c.cisa_kev === true || c.cisa_kev === '1';
}

/**
 * Check if CVE is a VulnCheck KEV
 * @param {Object} c - CVE object
 * @returns {boolean}
 */
function isVulnCheck(c) {
  return c.vulncheck_kev === 1 || c.vulncheck_kev === true || c.vulncheck_kev === '1';
}

/**
 * Check if a flag field is truthy
 * @param {Object} c - CVE object
 * @param {string} k - Field key
 * @returns {boolean}
 */
function flag(c, k) {
  return c[k] === 1 || c[k] === true || c[k] === '1';
}

/**
 * Check if CVE has any exploit code
 * @param {Object} c - CVE object
 * @returns {boolean}
 */
function hasExploit(c) {
  return flag(c, 'exploitdb') || flag(c, 'metasploit') || flag(c, 'nuclei') || flag(c, 'poc_github');
}

/**
 * Format date as relative time string
 * @param {string|number} d - Date string or timestamp
 * @returns {string} Formatted date
 */
function fmtDate(d) {
  if (!d) return '—';
  const dt = new Date(d);
  if (isNaN(dt)) return '—';
  const now = new Date();
  const days = Math.floor((now - dt) / 86400000);
  if (days < 1) return 'today';
  if (days < 2) return 'yesterday';
  if (days < 30) return days + 'd ago';
  if (days < 365) return Math.floor(days / 30) + 'mo ago';
  return dt.toISOString().slice(0, 10);
}

/**
 * Format date as absolute ISO date
 * @param {string} d - Date string
 * @returns {string} YYYY-MM-DD or —
 */
function fmtDateAbs(d) {
  if (!d) return '—';
  const dt = new Date(d);
  return isNaN(dt) ? '—' : dt.toISOString().slice(0, 10);
}

/**
 * Format date as precise timestamp for display (e.g., "Apr 18, 2026 3:42 PM")
 * @param {string|number} d - Date string or timestamp
 * @returns {string} Formatted timestamp
 */
function fmtTimestamp(d) {
  if (!d) return '—';
  const dt = new Date(d);
  if (isNaN(dt)) return '—';
  return dt.toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: 'numeric', minute: '2-digit'
  });
}

/**
 * Format EPSS score as percentage
 * @param {*} e - EPSS value (0-1)
 * @returns {string} Formatted percentage
 */
function fmtEpss(e) {
  const n = toNum(e);
  if (n === null) return '—';
  return (n * 100).toFixed(n < 0.01 ? 2 : 1) + '%';
}

/**
 * Extract vendor name from assigner email
 * @param {string} a - Assigner string
 * @returns {string} Vendor name
 */
function vendorFromAssigner(a) {
  if (!a) return '';
  if (a.includes('@')) {
    const dom = a.split('@')[1].split('.');
    const root = dom[dom.length - 2] || dom[0];
    const known = {
      microsoft: 'Microsoft', google: 'Google', apple: 'Apple', adobe: 'Adobe',
      redhat: 'Red Hat', hashicorp: 'HashiCorp', paloaltonetworks: 'Palo Alto', gitlab: 'GitLab',
      jetbrains: 'JetBrains', lenovo: 'Lenovo', emc: 'Dell', sap: 'SAP', hcl: 'HCL',
      qnapsecurity: 'QNAP', hackerone: 'via HackerOne', mitre: 'MITRE', vulncheck: 'VulnCheck',
      vuldb: 'VulDB', wordfence: 'Wordfence'
    };
    return known[root] || (root.charAt(0).toUpperCase() + root.slice(1));
  }
  return a;
}

// ───────────────── state ─────────────────
const state = {
  data: [],
  loaded: false,
  route: 'dashboard',
  sort: { kev: 'date_desc', emerging: 90, recent: 30 },
  lookup: { q: '', filter: 'all', sort: 'cvss-te_desc', results: [] }
};

// ───────────────── modules ─────────────────
const analytics = new Analytics();
const kevEnricher = new KevEnricher();
const exportManager = new ExportManager();

// ───────────────── data load ─────────────────

/**
 * Load CVE data from CSV and enrich with KEV dates
 */
async function load() {
  const startTime = Date.now();

  // Load KEV data in parallel with CSV
  const kevPromise = kevEnricher.loadKevData().then(() => {
    analytics.trackDataLoad('kev', Date.now() - startTime, true);
  }).catch(() => {
    analytics.trackDataLoad('kev', Date.now() - startTime, false);
  });

  const csvPath = CONFIG.CSV_PATH || 'cvss-te.csv';
  try {
    const r = await fetch(csvPath);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const txt = await r.text();
    const parsed = Papa.parse(txt, { header: true, dynamicTyping: true, skipEmptyLines: true });
    if (parsed.data && parsed.data.length > 0) {
      state.data = parsed.data.filter(row => row && row.cve);
      state.loaded = true;
      analytics.trackDataLoad('csv', Date.now() - startTime, true);
    }
  } catch (err) {
    console.error('Error loading CSV:', err);
    analytics.trackDataLoad('csv', Date.now() - startTime, false);
  }

  // Wait for KEV enrichment to complete
  await kevPromise;

  // Enrich data with KEV dates
  if (kevEnricher.kevMap.size > 0 && state.data.length > 0) {
    state.data = kevEnricher.enrichCves(state.data);
  }
}

// ───────────────── stats ─────────────────

/**
 * Render the statistics strip on the dashboard
 */
function renderStats() {
  const d = state.data;
  const stats = [
    { label: 'Total CVEs', value: d.length, foot: 'in dataset' },
    { label: 'Critical (TE)', value: d.filter(c => c['cvss-te_severity'] === 'CRITICAL').length, foot: 'threat-enriched', accent: true },
    { label: 'High (TE)', value: d.filter(c => c['cvss-te_severity'] === 'HIGH').length, foot: 'threat-enriched' },
    { label: 'CISA KEV', value: d.filter(isKev).length, foot: 'known exploited' },
    { label: 'Has exploit code', value: d.filter(hasExploit).length, foot: 'public PoC+' },
    { label: 'High EPSS', value: d.filter(c => (toNum(c.epss) ?? 0) >= 0.36).length, foot: '≥ 36% probability' },
  ];
  $('#stats').innerHTML = stats.map(s => `
    <div class="stat${s.accent ? ' accent' : ''}">
      <div class="stat-label">${esc(s.label)}</div>
      <div class="stat-value">${s.value.toLocaleString()}</div>
      <div class="stat-foot">${esc(s.foot)}</div>
    </div>`).join('');
  $('#meta-count').textContent = d.length.toLocaleString();

  // Track dashboard stats
  analytics.trackDashboardStats({
    total: d.length,
    cisaKevs: stats[3].value,
    critical: stats[1].value,
    high: stats[2].value,
    exploits: stats[4].value
  });
}

// ───────────────── CVE row ─────────────────

/**
 * Render a single CVE row for list display
 * @param {Object} c - CVE object
 * @returns {string} HTML string
 */
function cveRow(c) {
  const te = toNum(c['cvss-te_score']);
  const base = toNum(c.base_score);
  const sev = sevClass(c['cvss-te_severity']);
  const vendor = c.vendor_project || vendorFromAssigner(c.assigner);
  const desc = c.description || (c.base_vector ? 'CVSS vector ' + c.base_vector : '');

  const srcs = [
    [flag(c, 'exploitdb'), 'ExploitDB'],
    [flag(c, 'metasploit'), 'Metasploit'],
    [flag(c, 'nuclei'), 'Nuclei'],
    [flag(c, 'poc_github'), 'GitHub PoC'],
  ];
  const onCount = srcs.filter(s => s[0]).length;
  const srcTitle = srcs.map(([on, n]) => `${on ? '✓' : '·'} ${n}`).join('\n');

  const chips = [];
  if (isKev(c)) chips.push('<span class="chip kev">KEV</span>');
  if (isVulnCheck(c) && !isKev(c)) chips.push('<span class="chip ghost">VulnCheck</span>');
  const eps = toNum(c.epss);
  if (eps !== null && eps >= 0.7) chips.push(`<span class="chip high">EPSS ${(eps * 100).toFixed(0)}%</span>`);

  const teDiff = (te !== null && base !== null) ? (te - base) : null;
  const diffStr = teDiff !== null
    ? (teDiff > 0.05 ? `+${teDiff.toFixed(1)} vs base` : (teDiff < -0.05 ? `${teDiff.toFixed(1)} vs base` : ''))
    : '';

  return `
    <div class="cve-row${isKev(c) ? ' kev' : ''}" data-cve="${esc(c.cve)}" tabindex="0" role="button">
      <div class="cve-score">
        <div class="score-label">CVSS-TE</div>
        <div class="score-num" style="color:${sevColor(c['cvss-te_severity'])}">${te !== null ? te.toFixed(1) : '—'}</div>
      </div>
      <div class="cve-main">
        <div class="cve-id-row">
          <span class="cve-id">${esc(c.cve || '—')}</span>
          ${vendor ? `<span class="cve-vendor">${esc(vendor)}</span>` : ''}
          <span class="chip ${sev}">${esc(c['cvss-te_severity'] || '—')}</span>
          ${chips.join('')}
        </div>
        ${desc ? `<div class="cve-desc">${esc(desc)}</div>` : ''}
        <div class="cve-meta">
          <span>Base <span class="mono">${base !== null ? base.toFixed(1) : '—'}</span></span>
          <span>EPSS <span class="mono">${fmtEpss(c.epss)}</span></span>
          <span>${fmtDate(c.published_date)}</span>
          ${diffStr ? `<span style="color:${teDiff > 0 ? 'var(--crit)' : 'var(--ok)'}">${esc(diffStr)}</span>` : ''}
        </div>
      </div>
      <div class="cve-trail">
        <div class="src-pill ${onCount === 0 ? 'none' : ''}" title="${esc(srcTitle)}">
          <span class="src-icons">
            ${srcs.map(([on]) => `<span class="src-icon ${on ? 'on' : ''}"></span>`).join('')}
          </span>
          <span class="src-count">${onCount}</span>
          <span>/ ${srcs.length} src</span>
        </div>
      </div>
    </div>`;
}

/**
 * Render a list of CVE rows into a container
 * @param {HTMLElement} container - Target container
 * @param {Array} rows - Array of CVE objects
 * @param {string} emptyMsg - Message to show when empty
 */
function renderList(container, rows, emptyMsg = 'No matches') {
  if (!rows.length) {
    container.innerHTML = `<div class="empty">${esc(emptyMsg)}</div>`;
    return;
  }
  container.innerHTML = rows.map(cveRow).join('');
}

/**
 * Render skeleton loading rows
 * @param {HTMLElement} container - Target container
 * @param {number} n - Number of skeleton rows
 */
function skeletonRows(container, n = 6) {
  container.innerHTML = Array.from({ length: n }, () => `
    <div class="sk-row">
      <div class="skeleton" style="height:32px;width:50px"></div>
      <div>
        <div class="skeleton sk-line" style="width:40%"></div>
        <div class="skeleton sk-line" style="width:85%"></div>
        <div class="skeleton sk-line" style="width:60%"></div>
      </div>
      <div class="skeleton" style="height:14px;width:70px"></div>
    </div>`).join('');
}

/**
 * Sort CVE rows by given key
 * @param {Array} rows - CVE array
 * @param {string} key - Sort key
 * @returns {Array} Sorted copy
 */
function sortRows(rows, key) {
  const by = {
    'cvss-te_desc': (a, b) => (toNum(b['cvss-te_score']) ?? 0) - (toNum(a['cvss-te_score']) ?? 0),
    'cvss-te_asc': (a, b) => (toNum(a['cvss-te_score']) ?? 0) - (toNum(b['cvss-te_score']) ?? 0),
    'date_desc': (a, b) => new Date(b.cisa_kev_date_added || b.published_date || 0) - new Date(a.cisa_kev_date_added || a.published_date || 0),
    'date_asc': (a, b) => new Date(a.cisa_kev_date_added || a.published_date || 0) - new Date(b.cisa_kev_date_added || b.published_date || 0),
    'epss_desc': (a, b) => (toNum(b.epss) ?? 0) - (toNum(a.epss) ?? 0),
  };
  return [...rows].sort(by[key] || by['cvss-te_desc']);
}

// ───────────────── dashboard ─────────────────

/**
 * Render all dashboard sections
 */
function renderDashboard() {
  renderStats();

  const kevs = state.data.filter(isKev);
  const kevsSorted = sortRows(kevs, state.sort.kev).slice(0, 10);
  $('#count-kev').textContent = kevs.length.toLocaleString();
  renderList($('#list-kev'), kevsSorted, 'No CISA KEV entries found.');
  analytics.trackDashboardSection('cisa_kevs', 'view', { count: kevs.length });

  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - state.sort.emerging);
  const emerging = state.data.filter(c => {
    if (!c.published_date) return false;
    if (new Date(c.published_date) < cutoff) return false;
    const eps = toNum(c.epss) ?? 0;
    return eps >= 0.3 || hasExploit(c) || isKev(c) || isVulnCheck(c);
  });
  const emergingSorted = sortRows(emerging, 'cvss-te_desc').slice(0, 10);
  $('#count-emerging').textContent = emerging.length.toLocaleString();
  renderList($('#list-emerging'), emergingSorted, 'No emerging threats in window.');
  analytics.trackDashboardSection('emerging_threats', 'view', { count: emerging.length, days_filter: state.sort.emerging });

  const rCut = new Date();
  rCut.setDate(rCut.getDate() - state.sort.recent);
  const recent = state.data.filter(c => c.published_date && new Date(c.published_date) >= rCut);
  const recentSorted = sortRows(recent, 'date_desc').slice(0, 20);
  $('#count-recent').textContent = recent.length.toLocaleString();
  renderList($('#list-recent'), recentSorted, 'No CVEs published in window.');
  analytics.trackDashboardSection('recent_cves', 'view', { count: recent.length, days_filter: state.sort.recent });
}

// ───────────────── lookup ─────────────────

/**
 * Check if CVE matches current filter
 * @param {Object} c - CVE object
 * @param {string} f - Filter key
 * @returns {boolean}
 */
function matchesFilter(c, f) {
  switch (f) {
    case 'all': return true;
    case 'crit': return c['cvss-te_severity'] === 'CRITICAL';
    case 'high': return c['cvss-te_severity'] === 'HIGH';
    case 'med': return c['cvss-te_severity'] === 'MEDIUM';
    case 'low': return c['cvss-te_severity'] === 'LOW';
    case 'kev': return isKev(c);
    case 'exploited': return hasExploit(c);
    case 'epss': return (toNum(c.epss) ?? 0) >= 0.3;
    default: return true;
  }
}

/**
 * Render lookup results based on current search/filter/sort state
 */
function renderLookup() {
  const { q, filter, sort } = state.lookup;
  const qlc = q.trim().toLowerCase();
  const rows = state.data.filter(c => {
    if (!matchesFilter(c, filter)) return false;
    if (!qlc) return true;
    const hay = [c.cve, c.description, c.vendor_project, c.assigner, c.base_vector].filter(Boolean).join(' ').toLowerCase();
    return hay.includes(qlc);
  });
  const sorted = sortRows(rows, sort).slice(0, 500);

  // Store for export
  state.lookup.results = sorted;

  $('#result-count').textContent = rows.length.toLocaleString();
  renderList($('#list-lookup'), sorted, q ? `No CVEs match "${q}".` : 'No CVEs match filters.');
}

// ───────────────── modal ─────────────────

/**
 * Open CVE detail modal
 * @param {string} cve - CVE ID
 */
function openDetail(cve) {
  const c = state.data.find(x => x.cve === cve);
  if (!c) return;

  // Track CVE view
  analytics.trackCVEView(cve, c['cvss-te_severity']);

  const te = toNum(c['cvss-te_score']);
  const bt = toNum(c['cvss-bt_score']);
  const base = toNum(c.base_score);
  const teSev = sevClass(c['cvss-te_severity']);
  const vendor = c.vendor_project || vendorFromAssigner(c.assigner);
  const deltaBT = (te !== null && bt !== null) ? (te - bt) : null;
  const deltaBase = (te !== null && base !== null) ? (te - base) : null;

  const srcs = [
    ['ExploitDB', flag(c, 'exploitdb')],
    ['Metasploit', flag(c, 'metasploit')],
    ['Nuclei', flag(c, 'nuclei')],
    ['GitHub PoC', flag(c, 'poc_github')],
    ['CISA KEV', isKev(c)],
    ['VulnCheck', isVulnCheck(c)],
  ];

  const quality = [
    ['Reliability', toNum(c.reliability)],
    ['Ease of use', toNum(c.ease_of_use)],
    ['Effectiveness', toNum(c.effectiveness)],
    ['Quality score', toNum(c.quality_score)],
  ];

  const root = $('#modal-root');
  root.innerHTML = `
    <div class="modal-backdrop" id="mbd">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="mtitle">
        <div class="modal-head">
          <div>
            <div class="modal-title-row">
              <h3 class="modal-title" id="mtitle">${esc(c.cve || '—')}</h3>
              ${vendor ? `<span class="chip ghost">${esc(vendor)}</span>` : ''}
              <span class="chip ${teSev}">${esc(c['cvss-te_severity'] || '—')}</span>
              ${isKev(c) ? '<span class="chip kev">CISA KEV</span>' : ''}
              ${isVulnCheck(c) ? '<span class="chip ghost">VulnCheck KEV</span>' : ''}
            </div>
            <div class="modal-vendor-line">
              ${vendor ? `<span class="vendor-name">${esc(vendor)}</span> ·` : ''}
              assigned by <span class="mono">${esc(c.assigner || '—')}</span>
            </div>
          </div>
          <button class="modal-close" id="mclose" aria-label="Close">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
          </button>
        </div>

        <div class="modal-body">
          ${c.description ? `<div class="modal-section"><h4>Description</h4><div style="font-size:13.5px;line-height:1.65">${esc(c.description)}</div></div>` : ''}

          <div class="modal-section">
            <h4>Score evolution</h4>
            <div class="score-grid">
              <div class="score-cell">
                <div class="score-kind">Base · v${esc(c.cvss_version || '?')}</div>
                <div class="score-big" style="color:${sevColor(c.base_severity)}">${base !== null ? base.toFixed(1) : '—'}</div>
                <div class="score-sev">${esc(c.base_severity || '—')}</div>
              </div>
              <div class="score-cell">
                <div class="score-kind">CVSS-BT · threat</div>
                <div class="score-big" style="color:${sevColor(c['cvss-bt_severity'])}">${bt !== null ? bt.toFixed(1) : '—'}</div>
                <div class="score-sev">${esc(c['cvss-bt_severity'] || '—')}</div>
                ${deltaBT !== null && Math.abs(deltaBT) > 0.05 ? `<div class="score-delta ${deltaBT > 0 ? 'up' : 'down'}">vs base ${deltaBT > 0 ? '+' : ''}${deltaBT.toFixed(1)}</div>` : ''}
              </div>
              <div class="score-cell te">
                <div class="score-kind">CVSS-TE · enriched</div>
                <div class="score-big" style="color:${sevColor(c['cvss-te_severity'])}">${te !== null ? te.toFixed(1) : '—'}</div>
                <div class="score-sev">${esc(c['cvss-te_severity'] || '—')}</div>
                ${deltaBase !== null && Math.abs(deltaBase) > 0.05 ? `<div class="score-delta ${deltaBase > 0 ? 'up' : 'down'}">vs base ${deltaBase > 0 ? '+' : ''}${deltaBase.toFixed(1)}</div>` : ''}
              </div>
            </div>
          </div>

          <div class="modal-section">
            <h4>Exploit sources</h4>
            <div class="src-grid">
              ${srcs.map(([name, on]) => `
                <div class="src-card ${on ? 'on' : ''}">
                  <div class="src-name">${esc(name)}</div>
                  <div class="src-state">${on ? 'Present' : '—'}</div>
                </div>`).join('')}
            </div>
          </div>

          ${quality.some(q => q[1] !== null && q[1] > 0) ? `
          <div class="modal-section">
            <h4>Exploit quality</h4>
            <div class="quality-bars">
              ${quality.map(([label, val]) => `
                <div class="quality-bar">
                  <div class="label">${esc(label)}</div>
                  <div class="track"><div class="fill" style="width:${Math.min(100, (val || 0) * 100)}%"></div></div>
                  <div class="val">${val !== null ? val.toFixed(2) : '—'}</div>
                </div>`).join('')}
            </div>
          </div>` : ''}

          <div class="modal-section">
            <h4>Metadata</h4>
            <dl class="kv">
              <dt>Published</dt><dd>${esc(fmtDateAbs(c.published_date))}</dd>
              <dt>Last modified</dt><dd>${esc(fmtDateAbs(c.last_modified_date))}</dd>
              ${c.cisa_kev_date_added ? `<dt>KEV added</dt><dd>${esc(fmtDateAbs(c.cisa_kev_date_added))}</dd>` : ''}
              ${c.kev_due_date ? `<dt>KEV due date</dt><dd>${esc(fmtDateAbs(c.kev_due_date))}</dd>` : ''}
              ${c.kev_ransomware && c.kev_ransomware !== 'Unknown' ? `<dt>Ransomware use</dt><dd>${esc(c.kev_ransomware)}</dd>` : ''}
              <dt>EPSS</dt><dd>${esc(fmtEpss(c.epss))}${toNum(c.epss) !== null ? ` <span style="color:var(--fg-subtle)">(${toNum(c.epss).toFixed(5)})</span>` : ''}</dd>
              <dt>Exploit maturity</dt><dd class="mono">${esc(c.exploit_maturity || '—')}</dd>
              <dt>Exploit sources</dt><dd>${esc((c.exploit_sources ?? 0) + '')}</dd>
              <dt>Assigner</dt><dd>${esc(c.assigner || '—')}</dd>
            </dl>
          </div>

          ${c.base_vector ? `
          <div class="modal-section">
            <h4>Base vector</h4>
            <div class="vector">${esc(c.base_vector)}</div>
          </div>` : ''}

          ${c['cvss-bt_vector'] || c['cvss-te_vector'] ? `
          <div class="modal-section">
            <h4>Threat-enriched vector</h4>
            <div class="vector">${esc(c['cvss-te_vector'] || c['cvss-bt_vector'])}</div>
          </div>` : ''}

          <div class="modal-section">
            <h4>External references</h4>
            <div class="tag-row">
              <a class="btn" target="_blank" rel="noopener" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve)}">NVD ↗</a>
              <a class="btn" target="_blank" rel="noopener" href="https://www.cve.org/CVERecord?id=${encodeURIComponent(c.cve)}">CVE.org ↗</a>
              <a class="btn" target="_blank" rel="noopener" href="https://github.com/search?q=${encodeURIComponent(c.cve)}&type=repositories">GitHub ↗</a>
              ${isKev(c) ? `<a class="btn" target="_blank" rel="noopener" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV ↗</a>` : ''}
            </div>
          </div>
        </div>
      </div>
    </div>`;

  const close = () => {
    root.innerHTML = '';
    document.body.style.overflow = '';
    document.removeEventListener('keydown', onKey);
    analytics.trackModal('cve_detail', 'close');
  };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.body.style.overflow = 'hidden';
  document.addEventListener('keydown', onKey);
  $('#mbd', root).addEventListener('click', e => { if (e.target === e.currentTarget) close(); });
  $('#mclose', root).addEventListener('click', close);

  // Track external link clicks in modal
  $$('.tag-row a', root).forEach(link => {
    link.addEventListener('click', () => {
      analytics.trackExternalLink(link.href, 'cve_detail_modal');
    });
  });
}

// ───────────────── routing + events ─────────────────

/**
 * Navigate to a route
 * @param {string} route - Route name (dashboard, lookup, about)
 */
function go(route) {
  const prev = state.route;
  state.route = route;
  $$('.navtab').forEach(t => t.classList.toggle('active', t.dataset.route === route));
  $('#view-dashboard').classList.toggle('hidden', route !== 'dashboard');
  $('#view-lookup').classList.toggle('hidden', route !== 'lookup');
  $('#view-about').classList.toggle('hidden', route !== 'about');

  if (route === 'dashboard') renderDashboard();
  if (route === 'lookup') renderLookup();

  const h = '#/' + route;
  if (location.hash !== h) history.replaceState(null, '', h);
  try { localStorage.setItem('cvsste.route', route); } catch (_) { /* noop */ }
  window.scrollTo({ top: 0, behavior: 'instant' });

  // Track navigation
  analytics.trackPageView(route);
  if (prev !== route) {
    analytics.trackNavigation(prev, route, 'navtab');
  }
}

/**
 * Set theme and persist
 * @param {string} t - Theme name (dark or light)
 */
function setTheme(t) {
  document.body.setAttribute('data-theme', t);
  try { localStorage.setItem('cvsste.theme', t); } catch (_) { /* noop */ }
}

/**
 * Initialize navigation and all event listeners
 */
function initNav() {
  // Nav tabs
  $$('.navtab').forEach(t => t.addEventListener('click', () => go(t.dataset.route)));

  // KEV sort controls
  $$('.seg[data-seg="kev"] button').forEach(b => b.addEventListener('click', () => {
    $$('.seg[data-seg="kev"] button').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    state.sort.kev = b.dataset.sort;
    renderDashboard();
    analytics.trackDashboardControl('cisa_kevs', 'sort', b.dataset.sort);
  }));

  // Emerging threats window controls
  $$('.seg[data-seg="emerging"] button').forEach(b => b.addEventListener('click', () => {
    $$('.seg[data-seg="emerging"] button').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    state.sort.emerging = parseInt(b.dataset.days, 10);
    renderDashboard();
    analytics.trackDashboardControl('emerging_threats', 'filter', b.dataset.days);
  }));

  // Recent CVEs window controls
  $$('.seg[data-seg="recent"] button').forEach(b => b.addEventListener('click', () => {
    $$('.seg[data-seg="recent"] button').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    state.sort.recent = parseInt(b.dataset.days, 10);
    renderDashboard();
    analytics.trackDashboardControl('recent_cves', 'filter', b.dataset.days);
  }));

  // Theme toggle
  $('#theme-toggle').addEventListener('click', () => {
    const next = document.body.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    setTheme(next);
  });

  // ── Lookup events ──

  const input = $('#search-input');
  let deb;
  input.addEventListener('input', () => {
    clearTimeout(deb);
    deb = setTimeout(() => {
      state.lookup.q = input.value;
      renderLookup();
      if (input.value.trim()) {
        analytics.trackSearch(input.value.trim(), state.lookup.results.length);
      }
    }, 120);
  });

  // Clear button
  $('#btn-clear').addEventListener('click', () => {
    input.value = '';
    state.lookup.q = '';
    $$('#filterbar .filter-pill').forEach(p => p.classList.toggle('active', p.dataset.filter === 'all'));
    state.lookup.filter = 'all';
    renderLookup();
  });

  // Export button
  $('#btn-export').addEventListener('click', () => {
    if (state.lookup.results.length === 0) {
      return;
    }
    try {
      exportManager.exportToCSV(state.lookup.results);
      analytics.trackExport(state.lookup.results.length);
    } catch (err) {
      console.error('Export error:', err);
    }
  });

  // Filter pills
  $$('#filterbar .filter-pill').forEach(p => p.addEventListener('click', () => {
    $$('#filterbar .filter-pill').forEach(x => x.classList.remove('active'));
    p.classList.add('active');
    state.lookup.filter = p.dataset.filter;
    renderLookup();
    analytics.trackFilterChange('severity', p.dataset.filter);
  }));

  // Sort select
  $('#sort-select').addEventListener('change', e => {
    state.lookup.sort = e.target.value;
    renderLookup();
    analytics.trackSortChange(e.target.value);
  });

  // Slash to focus search
  document.addEventListener('keydown', e => {
    if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
      e.preventDefault();
      if (state.route !== 'lookup') go('lookup');
      setTimeout(() => $('#search-input').focus(), 50);
    }
  });

  // ── Delegated row clicks ──

  document.addEventListener('click', e => {
    const row = e.target.closest('.cve-row');
    if (row && row.dataset.cve) {
      analytics.trackCVECardClick(row.dataset.cve, state.route, '');
      openDetail(row.dataset.cve);
      return;
    }
  });

  // Keyboard activation for CVE rows
  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') {
      const row = e.target.closest && e.target.closest('.cve-row');
      if (row && row.dataset.cve) {
        e.preventDefault();
        openDetail(row.dataset.cve);
      }
    }
  });

  // Hash routing
  const handleHash = () => {
    const m = (location.hash || '').match(/^#\/(dashboard|lookup|about)/);
    if (m) go(m[1]);
  };
  window.addEventListener('hashchange', handleHash);
  handleHash();

  // Track external links in methodology page
  $$('#view-about a[target="_blank"]').forEach(link => {
    link.addEventListener('click', () => {
      analytics.trackExternalLink(link.href, 'methodology_page');
    });
  });
}

// ───────────────── boot ─────────────────

/**
 * Boot the application
 */
async function boot() {
  // Show skeleton loading
  ['list-kev', 'list-emerging', 'list-recent'].forEach(id => {
    const el = document.getElementById(id);
    if (el) skeletonRows(el);
  });
  $('#meta-updated').textContent = 'loading…';

  // Track page view
  analytics.trackPageView('initial_load', { referrer: document.referrer || 'direct' });

  // Load data
  await load();

  // Update last run time with precise timestamp
  $('#meta-updated').textContent = fmtTimestamp(Date.now());
  const lastRunPath = CONFIG.LAST_RUN_PATH || 'code/last_run.txt';
  try {
    const r = await fetch(lastRunPath);
    if (r.ok) {
      const t = (await r.text()).trim();
      if (t) $('#meta-updated').textContent = fmtTimestamp(t);
    }
  } catch (_) { /* noop */ }

  // Determine initial route
  const params = new URLSearchParams(location.search);
  const cveParam = params.get('cve');
  const stored = (() => { try { return localStorage.getItem('cvsste.route'); } catch (_) { return null; } })();
  const hashRoute = (location.hash || '').match(/^#\/(dashboard|lookup|about)/);
  const initial = hashRoute ? hashRoute[1] : (cveParam ? 'lookup' : (stored || 'dashboard'));

  // Initialize navigation and render
  initNav();
  go(initial);

  // Handle ?cve= parameter
  if (cveParam) {
    const exists = state.data.some(c => c.cve === cveParam);
    if (exists) {
      $('#search-input').value = cveParam;
      state.lookup.q = cveParam;
      renderLookup();
      openDetail(cveParam);
      analytics.trackQuickSearch(cveParam, 'url_parameter');
    }
  }
}

boot();
