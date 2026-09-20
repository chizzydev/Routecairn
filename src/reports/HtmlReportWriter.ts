import { mkdir } from "node:fs/promises";
import { basename, join, relative, sep } from "node:path";
import { durableAtomicWrite } from "../core/offensive/MutationJournal.js";
import type { Finding } from "../core/findings/Finding.js";
import type { RouteCairnReport, VulnerabilityWorkflow } from "./ReportTypes.js";
import { loadTriageState, triageFileName } from "../triage/TriageStore.js";
import type { TriageState, TriageStatus } from "../triage/TriageTypes.js";

interface DashboardFinding {
  id: string;
  title: string;
  type: string;
  severity: string;
  confidence: string;
  riskScore: number;
  url: string;
  sourceModule: string;
  falsePositiveStatus: string;
  needsManualVerification: boolean;
  evidenceSource: string;
  curlCommand: string;
  severityReason: string;
  statusCode: number | string;
  contentLength: number | string;
  contentType: string;
  bodyPreview: string;
  tags: string[];
  recommendation: string;
  impact: string;
  manualTestingSuggestions: string[];
  triageStatus: TriageStatus | "unreviewed";
  triageNote: string;
  triageUpdatedAt: string;
  triageUpdatedBy: string;
}

interface DashboardData {
  target: string;
  program: string;
  mode: string;
  profile?: RouteCairnReport["profile"];
  generatedAt: string;
  metadata: RouteCairnReport["metadata"];
  requestBudget?: RouteCairnReport["requestBudget"];
  transport?: RouteCairnReport["transport"];
  technologies: RouteCairnReport["technologies"];
  severityCounts: Record<string, number>;
  findingTypeCounts: Record<string, number>;
  findings: DashboardFinding[];
  workflows: VulnerabilityWorkflow[];
  apiEndpoints: NonNullable<RouteCairnReport["apiMapper"]>["endpoints"];
  apiProbe: RouteCairnReport["apiProbe"];
  authSurfaces: NonNullable<RouteCairnReport["authSurface"]>["surfaces"];
  authenticatedScan: RouteCairnReport["authenticatedScan"];
  roleComparison: RouteCairnReport["roleComparison"];
  stateAwareApi: RouteCairnReport["stateAwareApi"];
  parameterAnalysis: RouteCairnReport["parameterAnalysis"];
  workflowValidation: RouteCairnReport["workflowValidation"];
  nextJsReview: RouteCairnReport["nextJsReview"];
  proofMode: RouteCairnReport["proofMode"];
  supabaseAuthorization: RouteCairnReport["supabaseAuthorization"];
  authenticationLifecycle: RouteCairnReport["authenticationLifecycle"];
  businessInvariant: RouteCairnReport["businessInvariant"];
  controlledRace: RouteCairnReport["controlledRace"];
  apiGraphql: RouteCairnReport["apiGraphql"];
  protocolSecurity: RouteCairnReport["protocolSecurity"];
  linkPortalSecurity: RouteCairnReport["linkPortalSecurity"];
  operationalEndpointSecurity: RouteCairnReport["operationalEndpointSecurity"];
  billingEntitlement: RouteCairnReport["billingEntitlement"];
  secretBoundary: RouteCairnReport["secretBoundary"];
  activeVulnerability: RouteCairnReport["activeVulnerability"];
  assistedReview: RouteCairnReport["assistedReview"];
  js: {
    scripts: number;
    queuedEndpoints: number;
    sourceMaps: number;
    configValues: number;
  };
  browser: {
    screenshotPath?: string;
    screenshotRelativePath?: string;
    renderedLinks: number;
    networkRequests: number;
    consoleErrors: number;
    formsDetected: number;
    formsSubmitted: number;
  };
  discovered: {
    total: number;
    likelyValid: number;
    maybeFalsePositive: number;
    likelyFalsePositive: number;
  };
  triageSummary: Record<string, number>;
}

export class HtmlReportWriter {
  public async write(outputDir: string, report: RouteCairnReport): Promise<string> {
    await mkdir(outputDir, { recursive: true });
    const reportPath = `${outputDir}${sep}report.html`;
    const triage = await loadTriageState(join(outputDir, triageFileName), report);
    await durableAtomicWrite(reportPath, renderHtml(outputDir, report, triage));
    return reportPath;
  }
}

function renderHtml(outputDir: string, report: RouteCairnReport, triage: TriageState): string {
  const data = dashboardData(outputDir, report, triage);
  const json = safeJson(data);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>RouteCairn Report - ${escapeHtml(report.target)}</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #101316;
      --panel: #171b20;
      --panel-2: #1d232a;
      --text: #e9edf1;
      --muted: #9aa6b2;
      --line: #2d3640;
      --accent: #f0b429;
      --accent-2: #5cc8ff;
      --green: #43d17a;
      --blue: #7aa7ff;
      --red: #ff7070;
      --orange: #ffb45c;
      --shadow: 0 20px 60px rgba(0,0,0,.25);
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Arial, sans-serif;
    }
    a { color: inherit; }
    .layout { min-height: 100vh; display: grid; grid-template-columns: 280px minmax(0, 1fr); }
    .sidebar {
      position: sticky; top: 0; height: 100vh; padding: 22px 18px; border-right: 1px solid var(--line);
      background: #0d1013; overflow: auto;
    }
    .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 26px; }
    .mark { width: 34px; height: 34px; border: 1px solid #5b6672; display: grid; place-items: center; color: var(--accent); font-weight: 800; }
    .brand h1 { font-size: 18px; margin: 0; letter-spacing: 0; }
    .brand p { margin: 0; color: var(--muted); font-size: 12px; }
    .nav { display: grid; gap: 6px; }
    .nav button {
      width: 100%; border: 1px solid transparent; background: transparent; color: var(--muted); text-align: left;
      padding: 9px 10px; cursor: pointer; border-radius: 6px; font: inherit;
    }
    .nav button.active, .nav button:hover { background: var(--panel); color: var(--text); border-color: var(--line); }
    .side-meta { margin-top: 22px; padding-top: 18px; border-top: 1px solid var(--line); color: var(--muted); display: grid; gap: 8px; font-size: 12px; }
    .content { min-width: 0; }
    .topbar { padding: 22px 30px; border-bottom: 1px solid var(--line); background: rgba(16,19,22,.9); position: sticky; top: 0; z-index: 10; backdrop-filter: blur(10px); }
    .target { display: flex; justify-content: space-between; gap: 18px; align-items: flex-start; }
    .target h2 { margin: 0 0 6px; font-size: 24px; letter-spacing: 0; overflow-wrap: anywhere; }
    .target p { margin: 0; color: var(--muted); }
    .status-pill { display: inline-flex; align-items: center; gap: 8px; border: 1px solid var(--line); padding: 7px 10px; border-radius: 6px; color: var(--muted); white-space: nowrap; }
    .dot { width: 8px; height: 8px; border-radius: 999px; background: var(--green); }
    .main { padding: 28px 30px 48px; max-width: 1480px; }
    .section { display: none; }
    .section.active { display: block; }
    .grid { display: grid; gap: 14px; }
    .stats { grid-template-columns: repeat(6, minmax(0, 1fr)); }
    .card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); }
    .stat { padding: 16px; min-height: 94px; }
    .stat span { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    .stat strong { display: block; font-size: 28px; margin-top: 8px; }
    .band { padding: 18px; }
    .two { grid-template-columns: minmax(0, 1.2fr) minmax(320px, .8fr); align-items: start; }
    .three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .section-title { display: flex; justify-content: space-between; gap: 12px; align-items: end; margin: 0 0 14px; }
    .section-title h3 { margin: 0; font-size: 19px; }
    .section-title p { margin: 4px 0 0; color: var(--muted); }
    .controls { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
    .control, .search {
      border: 1px solid var(--line); background: var(--panel); color: var(--text); border-radius: 6px; padding: 9px 10px; font: inherit;
    }
    .search { min-width: 280px; flex: 1; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; background: var(--panel-2); position: sticky; top: 82px; z-index: 2; }
    td.url { overflow-wrap: anywhere; max-width: 420px; }
    .badge { display: inline-flex; align-items: center; border: 1px solid var(--line); border-radius: 999px; padding: 2px 8px; font-size: 12px; color: var(--muted); white-space: nowrap; }
    .sev-Critical, .sev-High { color: #ffd8d8; border-color: rgba(255,112,112,.55); background: rgba(255,112,112,.12); }
    .sev-Medium { color: #ffe8c7; border-color: rgba(255,180,92,.55); background: rgba(255,180,92,.12); }
    .sev-Low { color: #d9e8ff; border-color: rgba(122,167,255,.45); background: rgba(122,167,255,.11); }
    .sev-Informational { color: #d3f4ff; border-color: rgba(92,200,255,.45); background: rgba(92,200,255,.10); }
    .verify { color: #fff3c7; border-color: rgba(240,180,41,.55); background: rgba(240,180,41,.12); }
    .drawer { margin-top: 8px; padding: 12px; background: #11161b; border: 1px solid var(--line); border-radius: 6px; display: none; }
    .drawer.open { display: block; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }
    .btn { border: 1px solid var(--line); background: var(--panel-2); color: var(--text); border-radius: 6px; padding: 7px 9px; cursor: pointer; }
    .btn:hover { border-color: #52616f; }
    .workflow { padding: 16px; display: grid; gap: 10px; }
    .workflow h4 { margin: 0; font-size: 16px; }
    .workflow ul { margin: 6px 0 0; padding-left: 18px; color: var(--muted); }
    .split-list { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    .screenshot { width: 100%; border: 1px solid var(--line); border-radius: 8px; background: #080a0c; max-height: 560px; object-fit: contain; }
    .empty { color: var(--muted); padding: 16px; border: 1px dashed var(--line); border-radius: 8px; }
    .bar { height: 8px; background: #0d1013; border-radius: 999px; overflow: hidden; border: 1px solid var(--line); }
    .bar i { display: block; height: 100%; background: var(--accent); }
    @media (max-width: 1100px) {
      .layout { grid-template-columns: 1fr; }
      .sidebar { position: static; height: auto; border-right: 0; border-bottom: 1px solid var(--line); }
      .nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .stats, .two, .three, .split-list { grid-template-columns: 1fr; }
      .topbar { position: static; }
      th { position: static; }
      .target { display: block; }
      .status-pill { margin-top: 12px; }
    }
  </style>
</head>
<body>
  ${report.execution?.partial ? '<div role="alert">PARTIAL REPORT — execution did not complete. Missing coverage is not a security pass.</div>' : ""}
  ${report.execution && report.execution.cleanup.state !== "CLEAR" ? '<div role="alert">CLEANUP UNRESOLVED — inspect recovery before reusing disposable state.</div>' : ""}
  <div class="layout">
    <aside class="sidebar">
      <div class="brand"><div class="mark">RC</div><div><h1>RouteCairn</h1><p>Attack surface intelligence</p></div></div>
      <div class="nav" id="nav"></div>
      <div class="side-meta">
        <div><strong>Mode</strong><br><span id="sideMode"></span></div>
        <div><strong>Profile</strong><br><span id="sideProfile"></span></div>
        <div><strong>Generated</strong><br><span id="sideGenerated"></span></div>
        <div><strong>Program</strong><br><span id="sideProgram"></span></div>
      </div>
    </aside>
    <div class="content">
      <header class="topbar">
        <div class="target">
          <div><h2 id="targetTitle"></h2><p id="targetMeta"></p></div>
          <div class="status-pill"><span class="dot"></span><span>Report ready</span></div>
        </div>
      </header>
      <main class="main">
        <section class="section active" data-section="overview"></section>
        <section class="section" data-section="findings"></section>
        <section class="section" data-section="workflows"></section>
        <section class="section" data-section="manual"></section>
        <section class="section" data-section="proof"></section>
        <section class="section" data-section="browser"></section>
        <section class="section" data-section="intelligence"></section>
      </main>
    </div>
  </div>
  <script id="routecairn-data" type="application/json">${json}</script>
  <script>
    const data = JSON.parse(document.getElementById('routecairn-data').textContent);
    const sections = [
      ['overview', 'Overview'], ['findings', 'Findings'], ['workflows', 'Workflows'], ['manual', 'Manual Test Pack'], ['proof', 'Proof Blocks'], ['browser', 'Browser'], ['intelligence', 'Intelligence']
    ];
    const state = { severity: 'all', type: 'all', verification: 'all', triage: 'all', q: '' };
    const nav = document.getElementById('nav');
    nav.innerHTML = sections.map(([id,label], i) => '<button class="' + (i === 0 ? 'active' : '') + '" data-nav="' + id + '">' + label + '</button>').join('');
    nav.addEventListener('click', (event) => {
      const button = event.target.closest('button[data-nav]');
      if (!button) return;
      document.querySelectorAll('[data-nav]').forEach((item) => item.classList.toggle('active', item === button));
      document.querySelectorAll('.section').forEach((item) => item.classList.toggle('active', item.dataset.section === button.dataset.nav));
    });
    document.getElementById('targetTitle').textContent = data.target;
    document.getElementById('targetMeta').textContent = data.program + ' • ' + data.metadata.totalRequests + ' requests • ' + data.discovered.total + ' URLs checked';
    document.getElementById('sideMode').textContent = data.mode;
    document.getElementById('sideProfile').textContent = data.profile ? data.profile.displayName : 'Mode only';
    document.getElementById('sideGenerated').textContent = data.generatedAt;
    document.getElementById('sideProgram').textContent = data.program;

    const bySection = (name) => document.querySelector('[data-section="' + name + '"]');
    const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
    const badge = (text, cls = '') => '<span class="badge ' + cls + '">' + esc(text) + '</span>';
    const list = (items) => items && items.length ? '<ul>' + items.map((item) => '<li>' + esc(item) + '</li>').join('') + '</ul>' : '<span class="muted">none</span>';
    const sectionTitle = (title, sub) => '<div class="section-title"><div><h3>' + esc(title) + '</h3><p>' + esc(sub) + '</p></div></div>';

    function renderOverview() {
      const sev = data.severityCounts;
      bySection('overview').innerHTML = sectionTitle('Scan Overview', 'A compact view of scan volume, severity, and high-signal intelligence.') +
      '<div class="grid stats">' +
        stat('Profile', data.profile ? data.profile.name : data.mode) + stat('Requests', data.requestBudget ? (data.requestBudget.totalTransmitted + '/' + data.requestBudget.maxRequests) : data.metadata.totalRequests) + stat('Connections', data.transport ? data.transport.connectionsCreated : 'n/a') + stat('Pool reuse', data.transport ? data.transport.estimatedConnectionReuses : 'n/a') + stat('HTTP/2', data.transport ? data.transport.http2Connections : 'n/a') + stat('Cleanup reserve', data.requestBudget ? data.requestBudget.cleanupRemaining + '/' + data.requestBudget.cleanupReservedRequests : 'n/a') + stat('Findings', data.findings.length) + stat('Triaged', data.findings.filter(f => f.triageStatus !== 'unreviewed').length) + stat('Confirmed', data.triageSummary.confirmed || 0) + stat('Critical/High', (sev.Critical || 0) + (sev.High || 0)) + stat('Medium', sev.Medium || 0) +
        stat('Proof Blocks', data.proofMode?.blocks?.length || 0) + stat('Workflows', data.workflows.length) + stat('API Endpoints', data.apiEndpoints.length) + stat('API Probe', data.apiProbe?.endpointsReviewed?.length || 0) + stat('Auth-only', data.authenticatedScan?.authOnlySurfaces?.length || 0) + stat('A/B Diffs', (data.roleComparison?.accountAOnly?.length || 0) + (data.roleComparison?.accountBOnly?.length || 0)) + stat('API Reviews', data.stateAwareApi?.reviewedEndpoints?.length || 0) + stat('Params', data.parameterAnalysis?.totalParameters || 0) + stat('Templates', data.workflowValidation?.templates?.length || 0) + stat('Next Data', data.nextJsReview?.dataRoutes?.length || 0) +
      '</div>' +
      '<div class="grid two" style="margin-top:14px">' +
        '<div class="card band"><h3>Technologies</h3>' + (data.technologies.length ? data.technologies.map((t) => badge(t.name + ' • ' + t.confidence)).join(' ') : '<p class="empty">No technologies detected.</p>') + '</div>' +
        '<div class="card band"><h3>URL Classification</h3>' + progress('Likely valid', data.discovered.likelyValid, data.discovered.total) + progress('Maybe false positive', data.discovered.maybeFalsePositive, data.discovered.total) + progress('Likely false positive', data.discovered.likelyFalsePositive, data.discovered.total) + '</div>' +
      '</div>' +
      '<div class="grid three" style="margin-top:14px">' +
        '<div class="card band"><h3>Profile</h3><p>' + (data.profile ? esc(data.profile.description) + ' Focus: ' + esc(data.profile.reportFocus.join(', ')) : 'Legacy mode run without a named profile.') + '</p></div>' +
        '<div class="card band"><h3>JavaScript</h3><p>' + data.js.scripts + ' scripts, ' + data.js.queuedEndpoints + ' queued endpoints, ' + data.js.sourceMaps + ' source maps.</p></div>' +
        '<div class="card band"><h3>Browser</h3><p>' + data.browser.renderedLinks + ' rendered links, ' + data.browser.networkRequests + ' network requests, ' + data.browser.consoleErrors + ' console errors.</p></div>' +
        '<div class="card band"><h3>Auth Compare</h3><p>' + (data.authenticatedScan?.profile?.enabled ? (data.authenticatedScan.comparedUrls + ' URLs compared, ' + data.authenticatedScan.changedSurfaces.length + ' changed surfaces.') : 'No auth profile supplied.') + '</p></div>' +
      '</div>';
    }
    function stat(label, value) { return '<div class="card stat"><span>' + esc(label) + '</span><strong>' + esc(value) + '</strong></div>'; }
    function progress(label, value, total) { const pct = total ? Math.round((value / total) * 100) : 0; return '<p>' + esc(label) + ' <strong>' + value + '</strong></p><div class="bar"><i style="width:' + pct + '%"></i></div>'; }

    function filteredFindings() {
      return data.findings.filter((f) =>
        (state.severity === 'all' || f.severity === state.severity) &&
        (state.type === 'all' || f.type === state.type) &&
        (state.verification === 'all' || String(f.needsManualVerification) === state.verification) &&
        (state.triage === 'all' || f.triageStatus === state.triage) &&
        (!state.q || (f.title + ' ' + f.url + ' ' + f.type + ' ' + f.sourceModule + ' ' + f.triageStatus).toLowerCase().includes(state.q.toLowerCase()))
      );
    }
    function renderFindings() {
      const severities = ['all', ...new Set(data.findings.map(f => f.severity))];
      const types = ['all', ...new Set(data.findings.map(f => f.type))];
      bySection('findings').innerHTML = sectionTitle('Findings', 'Filter, group, and expand findings without digging through raw JSON.') +
      '<div class="controls"><input class="search" id="q" placeholder="Search title, URL, type, or source" value="' + esc(state.q) + '">' +
      select('severity', severities, state.severity) + select('type', types, state.type) +
      '<select id="verification" class="control"><option value="all">All verification labels</option><option value="true">Needs manual verification</option><option value="false">More directly evidenced</option></select>' +
      '<select id="triage" class="control"><option value="all">All triage statuses</option><option value="unreviewed">Unreviewed</option><option value="reviewed">Reviewed</option><option value="false-positive">False positive</option><option value="confirmed">Confirmed</option><option value="needs-retest">Needs retest</option></select></div>' +
      '<div class="card"><table><thead><tr><th>Finding</th><th>Severity</th><th>Triage</th><th>Risk</th><th>URL</th><th>Source</th><th></th></tr></thead><tbody id="findingRows"></tbody></table></div>';
      document.getElementById('verification').value = state.verification;
      document.getElementById('triage').value = state.triage;
      document.getElementById('q').addEventListener('input', (e) => { state.q = e.target.value; renderFindingRows(); });
      document.getElementById('severity').addEventListener('change', (e) => { state.severity = e.target.value; renderFindingRows(); });
      document.getElementById('type').addEventListener('change', (e) => { state.type = e.target.value; renderFindingRows(); });
      document.getElementById('verification').addEventListener('change', (e) => { state.verification = e.target.value; renderFindingRows(); });
      document.getElementById('triage').addEventListener('change', (e) => { state.triage = e.target.value; renderFindingRows(); });
      renderFindingRows();
    }
    function select(id, values, selected) { return '<select id="' + id + '" class="control">' + values.map(v => '<option value="' + esc(v) + '" ' + (v === selected ? 'selected' : '') + '>' + esc(v === 'all' ? 'All ' + id : v) + '</option>').join('') + '</select>'; }
    function renderFindingRows() {
      const rows = filteredFindings();
      document.getElementById('findingRows').innerHTML = rows.length ? rows.map((f, i) => findingRow(f, i)).join('') : '<tr><td colspan="7"><div class="empty">No findings match these filters.</div></td></tr>';
    }
    function findingRow(f, i) {
      return '<tr><td><strong>' + esc(f.title) + '</strong><br>' + badge(f.type) + (f.needsManualVerification ? ' ' + badge('needs manual verification', 'verify') : '') + '</td>' +
        '<td>' + badge(f.severity, 'sev-' + f.severity) + '<br>' + badge(f.confidence) + '</td><td>' + badge(f.triageStatus, f.triageStatus === 'confirmed' ? 'sev-High' : f.triageStatus === 'false-positive' ? 'sev-Informational' : 'verify') + '</td><td>' + esc(f.riskScore) + '</td><td class="url">' + esc(f.url) + '</td><td>' + esc(f.sourceModule) + '</td>' +
        '<td><button class="btn" data-drawer="finding-' + i + '">Proof</button></td></tr>' +
        '<tr><td colspan="7"><div class="drawer" id="finding-' + i + '">' + proofHtml(f) + '</div></td></tr>';
    }
    window.toggleDrawer = (id) => document.getElementById(id).classList.toggle('open');
    document.addEventListener('click', (event) => {
      const button = event.target.closest('[data-drawer]');
      if (button) window.toggleDrawer(button.getAttribute('data-drawer'));
    });
    function proofHtml(f) {
      return '<div class="grid two"><div><h4>Evidence</h4><p>' + esc(f.evidenceSource || 'none') + '</p><p><strong>Status:</strong> ' + esc(f.statusCode) + ' <strong>Length:</strong> ' + esc(f.contentLength) + ' <strong>Type:</strong> ' + esc(f.contentType || 'unknown') + '</p><p><strong>Severity reason:</strong> ' + esc(f.severityReason) + '</p><pre class="mono">' + esc(f.curlCommand) + '</pre></div>' +
        '<div><h4>Triage</h4><p><strong>Status:</strong> ' + esc(f.triageStatus) + '</p><p><strong>Note:</strong> ' + esc(f.triageNote || 'none') + '</p><p><strong>Updated:</strong> ' + esc(f.triageUpdatedAt || 'not triaged') + '</p><h4>Manual Notes</h4><p><strong>Impact:</strong> ' + esc(f.impact) + '</p><p><strong>Recommendation:</strong> ' + esc(f.recommendation) + '</p>' + list(f.manualTestingSuggestions) + '</div></div>' +
        (f.bodyPreview ? '<h4>Redacted Body Preview</h4><pre class="mono">' + esc(f.bodyPreview.slice(0, 1800)) + '</pre>' : '');
    }

    function renderWorkflows() {
      bySection('workflows').innerHTML = sectionTitle('Vulnerability Workflows', 'Safe manual testing plans. These are hypotheses, not confirmed vulnerabilities.') +
      (data.workflows.length ? '<div class="grid two">' + data.workflows.map(workflowHtml).join('') + '</div>' : '<div class="empty">No workflows generated.</div>');
    }
    function workflowHtml(w) { return '<div class="card workflow"><div><h4>' + esc(w.title) + '</h4>' + badge(w.category) + ' ' + badge('priority: ' + w.priority) + ' ' + badge(w.confidence) + '</div><p><strong>Target:</strong> ' + esc(w.target) + '</p><p><strong>Evidence:</strong> ' + esc((w.evidence || []).join(' ')) + '</p><div class="split-list"><div><strong>Safe test plan</strong>' + list(w.safeTestPlan) + '</div><div><strong>Avoid</strong>' + list(w.avoidActions) + '</div></div><p><strong>Related:</strong> ' + esc((w.relatedEndpoints || []).slice(0, 8).join(', ') || 'none') + '</p></div>'; }

    function renderManualPack() {
      const report = data.workflowValidation;
      bySection('manual').innerHTML = sectionTitle('Manual Test Pack', 'Structured proof templates. These are manual verification guides, not confirmed vulnerabilities.') +
        (!report || !report.templates.length ? '<div class="empty">No manual test templates generated.</div>' : '<div class="grid two">' + report.templates.map(templateHtml).join('') + '</div>');
    }
    function templateHtml(t) {
      return '<div class="card workflow"><div><h4>' + esc(t.title) + '</h4>' + badge(t.kind) + ' ' + badge('priority: ' + t.priority) + ' ' + badge('needs manual verification', 'verify') + '</div><p><strong>Target:</strong> ' + esc(t.target) + '</p><div class="split-list"><div><strong>Preconditions</strong>' + list(t.preconditions) + '<strong>Steps</strong>' + list(t.steps) + '</div><div><strong>Expected secure behavior</strong>' + list(t.expectedSecureBehavior) + '<strong>Evidence to capture</strong>' + list(t.evidenceToCapture) + '<strong>Do not</strong>' + list(t.avoidActions) + '</div></div><p><strong>Related:</strong> ' + esc((t.relatedEndpoints || []).slice(0, 8).join(', ') || 'none') + '</p></div>';
    }

    function renderProof() {
      if (data.proofMode && data.proofMode.blocks && data.proofMode.blocks.length) {
        bySection('proof').innerHTML = sectionTitle('Proof Mode Evidence', 'Re-tested proof blocks with safe requests, response summaries, and redacted auth comparisons.') +
          '<div class="grid">' + data.proofMode.blocks.map(proofModeBlockHtml).join('') + '</div>';
        return;
      }
      const proof = data.findings.filter(f => ['Critical','High','Medium'].includes(f.severity)).sort((a,b) => b.riskScore - a.riskScore);
      bySection('proof').innerHTML = sectionTitle('Proof Blocks', 'High-signal findings with reproduction commands and redacted evidence.') +
        (proof.length ? '<div class="grid">' + proof.map((f) => '<div class="card band"><h3>' + esc(f.title) + '</h3>' + badge(f.severity, 'sev-' + f.severity) + ' ' + (f.needsManualVerification ? badge('needs manual verification', 'verify') : '') + proofHtml(f) + '</div>').join('') + '</div>' : '<div class="empty">No Critical, High, or Medium proof blocks in this scan.</div>');
    }
    function proofModeBlockHtml(block) {
      const rows = block.comparisons.map(c => [c.label, c.request.curlCommand, c.response.statusCode || 'error', c.response.contentType || 'unknown', c.response.contentLength || 'unknown', c.response.bodyHash || 'none']);
      return '<div class="card band"><h3>' + esc(block.title) + '</h3>' + badge(block.severity, 'sev-' + block.severity) + ' ' + badge('needs manual verification', 'verify') +
        '<p><strong>Target:</strong> ' + esc(block.target) + '</p><p><strong>Why selected:</strong> ' + esc((block.whySelected || []).join(', ')) + '</p><p><strong>Severity reason:</strong> ' + esc(block.severityReason) + '</p>' +
        '<h4>Stable Evidence</h4>' + list(block.stableEvidence) + '<h4>Request/Response Proof</h4>' + simpleTable(rows, ['Label','Safe curl','Status','Type','Length','Hash']) +
        '<h4>Bounty Summary</h4><pre class="mono">' + esc(block.bountySubmissionSummary) + '</pre></div>';
    }

    function renderBrowser() {
      bySection('browser').innerHTML = sectionTitle('Browser Evidence', 'Rendered crawl output, screenshot, network counts, and form-safety state.') +
        '<div class="grid two"><div class="card band"><h3>Screenshot</h3>' + (data.browser.screenshotRelativePath ? '<img class="screenshot" src="' + esc(data.browser.screenshotRelativePath) + '" alt="Homepage screenshot">' : '<div class="empty">No screenshot captured.</div>') + '</div>' +
        '<div class="card band"><h3>Browser Crawl</h3><p>Rendered links: <strong>' + data.browser.renderedLinks + '</strong></p><p>Network requests: <strong>' + data.browser.networkRequests + '</strong></p><p>Console errors: <strong>' + data.browser.consoleErrors + '</strong></p><p>Forms detected: <strong>' + data.browser.formsDetected + '</strong></p><p>Forms submitted: <strong>' + data.browser.formsSubmitted + '</strong></p>' +
        (data.browser.authentication ? '<h4>Authenticated learning</h4><p>Bootstrap: <strong>' + esc(data.browser.authentication.bootstrapSucceeded ? 'succeeded' : 'failed') + '</strong> · ' + esc(data.browser.authentication.mode) + '</p><p>Storage metadata: <strong>' + data.browser.authentication.storage + '</strong> · Field observations: <strong>' + data.browser.authentication.fields + '</strong></p><p>Admin routes: <strong>' + data.browser.authentication.adminRoutes + '</strong> · Draft cases: <strong>' + data.browser.authentication.learnedCases + '</strong></p><p>Browser restarts: <strong>' + data.browser.authentication.restarts + '</strong></p><p><strong>Mutation authority:</strong> none from learned traffic; explicit operator case and approval required.</p>' : '') + '</div></div>';
    }

    function renderIntelligence() {
      bySection('intelligence').innerHTML = sectionTitle('Intelligence', 'API, auth, JavaScript, and technology signals extracted during the scan.') +
        '<div class="grid two"><div class="card band"><h3>API Endpoints</h3>' + simpleTable(data.apiEndpoints.map(e => [e.endpoint, e.routeType, e.riskTags.join(', ')]), ['Endpoint','Type','Tags']) + '</div>' +
        '<div class="card band"><h3>Auth Surfaces</h3>' + simpleTable(data.authSurfaces.map(a => [a.endpoint, a.purpose, a.abuseCategories.join(', ')]), ['Endpoint','Purpose','Categories']) + '</div></div>' +
        '<div class="card band" style="margin-top:14px"><h3>API Probe</h3>' + apiProbeHtml() + '</div>' +
        '<div class="card band" style="margin-top:14px"><h3>Authenticated Testing</h3>' + authCompareHtml() + '</div>' +
        '<div class="card band" style="margin-top:14px"><h3>Role Comparison</h3>' + roleCompareHtml() + '</div>' +
        '<div class="card band" style="margin-top:14px"><h3>State-Aware API Testing</h3>' + stateAwareApiHtml() + '</div>' +
        '<div class="card band" style="margin-top:14px"><h3>Parameter Analysis</h3>' + parameterAnalysisHtml() + '</div>' +
        '<div class="card band" style="margin-top:14px"><h3>Next.js Review</h3>' + nextJsReviewHtml() + '</div>' +
        '<div class="card band" style="margin-top:14px"><h3>Secret Boundary and Sensitive Exposure</h3>' + secretBoundaryHtml() + '</div>' +
        '<div class="card band" style="margin-top:14px"><h3>Protocol-Level Security</h3>' + protocolSecurityHtml() + '</div>' +
        '<div class="card band" style="margin-top:14px"><h3>Active Vulnerability Validation</h3>' + activeVulnerabilityHtml() + '</div>' +
        '<div class="card band" style="margin-top:14px"><h3>Assisted Security Review</h3>' + assistedReviewHtml() + '</div>';
    }
    function protocolSecurityHtml() {
      const report = data.protocolSecurity;
      if (!report || !report.enabled) return '<div class="empty">Protocol-level security testing was not configured.</div>';
      return '<p>Executed: <strong>' + esc(report.executedCases) + '/' + esc(report.plannedCases) + '</strong>; passed: ' + esc(report.passedCases) + '; failed: ' + esc(report.failedCases) + '; inconclusive: ' + esc(report.inconclusiveCases) + '; blocked: ' + esc(report.blockedCases) + '.</p>' + simpleTable(report.observations.map(v => [v.label, v.kind, v.actorAlias, v.outcome, v.reason, v.statusCode || '-', v.messageCount, v.eventCount, v.negotiatedProtocol || '-', v.cleanupOutcome || '-']), ['Case','Kind','Actor','Outcome','Reason','Status','Messages','Events','Protocol','Cleanup']);
    }
    function activeVulnerabilityHtml() {
      const report = data.activeVulnerability;
      if (!report || !report.enabled) return '<div class="empty">Active vulnerability validation was not configured.</div>';
      return '<p>Cases: <strong>' + esc(report.plannedCases) + '</strong> (' + esc(report.explicitCases) + ' explicit; ' + esc(report.discoveredCases) + ' discovery-compiled). Proven: <strong>' + esc(report.provenCases) + '</strong>; secure: ' + esc(report.secureCases) + '; inconclusive: ' + esc(report.inconclusiveCases) + '; blocked: ' + esc(report.blockedCases) + '.</p>' + simpleTable(report.coverage.map(v => [v.vulnerabilityClass, v.planned, v.proven, v.secure, v.inconclusive, v.blocked, v.notAssessed]), ['Class','Planned','Proven','Secure','Inconclusive','Blocked','Not assessed']);
    }
    function assistedReviewHtml() {
      const review = data.assistedReview;
      if (!review) return '<div class="empty">No assisted-review manifest was supplied.</div>';
      return '<p>Gate: <strong>' + esc(review.completionGate.state) + '</strong>; pending human review: ' + esc(review.humanReviewQueue.length) + '</p><p>Blockers: ' + esc(review.completionGate.blockers.join(', ') || 'none') + '</p><p>Operator report only; customer publication requires human acceptance.</p>' + simpleTable(Object.entries(review.coverageMatrix).filter(([, v]) => v.selected).map(([lane, v]) => [lane, v.outcomes.PROVEN, v.outcomes.INCONCLUSIVE, v.outcomes.NOT_ASSESSED, v.outcomes.BLOCKED, v.cleanupFailures]), ['Lane', 'Proven', 'Inconclusive', 'Not assessed', 'Blocked', 'Cleanup unresolved']);
    }
    function secretBoundaryHtml() {
      const report = data.secretBoundary;
      if (!report || !report.enabled) return '<div class="empty">Secret-boundary review was not selected.</div>';
      const rows = report.observations.map(o => [o.surface, o.candidateName, o.materialClass, o.boundary, o.impact, o.outcome, o.confidence]);
      return '<p>Analyzed <strong>' + esc(report.candidatesAnalyzed) + '</strong> candidates; confirmed findings: <strong>' + esc(report.confirmedFindings) + '</strong>.</p>' +
        '<p>Client-safe: <strong>' + esc(report.clientSafeMaterial) + '</strong> · Server-only: <strong>' + esc(report.serverOnlyMaterial) + '</strong> · Supabase anon/publishable/service-role: <strong>' + esc(report.supabase.anonKeys + '/' + report.supabase.publishableKeys + '/' + report.supabase.serviceRoleKeys) + '</strong>.</p>' +
        simpleTable(rows, ['Surface','Candidate','Class','Boundary','Impact','Outcome','Confidence']);
    }
    function nextJsReviewHtml() {
      const report = data.nextJsReview;
      if (!report || !report.detected) return '<div class="empty">Next.js was not detected.</div>';
      const dataRows = report.dataRoutes.map(r => [r.url, r.statusCode || 'error', r.cacheRisk, (r.dataIndicators || []).join(', ') || 'none', r.cacheControl || '']);
      const sourceRows = report.sourceMaps.map(s => [s.url, s.classification, s.severityHint, s.reason]);
      const findingRows = Object.entries(report.securityFindingCounts || {}).map(([type,count]) => [type,count]);
      const limitations = (report.coverage?.limitations || []).map(item => '<li>' + esc(item) + '</li>').join('');
      return '<h4>Technology intelligence</h4><p>Detection: ' + esc(report.detectionConfidence || 'unknown') + '. Router: ' + esc(report.routerKind || 'UNKNOWN') + '. Build ID metadata: ' + esc(report.buildIds.join(', ') || 'none') + '.</p>' +
        '<h4>Observed public surfaces</h4><p>' + esc(report.surfaces?.length || 0) + ' normalized surfaces; ' + esc(report.manifests?.length || 0) + ' manifests; normal public Next.js metadata is not a vulnerability by itself.</p>' +
        '<h4>Coverage</h4><p>Data: ' + esc(report.coverage?.dataSurfaceReview || 'unknown') + '; source maps: ' + esc(report.coverage?.sourceMapReview || 'unknown') + '; cache differential: ' + esc(report.coverage?.cacheDifferential || 'unknown') + '; additional request ceiling: ' + esc(report.requestBudget?.maximumAdditionalRequests || 0) + '.</p>' +
        '<h4>Security findings</h4>' + simpleTable(findingRows, ['Category','Count']) +
        '<h4>_next/data Routes</h4>' + simpleTable(dataRows, ['URL','Status','Cache Risk','Indicators','Cache-Control']) + '<h4>Source Maps</h4>' + simpleTable(sourceRows, ['URL','Class','Severity Hint','Reason']) +
        '<h4>Review limitations</h4><ul>' + limitations + '</ul>';
    }

    function parameterAnalysisHtml() {
      const report = data.parameterAnalysis;
      if (!report || !report.totalParameters) return '<div class="empty">No parameters identified.</div>';
      const rows = report.analyzedUrls.flatMap(a => a.parameters.filter(p => p.riskTags.includes('authorization-sensitive') || p.riskTags.includes('business-logic')).map(p => [a.url, p.name, p.location, p.kind, p.riskTags.join(', '), p.confidence]));
      return '<p>' + esc(report.totalParameters) + ' parameters analyzed. High-risk: ' + esc(report.highRiskParameters.length) + '.</p>' + simpleTable(rows, ['URL','Name','Location','Kind','Tags','Confidence']);
    }

    function stateAwareApiHtml() {
      const report = data.stateAwareApi;
      if (!report || !report.reviewedEndpoints.length) return '<div class="empty">No state-aware API candidates reviewed.</div>';
      const rows = report.reviewedEndpoints.map(r => {
        const statusFor = (method) => (r.safeMethodsTested.find(item => item.method === method)?.statusCode || 'error');
        return [r.endpoint, r.priority, r.candidateReasons.join(', '), r.accessComparison.signal, statusFor('GET'), statusFor('HEAD'), statusFor('OPTIONS'), r.accessComparison.needsManualVerification ? 'needs manual verification' : ''];
      });
      return '<p>Safe methods: ' + esc(report.safeMethods.join(', ')) + '. Skipped: ' + esc(report.skippedMethods.join(', ')) + '.</p>' + simpleTable(rows, ['Endpoint','Priority','Reasons','Signal','GET','HEAD','OPTIONS','Label']);
    }

    function roleCompareHtml() {
      const report = data.roleComparison;
      if (!report || !report.profileSet.enabled) return '<div class="empty">No Account A/B profiles supplied.</div>';
      const rows = report.results.filter(r => r.classification !== 'same-as-anonymous').map(r => [r.url, r.classification, r.anonymous.statusCode || 'error', r.accountA.statusCode || 'error', r.accountB.statusCode || 'error', r.needsManualVerification ? 'needs manual verification' : '', r.reason]);
      return '<p>' + esc(report.comparedUrls) + ' URLs compared. Account auth material redacted.</p>' + simpleTable(rows, ['URL','Class','Anon','A','B','Label','Reason']);
    }
    function apiProbeHtml() {
      const report = data.apiProbe;
      if (!report || !report.endpointsReviewed.length) return '<div class="empty">No API probe reviews recorded.</div>';
      const rows = report.endpointsReviewed.map(r => [r.endpoint, r.statusByMethod.OPTIONS || 'error', r.statusByMethod.HEAD || 'error', r.statusByMethod.GET || 'error', r.contentTypes.join(', ') || 'none', r.allowedMethods.join(', ') || 'none', r.schemaHints.join(', ') || 'none', r.graphQl.attempted ? (r.graphQl.available ? 'introspection-like evidence' : 'checked safely') : 'skipped']);
      return '<p>Safe methods: ' + esc(report.safeMethods.join(', ')) + '. Skipped: ' + esc(report.skippedMethods.join(', ')) + '.</p>' + simpleTable(rows, ['Endpoint','OPTIONS','HEAD','GET','Types','Allowed','Schema','GraphQL']);
    }

    function authCompareHtml() {
      const report = data.authenticatedScan;
      if (!report || !report.profile.enabled) return '<div class="empty">No auth profile supplied.</div>';
      const rows = report.results.filter(r => r.classification !== 'same-access').map(r => [r.url, r.classification, r.anonymous.statusCode || 'error', r.authenticated.statusCode || 'error', r.reason]);
      return '<p>' + esc(report.comparedUrls) + ' URLs compared. Auth material redacted: ' + esc(report.profile.redactionApplied) + '.</p>' + simpleTable(rows, ['URL','Class','Anon','Auth','Reason']);
    }
    function simpleTable(rows, headers) { if (!rows.length) return '<div class="empty">None recorded.</div>'; return '<table><thead><tr>' + headers.map(h => '<th>' + esc(h) + '</th>').join('') + '</tr></thead><tbody>' + rows.map(row => '<tr>' + row.map(cell => '<td class="url">' + esc(cell) + '</td>').join('') + '</tr>').join('') + '</tbody></table>'; }

    renderOverview(); renderFindings(); renderWorkflows(); renderManualPack(); renderProof(); renderBrowser(); renderIntelligence();
  </script>
</body>
</html>`;
}

function dashboardData(outputDir: string, report: RouteCairnReport, triage: TriageState): DashboardData {
  const findings = report.findings.map((finding) => toDashboardFinding(finding, triage));
  const screenshotPath = report.browserCrawl?.screenshotPath;
  const screenshotRelativePath = screenshotPath ? relative(outputDir, screenshotPath).split(sep).join("/") : undefined;

  return {
    target: report.target,
    program: report.program,
    mode: report.mode,
    profile: report.profile,
    generatedAt: report.metadata.completedAt,
    metadata: report.metadata,
    ...(report.requestBudget ? { requestBudget: report.requestBudget } : {}),
    ...(report.transport ? { transport: report.transport } : {}),
    technologies: report.technologies,
    severityCounts: countBy(findings, "severity"),
    findingTypeCounts: countBy(findings, "type"),
    findings,
    workflows: report.vulnerabilityWorkflows?.workflows ?? [],
    apiEndpoints: report.apiMapper?.endpoints ?? [],
    apiProbe: report.apiProbe,
    authSurfaces: report.authSurface?.surfaces ?? [],
    authenticatedScan: report.authenticatedScan,
    roleComparison: report.roleComparison,
    stateAwareApi: report.stateAwareApi,
    parameterAnalysis: report.parameterAnalysis,
    workflowValidation: report.workflowValidation,
    nextJsReview: report.nextJsReview,
    proofMode: report.proofMode,
    supabaseAuthorization: report.supabaseAuthorization,
    authenticationLifecycle: report.authenticationLifecycle,
    businessInvariant: report.businessInvariant,
    controlledRace: report.controlledRace,
    apiGraphql: report.apiGraphql,
    protocolSecurity: report.protocolSecurity,
    linkPortalSecurity: report.linkPortalSecurity,
    operationalEndpointSecurity: report.operationalEndpointSecurity,
    billingEntitlement: report.billingEntitlement,
    secretBoundary: report.secretBoundary,
    activeVulnerability: report.activeVulnerability,
    assistedReview: report.assistedReview,
    js: {
      scripts: report.jsIntelligence?.scripts.length ?? 0,
      queuedEndpoints: report.jsIntelligence?.queuedEndpoints.length ?? 0,
      sourceMaps: report.jsIntelligence?.sourceMaps.length ?? 0,
      configValues: report.jsIntelligence?.scripts.reduce((total, script) => total + script.configValues.length, 0) ?? 0
    },
    browser: {
      ...(screenshotPath ? { screenshotPath: basename(screenshotPath) } : {}),
      ...(screenshotRelativePath ? { screenshotRelativePath } : {}),
      renderedLinks: report.browserCrawl?.renderedLinks.length ?? 0,
      networkRequests: report.browserCrawl?.networkRequests.length ?? 0,
      consoleErrors: report.browserCrawl?.consoleErrors.length ?? 0,
      formsDetected: report.browserCrawl?.formsDetected ?? 0,
      formsSubmitted: report.browserCrawl?.formsSubmitted ?? 0,
      ...(report.browserCrawl?.authentication ? { authentication: {
        mode: report.browserCrawl.authentication.mode,
        bootstrapSucceeded: report.browserCrawl.authentication.bootstrapSucceeded,
        storage: report.browserCrawl.authentication.storage.length,
        fields: report.browserCrawl.authentication.fields.length,
        adminRoutes: report.browserCrawl.authentication.adminRoutes.length,
        learnedCases: report.browserCrawl.authentication.learnedTestCases.length,
        restarts: report.browserCrawl.authentication.browserRestartCount
      } } : {})
    },
    discovered: {
      total: report.discoveredUrls.length,
      likelyValid: report.discoveredUrls.filter((item) => item.falsePositiveStatus === "likely-valid").length,
      maybeFalsePositive: report.discoveredUrls.filter((item) => item.falsePositiveStatus === "maybe-false-positive").length,
      likelyFalsePositive: report.discoveredUrls.filter((item) => item.falsePositiveStatus === "likely-false-positive").length
    },
    triageSummary: countBy(findings, "triageStatus")
  };
}

function toDashboardFinding(finding: Finding, triage: TriageState): DashboardFinding {
  const triageEntry = triage.entries[finding.id];
  return {
    id: finding.id,
    title: finding.title,
    type: finding.type,
    severity: finding.severity,
    confidence: finding.confidence,
    riskScore: finding.riskScore,
    url: finding.url,
    sourceModule: finding.sourceModule,
    falsePositiveStatus: finding.falsePositiveStatus,
    needsManualVerification: finding.falsePositiveStatus !== "likely-valid" || finding.tags.includes("manual-review") || finding.type === "Interesting But Needs Manual Testing",
    evidenceSource: finding.evidence.source ?? "",
    curlCommand: finding.evidence.curlCommand ?? `curl -i "${finding.url}"`,
    severityReason: finding.evidence.severityReason ?? "Not recorded.",
    statusCode: finding.evidence.statusCode ?? "unknown",
    contentLength: finding.evidence.contentLength ?? "unknown",
    contentType: finding.evidence.contentType ?? "",
    bodyPreview: finding.evidence.bodyPreview ?? "",
    tags: finding.tags,
    recommendation: finding.recommendation,
    impact: finding.impact,
    manualTestingSuggestions: finding.manualTestingSuggestions,
    triageStatus: triageEntry?.status ?? "unreviewed",
    triageNote: triageEntry?.note ?? "",
    triageUpdatedAt: triageEntry?.updatedAt ?? "",
    triageUpdatedBy: triageEntry?.updatedBy ?? ""
  };
}

function countBy<T extends object>(items: T[], key: keyof T): Record<string, number> {
  return items.reduce<Record<string, number>>((counts, item) => {
    const value = String(item[key]);
    counts[value] = (counts[value] ?? 0) + 1;
    return counts;
  }, {});
}

function safeJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char] ?? char);
}
