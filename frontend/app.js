/**
 * ShieldCloud - Cloud Security Posture & Secret Leakage Dashboard Frontend Controller
 */

const API_BASE = 'http://localhost:8000';

let allFindings = [];
let currentFilter = 'ALL';
let currentSearch = '';
let activeFindingForModal = null;
let severityChart = null;
let serviceChart = null;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  initCharts();
  fetchStatusAndFindings();
});

function initEventListeners() {
  // Action Buttons
  document.getElementById('btnCloudScan').addEventListener('click', triggerCloudScan);
  document.getElementById('btnSecretScan').addEventListener('click', triggerSecretScan);
  document.getElementById('btnExport').addEventListener('click', exportReport);
  document.getElementById('btnAwsGuide').addEventListener('click', () => toggleModal('awsGuideModal', true));
  document.getElementById('btnClearTerminal').addEventListener('click', clearTerminal);

  // Search Input
  document.getElementById('searchInput').addEventListener('input', (e) => {
    currentSearch = e.target.value.toLowerCase();
    renderFindingsTable();
  });

  // Filter Pills
  document.querySelectorAll('.pill-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.pill-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.getAttribute('data-filter');
      renderFindingsTable();
    });
  });

  // KPI card clicks filter table
  document.querySelectorAll('.kpi-card[data-severity]').forEach(card => {
    card.addEventListener('click', () => {
      const sev = card.getAttribute('data-severity');
      const targetPill = document.querySelector(`.pill-btn[data-filter="${sev.toUpperCase()}"]`) || 
                         document.querySelector(`.pill-btn[data-filter="ALL"]`);
      if (targetPill) targetPill.click();
    });
  });

  // Remediation Modal Close & Dismiss
  document.getElementById('modalCloseBtn').addEventListener('click', () => toggleModal('remediationModal', false));
  document.getElementById('modalDismissBtn').addEventListener('click', () => toggleModal('remediationModal', false));
  
  // AWS Guide Modal Close
  document.getElementById('modalCloseGuideBtn').addEventListener('click', () => toggleModal('awsGuideModal', false));
  document.getElementById('modalCloseGuideConfirmBtn').addEventListener('click', () => toggleModal('awsGuideModal', false));

  // Copy Buttons
  document.getElementById('btnCopyCli').addEventListener('click', () => copyToClipboard('codeRemediationCli', 'btnCopyCli'));
  document.getElementById('btnCopyTf').addEventListener('click', () => copyToClipboard('codeRemediationTf', 'btnCopyTf'));

  // Tab Switcher inside Modal
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.getAttribute('data-tab');
      if (tab === 'cli') {
        document.getElementById('tabContentCli').classList.remove('hidden');
        document.getElementById('tabContentTf').classList.add('hidden');
      } else {
        document.getElementById('tabContentCli').classList.add('hidden');
        document.getElementById('tabContentTf').classList.remove('hidden');
      }
    });
  });
}

// Check Backend Status & Initial Findings
async function fetchStatusAndFindings() {
  try {
    const statusRes = await fetch(`${API_BASE}/api/status`);
    if (statusRes.ok) {
      const statusData = await statusRes.json();
      updateStatusPill(statusData);
      appendTerminalLog(`[${new Date().toLocaleTimeString()}] Connected to Security Core. Mode: ${statusData.mode} (Account: ${statusData.account_id})`, 'success');
    }

    const findingsRes = await fetch(`${API_BASE}/api/findings`);
    if (findingsRes.ok) {
      const data = await findingsRes.json();
      allFindings = data.findings || [];
      updateKPIs(data.summary);
      updateCharts(data.findings);
      renderFindingsTable();
    }
  } catch (err) {
    console.warn("Backend not yet responding, attempting fallback:", err);
    updateStatusPill({ mode: "Offline / Connecting", account_id: "localhost:8000" }, false);
    showToast("Backend service not detected. Start `python server.py` to activate live scanning.", "error");
    appendTerminalLog(`[${new Date().toLocaleTimeString()}] Warning: Backend at ${API_BASE} not connected. Run 'python server.py' to launch API.`, 'alert');
  }
}

function updateStatusPill(statusData, isConnected = true) {
  const textEl = document.getElementById('accountInfoText');
  const dot = document.querySelector('#awsStatusPill .pulse-dot');
  
  if (!isConnected) {
    textEl.textContent = "Backend Offline (Port 8000)";
    dot.className = "pulse-dot";
    return;
  }

  dot.className = "pulse-dot active";
  if (statusData.is_live) {
    textEl.textContent = `AWS Account: ${statusData.account_id} [LIVE]`;
  } else {
    textEl.textContent = `Mode: ${statusData.mode} (Acc: ${statusData.account_id})`;
  }
}

// Trigger Cloud Security Posture Scan
async function triggerCloudScan() {
  const btn = document.getElementById('btnCloudScan');
  btn.disabled = true;
  setScanning(true);
  appendTerminalLog(`[${new Date().toLocaleTimeString()}] Triggering Cloud Security Posture Management (CSPM) Scan...`, 'info');

  try {
    const res = await fetch(`${API_BASE}/api/scan/cloud`, { method: 'POST' });
    const data = await res.json();

    if (data.logs && Array.isArray(data.logs)) {
      data.logs.forEach(l => {
        const type = l.includes('[ALERT]') ? 'alert' : 'info';
        appendTerminalLog(l, type);
      });
    }

    allFindings = mergeFindings(allFindings, data.findings);
    updateKPIs(data.summary);
    updateCharts(allFindings);
    renderFindingsTable();
    showToast(`Cloud Scan Complete! Identified ${data.summary.total} findings.`, 'success');
  } catch (err) {
    showToast("Cloud Scan failed: Unable to connect to backend server.", "error");
    appendTerminalLog(`[${new Date().toLocaleTimeString()}] Scan error: ${err.message}`, 'alert');
  } finally {
    setScanning(false);
    btn.disabled = false;
  }
}

// Trigger Secret Leakage Scan
async function triggerSecretScan() {
  const btn = document.getElementById('btnSecretScan');
  btn.disabled = true;
  setScanning(true);
  appendTerminalLog(`[${new Date().toLocaleTimeString()}] Triggering Secret Leakage Prevention Scan...`, 'info');

  try {
    const res = await fetch(`${API_BASE}/api/scan/secrets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: "." })
    });
    const data = await res.json();

    if (data.logs && Array.isArray(data.logs)) {
      data.logs.forEach(l => appendTerminalLog(l, 'info'));
    }

    allFindings = mergeFindings(allFindings, data.findings);
    const summaryRes = await fetch(`${API_BASE}/api/findings`);
    if (summaryRes.ok) {
      const summaryData = await summaryRes.json();
      updateKPIs(summaryData.summary);
    }

    updateCharts(allFindings);
    renderFindingsTable();
    showToast(`Secret Scan Finished. Flagged ${data.findings.length} leaked credential(s)!`, 'success');
  } catch (err) {
    showToast("Secret Scan failed: Connection error.", "error");
    appendTerminalLog(`[${new Date().toLocaleTimeString()}] Secret scan error: ${err.message}`, 'alert');
  } finally {
    setScanning(false);
    btn.disabled = false;
  }
}

function mergeFindings(existing, fresh) {
  const map = new Map();
  existing.forEach(f => map.set(f.id, f));
  fresh.forEach(f => map.set(f.id, f));
  return Array.from(map.values());
}

// Update KPI Cards and Posture Score
function updateKPIs(summary) {
  if (!summary) return;

  document.getElementById('kpiTotal').textContent = summary.total;
  document.getElementById('kpiCritical').textContent = summary.critical;
  document.getElementById('kpiHigh').textContent = summary.high;
  document.getElementById('kpiMedium').textContent = summary.medium;
  document.getElementById('kpiLow').textContent = summary.low;

  // Update counts on filter pills
  document.getElementById('countAll').textContent = summary.total;
  document.getElementById('countCritical').textContent = summary.critical;
  document.getElementById('countHigh').textContent = summary.high;
  document.getElementById('countMedium').textContent = summary.medium;
  document.getElementById('countLow').textContent = summary.low;
  
  const secretCount = allFindings.filter(f => f.service === 'Secret Leakage').length;
  document.getElementById('countSecrets').textContent = secretCount;

  // Posture Score & Grade
  const score = summary.security_score !== undefined ? summary.security_score : 78;
  document.getElementById('securityScoreVal').textContent = score;
  document.getElementById('scoreProgressBar').style.width = `${score}%`;
  document.getElementById('scoreGrade').textContent = summary.grade || 'B+';

  const assessEl = document.getElementById('scoreAssessment');
  if (score >= 85) {
    assessEl.textContent = 'Strong Cloud Security Posture';
  } else if (score >= 65) {
    assessEl.textContent = 'Moderate Exposure Detected';
  } else {
    assessEl.textContent = 'High Vulnerability Risk!';
  }
}

// Render Findings Table
function renderFindingsTable() {
  const tbody = document.getElementById('findingsTableBody');
  tbody.innerHTML = '';

  const filtered = allFindings.filter(f => {
    // Severity filter
    if (currentFilter === 'CRITICAL' && f.severity !== 'CRITICAL') return false;
    if (currentFilter === 'HIGH' && f.severity !== 'HIGH') return false;
    if (currentFilter === 'MEDIUM' && f.severity !== 'MEDIUM') return false;
    if (currentFilter === 'LOW' && f.severity !== 'LOW') return false;
    if (currentFilter === 'SECRET' && f.service !== 'Secret Leakage') return false;

    // Search filter
    if (currentSearch) {
      const matchText = (f.title + ' ' + f.resource + ' ' + f.service + ' ' + (f.compliance || []).join(' ')).toLowerCase();
      if (!matchText.includes(currentSearch)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align: center; padding: 3rem; color: var(--text-muted);">
          No findings match the selected criteria.
        </td>
      </tr>
    `;
    return;
  }

  filtered.forEach(f => {
    const tr = document.createElement('tr');

    const complianceBadges = (f.compliance || []).map(c => `<span class="tag-comp">${c}</span>`).join('');

    tr.innerHTML = `
      <td><span class="badge-sev ${f.severity}">${f.severity}</span></td>
      <td><span class="service-tag">${getServiceIcon(f.service)} ${f.service}</span></td>
      <td>
        <div class="finding-title-wrap">
          <span class="finding-title">${escapeHtml(f.title)}</span>
          <span class="finding-arn">${escapeHtml(f.resource)}</span>
        </div>
      </td>
      <td><div class="compliance-tags-wrap">${complianceBadges}</div></td>
      <td style="text-align: right;">
        <button class="btn-view-rem" data-id="${f.id}">Remediate &rarr;</button>
      </td>
    `;

    tr.querySelector('.btn-view-rem').addEventListener('click', () => openRemediationModal(f));
    tbody.appendChild(tr);
  });
}

function getServiceIcon(service) {
  if (service === 'S3') return '🪣';
  if (service === 'IAM') return '🔑';
  if (service === 'EC2') return '🖥️';
  if (service === 'CloudTrail') return '📜';
  if (service === 'Secret Leakage') return '🛡️';
  return '☁️';
}

// Chart.js Visualizations
function initCharts() {
  const ctxDonut = document.getElementById('severityDonutChart').getContext('2d');
  severityChart = new Chart(ctxDonut, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [1, 1, 1, 1],
        backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#10b981'],
        borderWidth: 0,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: '#94a3b8', font: { family: 'Plus Jakarta Sans', size: 11 }, boxWidth: 12 }
        }
      },
      cutout: '72%'
    }
  });

  const ctxBar = document.getElementById('serviceBarChart').getContext('2d');
  serviceChart = new Chart(ctxBar, {
    type: 'bar',
    data: {
      labels: ['IAM', 'S3', 'EC2', 'Secrets', 'CloudTrail'],
      datasets: [{
        label: 'Issues',
        data: [3, 2, 1, 3, 1],
        backgroundColor: '#6366f1',
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { grid: { display: false }, ticks: { color: '#94a3b8' } },
        y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8', stepSize: 1 } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

function updateCharts(findings) {
  if (!severityChart || !serviceChart) return;

  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const serviceCounts = { IAM: 0, S3: 0, EC2: 0, 'Secret Leakage': 0, CloudTrail: 0 };

  findings.forEach(f => {
    if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++;
    if (serviceCounts[f.service] !== undefined) serviceCounts[f.service]++;
  });

  severityChart.data.datasets[0].data = [
    sevCounts.CRITICAL,
    sevCounts.HIGH,
    sevCounts.MEDIUM,
    sevCounts.LOW
  ];
  severityChart.update();

  serviceChart.data.labels = ['IAM', 'S3', 'EC2', 'Secrets', 'CloudTrail'];
  serviceChart.data.datasets[0].data = [
    serviceCounts.IAM,
    serviceCounts.S3,
    serviceCounts.EC2,
    serviceCounts['Secret Leakage'],
    serviceCounts.CloudTrail
  ];
  serviceChart.update();
}

// Open Remediation Modal
function openRemediationModal(finding) {
  activeFindingForModal = finding;

  const sevBadge = document.getElementById('modalSeverityBadge');
  sevBadge.textContent = finding.severity;
  sevBadge.className = `badge badge-sev ${finding.severity}`;

  document.getElementById('modalFindingTitle').textContent = finding.title;
  document.getElementById('modalResourceArn').textContent = finding.resource;
  document.getElementById('modalFindingDesc').textContent = finding.description;

  document.getElementById('codeRemediationCli').textContent = finding.remediation_cli || "# CLI remediation not available";
  document.getElementById('codeRemediationTf').textContent = finding.remediation_tf || "# Terraform config not available";

  toggleModal('remediationModal', true);
}

function toggleModal(modalId, show) {
  const modal = document.getElementById(modalId);
  if (show) modal.classList.remove('hidden');
  else modal.classList.add('hidden');
}

// Helpers
function setScanning(isScanning) {
  const bar = document.getElementById('progressBarContainer');
  if (isScanning) bar.classList.add('active');
  else bar.classList.remove('active');
}

function appendTerminalLog(msg, type = 'info') {
  const container = document.getElementById('terminalLogs');
  const div = document.createElement('div');
  div.className = `log-line ${type}`;
  div.textContent = msg;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function clearTerminal() {
  document.getElementById('terminalLogs').innerHTML = '';
}

function showToast(msg, type = 'success') {
  const toast = document.getElementById('toastNotification');
  toast.textContent = msg;
  toast.className = `toast-notification ${type}`;
  setTimeout(() => {
    toast.className = 'toast-notification hidden';
  }, 4500);
}

function copyToClipboard(elementId, btnId) {
  const text = document.getElementById(elementId).innerText;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    const orig = btn.innerText;
    btn.innerText = 'Copied!';
    setTimeout(() => { btn.innerText = orig; }, 2000);
  });
}

function exportReport() {
  window.open(`${API_BASE}/api/export?format=csv`, '_blank');
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.innerText = text || '';
  return div.innerHTML;
}
