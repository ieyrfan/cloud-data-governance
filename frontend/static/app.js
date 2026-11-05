"use strict";

// Browser sessions use an HttpOnly cookie. Never expose the bearer token to JavaScript storage.
const state = { token: "cookie", role: "REVIEWER", username: "", files: [], fileTotal: 0, filesTruncated: false, accessRequests: [], accessEvents: [], apiClients: [], webhookDeliveries: [], reviews: [], incidents: [], retentionControls: [], checkpoints: [], capabilities: null, policies: [], analytics: null, requestedResource: "", config: null, hasLoaded: false };
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const titles = { overview: "Home", inventory: "Documents", audit: "Activity", posture: "Security", requests: "Access requests", policies: "Protection rules", operations: "Reviews & retention", integrations: "Developer access" };
const descriptions = {
  overview: "See what needs attention and keep track of your documents.",
  inventory: "Find a document, check its sensitive information and open a protected copy.",
  audit: "Verify the event chain and inspect recorded actions.",
  posture: "Compare controls across raw and protected storage.",
  requests: "Review time-limited original-file access and deployment coverage.",
  policies: "Preview versioned protection decisions without submitting personal values.",
  operations: "Coordinate reviews, incidents, retention and signed audit checkpoints.",
  integrations: "Connect external applications to classification, protection and policy decisions."
};
const documentTypeLabels = {
  PASSPORT: "Passport / Travel document",
  IDENTITY: "Identity document", RESUME: "Resume / CV", PAYSLIP: "Payslip / Payroll",
  ACADEMIC_RESULT: "Academic result", FORM: "Form / Application",
  INVOICE: "Invoice / Financial", CERTIFICATE: "Certificate",
  CONTRACT: "Contract / Agreement", REPORT: "Report", OTHER: "Other document"
};
const roleExperiences = {
  ADMIN: {
    nav: ["overview", "inventory", "audit", "posture", "requests", "policies", "operations", "integrations"],
    navLabel: "Administration", title: "Manage your documents",
    eyebrow: "Administrator workspace",
    description: "Upload documents, review detected information and manage access requests.",
    scope: "Full operational control", primary: "inventory", primaryLabel: "Manage document inventory"
  },
  DATA_OWNER: {
    nav: ["overview", "inventory", "requests", "policies", "operations", "integrations"],
    navLabel: "Owner workspace", title: "Data owner workspace",
    eyebrow: "Accountability workspace",
    description: "Organise owned documents, review high-sensitivity evidence and decide justified original-file access.",
    scope: "Upload and access decisions", primary: "requests", primaryLabel: "Review access decisions"
  },
  REVIEWER: {
    nav: ["overview", "inventory", "requests", "integrations"],
    navLabel: "Document review", title: "Documents ready for review",
    eyebrow: "Reviewer workspace",
    description: "Work through the review queue using protected copies and content-free evidence.",
    scope: "Protected-copy access", primary: "inventory", primaryLabel: "Open review queue"
  },
  AUDITOR: {
    nav: ["overview", "inventory", "audit", "posture", "requests", "operations", "integrations"],
    navLabel: "Assurance workspace", title: "Audit and assurance workspace",
    eyebrow: "Auditor workspace",
    description: "Verify the decision trail, retrieval evidence and storage controls without changing operational data.",
    scope: "Read-only assurance", primary: "audit", primaryLabel: "Verify audit evidence"
  }
};

function setSidebarCollapsed(collapsed) {
  const shell = $(".app-shell");
  const toggle = $("#sidebar-toggle");
  shell.classList.toggle("sidebar-collapsed", collapsed);
  toggle.setAttribute("aria-expanded", String(!collapsed));
  toggle.setAttribute("aria-label", collapsed ? "Expand navigation" : "Collapse navigation");
  toggle.title = collapsed ? "Expand navigation" : "Collapse navigation";
  sessionStorage.setItem("sidebarCollapsed", String(collapsed));
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[char]));
}

function humanize(value, fallback = "Not available") {
  const words = String(value || fallback).replaceAll("_", " ").toLowerCase();
  return words.replace(/^./, character => character.toUpperCase());
}

function showToast(message, isError = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.className = `toast show${isError ? " error" : ""}`;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { toast.className = "toast"; }, 3600);
}

const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const csrf = document.cookie.split('; ').find(item => item.startsWith('ds_csrf='))?.split('=').slice(1).join('=');
  if (csrf) headers.set('X-CSRF-Token', decodeURIComponent(csrf));
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  const method = String(options.method || "GET").toUpperCase();
  const retryable = method === "GET";
  let lastError;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
      let payload = null;
      try { payload = await response.json(); } catch { payload = {}; }
      if (response.status === 401) {
        lockConsole(false);
        throw new Error("Your session expired. Sign in again.");
      }
      if (response.ok) return payload;
      const error = new Error(payload.detail || `Request failed (${response.status}).`);
      error.status = response.status;
      error.retryable = retryable && [429, 502, 503, 504].includes(response.status);
      if (!error.retryable || attempt === 2) throw error;
      lastError = error;
    } catch (error) {
      if (!retryable || error.retryable === false || error.message === "Your session expired. Sign in again." || attempt === 2) throw error;
      lastError = error;
    }
    await sleep(300 * (attempt + 1));
  }
  throw lastError || new Error("The service did not respond.");
}

async function downloadEvidencePack(resourceId) {
  try {
    const response = await fetch(`/files/evidence-pack?resource_id=${encodeURIComponent(resourceId)}`, {
      credentials: "same-origin"
    });
    if (response.status === 401) {
      await lockConsole(false);
      throw new Error("Your session expired. Sign in again.");
    }
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || `Evidence export failed (${response.status}).`);
    }
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") || "";
    const filename = disposition.match(/filename="([^"]+)"/)?.[1] || "DataSentinel-Evidence.zip";
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast("Evidence pack downloaded without document content.");
  } catch (error) {
    showToast(error.message, true);
  }
}

function formatDate(value) {
  if (!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Invalid date" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function resourceParts(uri) {
  const clean = String(uri || "");
  const segments = clean.split("/");
  return { name: segments.at(-1) || clean, path: clean };
}

function sensitivityTag(value) {
  const label = value || "UNKNOWN";
  return `<span class="tag tag-${escapeHtml(label.toLowerCase())}">${escapeHtml(label)}</span>`;
}

function riskTag(value) {
  const label = value || "INFO";
  return `<span class="tag risk-${escapeHtml(label.toLowerCase())}">${escapeHtml(label)}</span>`;
}

function documentTypeTag(item) {
  const key = String(item.document_type || item.findings?.document_type?.key || "OTHER").toUpperCase();
  const label = item.document_type_label || item.findings?.document_type?.label || documentTypeLabels[key] || documentTypeLabels.OTHER;
  return `<span class="document-type-badge type-${escapeHtml(key.toLowerCase())}">${escapeHtml(label)}</span>`;
}

function applyRoleExperience() {
  const experience = roleExperiences[state.role] || roleExperiences.REVIEWER;
  const overviewNav = $('[data-view="overview"]');
  $("span", overviewNav).textContent = experience.navLabel;
  overviewNav.title = experience.navLabel;
  $$(".nav-item").forEach(button => { button.hidden = !experience.nav.includes(button.dataset.view); });
  const adminTools = $(".nav-admin-tools");
  const hasAdminTools = adminTools && $$(".nav-item:not([hidden])", adminTools).length > 0;
  if (adminTools) adminTools.parentElement.querySelector(".admin-tools-label").hidden = !hasAdminTools;
  if (adminTools) adminTools.hidden = !hasAdminTools;
  const adminDivider = $(".nav-divider");
  if (adminDivider) adminDivider.hidden = !hasAdminTools;
  $(".nav-list").style.setProperty("--visible-nav-items", experience.nav.length);
  $("#role-workspace-eyebrow").textContent = experience.eyebrow;
  $("#role-workspace-title").textContent = experience.title;
  $("#role-workspace-description").textContent = experience.description;
  $("#role-workspace-scope").textContent = experience.scope;
  $("#role-primary-action").textContent = experience.primaryLabel;
  $("#role-primary-action").dataset.targetView = experience.primary;
  const canUpload = ["ADMIN", "DATA_OWNER"].includes(state.role) && Boolean(state.config?.upload_enabled);
  $("#upload-button").hidden = !canUpload;
  $("#upload-button").disabled = !canUpload;
  const currentView = location.hash.slice(1);
  switchView(experience.nav.includes(currentView) ? currentView : "overview", false, "replace");
}

function signalLabel(value) {
  const labels = {
    my_ic: "Malaysian NRIC",
    malaysian_nric: "Malaysian NRIC",
    email: "Email address",
    email_address: "Email address",
    my_phone: "Malaysian phone number",
    malaysian_phone: "Malaysian phone number",
    credit_card: "Payment card number",
    payment_card: "Payment card number",
    address: "Postal address",
    name: "Person name"
  };
  return labels[String(value || "").toLowerCase()] || humanize(value);
}

function renderActivity(item) {
  const trace = $("#activity-trace");
  if (!item) {
    $("#activity-resource").textContent = "No completed classification run";
    $("#activity-time").textContent = "—";
    trace.innerHTML = "<li class='activity-empty'>New activity will appear after the first object is classified.</li>";
    return;
  }

  const resource = resourceParts(item.resource_id);
  const bucket = String(item.resource_id || "").replace("s3://", "").split("/")[0] || "raw data zone";
  const findings = item.findings || {};
  const signals = (findings.pattern_types_detected || []).map(signalLabel);
  const signalCount = Number(findings.pattern_matches_count || 0);
  const confidence = Math.round(Number(item.confidence_score || 0) * 100);
  const rawRiskScore = Number(item.risk_score || 0);
  const riskScore = Math.round(rawRiskScore <= 1 ? rawRiskScore * 100 : rawRiskScore);
  const actions = item.governance_actions || {};
  const completedActions = [
    actions.redacted_copy_created ? "redacted copy created" : "content retained without redaction",
    actions.retention_tags_applied ? "retention tags applied" : null,
    actions.audit_event_created ? "audit record chained" : null
  ].filter(Boolean);
  const stages = [
    ["Received", `${resource.name} entered the private ${bucket} raw zone.`],
    ["Detected", signalCount ? `${signalCount} validated pattern${signalCount === 1 ? "" : "s"}: ${signals.join(", ") || "sensitive-data signals"}.` : "No sensitive-data patterns were detected."],
    ["Decided", `${humanize(item.sensitivity_level)} at ${confidence}% confidence · ${humanize(item.risk_level)} review priority (${riskScore}/100 sensitivity baseline).`],
    ["Protected and recorded", `${completedActions.join(" · ") || "No downstream action evidence was recorded"}.`]
  ];

  $("#activity-resource").textContent = resource.name;
  $("#activity-time").textContent = formatDate(item.timestamp);
  trace.innerHTML = stages.map(([label, detail], index) => `<li><span class="activity-index">${String(index + 1).padStart(2, "0")}</span><div><span class="activity-stage">${escapeHtml(label)}</span><p>${escapeHtml(detail)}</p></div><span class="activity-state">Complete</span></li>`).join("");
}

function fileRow(item, full = false) {
  const resource = resourceParts(item.resource_id);
  const findings = item.findings || {};
  resource.name = findings.display_filename || resource.name;
  const signals = Number(findings.pattern_matches_count || 0);
  return `<tr>
    <td class="resource-cell"><span class="resource-name" title="${escapeHtml(resource.name)}">${escapeHtml(resource.name)}</span><span class="resource-path" title="${escapeHtml(resource.path)}">${escapeHtml(resource.path)}</span></td>
    <td data-label="Document type">${documentTypeTag(item)}</td>
    <td data-label="Sensitivity">${sensitivityTag(item.sensitivity_level)}</td>
    ${full ? `<td data-label="Signals">${signals} pattern${signals === 1 ? "" : "s"}</td>` : ""}
    <td data-label="Confidence">${Math.round(Number(item.confidence_score || 0) * 100)}%</td>
    <td data-label="Priority">${riskTag(item.risk_level)}</td>
    <td data-label="Classified">${escapeHtml(formatDate(item.timestamp))}</td>
    <td><button class="row-action" data-resource="${escapeHtml(item.resource_id)}" aria-label="View details for ${escapeHtml(resource.name)}"><span class="row-action-label">View evidence</span><span aria-hidden="true">→</span></button></td>
  </tr>`;
}

function renderSummary(summary) {
  const sensitivity = summary.sensitivity_breakdown || {};
  const total = Number(summary.total_files_scanned || 0);
  const restricted = Number(sensitivity.RESTRICTED || 0);
  const confidential = Number(sensitivity.CONFIDENTIAL || 0);
  const reviewCount = Number(summary.review_required || 0);
  const unknownCount = Number(summary.records_with_unknown_classification || 0);
  state.role = summary.access_role || "REVIEWER";
  state.username = summary.username || "";
  $("#access-role-badge").hidden = false;
  const roleLabels = { ADMIN: "Administrator", DATA_OWNER: "Data owner", REVIEWER: "Reviewer", AUDITOR: "Auditor" };
  $("#access-role-badge").textContent = `${roleLabels[state.role] || humanize(state.role)} · ${state.username}`;
  applyRoleExperience();
  const latest = state.files[0];
  $("#metric-total").textContent = summary.total_files_scanned ?? 0;
  $("#metric-restricted").textContent = restricted;
  $("#metric-review").textContent = reviewCount;
  $("#metric-readiness").textContent = summary.governance_readiness_score ?? 0;
  const passedChecks = Number(summary.readiness_checks_passed || 0);
  const totalChecks = Number(summary.readiness_checks_total || 0);
  $("#readiness-basis").textContent = totalChecks
    ? `${passedChecks}/${totalChecks} required actions recorded`
    : "No action evidence available";
  $("#distribution-total").textContent = `${total} files`;
  $("#evidence-mode").textContent = state.config?.demo_mode ? "Demo snapshot · not live AWS" : "Live AWS evidence";
  $("#attention-title").textContent = reviewCount ? `${reviewCount} resources need review` : "Review queue is clear";
  $("#attention-detail").textContent = reviewCount
    ? `${restricted} restricted and ${confidential} confidential across ${total} classified resources${unknownCount ? `; ${unknownCount} unknown` : ""}. Open the queue to inspect the evidence behind each decision.`
    : `${total} classified resources are currently outside the review queue${unknownCount ? `; ${unknownCount} require classification repair` : ""}.`;
  $("#data-freshness").textContent = summary.last_classification_at ? `Latest evidence ${formatDate(summary.last_classification_at)}` : "No classification evidence yet";
  renderActivity(latest);

  const colors = { RESTRICTED: "var(--danger)", CONFIDENTIAL: "var(--warning)", INTERNAL: "var(--info)", PUBLIC: "var(--success)", UNKNOWN: "var(--muted)" };
  const scaleTotal = Math.max(1, total);
  $("#sensitivity-chart").innerHTML = Object.entries(colors).map(([label, color]) => {
    const count = Number(sensitivity[label] || 0);
    const width = Math.round(count / scaleTotal * 100);
    return `<div class="bar-row" style="--bar:${color}"><span class="bar-label"><i class="swatch"></i>${label}</span><span class="bar-track"><i class="bar-fill" style="width:${width}%"></i></span><strong class="bar-value">${count}</strong></div>`;
  }).join("");
  const typeBreakdown = summary.document_type_breakdown || {};
  $("#document-type-summary").innerHTML = Object.entries(documentTypeLabels)
    .filter(([key]) => Number(typeBreakdown[key] || 0) > 0)
    .map(([key, label]) => `<button type="button" class="document-type-card" data-document-type="${key}"><span>${escapeHtml(label)}</span><strong>${Number(typeBreakdown[key] || 0)}</strong><small>View ${Number(typeBreakdown[key] || 0) === 1 ? "file" : "files"}</small></button>`)
    .join("") || `<div class="catalogue-empty"><strong>No categorised documents yet</strong><span>New files will be organised automatically after classification.</span></div>`;
}

function renderFiles() {
  const recent = state.files.slice(0, 5);
  $("#recent-files-body").innerHTML = recent.map(item => fileRow(item, false)).join("");
  $("#recent-empty").hidden = recent.length > 0;
  filterInventory();
}

function filterInventory() {
  const search = $("#resource-search").value.trim().toLowerCase();
  const sensitivity = $("#sensitivity-filter").value;
  const documentType = $("#document-type-filter").value;
  const filtered = state.files.filter(item => {
    const matchesSearch = !search || item.resource_id.toLowerCase().includes(search);
    const matchesQueue = !sensitivity || (sensitivity === "REVIEW" ? ["RESTRICTED", "CONFIDENTIAL"].includes(item.sensitivity_level) : item.sensitivity_level === sensitivity);
    const itemType = String(item.document_type || item.findings?.document_type?.key || "OTHER").toUpperCase();
    const matchesType = !documentType || itemType === documentType;
    return matchesSearch && matchesQueue && matchesType;
  });
  $("#inventory-body").innerHTML = filtered.map(item => fileRow(item, true)).join("");
  $("#inventory-count").textContent = state.filesTruncated
    ? `${filtered.length} shown of ${state.fileTotal}`
    : `${filtered.length} resource${filtered.length === 1 ? "" : "s"}`;
  $("#inventory-empty").hidden = filtered.length > 0;
}

function renderAudit(payload) {
  const events = payload.items || [];
  const total = Number(payload.total_count ?? events.length);
  const verification = payload.integrity || {};
  $("#audit-count").textContent = events.length < total ? `${events.length} shown of ${total}` : `${total} event${total === 1 ? "" : "s"}`;
  $("#audit-empty").hidden = events.length > 0;
  const integrity = $("#audit-integrity");
  integrity.textContent = events.length ? (verification.verified ? `Full ledger verified · ${verification.checked_events}` : "Integrity failure") : "No ledger to verify";
  integrity.title = verification.message || "Audit verification status unavailable";
  integrity.classList.toggle("attention", events.length > 0 && !verification.verified);
  $("#audit-list").innerHTML = events.map((event, index) => {
    const action = humanize(event.action, "Governance event");
    const details = event.details || {};
    const decision = details.sensitivity ? `${humanize(details.sensitivity)} · ${Math.round(Number(details.confidence || 0) * 100)}% confidence` : "Decision metadata unavailable";
    return `<li class="audit-event"><span class="audit-sequence">${String(total - index).padStart(2, "0")}</span><div><strong>${escapeHtml(action)}</strong><p>${escapeHtml(resourceParts(event.resource).name)} · ${escapeHtml(decision)}</p><small>${escapeHtml(event.actor || "Unknown actor")}</small><code class="hash">${escapeHtml(String(event.current_hash || "unavailable").slice(0, 24))}…</code></div><time class="event-time">${escapeHtml(formatDate(event.timestamp))}</time></li>`;
  }).join("");
}

function renderAccessEvents(payload) {
  state.accessEvents = payload.items || [];
  const total = Number(payload.count || state.accessEvents.length);
  $("#access-event-count").textContent = `${total} event${total === 1 ? "" : "s"}`;
  $("#access-events-empty").hidden = state.accessEvents.length > 0;
  $("#access-events-body").innerHTML = state.accessEvents.map(event => {
    const resource = resourceParts(event.resource_id);
    const correlation = String(event.correlation_id || "unavailable");
    return `<tr>
      <td class="resource-cell"><span class="resource-name">${escapeHtml(resource.name)}</span><span class="resource-path">${escapeHtml(resource.path)}</span></td>
      <td data-label="Copy"><span class="tag tag-${event.variant === "ORIGINAL" ? "restricted" : "internal"}">${escapeHtml(humanize(event.variant))}</span></td>
      <td data-label="Actor"><strong>${escapeHtml(event.actor || "Unknown")}</strong><small>${escapeHtml(humanize(event.actor_role))}</small></td>
      <td data-label="Access basis">${escapeHtml(humanize(event.access_basis))}</td>
      <td data-label="Issued">${escapeHtml(formatDate(event.created_at))}</td>
      <td data-label="Correlation"><code class="correlation-id" title="${escapeHtml(correlation)}">${escapeHtml(correlation.slice(0, 12))}</code></td>
    </tr>`;
  }).join("");
}

function renderPosture(posture) {
  $("#posture-score").textContent = `${posture.checks_passed || 0}/${posture.checks_total || 0} passed`;
  $("#posture-score").classList.toggle("attention", posture.status !== "PASS");
  const buckets = posture.buckets || [];
  const controls = [...new Set(buckets.flatMap(bucket => bucket.checks.map(check => check.control)))];
  const head = buckets.map(bucket => `<th><span>${escapeHtml(bucket.bucket)}</span><small>${bucket.bucket.includes("raw") ? "Raw ingestion" : "Protected output"}</small></th>`).join("");
  const rows = controls.map(control => `<tr><th scope="row">${escapeHtml(control)}</th>${buckets.map(bucket => {
    const check = bucket.checks.find(item => item.control === control);
    const passed = check?.status === "PASS";
    const zone = bucket.bucket.includes("raw") ? "Raw ingestion" : "Protected output";
    return `<td data-label="${zone}"><span class="control-result ${passed ? "pass" : "fail"}"><b>${passed ? "✓ Pass" : "! Check"}</b><small>${escapeHtml(check?.detail || "No result")}</small></span></td>`;
  }).join("")}</tr>`).join("");
  $("#posture-buckets").innerHTML = buckets.length ? `<section class="panel posture-matrix"><div class="table-wrap"><table><thead><tr><th>Control</th>${head}</tr></thead><tbody>${rows}</tbody></table></div></section>` : `<div class="empty-state"><strong>No posture response</strong><span>Refresh the console after the storage checks are available.</span></div>`;
}

function renderSystemStatus(payload) {
  const checks = payload.checks || [];
  checks.forEach(check => {
    const step = $(`[data-system-check="${check.id}"]`);
    if (!step) return;
    const badge = $(".service-state", step);
    const status = String(check.status || "UNKNOWN").toLowerCase();
    badge.textContent = humanize(check.status);
    badge.className = `service-state status-${status}`;
    badge.title = check.detail || "Dependency status unavailable";
  });
  const healthy = payload.overall === "OPERATIONAL" || payload.overall === "SNAPSHOT";
  $("#classifier-state").textContent = payload.mode === "demo"
    ? "Snapshot evidence loaded"
    : healthy ? "AWS pipeline operational" : "AWS pipeline degraded";
  $(".system-state").classList.toggle("degraded", !healthy);
}

function requestStatusTag(status) {
  return `<span class="request-status status-${escapeHtml(String(status || "PENDING").toLowerCase())}">${escapeHtml(humanize(status))}</span>`;
}

function renderAccessRequests(payload, capabilities) {
  state.accessRequests = payload.items || [];
  state.capabilities = capabilities;
  const privileged = ["ADMIN", "DATA_OWNER"].includes(state.role);
  $("#request-pending").textContent = `${payload.pending || 0} pending`;
  $("#request-scope").textContent = privileged ? "You can approve or reject requests" : state.role === "AUDITOR" ? "Read-only decision evidence" : "Showing your requests only";
  $("#request-count").textContent = `${payload.count || 0} request${payload.count === 1 ? "" : "s"}`;
  $("#requests-empty").hidden = state.accessRequests.length > 0;
  $("#requests-body").innerHTML = state.accessRequests.map(item => {
    const resource = resourceParts(item.resource_id);
    const actions = privileged && item.status === "PENDING" ? `<div class="decision-actions"><button class="row-action approve" data-request-decision="APPROVE" data-request-id="${escapeHtml(item.request_id)}">Approve</button><button class="row-action reject" data-request-decision="REJECT" data-request-id="${escapeHtml(item.request_id)}">Reject</button></div>` : `<span class="decision-by">${item.decided_by ? `by ${escapeHtml(item.decided_by)}` : "Awaiting decision"}</span>`;
    return `<tr><td class="resource-cell"><span class="resource-name">${escapeHtml(resource.name)}</span><span class="resource-path">${escapeHtml(resource.path)}</span></td><td data-label="Requester"><strong>${escapeHtml(item.requester)}</strong><small>${escapeHtml(humanize(item.requester_role))}</small></td><td data-label="Reason">${escapeHtml(item.justification)}</td><td data-label="Status">${requestStatusTag(item.status)}</td><td data-label="Expiry">${item.access_expires_at ? escapeHtml(formatDate(item.access_expires_at)) : "—"}</td><td>${actions}</td></tr>`;
  }).join("");
  const implemented = capabilities.implemented || [];
  const integrations = capabilities.integration_ready || [];
  $("#implemented-count").textContent = `${implemented.length} active controls`;
  $("#integration-count").textContent = `${integrations.length} integration targets`;
  $("#implemented-controls").innerHTML = implemented.map(item => `<li>${escapeHtml(item)}</li>`).join("");
  $("#integration-controls").innerHTML = integrations.map(item => `<li>${escapeHtml(item)}</li>`).join("");
  $("#capability-statement").textContent = capabilities.statement || "";
}

function renderPolicyStudio(payload, analytics) {
  state.policies = payload.items || [];
  state.analytics = analytics;
  $("#policy-profile").innerHTML = state.policies.map(item => `<option value="${escapeHtml(item.key)}">${escapeHtml(item.label)} · ${escapeHtml(item.policy_version)}</option>`).join("");
  $("#analytics-documents").textContent = analytics.documents ?? 0;
  $("#analytics-classification").textContent = `${analytics.classification_coverage_percent ?? 0}%`;
  $("#analytics-protection").textContent = `${analytics.protected_copy_coverage_percent ?? 0}%`;
  $("#analytics-review").textContent = analytics.review_queue ?? 0;
  const editable = ["ADMIN", "DATA_OWNER"].includes(state.role);
  $("#policy-simulate").disabled = !editable;
  $("#policy-permission-note").textContent = editable
    ? "Simulation uses signal types only and never sends personal values."
    : "This role can inspect profiles; simulation is limited to administrators and data owners.";
}

function statusTag(status) {
  const value = String(status || "UNKNOWN").toUpperCase();
  const className = value === "ACTIVE" || value === "DELIVERED" ? "internal" : value === "REVOKED" || value === "DISABLED" ? "restricted" : "unknown";
  return `<span class="tag tag-${className}">${escapeHtml(humanize(value))}</span>`;
}

function revealOneTimeSecret(secret, label = "credential") {
  const panel = $("#api-secret-reveal");
  $("#api-secret-value").textContent = secret;
  $("#api-secret-copy").dataset.secretLabel = label;
  panel.hidden = false;
  panel.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "nearest" });
}

function renderIntegrationControlPlane() {
  const panel = $("#integration-management");
  const deliveriesPanel = $("#webhook-delivery-panel");
  const visible = ["ADMIN", "DATA_OWNER", "AUDITOR"].includes(state.role);
  panel.hidden = !visible;
  deliveriesPanel.hidden = !visible;
  if (!visible) return;
  const canManage = state.role === "ADMIN";
  $("#api-client-form").hidden = !canManage;
  $("#integration-permission-note").textContent = canManage
    ? "Create, rotate and revoke scoped machine identities without exposing stored secrets."
    : "Read-only application identity and webhook evidence for governance review.";
  $("#api-client-count").textContent = `${state.apiClients.length} client${state.apiClients.length === 1 ? "" : "s"}`;
  $("#api-clients-empty").hidden = state.apiClients.length > 0;
  $("#api-clients-body").innerHTML = state.apiClients.map(client => {
    const scopes = (client.scopes || []).map(humanize).join(" · ") || "No scopes";
    const webhook = client.webhook;
    const webhookCell = webhook
      ? `<div class="webhook-state">${statusTag(webhook.status)}<small title="${escapeHtml(webhook.url)}">${escapeHtml(webhook.destination_host || webhook.url)}</small></div>`
      : `<span class="client-scopes">Not configured</span>`;
    const actions = canManage ? `<div class="client-actions"><button class="row-action" type="button" data-client-webhook data-tenant-id="${escapeHtml(client.tenant_id)}" data-client-id="${escapeHtml(client.client_id)}" data-client-label="${escapeHtml(client.label)}" data-webhook-url="${escapeHtml(webhook?.url || "")}">${webhook ? "Rotate webhook" : "Add webhook"}</button><button class="row-action" type="button" data-client-rotate data-tenant-id="${escapeHtml(client.tenant_id)}" data-client-id="${escapeHtml(client.client_id)}">Rotate key</button><button class="row-action reject" type="button" data-client-revoke data-tenant-id="${escapeHtml(client.tenant_id)}" data-client-id="${escapeHtml(client.client_id)}">Revoke</button></div>` : `<span class="client-scopes">Read only</span>`;
    return `<tr><td><span class="client-identity"><strong>${escapeHtml(client.label)}</strong><small>${escapeHtml(client.tenant_id)} / ${escapeHtml(client.client_id)} · ${escapeHtml(client.key_fingerprint || "no fingerprint")}</small></span></td><td data-label="Scopes"><span class="client-scopes">${escapeHtml(scopes)}</span></td><td data-label="Status">${statusTag(client.status)}</td><td data-label="Expires">${escapeHtml(formatDate(client.expires_at))}</td><td data-label="Webhook">${webhookCell}</td><td>${actions}</td></tr>`;
  }).join("");

  $("#webhook-delivery-count").textContent = `${state.webhookDeliveries.length} deliver${state.webhookDeliveries.length === 1 ? "y" : "ies"}`;
  $("#webhook-deliveries-empty").hidden = state.webhookDeliveries.length > 0;
  $("#webhook-deliveries-body").innerHTML = state.webhookDeliveries.map(item => `<tr><td><strong>${escapeHtml(humanize(item.event_type))}</strong><small class="client-scopes">${escapeHtml(item.event_id || "No event ID")}</small></td><td data-label="Application">${escapeHtml(item.tenant_id)} / ${escapeHtml(item.client_id)}</td><td data-label="Destination">${escapeHtml(item.destination_host || "Not recorded")}</td><td data-label="Status">${statusTag(item.status)} <small>${escapeHtml(String(item.http_status || ""))}</small></td><td data-label="Delivered">${escapeHtml(formatDate(item.created_at))}</td></tr>`).join("");
}

async function loadIntegrationControlPlane() {
  if (!["ADMIN", "DATA_OWNER", "AUDITOR"].includes(state.role)) {
    state.apiClients = [];
    state.webhookDeliveries = [];
    renderIntegrationControlPlane();
    return;
  }
  const clientsPayload = await api("/api-clients");
  const clients = (clientsPayload.items || []).slice(0, 50);
  for (const client of clients) {
    try {
      client.webhook = await api(`/api-clients/${encodeURIComponent(client.tenant_id)}/${encodeURIComponent(client.client_id)}/webhook`);
    } catch (error) {
      if (error.status !== 404) throw error;
      client.webhook = null;
    }
  }
  const deliveries = await api("/webhook-deliveries");
  state.apiClients = clients;
  state.webhookDeliveries = deliveries.items || [];
  renderIntegrationControlPlane();
}

async function createApiClient(event) {
  event.preventDefault();
  const button = $("#api-client-create");
  button.disabled = true;
  try {
    const scopes = $$("input[name='api-scope']:checked").map(input => input.value);
    if (!scopes.length) throw new Error("Select at least one capability.");
    const created = await api("/api-clients", { method: "POST", body: JSON.stringify({ tenant_id: $("#api-tenant-id").value.trim(), client_id: $("#api-client-id").value.trim(), label: $("#api-client-label").value.trim(), scopes, expires_in_days: 30 }) });
    revealOneTimeSecret(created.api_key, "API credential");
    $("#api-client-form").reset();
    await loadIntegrationControlPlane();
    showToast("API client created. Copy the credential before leaving this page.");
  } catch (error) {
    showToast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

async function rotateApiClient(tenantId, clientId) {
  try {
    const rotated = await api(`/api-clients/${encodeURIComponent(tenantId)}/${encodeURIComponent(clientId)}/rotate`, { method: "POST" });
    revealOneTimeSecret(rotated.api_key, "rotated API credential");
    await loadIntegrationControlPlane();
    showToast("The previous API credential was revoked immediately.");
  } catch (error) { showToast(error.message, true); }
}

async function revokeApiClient(tenantId, clientId) {
  try {
    await api(`/api-clients/${encodeURIComponent(tenantId)}/${encodeURIComponent(clientId)}`, { method: "DELETE" });
    await loadIntegrationControlPlane();
    showToast("API client revoked.");
  } catch (error) { showToast(error.message, true); }
}

function openWebhookDialog(button) {
  $("#webhook-tenant-id").value = button.dataset.tenantId;
  $("#webhook-client-id").value = button.dataset.clientId;
  $("#webhook-client-label").textContent = `${button.dataset.clientLabel} · ${button.dataset.tenantId}/${button.dataset.clientId}`;
  $("#webhook-url").value = button.dataset.webhookUrl || "";
  $("#webhook-error").textContent = "";
  $("#webhook-dialog").showModal();
}

async function saveWebhook(event) {
  event.preventDefault();
  const tenantId = $("#webhook-tenant-id").value;
  const clientId = $("#webhook-client-id").value;
  const button = $("#webhook-save");
  button.disabled = true;
  $("#webhook-error").textContent = "";
  try {
    const result = await api(`/api-clients/${encodeURIComponent(tenantId)}/${encodeURIComponent(clientId)}/webhook`, { method: "PUT", body: JSON.stringify({ url: $("#webhook-url").value.trim() }) });
    $("#webhook-dialog").close();
    revealOneTimeSecret(result.signing_secret, "webhook signing secret");
    await loadIntegrationControlPlane();
    showToast("Webhook saved. Copy the signing secret before leaving this page.");
  } catch (error) {
    $("#webhook-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function runPolicySimulation(event) {
  event.preventDefault();
  const signalTypes = $$("input[name='policy-signal']:checked").map(input => input.value);
  const result = $("#policy-result");
  result.innerHTML = "<span>Evaluating the selected profile…</span>";
  try {
    const payload = await api("/policies/simulate", { method: "POST", body: JSON.stringify({ profile: $("#policy-profile").value, signal_types: signalTypes, extraction_complete: $("#policy-extraction-complete").checked }) });
    result.innerHTML = `<div><span>Decision</span><strong>${sensitivityTag(payload.decision)}</strong></div><div><span>Policy</span><strong>${escapeHtml(payload.policy_id)} · ${escapeHtml(payload.policy_version)}</strong></div><p>${escapeHtml(payload.reason)}</p><small>${payload.protected_copy_required ? "Protected copy required" : "No protected copy required"} · ${payload.human_review_required ? "Human review required" : "No human review required"}</small>`;
  } catch (error) {
    result.innerHTML = `<strong>Simulation unavailable</strong><span>${escapeHtml(error.message)}</span>`;
  }
}

function renderOperationsControlPlane() {
  const visibleIncidents = state.incidents.filter(item => item.status !== "RESOLVED");
  const legalHolds = state.retentionControls.filter(item => item.legal_hold);
  $("#operations-review-count").textContent = state.reviews.length;
  $("#operations-incident-count").textContent = visibleIncidents.length;
  $("#operations-hold-count").textContent = legalHolds.length;
  $("#operations-checkpoint-count").textContent = state.checkpoints.length;
  $("#incident-count").textContent = `${state.incidents.length} incident${state.incidents.length === 1 ? "" : "s"}`;
  $("#incidents-empty").hidden = state.incidents.length > 0;
  const nextStatus = { OPEN: "TRIAGED", TRIAGED: "CONTAINED", CONTAINED: "RESOLVED" };
  const canTransition = ["ADMIN", "DATA_OWNER"].includes(state.role);
  $("#incidents-body").innerHTML = state.incidents.map(item => {
    const next = nextStatus[item.status];
    const action = canTransition && next ? `<button class="row-action" type="button" data-incident-id="${escapeHtml(item.incident_id)}" data-incident-status="${next}">Mark ${humanize(next)}</button>` : "";
    return `<tr><td><strong>${escapeHtml(item.title)}</strong><small class="client-scopes">${escapeHtml(item.incident_id)}</small></td><td>${sensitivityTag(item.severity)}</td><td>${statusTag(item.status)}</td><td data-label="Resource">${escapeHtml(item.resource_id || "Platform-wide")}</td><td data-label="Updated">${escapeHtml(formatDate(item.updated_at))}</td><td>${action}</td></tr>`;
  }).join("");
  const retentionEvidence = state.retentionControls.map(item => `<div class="contract-row"><strong>${item.legal_hold ? "Legal hold" : `${escapeHtml(item.retention_days)}-day retention`}</strong><span>${escapeHtml(item.resource_id)} · retain until ${escapeHtml(formatDate(item.retain_until))}</span></div>`);
  const checkpointEvidence = state.checkpoints.map(item => `<div class="contract-row"><strong>${item.signature_valid ? "Verified checkpoint" : "Invalid checkpoint"}</strong><span>${escapeHtml(String(item.event_count))} events · ${escapeHtml(formatDate(item.generated_at))} · external anchor ${item.external_anchor_active ? "active" : "not active"}</span></div>`);
  $("#control-evidence-list").innerHTML = [...retentionEvidence, ...checkpointEvidence].join("") || `<div class="empty-state"><strong>No preservation evidence yet</strong><span>Create a retention control or signed checkpoint.</span></div>`;
  const canManage = ["ADMIN", "DATA_OWNER"].includes(state.role);
  $("#retention-form").hidden = !canManage;
  $("#checkpoint-create").hidden = !["ADMIN", "AUDITOR"].includes(state.role);
}

async function loadOperationsControlPlane() {
  state.reviews = [];
  state.incidents = [];
  state.retentionControls = [];
  state.checkpoints = [];
  if (state.role === "REVIEWER") return;
  const reviews = await api("/reviews");
  const incidents = await api("/incidents");
  const retention = await api("/retention-controls");
  state.reviews = reviews.items || [];
  state.incidents = incidents.items || [];
  state.retentionControls = retention.items || [];
  if (["ADMIN", "AUDITOR"].includes(state.role)) {
    const checkpoints = await api("/audit/checkpoints");
    state.checkpoints = checkpoints.items || [];
  }
  renderOperationsControlPlane();
}

async function createIncident(event) {
  event.preventDefault();
  $("#incident-error").textContent = "";
  try {
    await api("/incidents", { method: "POST", body: JSON.stringify({ title: $("#incident-title").value.trim(), severity: $("#incident-severity").value, resource_id: $("#incident-resource").value.trim(), summary: $("#incident-summary").value.trim() }) });
    event.currentTarget.reset();
    await loadOperationsControlPlane();
    showToast("Security incident recorded.");
  } catch (error) { $("#incident-error").textContent = error.message; }
}

async function saveRetentionControl(event) {
  event.preventDefault();
  $("#retention-error").textContent = "";
  try {
    await api("/retention-controls", { method: "PUT", body: JSON.stringify({ resource_id: $("#retention-resource").value.trim(), retention_days: Number($("#retention-days").value), legal_hold: $("#retention-legal-hold").checked }) });
    await loadOperationsControlPlane();
    showToast("Retention control saved.");
  } catch (error) { $("#retention-error").textContent = error.message; }
}

async function createAuditCheckpoint() {
  try {
    await api("/audit/checkpoints", { method: "POST" });
    await loadOperationsControlPlane();
    showToast("Audit-head checkpoint signed and verified.");
  } catch (error) { showToast(error.message, true); }
}

async function transitionIncident(button) {
  const status = button.dataset.incidentStatus;
  try {
    await api(`/incidents/${encodeURIComponent(button.dataset.incidentId)}`, { method: "PATCH", body: JSON.stringify({ status, note: `Transitioned to ${status} from the DataSentinel operations console.` }) });
    await loadOperationsControlPlane();
    showToast(`Incident moved to ${humanize(status)}.`);
  } catch (error) { showToast(error.message, true); }
}

async function loadAll(showMessage = false) {
  const initialLoad = !state.hasLoaded;
  $("#overview-error").hidden = true;
  if (initialLoad) $("#overview-loading").hidden = false;
  $("#refresh-button").disabled = true;
  $("#refresh-label").textContent = "Refreshing…";
  $("#main-content").setAttribute("aria-busy", "true");
  try {
    // The Learner Lab API Lambda is intentionally capped at two concurrent executions.
    // Sequential reads keep the console reliable during cold starts and shared demos.
    const summary = await api("/dashboard/summary");
    const files = await api("/files");
    const audit = await api("/audit");
    const accessEvents = await api("/access-events");
    const posture = await api("/posture");
    const systemStatus = await api("/system/status");
    const requests = await api("/access-requests");
    const capabilities = await api("/capabilities");
    const policies = await api("/policies");
    const analytics = await api("/analytics");
    state.files = files.items || [];
    state.fileTotal = Number(files.total_count ?? state.files.length);
    state.filesTruncated = Boolean(files.truncated);
    renderSummary(summary);
    renderFiles();
    renderAudit(audit);
    renderAccessEvents(accessEvents);
    renderPosture(posture);
    renderSystemStatus(systemStatus);
    renderAccessRequests(requests, capabilities);
    renderPolicyStudio(policies, analytics);
    await loadOperationsControlPlane();
    await loadIntegrationControlPlane();
    $("#overview-loading").hidden = true;
    $("#overview-content").hidden = false;
    state.hasLoaded = true;
    if (showMessage) showToast("Governance evidence refreshed.");
  } catch (error) {
    $("#overview-loading").hidden = true;
    $("#classifier-state").textContent = "Evidence unavailable";
    if (initialLoad) {
      $("#overview-error-message").textContent = `${error.message} Check the service and try again.`;
      $("#overview-error").hidden = false;
    } else if (state.token) {
      showToast(`${error.message} Existing evidence remains visible.`, true);
    }
  } finally {
    $("#refresh-button").disabled = false;
    $("#refresh-label").textContent = "Refresh";
    $("#main-content").removeAttribute("aria-busy");
  }
}

function switchView(name, moveFocus = false, historyMode = "push") {
  if (!titles[name]) return;
  const experience = roleExperiences[state.role] || roleExperiences.REVIEWER;
  if (state.hasLoaded && !experience.nav.includes(name)) name = "overview";
  $$(".view").forEach(view => { view.hidden = view.id !== `${name}-view`; view.classList.toggle("active", view.id === `${name}-view`); });
  $$(".nav-item").forEach(button => { const active = button.dataset.view === name; button.classList.toggle("active", active); active ? button.setAttribute("aria-current", "page") : button.removeAttribute("aria-current"); });
  const viewTitle = name === "overview" ? experience.title : titles[name];
  $("#view-title").textContent = viewTitle;
  $("#view-description").textContent = name === "overview" ? experience.description : descriptions[name];
  document.title = `${viewTitle} · DataSentinel`;
  if (location.hash !== `#${name}`) {
    const method = historyMode === "replace" ? "replaceState" : "pushState";
    history[method]({ view: name }, "", `#${name}`);
  }
  if (moveFocus) $("#view-title").focus({ preventScroll: true });
  if (window.innerWidth < 760) {
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" });
  }
}

async function lockConsole(notify = true) {
  state.token = "";
  if (state.hasLoaded) {
    try {
      const csrf = document.cookie.split('; ').find(item => item.startsWith('ds_csrf='))?.split('=').slice(1).join('=');
      await fetch("/auth/logout", { method: "POST", credentials: "same-origin", headers: csrf ? {"X-CSRF-Token": decodeURIComponent(csrf)} : {} });
    } catch {
      // The browser is still locked locally when the network is unavailable.
    }
  }
  if (!$("#auth-dialog").open) $("#auth-dialog").showModal();
  if (notify) showToast("Console locked.");
}

function intelligencePanel(findings) {
  const intelligence = findings?.pii_intelligence;
  if (!intelligence?.summary || !Array.isArray(intelligence.findings)) return "";
  const summary = intelligence.summary;
  const severityOptions = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const cards = [
    ["PII risk", `${escapeHtml(summary.risk || "LOW")} · ${Number(summary.risk_score || 0)}/100`],
    ["Unique findings", Number(summary.unique_findings || 0)],
    ["PII density", `${(Number(summary.pii_density || 0) * 100).toFixed(1)}%`],
    ["Record clusters", Number(summary.record_clusters || 0)],
  ].map(([label, value]) => `<div><span>${label}</span><strong>${value}</strong></div>`).join("");
  const rows = intelligence.findings.map(finding => `<li data-intelligence-finding data-severity="${escapeHtml(finding.severity || "LOW")}" data-search="${escapeHtml(`${finding.entity_type || ""} ${finding.category || ""} ${finding.context || ""}`.toLowerCase())}"><div><span class="finding-severity finding-severity-${escapeHtml((finding.severity || "LOW").toLowerCase())}">${escapeHtml(finding.severity || "LOW")}</span><strong>${escapeHtml(humanize(finding.entity_type || "Sensitive signal"))}</strong><code>${escapeHtml(finding.masked_value || "[PROTECTED]")}</code></div><p>${escapeHtml((finding.explanation || ["Sensitive structure and context were detected."])[0])}</p><small>${Math.round(Number(finding.confidence || 0) * 100)}% confidence · line ${Number(finding.line || 0)}, column ${Number(finding.column || 0)} · ${escapeHtml((finding.methods || []).map(humanize).join(" + "))}</small></li>`).join("");
  return `<section class="intelligence-panel"><div class="intelligence-heading"><div><p class="eyebrow">PII intelligence</p><h3>Masked findings and reasons</h3></div><span>Raw values are never sent to this view</span></div><div class="intelligence-summary">${cards}</div><div class="finding-toolbar"><label>Severity<select data-finding-severity>${severityOptions.map(option => `<option value="${option}">${humanize(option)}</option>`).join("")}</select></label><label>Search findings<input data-finding-search type="search" placeholder="Type, category or context"></label></div><ul class="finding-list">${rows || "<li class='empty-state'>No detailed findings were recorded for this legacy classification.</li>"}</ul></section>`;
}

function bindIntelligenceFilters(container) {
  const severity = $("[data-finding-severity]", container);
  const search = $("[data-finding-search]", container);
  if (!severity || !search) return;
  const apply = () => {
    const query = search.value.trim().toLowerCase();
    $$('[data-intelligence-finding]', container).forEach(item => {
      item.hidden = (severity.value !== "ALL" && item.dataset.severity !== severity.value)
        || (query && !item.dataset.search.includes(query));
    });
  };
  severity.addEventListener("change", apply);
  search.addEventListener("input", apply);
}

async function showDetails(resourceId) {
  const dialog = $("#detail-dialog");
  $("#detail-content").innerHTML = "<div class='loading-panel'>Loading resource evidence…</div>";
  dialog.showModal();
  try {
    const item = await api(`/files/risk?resource_id=${encodeURIComponent(resourceId)}`);
    const actions = item.governance_actions || {};
    const rawRiskScore = Number(item.risk_score || 0);
    const riskScore = Math.round(rawRiskScore <= 1 ? rawRiskScore * 100 : rawRiskScore);
    $("#detail-title").textContent = item.findings?.display_filename || resourceParts(resourceId).name;
    const protectedButton = item.protected_copy_available
      ? `<button class="button button-primary" type="button" data-file-access="protected" data-resource="${escapeHtml(resourceId)}">Open protected copy</button>`
      : `<button class="button button-secondary" type="button" disabled>Protected copy unavailable</button>`;
    const originalButton = "";
    const accessNote = "Original-file server access is disabled. Ask the sender if unredacted information is required; DataSentinel only provides the protected copy and content-free evidence.";
    const explanation = item.explanation || {};
    const signals = (explanation.detected_signal_types || []).map(signal => `<span>${escapeHtml(signalLabel(signal))}</span>`).join("");
    $("#detail-content").innerHTML = `<p class="resource-path">${escapeHtml(resourceId)}</p><div class="detail-grid"><div class="detail-item"><span>Document type</span><strong>${documentTypeTag(item)}</strong><small>${Math.round(Number(item.findings?.document_type?.confidence || 0) * 100)}% category confidence</small></div><div class="detail-item"><span>Sensitivity</span><strong>${sensitivityTag(item.sensitivity)}</strong></div><div class="detail-item"><span>Confidence</span><strong>${Math.round(Number(item.confidence_score || 0) * 100)}%</strong></div><div class="detail-item"><span>Review priority</span><strong>${riskTag(item.risk_level)} · ${riskScore}/100</strong><small>Sensitivity baseline; exposure and access breadth are not yet measured.</small></div><div class="detail-item"><span>Status</span><strong>${escapeHtml(humanize(item.compliance_status))}</strong></div><div class="detail-item"><span>Signals</span><strong>${escapeHtml(item.findings?.pattern_matches_count || 0)} validated patterns</strong></div><div class="detail-item"><span>Classified</span><strong>${escapeHtml(formatDate(item.timestamp))}</strong></div></div>${intelligencePanel(item.findings)}<section class="decision-explanation"><div><p class="eyebrow">Why DataSentinel decided this</p><h3>${escapeHtml(explanation.policy_id || "Recorded classifier policy")} <small>v${escapeHtml(explanation.policy_version || "current")}</small></h3></div><p>${escapeHtml(explanation.rationale || "No classification explanation was recorded for this legacy result.")}</p>${signals ? `<div class="signal-list" aria-label="Detected signal types">${signals}</div>` : ""}<small>Signal types are shown without disclosing detected values.</small></section><div class="evidence-access"><p class="eyebrow">Document access</p><p>${escapeHtml(accessNote)}</p><div class="evidence-actions">${protectedButton}${originalButton}<button class="button button-secondary" type="button" data-evidence-pack data-resource="${escapeHtml(resourceId)}">Download evidence pack</button></div></div><p class="eyebrow">Governance actions</p><ul class="control-list">${Object.entries(actions).filter(([,done]) => done === true).map(([name]) => `<li>${escapeHtml(humanize(name))}</li>`).join("") || "<li>No action evidence recorded</li>"}</ul>`;
    bindIntelligenceFilters($("#detail-content"));
    if (item.sensitivity === "UNKNOWN" && ["ADMIN", "DATA_OWNER"].includes(state.role)) {
      $(".evidence-actions", $("#detail-content")).insertAdjacentHTML("beforeend", `<button class="button button-secondary" type="button" data-reprocess data-resource="${escapeHtml(resourceId)}">Reprocess with current policy</button>`);
    }
  } catch (error) {
    $("#detail-content").innerHTML = `<div class="empty-state"><strong>Unable to load details</strong><span>${escapeHtml(error.message)}</span></div>`;
  }
}

async function reprocessResource(resourceId) {
  try {
    await api("/files/reprocess", { method: "POST", body: JSON.stringify({ resource_id: resourceId, reason: "Re-run after manual review with the current classifier and policy version." }) });
    $("#detail-dialog").close();
    showToast("Reprocessing queued. Existing classification history is preserved.");
    await loadAll(false);
  } catch (error) {
    showToast(error.message, true);
  }
}

function openAccessRequest(resourceId) {
  state.requestedResource = resourceId;
  $("#request-resource").textContent = resourceId;
  $("#request-justification").value = "";
  $("#request-error").textContent = "";
  $("#detail-dialog").close();
  $("#request-dialog").showModal();
}

async function submitAccessRequest(event) {
  event.preventDefault();
  const button = $("#request-submit");
  button.disabled = true;
  $("#request-error").textContent = "";
  try {
    const item = await api("/access-requests", { method: "POST", body: JSON.stringify({ resource_id: state.requestedResource, justification: $("#request-justification").value.trim() }) });
    $("#request-dialog").close();
    showToast(item.status === "APPROVED" ? "Original access approved for 15 minutes." : "Request submitted to the decision queue.");
    await loadAll();
    switchView("requests", true);
  } catch (error) { $("#request-error").textContent = error.message; }
  finally { button.disabled = false; }
}

async function decideAccessRequest(requestId, decision) {
  try {
    await api(`/access-requests/${encodeURIComponent(requestId)}`, { method: "PATCH", body: JSON.stringify({ decision, note: `${humanize(decision)} from the DataSentinel console.` }) });
    showToast(decision === "APPROVE" ? "Access approved for 15 minutes." : "Access request rejected.");
    await loadAll();
  } catch (error) { showToast(error.message, true); }
}

async function openFileCopy(resourceId, variant) {
  const preview = window.open("", "_blank");
  if (preview) {
    preview.opener = null;
    preview.document.title = "Preparing secure document";
    preview.document.body.textContent = "Preparing a short-lived secure link…";
  }
  try {
    const payload = await api(`/files/download?resource_id=${encodeURIComponent(resourceId)}&variant=${encodeURIComponent(variant)}&disposition=inline`);
    if (preview) preview.location.replace(payload.url);
    else window.location.assign(payload.url);
    if (payload.access_event) {
      const current = state.accessEvents.filter(event => event.correlation_id !== payload.access_event.correlation_id);
      renderAccessEvents({ items: [payload.access_event, ...current], count: current.length + 1 });
    }
    const evidence = ` Evidence ${String(payload.correlation_id || "").slice(0, 8)}.`;
    showToast((variant === "original" ? "Administrator original-file access granted for 2 minutes." : "Protected copy opened with a 2-minute link.") + evidence);
  } catch (error) {
    if (preview) preview.close();
    showToast(error.message, true);
  }
}

async function downloadProtectedCopy(resourceId) {
  const payload = await api(`/files/download?resource_id=${encodeURIComponent(resourceId)}&variant=protected&disposition=attachment`);
  // The response is an attachment, so navigating to the short-lived URL starts
  // the browser download without exposing the original document.
  window.location.assign(payload.url);
  if (payload.access_event) {
    const current = state.accessEvents.filter(event => event.correlation_id !== payload.access_event.correlation_id);
    renderAccessEvents({ items: [payload.access_event, ...current], count: current.length + 1 });
  }
}

async function uploadFile(event) {
  event.preventDefault();
  const file = $("#file-input").files[0];
  const errorNode = $("#upload-error");
  errorNode.textContent = "";
  if (!file) { errorNode.textContent = "Choose a supported file first."; return; }
  if (file.size > 5 * 1024 * 1024) { errorNode.textContent = "File exceeds the 5 MB dashboard limit."; return; }
  $("#upload-submit").disabled = true;
  $("#upload-progress").hidden = false;
  $("#upload-stage").textContent = "Preparing a short-lived secure upload…";
  try {
    const mimeByExtension = { txt: "text/plain", csv: "text/csv", json: "application/json", pdf: "application/pdf", md: "text/markdown", log: "text/plain", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", html: "text/html", htm: "text/html", xml: "application/xml", yaml: "application/yaml", yml: "application/yaml", ini: "text/plain", cfg: "text/plain" };
    const extension = file.name.split(".").pop().toLowerCase();
    const contentType = mimeByExtension[extension] || file.type || "application/octet-stream";
    const request = await api("/uploads/presign", { method: "POST", body: JSON.stringify({ filename: file.name, content_type: contentType }) });
    const form = new FormData();
    Object.entries(request.form_fields).forEach(([name, value]) => form.append(name, value));
    form.append("file", file);
    let upload;
    try {
      $("#upload-stage").textContent = "Transferring the file to the private raw-data zone…";
      upload = await fetch(request.upload_url, { method: "POST", body: form });
    } catch (error) {
      if (error instanceof TypeError) {
        throw new Error("The secure storage connection was blocked. Refresh and try again; if it continues, contact the administrator.");
      }
      throw error;
    }
    if (!upload.ok) throw new Error(`S3 upload failed (${upload.status}).`);
    $("#upload-stage").textContent = "Classifying content and creating the protected copy…";
    let classification = null;
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      try {
        classification = await api(`/files/risk?resource_id=${encodeURIComponent(request.resource_id)}`);
        break;
      } catch (error) {
        if (error.status !== 404) throw error;
      }
      await sleep(2000);
    }
    $("#upload-dialog").close();
    $("#upload-form").reset();
    $("#file-label").textContent = "Choose a file";
    await loadAll(false);
    if (classification) {
      switchView("inventory");
      showToast(`${humanize(classification.sensitivity)} classification complete. Protected copy is ready.`);
      if (classification.protected_copy_available === true) {
        try {
          await downloadProtectedCopy(request.resource_id);
          showToast("Protected copy download started.");
        } catch (error) {
          showToast(`Protected copy is ready, but automatic download could not start: ${error.message}`, true);
        }
      }
    } else {
      showToast("Upload accepted. Processing is taking longer than usual; refresh shortly.");
    }
  } catch (error) {
    errorNode.textContent = error.message;
  } finally {
    $("#upload-submit").disabled = false;
    $("#upload-progress").hidden = true;
    $("#upload-stage").textContent = "";
  }
}

async function initialise() {
  try {
    const configResponse = await fetch("/config");
    if (!configResponse.ok) throw new Error(`Configuration request failed (${configResponse.status}).`);
    state.config = await configResponse.json();
    const environment = `${state.config.environment} · ${state.config.region}`.toUpperCase();
    $("#environment-badge").innerHTML = `<span class="environment-dot"></span>${escapeHtml(environment)}`;
    const privacyMode = $("#privacy-mode");
    if (state.config.service_mode === "ephemeral_redaction") {
      privacyMode.textContent = "Privacy mode: original uploads are deleted after processing";
      privacyMode.hidden = false;
    }
    $("#upload-button").disabled = !state.config.upload_enabled;
    $("#upload-button").title = state.config.upload_enabled ? "Upload a document for classification" : "Uploads are disabled in local demo mode";
    $("#auth-hint").textContent = "Use the temporary credentials supplied by the deployment administrator.";
  } catch {
    $("#classifier-state").textContent = "Service unreachable";
  }
  const requestedView = location.hash.slice(1);
  switchView(titles[requestedView] ? requestedView : "overview", false, "replace");
  await loadAll().catch(() => $("#auth-dialog").showModal());
}

$("#auth-form").addEventListener("submit", async event => {
  event.preventDefault();
  const username = $("#username-input").value.trim();
  const password = $("#password-input").value;
  $("#auth-error").textContent = "";
  $("#auth-submit").disabled = true;
  $("#auth-submit").textContent = "Signing in…";
  try {
    const response = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
      credentials: "same-origin"
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || "Sign-in failed.");
    state.token = "cookie";
    state.role = payload.access_role || "ADMIN";
    $("#auth-dialog").close();
    await loadAll();
  } catch (error) {
    state.token = "";
    $("#auth-error").textContent = error.message;
  } finally {
    $("#auth-submit").disabled = false;
    $("#auth-submit").textContent = "Open console";
  }
});

$("#upload-form").addEventListener("submit", uploadFile);
$("#request-form").addEventListener("submit", submitAccessRequest);
$("#policy-form").addEventListener("submit", runPolicySimulation);
$("#incident-form").addEventListener("submit", createIncident);
$("#retention-form").addEventListener("submit", saveRetentionControl);
$("#checkpoint-create").addEventListener("click", createAuditCheckpoint);
$("#api-client-form").addEventListener("submit", createApiClient);
$("#webhook-form").addEventListener("submit", saveWebhook);
$("#api-secret-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("#api-secret-value").textContent);
    showToast(`${humanize($("#api-secret-copy").dataset.secretLabel)} copied.`);
  } catch { showToast("Copy was blocked. Select the value and copy it manually.", true); }
});
$("#file-input").addEventListener("change", event => { $("#file-label").textContent = event.target.files[0]?.name || "Choose a file"; });
$("#refresh-button").addEventListener("click", () => loadAll(true));
$("#retry-button").addEventListener("click", () => loadAll());
$("#upload-button").addEventListener("click", () => $("#upload-dialog").showModal());
$("#demo-guide-button").addEventListener("click", () => $("#demo-guide-dialog").showModal());
$("#lock-button").addEventListener("click", () => lockConsole());
$("#sidebar-toggle").addEventListener("click", () => {
  setSidebarCollapsed(!$(".app-shell").classList.contains("sidebar-collapsed"));
});
$("#toggle-password").addEventListener("click", () => {
  const input = $("#password-input");
  const visible = input.type === "text";
  input.type = visible ? "password" : "text";
  $("#toggle-password").textContent = visible ? "Show" : "Hide";
  $("#toggle-password").setAttribute("aria-label", visible ? "Show password" : "Hide password");
  input.focus();
});
$("#auth-dialog").addEventListener("cancel", event => event.preventDefault());
$("#resource-search").addEventListener("input", filterInventory);
$("#sensitivity-filter").addEventListener("change", filterInventory);
$("#document-type-filter").addEventListener("change", filterInventory);
window.addEventListener("popstate", () => switchView(location.hash.slice(1), false, "replace"));
document.addEventListener("click", event => {
  const demoAction = event.target.closest("[data-demo-action]");
  if (demoAction) {
    $("#demo-guide-dialog").close();
    if (demoAction.dataset.demoAction === "upload") $("#upload-dialog").showModal();
    else switchView(demoAction.dataset.demoAction, true);
  }
  const reviewQueue = event.target.closest("[data-review-queue]");
  if (reviewQueue) {
    $("#sensitivity-filter").value = "REVIEW";
    filterInventory();
    switchView("inventory", true);
  }
  const typeCard = event.target.closest("[data-document-type]");
  if (typeCard) {
    $("#document-type-filter").value = typeCard.dataset.documentType;
    filterInventory();
    switchView("inventory", true);
  }
  const rolePrimary = event.target.closest("[data-role-primary]");
  if (rolePrimary) {
    if (state.role === "REVIEWER") $("#sensitivity-filter").value = "REVIEW";
    filterInventory();
    switchView(rolePrimary.dataset.targetView || "overview", true);
  }
  const nav = event.target.closest("[data-view], [data-go-view]");
  if (nav) switchView(nav.dataset.view || nav.dataset.goView, true);
  const details = event.target.closest("[data-resource]");
  if (details?.hasAttribute("data-evidence-pack")) downloadEvidencePack(details.dataset.resource);
  else if (details?.hasAttribute("data-request-access")) openAccessRequest(details.dataset.resource);
  else if (details?.hasAttribute("data-reprocess")) reprocessResource(details.dataset.resource);
  else if (details?.dataset.fileAccess) openFileCopy(details.dataset.resource, details.dataset.fileAccess);
  else if (details) showDetails(details.dataset.resource);
  const decision = event.target.closest("[data-request-decision]");
  if (decision) decideAccessRequest(decision.dataset.requestId, decision.dataset.requestDecision);
  const incident = event.target.closest("[data-incident-id]");
  if (incident) transitionIncident(incident);
  const webhook = event.target.closest("[data-client-webhook]");
  if (webhook) openWebhookDialog(webhook);
  const rotateClient = event.target.closest("[data-client-rotate]");
  if (rotateClient) rotateApiClient(rotateClient.dataset.tenantId, rotateClient.dataset.clientId);
  const revokeClient = event.target.closest("[data-client-revoke]");
  if (revokeClient) revokeApiClient(revokeClient.dataset.tenantId, revokeClient.dataset.clientId);
  const close = event.target.closest("[data-close-dialog]");
  if (close) $(`#${close.dataset.closeDialog}`).close();
});

setSidebarCollapsed(sessionStorage.getItem("sidebarCollapsed") === "true");
initialise();
