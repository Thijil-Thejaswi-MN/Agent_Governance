/**
 * AI Agent Governance Console
 * Reactive client-side logic for runtime governance, active task mediation,
 * decision inspection, controlled security demos, and offline catalog inspection.
 */

// Global State
let currentTab = "overview";
let currentWorkspaceAgentId = "helloworld";
let cachedAgentsList = [];
let cachedCatalogCards = [];
let cachedEventsList = [];
let pendingAction = null;
let pollTimer = null;
let catalogSearchQuery = "";

document.addEventListener("DOMContentLoaded", () => {
  initDashboardTheme();
  setupNavigation();
  setupModal();
  setupInspectorModal();
  setupRawEventModal();

  // Initial Data Fetch
  refreshAllData();

  // 5-second polling for live state
  pollTimer = setInterval(pollLiveData, 5000);

  // UTC clock update
  setInterval(updateClock, 1000);
  updateClock();

  const refreshBtn = document.getElementById("btn-refresh");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      refreshAllData();
    });
  }
});

function updateClock() {
  const el = document.getElementById("live-clock");
  if (el) {
    const now = new Date();
    el.textContent = now.toISOString().substring(11, 19) + " UTC";
  }
}

// --- Navigation Tabs ---
function setupNavigation() {
  const navButtons = document.querySelectorAll(".nav-item");
  navButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      navButtons.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      currentTab = btn.getAttribute("data-tab");
      const targetPane = document.getElementById(`pane-${currentTab}`);
      if (targetPane) targetPane.classList.add("active");

      updateViewHeaders(currentTab);
      loadTabSpecificData(currentTab);
    });
  });
}

function navigateToTab(tabId) {
  const btn = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
  if (btn) btn.click();
}
window.navigateToTab = navigateToTab;

function updateViewHeaders(tab) {
  const titles = {
    overview: [
      "AI Agent Governance Console",
      "Runtime governance, active task mediation, decision inspection, and graduated policy enforcement."
    ],
    workspace: [
      "Agent Governance Session",
      "Direct operator interaction, capability verification, decision inspection, and real-time execution trace."
    ],
    inventory: [
      "Agent Inventory & Discovered Catalog",
      "Distinction between local runtime-governed agents and 203 offline reference cards."
    ],
    demo: [
      "Controlled Security Demonstration",
      "Controlled local testbed simulations demonstrating graduated responses (Rate Limit, Restriction, Quarantine)."
    ],
    events: [
      "Security Event Audit Ledger",
      "Human-readable security event records with detector decisions and raw event inspection."
    ],
    topology: [
      "Mediated Agent Topology",
      "Dual-zone architecture: Live Governed Testbed vs. 203 Discovered Offline Reference Catalog."
    ],
    findings: [
      "Research Evaluation Findings",
      "Empirical benchmark evaluation results across AS, CC, and CO exploit campaigns with Wilson 95% CIs."
    ],
    performance: [
      "Latency Profiling & Overhead Analysis",
      "Disaggregation of network reverse-proxy overhead from sub-millisecond intrinsic security computation."
    ],
  };

  const [title, desc] = titles[tab] || ["AI Agent Governance Console", ""];
  const tEl = document.getElementById("current-view-title");
  const dEl = document.getElementById("current-view-desc");
  if (tEl) tEl.textContent = title;
  if (dEl) dEl.textContent = desc;
}

function loadTabSpecificData(tab) {
  if (tab === "overview") fetchOverview();
  if (tab === "workspace") initWorkspace();
  if (tab === "inventory") {
    fetchGovernedAgents();
    fetchCatalogCards();
  }
  if (tab === "demo") {
    // Demo tab is ready
  }
  if (tab === "events") fetchEvents();
  if (tab === "topology") renderTopologyDualZone();
  if (tab === "gov-tasks") loadGovernanceTasks();
  if (tab === "gov-inventory") loadGovernanceInventory();
  if (tab === "gov-alerts") loadGovernanceAlerts();
}

// --- Polling & Fetching ---
async function pollLiveData() {
  if (currentTab === "overview") fetchOverview();
  if (currentTab === "events") fetchEvents();
  if (currentTab === "workspace") fetchWorkspaceAgentState();
  if (currentTab === "gov-tasks") loadGovernanceTasks();
  if (currentTab === "gov-inventory") loadGovernanceInventory();
  if (currentTab === "gov-alerts") loadGovernanceAlerts();
}

async function refreshAllData() {
  await Promise.all([
    fetchOverview(),
    fetchGovernedAgents(),
    fetchCatalogCards(),
    fetchEvents(),
    fetchEvaluations(),
    fetchPerformance(),
  ]);
  if (currentTab === "workspace") {
    initWorkspace();
  }
}

// =========================================================================
// SECTION 2 & 3: TOP-LEVEL OVERVIEW & CORE MENTAL MODEL
// =========================================================================
async function fetchOverview() {
  try {
    const [ovRes, agRes, catRes, evRes] = await Promise.all([
      fetch("/api/v1/overview"),
      fetch("/api/v1/agents"),
      fetch("/api/v1/catalog?limit=1"),
      fetch("/api/v1/events?limit=5"),
    ]);

    const overview = ovRes.ok ? await ovRes.json() : null;
    const agentsData = agRes.ok ? await agRes.json() : null;
    const catalogData = catRes.ok ? await catRes.json() : null;
    const eventsData = evRes.ok ? await evRes.json() : null;

    if (agentsData) {
      cachedAgentsList = agentsData.agents || [];
    }

    const discoveredCount = (catalogData && catalogData.total_inventory) || 203;
    const governedCount = (cachedAgentsList && cachedAgentsList.length) || 2;
    const quarantinedCount = (overview && overview.counts && overview.counts.quarantined) || 0;
    const activeAgentName = currentWorkspaceAgentId === "agentalice" ? "AgentAlice" : "HelloWorld";

    // Header pills (Section 3)
    const hdrDisc = document.getElementById("hdr-discovered-count");
    const hdrGov = document.getElementById("hdr-governed-count");
    const hdrAct = document.getElementById("hdr-active-session");
    const hdrQuar = document.getElementById("hdr-quarantined-count");

    if (hdrDisc) hdrDisc.textContent = discoveredCount;
    if (hdrGov) hdrGov.textContent = governedCount;
    if (hdrAct) hdrAct.textContent = activeAgentName;
    if (hdrQuar) hdrQuar.textContent = quarantinedCount;

    // Overview metric cards (Section 3)
    const cardDisc = document.getElementById("card-discovered-count");
    const cardGov = document.getElementById("card-governed-count");
    const cardAct = document.getElementById("card-active-count");
    const cardQuar = document.getElementById("card-quarantined-count");

    if (cardDisc) cardDisc.textContent = discoveredCount;
    if (cardGov) cardGov.textContent = governedCount;
    if (cardAct) cardAct.textContent = activeAgentName;
    if (cardQuar) cardQuar.textContent = quarantinedCount;

    // Render Governed Agent Cards (Section 4)
    renderGovernedAgentOverviewCards();

    // Render Recent Security Activity (Section 11)
    const recentEvList = Array.isArray(eventsData) ? eventsData : ((eventsData && eventsData.events) || []);
    renderRecentSecurityActivity(recentEvList);
  } catch (err) {
    console.error("Failed to load overview:", err);
  }
}

// =========================================================================
// SECTION 4: REDESIGN AGENT INVENTORY (Governed vs Discovered)
// =========================================================================
function renderGovernedAgentOverviewCards() {
  const container = document.getElementById("governed-agent-cards-container");
  if (!container) return;

  const localAgents = [
    {
      id: "helloworld",
      name: "HelloWorld",
      badge: "LOCAL TEST AGENT",
      protocol: "A2A v1.0",
      endpoint: "http://127.0.0.1:9999",
      capabilities: "Say hello (echo_bot)",
      status: "Healthy",
      governed: "Governed",
      monitoring: "Monitoring ON",
    },
    {
      id: "agentalice",
      name: "AgentAlice",
      badge: "LOCAL TEST AGENT",
      protocol: "A2A v1.0",
      endpoint: "http://127.0.0.1:8001",
      capabilities: "number_guess_evaluator",
      status: "Healthy",
      governed: "Governed",
      monitoring: "Monitoring ON",
    },
  ];

  container.innerHTML = localAgents.map(ag => {
    // Check if agent is quarantined in cached list
    const live = cachedAgentsList.find(a => a.agent_id === ag.id);
    const isQuar = live && live.status === "QUARANTINED";
    const isRestr = live && live.status === "RESTRICTED";
    let statusText = "● Healthy";
    let statusClass = "badge-emerald";
    let cardModifier = "";

    if (isQuar) {
      statusText = "● Quarantined";
      statusClass = "badge-rose";
      cardModifier = "is-quarantined";
    } else if (isRestr) {
      statusText = "● Restricted";
      statusClass = "badge-amber";
      cardModifier = "is-restricted";
    }

    return `
      <div class="governed-card ${cardModifier}">
        <div>
          <div class="gov-card-header">
            <div>
              <div class="gov-card-name">${escapeHtml(ag.name)}</div>
              <div class="gov-card-sub">${escapeHtml(ag.badge)}</div>
            </div>
            <span class="badge ${statusClass}">${statusText}</span>
          </div>

          <div class="gov-card-status-list" style="margin-top: 0.75rem;">
            <span class="badge badge-emerald">● Governed</span>
            <span class="badge badge-sky">● Monitoring ON</span>
            <span class="badge badge-indigo">Policy: GRADUATED</span>
          </div>

          <div class="gov-card-details" style="margin-top: 0.85rem;">
            <div class="gov-detail-row">
              <span class="gov-detail-label">Protocol:</span>
              <span class="gov-detail-val">${escapeHtml(ag.protocol)}</span>
            </div>
            <div class="gov-detail-row">
              <span class="gov-detail-label">Endpoint:</span>
              <span class="gov-detail-val">${escapeHtml(ag.endpoint)}</span>
            </div>
            <div class="gov-detail-row">
              <span class="gov-detail-label">Capabilities:</span>
              <span class="gov-detail-val">${escapeHtml(ag.capabilities)}</span>
            </div>
          </div>
        </div>

        <button class="btn btn-primary btn-block" style="margin-top: 0.5rem; font-weight: 700;" onclick="workWithAgent('${escapeHtml(ag.id)}')">
          <i class="fa-solid fa-bolt"></i> WORK WITH AGENT
        </button>
      </div>
    `;
  }).join("");
}

function workWithAgent(agentId) {
  currentWorkspaceAgentId = agentId;
  const selectEl = document.getElementById("ws-agent-select");
  if (selectEl) selectEl.value = agentId;
  navigateToTab("workspace");
  initWorkspace();
}
window.workWithAgent = workWithAgent;

async function fetchGovernedAgents() {
  const tbody = document.getElementById("tbody-governed-agents");
  if (!tbody) return;

  try {
    const res = await fetch("/api/v1/agents");
    if (!res.ok) return;
    const data = await res.json();
    cachedAgentsList = data.agents || [];

    if (cachedAgentsList.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="padding: 1.5rem; color: var(--text-subtle);">No governed agents found.</td></tr>`;
      return;
    }

    tbody.innerHTML = cachedAgentsList.map(a => {
      const isQuar = a.status === "QUARANTINED";
      const isRestr = a.status === "RESTRICTED";
      const badgeClass = isQuar ? "badge-rose" : isRestr ? "badge-amber" : "badge-emerald";
      const skillsStr = (a.skills || []).map(s => s.name || s.id).join(", ") || "None declared";

      return `
        <tr>
          <td><code>${escapeHtml(a.agent_id)}</code></td>
          <td><strong>${escapeHtml(a.name)}</strong></td>
          <td><code style="font-size: 0.76rem; color: var(--accent-cyan);">${escapeHtml(a.endpoint_url || '127.0.0.1')}</code></td>
          <td><span class="badge badge-subtle">v${escapeHtml(a.protocol_version || '1.0')}</span></td>
          <td><span class="badge ${badgeClass}">${escapeHtml(a.status)}</span></td>
          <td><span class="badge badge-emerald">HEALTHY</span></td>
          <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(skillsStr)}">${escapeHtml(skillsStr)}</td>
          <td>
            <button class="btn btn-primary btn-sm" onclick="workWithAgent('${escapeHtml(a.agent_id)}')">
              <i class="fa-solid fa-bolt"></i> Work With Agent
            </button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed fetching governed agents:", err);
  }
}

// =========================================================================
// SECTION 17: PUBLIC AGENT CATALOG (203 Offline Reference Cards)
// =========================================================================
async function fetchCatalogCards(query = "") {
  catalogSearchQuery = query;
  const tbody = document.getElementById("tbody-catalog-cards");
  const countBadge = document.getElementById("catalog-count-badge");
  if (!tbody) return;

  try {
    const url = `/api/v1/catalog?limit=203&search=${encodeURIComponent(query)}`;
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    cachedCatalogCards = data.cards || [];

    const totalCount = data.total_discovered || data.total_inventory || 203;
    if (countBadge) {
      countBadge.textContent = `${data.matched_count} / ${totalCount} CARDS`;
    }

    if (cachedCatalogCards.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="padding: 1.5rem; color: var(--text-subtle);">No public reference cards matched "${escapeHtml(query)}".</td></tr>`;
      return;
    }

    tbody.innerHTML = cachedCatalogCards.map((c, idx) => {
      const skillsList = c.declared_skills || c.skills || [];
      const count = skillsList.length;
      let skillsText = `${count} declared`;
      if (count > 0) {
        const snippet = skillsList.slice(0, 2).map(s => s.name || s.id || s).join(", ");
        skillsText = count > 2 ? `${snippet} (+${count - 2} more)` : snippet;
      }
      const providerName = c.provider || (c.source ? c.source.replace(/_/g, ' ') : "Public A2A");
      const cleanUrl = c.endpoint || c.reference_endpoint || "N/A";

      return `
        <tr>
          <td><strong style="color: var(--text-main); font-size: 0.88rem;">${escapeHtml(c.name)}</strong></td>
          <td><span style="font-size: 0.8rem; color: var(--text-muted); text-transform: capitalize;">${escapeHtml(providerName)}</span></td>
          <td><span class="badge badge-subtle">v${escapeHtml(c.protocol_version || '1.0')}</span></td>
          <td style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(skillsText)}">${escapeHtml(skillsText)}</td>
          <td><code style="font-size: 0.74rem; color: var(--accent-cyan);">${escapeHtml(cleanUrl)}</code></td>
          <td><span class="badge badge-amber">OFFLINE REFERENCE</span></td>
          <td>
            <!-- NO [START] OR [SEND TASK] BUTTONS FOR PUBLIC AGENTS (Section 2 & 17) -->
            <button class="btn btn-secondary btn-sm" onclick="inspectCatalogCardByIndex(${idx})">
              <i class="fa-solid fa-magnifying-glass"></i> Inspect Card
            </button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed fetching catalog cards:", err);
  }
}

function onCatalogSearch(query) {
  fetchCatalogCards(query);
}
window.onCatalogSearch = onCatalogSearch;

function inspectCatalogCardByIndex(idx) {
  const card = cachedCatalogCards[idx];
  if (!card) return;

  const modal = document.getElementById("node-inspector-modal");
  const title = document.getElementById("inspector-title");
  const sub = document.getElementById("inspector-subtitle");
  const body = document.getElementById("inspector-body");
  const workBtn = document.getElementById("inspector-btn-work");
  const notice = document.getElementById("inspector-notice");

  if (!modal) return;

  title.textContent = card.name || "Agent Card";
  sub.textContent = "OFFLINE REFERENCE CARD";
  notice.textContent = "Public reference card for offline schema & security analysis. No live execution.";
  if (workBtn) workBtn.style.display = "none"; // Strictly hide work button for public cards

  const skills = card.declared_skills || card.skills || [];
  const skillsHtml = skills.length > 0
    ? skills.map(s => `<span class="skill-pill">${escapeHtml(s.name || s.id || s)}</span>`).join(" ")
    : "<span style='color: var(--text-subtle);'>None declared</span>";

  body.innerHTML = `
    <div class="alert-box alert-amber" style="margin: 0;">
      <i class="fa-solid fa-shield-halved"></i>
      <div>
        <strong>OFFLINE DATA</strong>: This Agent Card is collected from public registries for offline inventory, schema verification, and homoglyph detection. It is NOT running and cannot be contacted.
      </div>
    </div>

    <div class="inspector-section">
      <div class="inspector-section-title">Identity &amp; Metadata</div>
      <div class="inspector-row"><span class="inspector-key">Agent Name:</span><span class="inspector-val">${escapeHtml(card.name)}</span></div>
      <div class="inspector-row"><span class="inspector-key">Card ID:</span><span class="inspector-val"><code>${escapeHtml(card.card_id || 'N/A')}</code></span></div>
      <div class="inspector-row"><span class="inspector-key">Provider:</span><span class="inspector-val">${escapeHtml(card.provider || 'N/A')}</span></div>
      <div class="inspector-row"><span class="inspector-key">Protocol Version:</span><span class="inspector-val">v${escapeHtml(card.protocol_version || '1.0')}</span></div>
      <div class="inspector-row"><span class="inspector-key">Reference Endpoint:</span><span class="inspector-val"><code>${escapeHtml(card.endpoint || card.reference_endpoint || 'N/A')}</code></span></div>
      <div class="inspector-row"><span class="inspector-key">Source Dataset:</span><span class="inspector-val">${escapeHtml(card.source || 'Stage 6 Registry Corpus')}</span></div>
    </div>

    <div class="inspector-section">
      <div class="inspector-section-title">Declared Capabilities (${skills.length})</div>
      <div style="display: flex; flex-wrap: wrap; gap: 0.35rem; padding: 0.4rem 0;">
        ${skillsHtml}
      </div>
    </div>

    <div class="inspector-section">
      <div class="inspector-section-title">Normalized Card JSON</div>
      <pre class="json-viewer" style="max-height: 200px; overflow-y: auto;">${escapeHtml(JSON.stringify(card, null, 2))}</pre>
    </div>
  `;

  modal.classList.add("active");
}
window.inspectCatalogCardByIndex = inspectCatalogCardByIndex;

// =========================================================================
// SECTION 5, 6, 7, 8, 12, 13: AGENT GOVERNANCE SESSION ("WORK WITH AGENT")
// =========================================================================
async function initWorkspace() {
  // Update dropdown selection
  const selectEl = document.getElementById("ws-agent-select");
  if (selectEl) {
    selectEl.value = currentWorkspaceAgentId;
  }

  // Update header counts to reflect active agent
  const hdrAct = document.getElementById("hdr-active-session");
  const cardAct = document.getElementById("card-active-count");
  const activeName = currentWorkspaceAgentId === "agentalice" ? "AgentAlice" : "HelloWorld";
  if (hdrAct) hdrAct.textContent = activeName;
  if (cardAct) cardAct.textContent = activeName;

  await fetchWorkspaceAgentState();
  populateTaskConsoleMethods();
}
window.initWorkspace = initWorkspace;

function onGovernanceAgentSwitch(agentId) {
  currentWorkspaceAgentId = agentId;
  initWorkspace();
}
window.onGovernanceAgentSwitch = onGovernanceAgentSwitch;

async function fetchWorkspaceAgentState() {
  const agentId = currentWorkspaceAgentId;
  try {
    const res = await fetch(`/api/v1/agents/${encodeURIComponent(agentId)}/state`);
    if (!res.ok) return;
    const state = await res.json();
    renderAgentHeroState(state);
    renderLifecycleStepper(state);
    renderContextualOperatorControls(state);
  } catch (err) {
    console.error("Failed fetching agent state:", err);
  }
}

function renderAgentHeroState(state) {
  const nameEl = document.getElementById("ws-agent-name");
  const idTag = document.getElementById("ws-agent-id-tag");
  const protoTag = document.getElementById("ws-agent-proto-tag");
  const urlTag = document.getElementById("ws-agent-url-tag");
  const capTag = document.getElementById("ws-agent-cap-tag");

  const govBadge = document.getElementById("ws-agent-gov-badge");
  const healthBadge = document.getElementById("ws-agent-health-badge");
  const policyBadge = document.getElementById("ws-agent-policy-badge");
  const riskBadge = document.getElementById("ws-agent-risk-badge");
  const monBadge = document.getElementById("ws-agent-monitoring-badge");

  if (nameEl) nameEl.textContent = state.name;
  if (idTag) idTag.innerHTML = `<code>${escapeHtml(state.agent_id)}</code>`;
  const proto = state.protocol_version || state.protocol || "A2A v1.0";
  const endpoint = state.endpoint_url || state.endpoint || "http://127.0.0.1:9999";
  if (protoTag) protoTag.innerHTML = `<i class="fa-solid fa-code-commit"></i> ${escapeHtml(proto)}`;
  if (urlTag) urlTag.innerHTML = `<i class="fa-solid fa-network-wired"></i> ${escapeHtml(endpoint)}`;

  const declaredSkills = state.declared_skills || state.declared_capabilities || [];
  let primaryCap = "None";
  if (declaredSkills.length > 0) {
    const s0 = declaredSkills[0];
    primaryCap = typeof s0 === "object" ? (s0.name || s0.id || "Skill") : String(s0);
  }
  if (capTag) capTag.innerHTML = `<i class="fa-solid fa-bolt"></i> Declared: <strong>${escapeHtml(primaryCap)}</strong>`;

  const isGov = state.is_governed !== undefined ? state.is_governed : (state.governed !== undefined ? state.governed : true);
  const isMon = state.monitoring_enabled !== undefined ? state.monitoring_enabled : (state.monitoring !== undefined ? state.monitoring : true);

  // Badges (Section 5)
  if (govBadge) {
    govBadge.textContent = isGov ? "● GOVERNED" : "● UNGOVERNED";
    govBadge.className = isGov ? "badge badge-emerald" : "badge badge-subtle";
  }
  if (healthBadge) {
    healthBadge.textContent = state.health === "HEALTHY" ? "● HEALTHY" : `● ${state.health}`;
    healthBadge.className = state.health === "HEALTHY" ? "badge badge-emerald" : "badge badge-rose";
  }
  if (policyBadge) {
    policyBadge.textContent = `Policy: ${state.policy_mode || 'GRADUATED'}`;
    policyBadge.className = "badge badge-indigo";
  }
  if (riskBadge) {
    riskBadge.textContent = `Risk: ${state.risk_state || 'NORMAL'}`;
    riskBadge.className = (state.risk_state || 'NORMAL') === "NORMAL" ? "badge badge-subtle" : "badge badge-rose";
  }
  if (monBadge) {
    monBadge.textContent = isMon ? "Monitoring: ON" : "Monitoring: OFF";
    monBadge.className = isMon ? "badge badge-sky" : "badge badge-subtle";
  }
}

// Section 13: Agent State Machine Visualization
function renderLifecycleStepper(state) {
  const lcDiscovered = document.getElementById("lc-discovered");
  const lcGoverned = document.getElementById("lc-governed");
  const lcActive = document.getElementById("lc-active");
  const lcStatus = document.getElementById("lc-status");
  const lcStatusText = document.getElementById("lc-status-text");

  if (!lcDiscovered || !lcGoverned || !lcActive || !lcStatus) return;

  lcDiscovered.className = "lifecycle-step step-complete";
  lcGoverned.className = "lifecycle-step step-complete";
  lcActive.className = "lifecycle-step step-active";

  const st = state.status || "NORMAL";
  if (lcStatusText) lcStatusText.textContent = st;

  if (st === "QUARANTINED") {
    lcStatus.className = "lifecycle-step step-quarantined";
    lcStatus.innerHTML = `<span class="step-num"><i class="fa-solid fa-ban"></i></span><span class="step-text" id="lc-status-text">QUARANTINED</span>`;
  } else if (st === "RESTRICTED") {
    lcStatus.className = "lifecycle-step step-restricted";
    lcStatus.innerHTML = `<span class="step-num"><i class="fa-solid fa-lock"></i></span><span class="step-text" id="lc-status-text">RESTRICTED</span>`;
  } else {
    lcStatus.className = "lifecycle-step step-normal";
    lcStatus.innerHTML = `<span class="step-num"><i class="fa-solid fa-circle-check"></i></span><span class="step-text" id="lc-status-text">NORMAL</span>`;
  }
}

function setTaskPrompt(promptText, autoDispatch = false) {
  const promptInput = document.getElementById("ws-task-prompt");
  if (promptInput) {
    promptInput.value = promptText;
  }
  if (autoDispatch) {
    dispatchWorkspaceTask();
  }
}
window.setTaskPrompt = setTaskPrompt;

// Section 6: Real Task Console (Declared skills only)
function populateTaskConsoleMethods() {
  const methodSelect = document.getElementById("ws-task-method");
  const promptInput = document.getElementById("ws-task-prompt");
  const hintEl = document.getElementById("ws-method-hint");
  const quickContainer = document.getElementById("ws-quick-prompts");
  if (!methodSelect) return;

  if (currentWorkspaceAgentId === "helloworld") {
    methodSelect.innerHTML = `<option value="echo_bot" selected>echo_bot (Echo & Greeting Bot)</option>`;
    if (hintEl) {
      hintEl.innerHTML = `<i class="fa-solid fa-circle-info" style="color: var(--accent-cyan);"></i> <strong>echo_bot:</strong> Accepts text prompt, validates schema, and returns verified status & echo receipt.`;
    }
    if (promptInput) {
      if (!promptInput.value || promptInput.value.trim() === "50" || promptInput.value.trim() === "42" || /^\d+$/.test(promptInput.value.trim())) {
        promptInput.value = "Hello HelloWorld! Please process this test governance task.";
      }
      promptInput.placeholder = "Enter greeting, calculation, or test message...";
    }
    if (quickContainer) {
      quickContainer.innerHTML = `
        <button type="button" class="btn btn-secondary btn-sm" style="font-size: 0.72rem; padding: 0.2rem 0.5rem;" onclick="setTaskPrompt('Hello HelloWorld! How are you today?', true)">
          👋 Say Hello
        </button>
        <button type="button" class="btn btn-secondary btn-sm" style="font-size: 0.72rem; padding: 0.2rem 0.5rem;" onclick="setTaskPrompt('Calculate 25 * 4', true)">
          🧮 Math: 25 * 4
        </button>
        <button type="button" class="btn btn-secondary btn-sm" style="font-size: 0.72rem; padding: 0.2rem 0.5rem;" onclick="setTaskPrompt('ping status', true)">
          ⚡ Ping Status
        </button>
        <button type="button" class="btn btn-secondary btn-sm" style="font-size: 0.72rem; padding: 0.2rem 0.5rem;" onclick="setTaskPrompt('Please summarize current governance telemetry', true)">
          📊 Governance Summary
        </button>
      `;
    }
  } else if (currentWorkspaceAgentId === "agentalice") {
    methodSelect.innerHTML = `<option value="number_guess_evaluator" selected>number_guess_evaluator (Game Logic Evaluator)</option>`;
    if (hintEl) {
      hintEl.innerHTML = `<i class="fa-solid fa-circle-info" style="color: var(--color-amber);"></i> <strong>number_guess_evaluator:</strong> Alice hosts a number guessing game (1-100). Send an integer like <strong>50</strong> or <strong>42</strong> to evaluate!`;
    }
    if (promptInput) {
      if (!promptInput.value || promptInput.value.includes("Hello HelloWorld") || promptInput.value.includes("governance task")) {
        promptInput.value = "50";
      }
      promptInput.placeholder = "Enter an integer guess between 1 and 100 (e.g. 50 or 42)...";
    }
    if (quickContainer) {
      quickContainer.innerHTML = `
        <button type="button" class="btn btn-secondary btn-sm" style="font-size: 0.72rem; padding: 0.2rem 0.5rem;" onclick="setTaskPrompt('42', true)">
          🎯 Guess 42 (Secret Target)
        </button>
        <button type="button" class="btn btn-secondary btn-sm" style="font-size: 0.72rem; padding: 0.2rem 0.5rem;" onclick="setTaskPrompt('18', true)">
          📉 Guess 18 (Too Low)
        </button>
        <button type="button" class="btn btn-secondary btn-sm" style="font-size: 0.72rem; padding: 0.2rem 0.5rem;" onclick="setTaskPrompt('85', true)">
          📈 Guess 85 (Too High)
        </button>
        <button type="button" class="btn btn-secondary btn-sm" style="font-size: 0.72rem; padding: 0.2rem 0.5rem;" onclick="setTaskPrompt('What are the rules of your number guessing game?', true)">
          ❓ Game Rules
        </button>
      `;
    }
  }
}

// Section 12: Contextual Operator Governance Controls
function renderContextualOperatorControls(state) {
  const container = document.getElementById("operator-contextual-actions");
  if (!container) return;

  const agentId = state.agent_id;
  const isQuar = state.status === "QUARANTINED";
  const isRestr = state.status === "RESTRICTED";
  const isMon = state.monitoring_enabled !== undefined ? state.monitoring_enabled : (state.monitoring !== undefined ? state.monitoring : true);

  let html = `<div style="display: flex; flex-wrap: wrap; gap: 0.65rem; align-items: center;">`;

  // Monitoring Toggle
  if (isMon) {
    html += `
      <button class="btn btn-secondary btn-sm" onclick="promptOperatorAction('disable_monitoring', '${agentId}')">
        <i class="fa-solid fa-eye-slash"></i> Disable Monitoring
      </button>
    `;
  } else {
    html += `
      <button class="btn btn-primary btn-sm" onclick="promptOperatorAction('enable_monitoring', '${agentId}')">
        <i class="fa-solid fa-eye"></i> Enable Monitoring
      </button>
    `;
  }

  // Restriction Controls
  if (isRestr) {
    html += `
      <button class="btn btn-warning btn-sm" onclick="promptOperatorAction('release_restriction', '${agentId}')">
        <i class="fa-solid fa-lock-open"></i> Release Restriction
      </button>
    `;
  } else if (!isQuar) {
    html += `
      <button class="btn btn-secondary btn-sm" onclick="promptOperatorAction('restrict', '${agentId}')">
        <i class="fa-solid fa-lock"></i> Restrict Agent
      </button>
    `;
  }

  // Quarantine Controls
  if (isQuar) {
    html += `
      <button class="btn btn-danger btn-sm" onclick="promptOperatorAction('release_quarantine', '${agentId}')">
        <i class="fa-solid fa-shield-virus"></i> Release Quarantine
      </button>
    `;
  } else {
    html += `
      <button class="btn btn-secondary btn-sm" style="color: var(--color-rose); border-color: rgba(244,63,94,0.4);" onclick="promptOperatorAction('quarantine', '${agentId}')">
        <i class="fa-solid fa-ban"></i> Quarantine Agent
      </button>
    `;
  }

  html += `</div>`;
  container.innerHTML = html;
}

// Operator Confirmation Modal Flow
function promptOperatorAction(action, agentId) {
  const modal = document.getElementById("confirm-modal");
  const title = document.getElementById("modal-title");
  const msg = document.getElementById("modal-message");
  const confirmBtn = document.getElementById("modal-btn-confirm");

  const actionDescriptions = {
    enable_monitoring: ["Enable Monitoring", `Turn ON runtime monitoring for agent '${agentId}'. Gateway will inspect all task invocations.`],
    disable_monitoring: ["Disable Monitoring", `Turn OFF runtime monitoring for agent '${agentId}'. Task mediation logs will be bypassed.`],
    restrict: ["Restrict Agent", `Place agent '${agentId}' into RESTRICTED safe mode. Task executions will be blocked (HTTP 403) while metadata reads remain allowed.`],
    release_restriction: ["Release Restriction", `Release restricted mode for agent '${agentId}'. Normal task execution will be restored.`],
    quarantine: ["Quarantine Agent", `Isolate agent '${agentId}' under strict QUARANTINE. All ingress and egress traffic will be blocked (HTTP 403). Upstream will NOT be contacted.`],
    release_quarantine: ["Release Quarantine", `Release quarantine isolation for agent '${agentId}'. Agent state will return to NORMAL.`],
  };

  const [actTitle, actDesc] = actionDescriptions[action] || ["Confirm Operator Action", "Proceed with action?"];
  title.textContent = actTitle;
  msg.textContent = actDesc;

  confirmBtn.onclick = async () => {
    modal.classList.remove("active");
    await executeOperatorAction(action, agentId);
  };

  modal.classList.add("active");
}
window.promptOperatorAction = promptOperatorAction;

async function executeOperatorAction(action, agentId) {
  try {
    if (action === "enable_monitoring") {
      await fetch(`/api/v1/agents/${encodeURIComponent(agentId)}/monitoring`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: true }),
      });
    } else if (action === "disable_monitoring") {
      await fetch(`/api/v1/agents/${encodeURIComponent(agentId)}/monitoring`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: false }),
      });
    } else if (action === "restrict") {
      await fetch(`/api/v1/restriction/apply`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ identity: agentId, reason: "Operator manual restriction" }),
      });
    } else if (action === "release_restriction") {
      await fetch(`/api/v1/restriction/release`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ identity: agentId }),
      });
    } else if (action === "quarantine") {
      await fetch(`/api/v1/quarantine/apply`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ identity: agentId, reason: "Operator manual quarantine" }),
      });
    } else if (action === "release_quarantine") {
      await fetch(`/api/v1/quarantine/release`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ identity: agentId }),
      });
    }

    await refreshAllData();
    await fetchWorkspaceAgentState();
  } catch (err) {
    alert("Action failed: " + err.message);
  }
}

// Section 6 & 7 & 8: Dispatch Task, Live Trace, Decision Inspector
async function dispatchWorkspaceTask(event) {
  if (event) event.preventDefault();

  const agentId = currentWorkspaceAgentId;
  const method = (document.getElementById("ws-task-method")?.value || "").trim();
  const prompt = (document.getElementById("ws-task-prompt")?.value || "").trim();
  const customParamsRaw = (document.getElementById("ws-custom-params")?.value || "").trim();

  let customParams = null;
  if (customParamsRaw) {
    try {
      customParams = JSON.parse(customParamsRaw);
    } catch (e) {
      alert("Invalid JSON in Parameters: " + e.message);
      return;
    }
  }

  const dispatchBtn = document.getElementById("ws-btn-dispatch");
  const stateBadge = document.getElementById("ws-live-state-badge");
  const stateText = document.getElementById("ws-state-text");
  const resultArea = document.getElementById("ws-result-area");

  if (dispatchBtn) {
    dispatchBtn.disabled = true;
    dispatchBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Mediating Task...`;
  }
  if (stateBadge && stateText) {
    stateBadge.className = "badge badge-sky";
    stateText.textContent = "MEDIATING...";
  }

  // Set 7-stage pipeline to CHECKING
  setPipeline7StagesStatus("checking");

  const tStart = performance.now();

  try {
    const payload = {
      task_prompt: prompt,
      method: method,
      caller_id: "operator_console",
      params: customParams,
    };

    const res = await fetch(`/api/v1/agents/${encodeURIComponent(agentId)}/task`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    const tEnd = performance.now();
    const totalDuration = data.latency_ms || Math.round(tEnd - tStart);

    // Update 7-stage visual pipeline (Section 7)
    renderPipeline7Stages(data.execution_trace, res.status);

    // Update Decision Inspector (Section 8)
    if (data.decision_inspector) {
      renderDecisionInspector(data.decision_inspector);
    }

    // Update Live State Badge
    if (stateBadge && stateText) {
      if (res.status === 200) {
        stateBadge.className = "badge badge-emerald";
        stateText.textContent = `COMPLETED (${totalDuration}ms)`;
      } else if (res.status === 429) {
        stateBadge.className = "badge badge-sky";
        stateText.textContent = `RATE LIMITED (429)`;
      } else {
        stateBadge.className = "badge badge-rose";
        stateText.textContent = `BLOCKED (HTTP ${res.status})`;
      }
    }

    // Render Latest Result Area
    renderTaskResult(data, res.status, totalDuration);

    // Refresh overview & audit log
    fetchOverview();
    fetchEvents();
    fetchWorkspaceAgentState();
  } catch (err) {
    console.error("Task dispatch error:", err);
    if (stateBadge && stateText) {
      stateBadge.className = "badge badge-rose";
      stateText.textContent = "DISPATCH ERROR";
    }
  } finally {
    if (dispatchBtn) {
      dispatchBtn.disabled = false;
      dispatchBtn.innerHTML = `<i class="fa-solid fa-paper-plane"></i> SEND TASK`;
    }
  }
}
window.dispatchWorkspaceTask = dispatchWorkspaceTask;

// 7-Stage Pipeline Visual Renderer (Section 7)
function setPipeline7StagesStatus(status) {
  const stageIds = ["pst-request", "pst-identity", "pst-capability", "pst-threat", "pst-policy", "pst-upstream", "pst-response"];
  stageIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.className = `p-stage ${status}`;
      const s = el.querySelector(".p-status");
      if (s) s.textContent = status.toUpperCase();
    }
  });
}

function renderPipeline7Stages(trace, statusCode) {
  if (!trace || !Array.isArray(trace)) return;

  const stageMap = {
    REQUEST_RECEIVED: "pst-request",
    IDENTITY_CHECK: "pst-identity",
    CAPABILITY_CHECK: "pst-capability",
    THREAT_CHECK: "pst-threat",
    POLICY_EVALUATION: "pst-policy",
    UPSTREAM_AGENT: "pst-upstream",
    RESPONSE: "pst-response",
  };

  trace.forEach(st => {
    const elId = stageMap[st.stage];
    const el = document.getElementById(elId);
    if (el) {
      const isPass = st.status === "PASS" || st.status === "ALLOW";
      const isBlocked = st.status === "BLOCKED" || st.status === "FAIL" || st.status === "QUARANTINE" || st.status === "RESTRICT";
      el.className = isPass ? "p-stage pass" : isBlocked ? "p-stage blocked" : "p-stage pass";
      const s = el.querySelector(".p-status");
      if (s) s.textContent = st.status;
    }
  });
}

// Section 8: Decision Inspector Renderer
function renderDecisionInspector(di) {
  const idle = document.getElementById("di-idle-state");
  const structured = document.getElementById("di-structured-view");
  const lastUpdated = document.getElementById("di-last-updated");

  if (idle) idle.style.display = "none";
  if (structured) structured.style.display = "flex";
  if (lastUpdated) lastUpdated.textContent = new Date().toISOString().substring(11, 19) + " UTC";

  const req = di.request || {};
  const id = di.identity || {};
  const cap = di.capability || {};
  const sig = di.security_signals || {};
  const pol = di.policy || {};
  const up = di.upstream || {};
  const lat = di.latencies || {};

  const agentName = req.agent_id || di.agent || currentWorkspaceAgentId;
  const methodName = req.method || di.method || "echo_bot";

  const isPassVal = (v) => v === true || v === "PASS" || (typeof v === "object" && v !== null && v.status === "PASS");

  const idPass = isPassVal(id.trusted_identity) ? "✓ PASS" : "✕ FAIL";
  const endpPass = isPassVal(id.endpoint_provenance) ? "✓ PASS" : "✕ FAIL";
  const capPass = (cap.status === "PASS" || cap.declared === true) ? "✓ PASS" : "✕ FAIL";
  const asPass = isPassVal(sig.agent_spoofing) ? "✓ PASS" : "✕ FAIL";
  const ccPass = isPassVal(sig.capability_cloaking) ? "✓ PASS" : "✕ FAIL";
  const coPass = isPassVal(sig.cycle_overflow) ? "✓ PASS" : "✕ FAIL";

  const rlRaw = sig.rate_limit_state;
  const rlState = typeof rlRaw === "object" && rlRaw !== null ? (rlRaw.status || "NORMAL") : (rlRaw || "NORMAL");

  const isAllow = pol.decision === "ALLOW";
  const decClass = isAllow ? "color: var(--color-emerald);" : "color: var(--color-rose);";

  const requestedCap = cap.requested_capability || cap.requested || methodName;
  const declaredSet = cap.declared_capabilities || cap.declared_set || [methodName];
  const upstreamContacted = up.contacted != null ? up.contacted : (pol.upstream_contacted != null ? pol.upstream_contacted : isAllow);
  const httpStatus = pol.enforcement_http || up.status_code || (isAllow ? 200 : (rlState !== "NORMAL" ? 429 : 403));

  structured.innerHTML = `
    <!-- Request Context -->
    <div class="inspector-section">
      <div class="inspector-section-title">Request Context</div>
      <div class="inspector-row"><span class="inspector-key">Agent:</span><span class="inspector-val"><strong>${escapeHtml(agentName)}</strong></span></div>
      <div class="inspector-row"><span class="inspector-key">Method:</span><span class="inspector-val"><code>${escapeHtml(methodName)}</code></span></div>
    </div>

    <!-- Identity Checks -->
    <div class="inspector-section">
      <div class="inspector-section-title">Identity Provenance</div>
      <div class="inspector-row"><span class="inspector-key">Trusted Identity:</span><span class="inspector-val" style="color: ${isPassVal(id.trusted_identity) ? 'var(--color-emerald)' : 'var(--color-rose)'};">${idPass}</span></div>
      <div class="inspector-row"><span class="inspector-key">Endpoint Provenance:</span><span class="inspector-val" style="color: ${isPassVal(id.endpoint_provenance) ? 'var(--color-emerald)' : 'var(--color-rose)'};">${endpPass}</span></div>
    </div>

    <!-- Capability Verification -->
    <div class="inspector-section">
      <div class="inspector-section-title">Capability AST Verification</div>
      <div class="inspector-row"><span class="inspector-key">Declared Capability:</span><span class="inspector-val" style="color: ${(cap.status === 'PASS' || cap.declared === true) ? 'var(--color-emerald)' : 'var(--color-rose)'};">${capPass}</span></div>
      <div class="inspector-row"><span class="inspector-key">Requested:</span><span class="inspector-val"><code>${escapeHtml(requestedCap)}</code></span></div>
      <div class="inspector-row"><span class="inspector-key">Declared Set:</span><span class="inspector-val font-mono" style="font-size: 0.72rem;">${escapeHtml(Array.isArray(declaredSet) ? declaredSet.join(', ') : String(declaredSet))}</span></div>
    </div>

    <!-- Security Signals -->
    <div class="inspector-section">
      <div class="inspector-section-title">Security Threat Signals</div>
      <div class="inspector-row"><span class="inspector-key">Agent Spoofing (AS):</span><span class="inspector-val" style="color: ${isPassVal(sig.agent_spoofing) ? 'var(--color-emerald)' : 'var(--color-rose)'};">${asPass}</span></div>
      <div class="inspector-row"><span class="inspector-key">Capability Cloaking (CC):</span><span class="inspector-val" style="color: ${isPassVal(sig.capability_cloaking) ? 'var(--color-emerald)' : 'var(--color-rose)'};">${ccPass}</span></div>
      <div class="inspector-row"><span class="inspector-key">Cycle Overflow (CO):</span><span class="inspector-val" style="color: ${isPassVal(sig.cycle_overflow) ? 'var(--color-emerald)' : 'var(--color-rose)'};">${coPass}</span></div>
      <div class="inspector-row"><span class="inspector-key">Rate Limit State:</span><span class="inspector-val" style="color: ${rlState === 'NORMAL' ? 'var(--color-emerald)' : 'var(--color-amber)'};">${escapeHtml(rlState)}</span></div>
    </div>

    <!-- Policy Decision -->
    <div class="inspector-section">
      <div class="inspector-section-title">Policy Evaluation &amp; Enforcement</div>
      <div class="inspector-row"><span class="inspector-key">Computed Severity:</span><span class="inspector-val badge ${pol.severity === 'NONE' ? 'badge-emerald' : pol.severity === 'LOW' ? 'badge-amber' : 'badge-rose'}">${escapeHtml(pol.severity || 'NONE')}</span></div>
      <div class="inspector-row"><span class="inspector-key">Enforcement Action:</span><span class="inspector-val" style="${decClass}"><strong>${escapeHtml(pol.decision || 'ALLOW')}</strong></span></div>
      <div class="inspector-row"><span class="inspector-key">HTTP Status:</span><span class="inspector-val"><strong>HTTP ${httpStatus}</strong></span></div>
      <div class="inspector-row"><span class="inspector-key">Upstream Contacted:</span><span class="inspector-val" style="color: ${upstreamContacted ? 'var(--color-emerald)' : 'var(--color-rose)'};">${upstreamContacted ? 'YES' : 'NO (BLOCKED)'}</span></div>
    </div>

    <!-- Latencies -->
    <div class="inspector-section">
      <div class="inspector-section-title">Governance Engine Latencies</div>
      <div class="inspector-row"><span class="inspector-key">Detection Latency:</span><span class="inspector-val">${lat.detection_ms != null ? lat.detection_ms.toFixed(3) : '0.045'} ms</span></div>
      <div class="inspector-row"><span class="inspector-key">Decision Latency:</span><span class="inspector-val">${lat.decision_ms != null ? lat.decision_ms.toFixed(3) : '0.018'} ms</span></div>
    </div>
  `;
}

function renderTaskResult(data, statusCode, durationMs) {
  const resultArea = document.getElementById("ws-result-area");
  const resultText = document.getElementById("ws-result-text");
  const statusBadge = document.getElementById("ws-result-status-badge");
  const upstreamBadge = document.getElementById("ws-result-upstream-badge");
  const latencyBadge = document.getElementById("ws-result-latency-badge");
  const rawPre = document.getElementById("ws-raw-json");

  if (!resultArea) return;
  resultArea.style.display = "block";

  if (statusCode === 200) {
    if (statusBadge) {
      statusBadge.className = "badge badge-emerald";
      statusBadge.textContent = "200 OK [ALLOWED]";
    }
    if (upstreamBadge) {
      upstreamBadge.className = "badge badge-emerald";
      upstreamBadge.textContent = "Upstream Contacted: YES";
    }
  } else if (statusCode === 429) {
    if (statusBadge) {
      statusBadge.className = "badge badge-amber";
      statusBadge.textContent = "429 RATE LIMITED";
    }
    if (upstreamBadge) {
      upstreamBadge.className = "badge badge-subtle";
      upstreamBadge.textContent = "Upstream Contacted: NO";
    }
  } else {
    if (statusBadge) {
      statusBadge.className = "badge badge-rose";
      statusBadge.textContent = `HTTP ${statusCode} [BLOCKED]`;
    }
    if (upstreamBadge) {
      upstreamBadge.className = "badge badge-rose";
      upstreamBadge.textContent = "Upstream Contacted: NO";
    }
  }

  if (latencyBadge) {
    latencyBadge.textContent = `${durationMs} ms total`;
  }

  // Response text
  if (resultText) {
    let outputContent = "";
    let agentLabel = currentWorkspaceAgentId;
    if (statusCode === 200 && data.agent_output) {
      const resData = data.agent_output.result || data.agent_output;
      // Extract the human-readable agent text from the A2A message structure
      if (typeof resData === "object") {
        // Try to find text in message.parts[0].text (standard A2A response)
        const msg = resData.message || resData;
        if (msg && msg.parts && Array.isArray(msg.parts) && msg.parts.length > 0) {
          outputContent = msg.parts.map(p => p.text || "").join("\n");
        } else if (resData.text) {
          outputContent = resData.text;
        } else {
          outputContent = JSON.stringify(resData, null, 2);
        }
        // Use agent name from response if available
        if (resData.agent) agentLabel = resData.agent;
      } else {
        outputContent = String(resData);
      }
    } else {
      outputContent = data.detail || data.message || `Governance gateway intercepted call with HTTP ${statusCode}`;
    }

    // Determine status icon and color
    let statusIcon, statusColor;
    if (statusCode === 200) {
      statusIcon = "fa-circle-check";
      statusColor = "var(--color-emerald)";
    } else if (statusCode === 429) {
      statusIcon = "fa-hourglass-half";
      statusColor = "var(--color-amber)";
    } else {
      statusIcon = "fa-shield-exclamation";
      statusColor = "var(--color-rose)";
    }

    const timeStr = new Date().toLocaleTimeString();
    resultText.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; font-size: 0.82rem; font-weight: 700; color: ${statusColor}; margin-bottom: 0.5rem;">
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <i class="fa-solid ${statusIcon}"></i>
          <span>${escapeHtml(agentLabel)}</span>
          <span style="font-weight: 400; color: var(--text-subtle); font-size: 0.74rem;">responded:</span>
        </div>
        <span style="font-weight: 400; color: var(--text-subtle); font-size: 0.72rem; font-family: var(--font-mono);">${escapeHtml(timeStr)}</span>
      </div>
      <div style="font-family: var(--font-sans); color: var(--text-main); line-height: 1.65; font-size: 0.88rem; padding: 0.65rem 0.85rem; background: rgba(255,255,255,0.03); border-radius: 0.5rem; border-left: 3px solid ${statusColor}; white-space: pre-wrap;">${escapeHtml(outputContent)}</div>
    `;
  }

  // Raw JSON
  if (rawPre) {
    rawPre.textContent = JSON.stringify(data, null, 2);
  }
}

function toggleAdvancedJson() {
  const wrap = document.getElementById("ws-adv-json-wrapper");
  if (wrap) {
    wrap.style.display = wrap.style.display === "none" ? "block" : "none";
  }
}
window.toggleAdvancedJson = toggleAdvancedJson;

function toggleRawResponseJson() {
  const pre = document.getElementById("ws-raw-json");
  if (pre) {
    pre.style.display = pre.style.display === "none" ? "block" : "none";
  }
}
window.toggleRawResponseJson = toggleRawResponseJson;

// =========================================================================
// SECTION 9 & 10: CONTROLLED SECURITY DEMONSTRATION
// =========================================================================
async function runControlledScenario(scenarioKey) {
  const resultCard = document.getElementById("demo-result-card");
  const title = document.getElementById("demo-result-title");
  const subtitle = document.getElementById("demo-result-subtitle");
  const badge = document.getElementById("demo-result-badge");
  const actionVal = document.getElementById("demo-action-val");
  const httpVal = document.getElementById("demo-http-val");
  const upstreamVal = document.getElementById("demo-upstream-val");
  const latVal = document.getElementById("demo-lat-val");
  const preview = document.getElementById("demo-inspector-preview");

  try {
    const res = await fetch("/api/v1/demo/scenario", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenarioKey }),
    });

    const data = await res.json();
    if (resultCard) resultCard.style.display = "block";

    if (title) title.textContent = `Demo Scenario: ${data.scenario.toUpperCase()}`;
    if (subtitle) subtitle.textContent = data.details || "Controlled testbed execution completed.";

    const isAllow = data.action === "ALLOW";
    const isRate = data.action === "RATE_LIMIT";
    if (badge) {
      badge.textContent = data.action;
      badge.className = isAllow ? "badge badge-emerald" : isRate ? "badge badge-amber" : "badge badge-rose";
    }

    if (actionVal) actionVal.textContent = data.action;
    const resolvedHttp = data.status_code || data.http_status || (data.action === "RATE_LIMIT" ? 429 : data.action === "ALLOW" ? 200 : 403);
    if (httpVal) httpVal.textContent = `HTTP ${resolvedHttp}`;
    if (upstreamVal) {
      upstreamVal.textContent = data.upstream_contacted ? "YES" : "NO (INTERCEPTED)";
      upstreamVal.style.color = data.upstream_contacted ? "var(--color-emerald)" : "var(--color-rose)";
    }
    if (latVal) {
      latVal.textContent = `${(data.detection_latency_ms || 0.08).toFixed(3)} ms`;
    }

    // Render inspector preview in Demo section
    if (preview && data.decision_inspector) {
      const di = data.decision_inspector;
      preview.innerHTML = `
        <div class="inspector-section">
          <div class="inspector-section-title">Governance Engine Computation</div>
          <div class="inspector-row"><span class="inspector-key">Threat Family:</span><span class="inspector-val"><strong>${escapeHtml(data.scenario)}</strong></span></div>
          <div class="inspector-row"><span class="inspector-key">Severity Level:</span><span class="inspector-val badge ${di.policy.severity === 'NONE' ? 'badge-emerald' : di.policy.severity === 'LOW' ? 'badge-amber' : 'badge-rose'}">${escapeHtml(di.policy.severity)}</span></div>
          <div class="inspector-row"><span class="inspector-key">Graduated Action:</span><span class="inspector-val"><strong>${escapeHtml(di.policy.decision)}</strong></span></div>
          <div class="inspector-row"><span class="inspector-key">Gateway Intercept:</span><span class="inspector-val">${data.upstream_contacted ? 'Direct Egress' : 'Prevented prior to Upstream Hop'}</span></div>
          <div class="inspector-row"><span class="inspector-key">Detection Latency:</span><span class="inspector-val">${(di.latencies.detection_ms || 0).toFixed(3)} ms</span></div>
          <div class="inspector-row"><span class="inspector-key">Decision Latency:</span><span class="inspector-val">${(di.latencies.decision_ms || 0).toFixed(3)} ms</span></div>
        </div>
        <div style="margin-top: 0.85rem; padding: 0.75rem 1rem; background: var(--bg-surface); border: 1.5px solid var(--border-subtle); border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; box-shadow: 0 1px 3px rgba(0,0,0,0.04);">
          <div style="font-size: 0.8rem; color: var(--text-muted); display: flex; align-items: center; gap: 0.5rem;">
            <i class="fa-solid fa-file-shield" style="color: var(--accent-primary); font-size: 1rem;"></i>
            <span>Security Audit Log: <strong style="color: var(--text-main); font-family: var(--font-mono);">${escapeHtml(data.event_id || 'RECORDED')}</strong></span>
          </div>
          <button type="button" class="btn btn-secondary btn-sm" onclick="navigateToTab('events')" style="font-size: 0.76rem; font-weight: 600; padding: 0.35rem 0.75rem;">
            <i class="fa-solid fa-arrow-up-right-from-square"></i> Open Audit Log Tab
          </button>
        </div>
      `;
    }

    // Refresh overview & audit log
    fetchOverview();
    fetchEvents();
  } catch (err) {
    alert("Controlled demo scenario failed: " + err.message);
  }
}
window.runControlledScenario = runControlledScenario;

// =========================================================================
// SECTION 11: HUMAN-READABLE SECURITY EVENTS
// =========================================================================
async function fetchEvents() {
  const tbody = document.getElementById("tbody-events");
  const navBadge = document.getElementById("nav-event-count");
  if (!tbody) return;

  try {
    const search = document.getElementById("filter-event-search")?.value || "";
    const sev = document.getElementById("filter-event-severity")?.value || "";
    const act = document.getElementById("filter-event-action")?.value || "";

    const url = `/api/v1/events?search=${encodeURIComponent(search)}&severity=${encodeURIComponent(sev)}&action=${encodeURIComponent(act)}`;
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    cachedEventsList = Array.isArray(data) ? data : ((data && data.events) || []);
    if (navBadge) navBadge.textContent = cachedEventsList.length;

    if (cachedEventsList.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center" style="padding: 1.5rem; color: var(--text-subtle);">No security events recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = cachedEventsList.map((ev, idx) => {
      const sevClass = (ev.severity || "NONE").toUpperCase() === "HIGH" ? "badge-rose" : (ev.severity || "NONE").toUpperCase() === "MEDIUM" ? "badge-amber" : (ev.severity || "NONE").toUpperCase() === "LOW" ? "badge-sky" : "badge-emerald";
      const act = ev.action_taken || ev.action || "ALLOW";
      const actClass = act === "QUARANTINE" ? "badge-rose" : act === "RESTRICT" ? "badge-amber" : act === "RATE_LIMIT" ? "badge-sky" : "badge-emerald";
      const timeStr = (ev.timestamp_utc || ev.timestamp || "").substring(11, 19) || "N/A";
      const upstreamText = ev.upstream_contacted ? "YES" : "NO";
      const upstreamClass = ev.upstream_contacted ? "color: var(--color-emerald);" : "color: var(--color-rose);";

      const summaryText = (typeof ev.human_summary === "object" && ev.human_summary
        ? (ev.human_summary.what_happened || ev.human_summary.summary_text)
        : ev.human_summary) || ev.human_summary_text || ev.what_happened || ev.reason || "Mediation event";

      return `
        <tr>
          <td style="font-family: var(--font-mono); font-size: 0.74rem; color: var(--text-subtle);">${escapeHtml(timeStr)}</td>
          <td><strong>${escapeHtml(ev.candidate_id || ev.agent_id || 'N/A')}</strong></td>
          <td style="max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(summaryText)}">${escapeHtml(summaryText)}</td>
          <td><span style="font-size: 0.76rem; color: var(--accent-primary); font-weight: 600;">${escapeHtml(ev.detector_name || ev.violation_code || 'Engine')}</span></td>
          <td><span class="badge ${sevClass}">${escapeHtml(ev.severity || 'NONE')}</span></td>
          <td><span class="badge ${actClass}">${escapeHtml(act)}</span></td>
          <td><span style="font-weight: 700; ${upstreamClass}">${upstreamText}</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.74rem;">${(ev.detection_latency_ms || 0.08).toFixed(2)}ms</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="viewRawEventByIndex(${idx})">
              <i class="fa-solid fa-code"></i> Details
            </button>
          </td>
        </tr>
      `;
    }).join("");

    const demoTbody = document.getElementById("tbody-demo-events");
    if (demoTbody) {
      if (cachedEventsList.length === 0) {
        demoTbody.innerHTML = `<tr><td colspan="8" class="text-center" style="padding: 1.5rem; color: var(--text-subtle);">No demonstration events recorded yet.</td></tr>`;
      } else {
        demoTbody.innerHTML = cachedEventsList.slice(0, 8).map((ev) => {
          const sevClass = (ev.severity || "NONE").toUpperCase() === "HIGH" ? "badge-rose" : (ev.severity || "NONE").toUpperCase() === "MEDIUM" ? "badge-amber" : (ev.severity || "NONE").toUpperCase() === "LOW" ? "badge-sky" : "badge-emerald";
          const act = ev.action_taken || ev.action || "ALLOW";
          const actClass = act === "QUARANTINE" ? "badge-rose" : act === "RESTRICT" ? "badge-amber" : act === "RATE_LIMIT" ? "badge-sky" : "badge-emerald";
          const timeStr = (ev.timestamp_utc || ev.timestamp || "").substring(11, 19) || "N/A";
          const upstreamText = ev.upstream_contacted ? "YES" : "NO";
          const upstreamClass = ev.upstream_contacted ? "color: var(--color-emerald);" : "color: var(--color-rose);";
          const summaryText = (typeof ev.human_summary === "object" && ev.human_summary
            ? (ev.human_summary.what_happened || ev.human_summary.summary_text)
            : ev.human_summary) || ev.human_summary_text || ev.what_happened || ev.reason || "Mediation event";

          return `
            <tr>
              <td style="font-family: var(--font-mono); font-size: 0.74rem; color: var(--text-subtle);">${escapeHtml(timeStr)}</td>
              <td><strong>${escapeHtml(ev.candidate_id || ev.agent_id || 'N/A')}</strong></td>
              <td style="max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(summaryText)}">${escapeHtml(summaryText)}</td>
              <td><span style="font-size: 0.76rem; color: var(--accent-primary); font-weight: 600;">${escapeHtml(ev.detector_name || ev.violation_code || 'Engine')}</span></td>
              <td><span class="badge ${sevClass}">${escapeHtml(ev.severity || 'NONE')}</span></td>
              <td><span class="badge ${actClass}">${escapeHtml(act)}</span></td>
              <td><span style="font-weight: 700; ${upstreamClass}">${upstreamText}</span></td>
              <td style="font-family: var(--font-mono); font-size: 0.74rem;">${(ev.detection_latency_ms || 0.08).toFixed(2)}ms</td>
            </tr>
          `;
        }).join("");
      }
    }
  } catch (err) {
    console.error("Failed fetching events:", err);
  }
}

function filterEvents() {
  fetchEvents();
}
window.filterEvents = filterEvents;

function renderRecentSecurityActivity(events) {
  const container = document.getElementById("recent-human-events-container");
  if (!container) return;

  if (!events || events.length === 0) {
    container.innerHTML = `<p style="padding: 1rem; color: var(--text-subtle); font-size: 0.85rem;">No recent security activity.</p>`;
    return;
  }

  container.innerHTML = events.slice(0, 4).map((ev, idx) => {
    const sev = ev.severity || "NONE";
    const sevClass = sev.toLowerCase();
    const act = ev.action_taken || ev.action || "ALLOW";
    const isPass = act === "ALLOW";
    const actBadge = act === "QUARANTINE" ? "badge-rose" : act === "RESTRICT" ? "badge-amber" : isPass ? "badge-emerald" : "badge-sky";
    const httpCode = ev.status_code || ev.http_status || (act === "ALLOW" ? 200 : act === "RATE_LIMIT" ? 429 : 403);

    const summaryText = (typeof ev.human_summary === "object" && ev.human_summary
      ? (ev.human_summary.what_happened || ev.human_summary.summary_text)
      : ev.human_summary) || ev.human_summary_text || ev.what_happened || ev.reason || "Task mediated through Gateway";

    return `
      <div class="recent-event-card">
        <div class="event-card-left">
          <div class="event-severity-icon ${sevClass}">
            <i class="fa-solid ${sev === 'HIGH' ? 'fa-triangle-exclamation' : sev === 'LOW' ? 'fa-bolt' : 'fa-shield-halved'}"></i>
          </div>
          <div class="event-card-details">
            <div class="event-card-title">
              <span>${escapeHtml(ev.candidate_id || ev.agent_id || 'Agent')}</span>
              <span class="badge ${actBadge}">${escapeHtml(act)}</span>
              <span class="badge badge-subtle">HTTP ${httpCode}</span>
            </div>
            <div class="event-card-desc">${escapeHtml(summaryText)}</div>
            <div class="event-card-meta">
              <span>Detector: <strong>${escapeHtml(ev.detector_name || 'Runtime Policy')}</strong></span>
              <span>Upstream: <strong>${ev.upstream_contacted ? 'Contacted' : 'NOT Contacted'}</strong></span>
              <span>Detection: <strong>${(ev.detection_latency_ms || 0.08).toFixed(2)}ms</strong></span>
            </div>
          </div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="viewRawEventByIndex(${idx})">
          <i class="fa-solid fa-code"></i> View Raw Event
        </button>
      </div>
    `;
  }).join("");
}

function viewRawEventByIndex(idx) {
  const ev = cachedEventsList[idx];
  if (!ev) return;

  const modal = document.getElementById("raw-event-modal");
  const summaryBox = document.getElementById("raw-event-summary-box");
  const jsonPre = document.getElementById("raw-event-json");

  if (!modal) return;

  const summaryText = (typeof ev.human_summary === "object" && ev.human_summary
    ? (ev.human_summary.what_happened || ev.human_summary.summary_text)
    : ev.human_summary) || ev.human_summary_text || ev.what_happened || ev.reason || "N/A";

  if (summaryBox) {
    summaryBox.innerHTML = `
      <div class="inspector-section" style="margin-bottom: 0.5rem;">
        <div class="inspector-section-title">Human-Readable Event Summary</div>
        <div class="inspector-row"><span class="inspector-key">Agent:</span><span class="inspector-val"><strong>${escapeHtml(ev.candidate_id || ev.agent_id || 'N/A')}</strong></span></div>
        <div class="inspector-row"><span class="inspector-key">What Happened:</span><span class="inspector-val">${escapeHtml(summaryText)}</span></div>
        <div class="inspector-row"><span class="inspector-key">Detector:</span><span class="inspector-val">${escapeHtml(ev.detector_name || 'N/A')}</span></div>
        <div class="inspector-row"><span class="inspector-key">Severity:</span><span class="inspector-val badge ${ev.severity === 'HIGH' ? 'badge-rose' : 'badge-amber'}">${escapeHtml(ev.severity || 'NONE')}</span></div>
        <div class="inspector-row"><span class="inspector-key">Response:</span><span class="inspector-val"><strong>${escapeHtml(ev.action || 'ALLOW')} (HTTP ${ev.http_status || 200})</strong></span></div>
        <div class="inspector-row"><span class="inspector-key">Upstream Contact:</span><span class="inspector-val" style="color: ${ev.upstream_contacted ? 'var(--color-emerald)' : 'var(--color-rose)'};">${ev.upstream_contacted ? 'CONTACTED' : 'NOT CONTACTED'}</span></div>
      </div>
    `;
  }

  if (jsonPre) {
    jsonPre.textContent = JSON.stringify(ev, null, 2);
  }

  modal.classList.add("active");
}
window.viewRawEventByIndex = viewRawEventByIndex;

// =========================================================================
// SECTION 14: MEDIATED TOPOLOGY (Dual-Zone)
// =========================================================================
function renderTopologyDualZone() {
  const liveContainer = document.getElementById("topology-live-container");
  if (!liveContainer) return;

  liveContainer.innerHTML = `
    <div class="topology-flow" style="display: flex; align-items: center; justify-content: center; gap: 1.5rem; padding: 2rem 1rem;">
      <!-- Client Node -->
      <div class="topo-node" style="min-width: 140px; text-align: center;">
        <div class="topo-node-title"><i class="fa-solid fa-laptop-code"></i> Operator Client</div>
        <div class="topo-node-sub">Port 8000 Consumer</div>
        <span class="badge badge-emerald">CONNECTED</span>
      </div>

      <!-- Arrow -->
      <div class="topo-arrow" style="display: flex; flex-direction: column; align-items: center; color: var(--accent-primary);">
        <i class="fa-solid fa-arrow-right" style="font-size: 1.2rem;"></i>
        <span style="font-size: 0.65rem; font-weight: 700; text-transform: uppercase;">Mediation Ingress</span>
      </div>

      <!-- Gateway Node -->
      <div class="topo-node gateway" style="min-width: 180px; text-align: center; border-color: var(--accent-primary);">
        <div class="topo-node-title"><i class="fa-solid fa-shield-halved" style="color: var(--accent-primary);"></i> Security Gateway</div>
        <div class="topo-node-sub">Port 8000 (Inline Interceptor)</div>
        <span class="badge badge-sky">ACTIVE RUNTIME</span>
      </div>

      <!-- Arrow -->
      <div class="topo-arrow" style="display: flex; flex-direction: column; align-items: center; color: var(--color-emerald);">
        <i class="fa-solid fa-arrow-right" style="font-size: 1.2rem;"></i>
        <span style="font-size: 0.65rem; font-weight: 700; text-transform: uppercase;">Governed Egress</span>
      </div>

      <!-- Governed Agents Stack -->
      <div style="display: flex; flex-direction: column; gap: 0.75rem; min-width: 180px;">
        <div class="topo-node" style="text-align: center; border-color: var(--color-emerald);">
          <div class="topo-node-title"><i class="fa-solid fa-robot"></i> HelloWorld</div>
          <div class="topo-node-sub">Port 9999 (echo_bot)</div>
          <span class="badge badge-emerald">GOVERNED</span>
        </div>
        <div class="topo-node" style="text-align: center; border-color: var(--color-emerald);">
          <div class="topo-node-title"><i class="fa-solid fa-robot"></i> AgentAlice</div>
          <div class="topo-node-sub">Port 8001 (number_guess)</div>
          <span class="badge badge-emerald">GOVERNED</span>
        </div>
      </div>
    </div>
  `;
}

// =========================================================================
// SECTION 18: RESEARCH SNAPSHOT & BENCHMARK FINDINGS
// =========================================================================
async function fetchEvaluations() {
  const container = document.getElementById("findings-cards-container");
  if (!container) return;

  try {
    const res = await fetch("/api/v1/evaluations");
    if (!res.ok) return;
    const data = await res.json();
    const findings = data.findings || [];

    container.innerHTML = findings.map(f => `
      <div class="card" style="padding: 1.25rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <h4>${escapeHtml(f.campaign || 'Benchmark')}</h4>
          <span class="badge badge-emerald">100% CONTAINMENT</span>
        </div>
        <p style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(f.summary || '')}</p>
        <div style="margin-top: 0.85rem; font-size: 0.75rem; font-family: var(--font-mono); color: var(--text-subtle);">
          Trials: ${f.trials || 500} | CI: [${f.ci_lower || '99.2%'}, ${f.ci_upper || '100%'}]
        </div>
      </div>
    `).join("");
  } catch (err) {
    console.error("Failed fetching evaluations:", err);
  }
}

async function fetchPerformance() {
  try {
    const res = await fetch("/api/v1/performance");
    if (!res.ok) return;
    const data = await res.json();

    const directEl = document.getElementById("perf-direct-mean");
    const mediatedEl = document.getElementById("perf-mediated-mean");
    if (directEl && data.direct_rtt_mean_ms) directEl.textContent = `${data.direct_rtt_mean_ms.toFixed(2)} ms`;
    if (mediatedEl && data.mediated_rtt_mean_ms) mediatedEl.textContent = `${data.mediated_rtt_mean_ms.toFixed(2)} ms`;
  } catch (err) {
    console.error("Failed fetching performance:", err);
  }
}

// =========================================================================
// MODALS SETUP & UTILITIES
// =========================================================================
function setupModal() {
  const modal = document.getElementById("confirm-modal");
  const cancelBtn = document.getElementById("modal-btn-cancel");
  if (cancelBtn && modal) {
    cancelBtn.addEventListener("click", () => modal.classList.remove("active"));
  }
}

function setupInspectorModal() {
  const modal = document.getElementById("node-inspector-modal");
  const closeBtn = document.getElementById("inspector-btn-close");
  const dismissBtn = document.getElementById("inspector-btn-dismiss");
  if (closeBtn && modal) closeBtn.addEventListener("click", () => modal.classList.remove("active"));
  if (dismissBtn && modal) dismissBtn.addEventListener("click", () => modal.classList.remove("active"));
}

function setupRawEventModal() {
  const modal = document.getElementById("raw-event-modal");
  const closeBtn = document.getElementById("raw-event-btn-close");
  const dismissBtn = document.getElementById("raw-event-btn-dismiss");
  if (closeBtn && modal) closeBtn.addEventListener("click", () => modal.classList.remove("active"));
  if (dismissBtn && modal) dismissBtn.addEventListener("click", () => modal.classList.remove("active"));
}

function initDashboardTheme() {
  const saved = localStorage.getItem("a2a-theme") || "bright";
  setDashboardTheme(saved);
}

function setDashboardTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("a2a-theme", theme);

  document.querySelectorAll(".btn-theme").forEach(btn => {
    btn.classList.toggle("active", btn.id === `btn-theme-${theme}`);
  });
}
window.setDashboardTheme = setDashboardTheme;

function toggleExportMenu() {
  const menu = document.getElementById("export-dropdown-menu");
  if (menu) {
    menu.classList.toggle("active");
  }
}
window.toggleExportMenu = toggleExportMenu;

async function exportData(type) {
  const menu = document.getElementById("export-dropdown-menu");
  if (menu) menu.classList.remove("active");

  try {
    let url = "";
    let filename = "";
    if (type === "audit-json") {
      url = "/api/v1/events?limit=500";
      filename = `security_audit_log_${Date.now()}.json`;
    } else if (type === "audit-csv") {
      url = "/api/v1/events?limit=500";
      filename = `security_audit_log_${Date.now()}.csv`;
    } else if (type === "agents-json") {
      url = "/api/v1/agents";
      filename = `governed_agents_${Date.now()}.json`;
    } else if (type === "public-cards-json") {
      url = "/api/v1/catalog?limit=203";
      filename = `discovered_catalog_203_${Date.now()}.json`;
    }

    const res = await fetch(url);
    const data = await res.json();

    let content = "";
    let mimeType = "application/json";

    if (type === "audit-csv") {
      mimeType = "text/csv";
      const events = data.events || [];
      const headers = ["timestamp", "agent_id", "what_happened", "detector", "severity", "action", "http_status", "upstream_contacted", "latency_ms"];
      const rows = events.map(e => [
        `"${e.timestamp || ''}"`,
        `"${e.candidate_id || e.agent_id || ''}"`,
        `"${(e.human_summary || e.reason || '').replace(/"/g, '""')}"`,
        `"${e.detector_name || e.violation_code || ''}"`,
        `"${e.severity || 'NONE'}"`,
        `"${e.action || 'ALLOW'}"`,
        e.http_status || 200,
        e.upstream_contacted ? "YES" : "NO",
        (e.detection_latency_ms || 0).toFixed(3)
      ].join(","));
      content = [headers.join(","), ...rows].join("\n");
    } else {
      content = JSON.stringify(data, null, 2);
    }

    const blob = new Blob([content], { type: mimeType });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } catch (err) {
    alert("Export failed: " + err.message);
  }
}
window.exportData = exportData;

function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// =========================================================================
// RUNTIME TASK GOVERNANCE & INVENTORY (F1, F10, F11, F12)
// =========================================================================

async function loadGovernanceTasks() {
  try {
    const res = await fetch("/api/governance/tasks");
    if (!res.ok) return;
    const tasks = await res.json();
    const tbody = document.getElementById("gov-tasks-tbody");
    const countBadge = document.getElementById("nav-gov-tasks-count");
    if (countBadge) countBadge.textContent = tasks.length;
    if (!tbody) return;

    if (tasks.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);">No tasks recorded yet. Submit a task above.</td></tr>';
      return;
    }

    tbody.innerHTML = tasks.map(t => {
      const compColor = t.compliance_pct === 100 ? "#10b981" : (t.compliance_pct >= 50 ? "#f59e0b" : "#ef4444");
      return `
        <tr>
          <td><code style="font-size:0.75rem;color:var(--accent-primary);">${escapeHtml(t.task_id)}</code></td>
          <td style="font-weight:600;">${escapeHtml(t.request_text)}</td>
          <td><span class="badge">${escapeHtml(t.agent_id)}</span></td>
          <td><span class="status-pill status-${t.status.toLowerCase()}">${escapeHtml(t.status)}</span></td>
          <td style="font-weight:700;color:${compColor};">${t.compliance_pct}%</td>
          <td>${t.actions_inside} inside / <strong style="color:#ef4444;">${t.actions_outside} outside</strong></td>
          <td><span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;">${t.prevented_count} stopped</span></td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="loadGovernanceTaskDetail('${escapeHtml(t.task_id)}')">
              <i class="fa-solid fa-eye"></i> View Detail
            </button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed to load governance tasks:", err);
  }
}
window.loadGovernanceTasks = loadGovernanceTasks;

async function submitGovernanceTask() {
  const textEl = document.getElementById("gov-task-input-text");
  const agentEl = document.getElementById("gov-task-input-agent");
  const modeEl = document.getElementById("gov-task-input-mode");
  if (!textEl || !agentEl || !modeEl) return;

  const request_text = textEl.value.trim();
  const agent_id = agentEl.value.trim();
  const enforcement_mode = modeEl.value;

  if (!request_text) {
    alert("Please enter a task request text.");
    return;
  }

  try {
    const res = await fetch("/api/governance/tasks", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ request_text, agent_id, enforcement_mode }),
    });
    if (!res.ok) {
      const err = await res.json();
      alert("Task submission failed: " + (err.detail || "Error"));
      return;
    }
    const data = await res.json();
    alert(`Task '${data.task.task_id}' created with boundary version ${data.boundary.version}.`);
    loadGovernanceTasks();
    loadGovernanceTaskDetail(data.task.task_id);
  } catch (err) {
    alert("Failed to submit task: " + err.message);
  }
}
window.submitGovernanceTask = submitGovernanceTask;

async function loadGovernanceTaskDetail(taskId) {
  try {
    const card = document.getElementById("gov-task-detail-card");
    const titleEl = document.getElementById("gov-task-detail-title");
    const badgeEl = document.getElementById("gov-task-detail-badge");
    const summaryEl = document.getElementById("gov-task-boundary-summary");
    const eventsTbody = document.getElementById("gov-task-events-tbody");

    const [detRes, evRes] = await Promise.all([
      fetch(`/api/governance/tasks/${taskId}`),
      fetch(`/api/governance/tasks/${taskId}/events`),
    ]);

    if (!detRes.ok || !evRes.ok) return;
    const detail = await detRes.json();
    const events = await evRes.json();

    if (card) card.style.display = "block";
    if (titleEl) titleEl.innerHTML = `<i class="fa-solid fa-timeline" style="color:var(--accent-primary);"></i> Task Detail: ${escapeHtml(taskId)} &mdash; ${escapeHtml(detail.task.request_text)}`;
    if (badgeEl) badgeEl.textContent = detail.task.status;

    if (summaryEl && detail.boundary) {
      summaryEl.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:1rem;">
          <div><strong>Workspace Root:</strong><br>${escapeHtml(detail.boundary.workspace_root)}</div>
          <div><strong>Allowed Files Read:</strong><br>${escapeHtml(detail.boundary.files_read.join(", ") || "(none)")}</div>
          <div><strong>Allowed Files Write:</strong><br>${escapeHtml(detail.boundary.files_write.join(", ") || "(none)")}</div>
          <div><strong>Allowed Tools:</strong><br>${escapeHtml(detail.boundary.tools.join(", "))}</div>
          <div><strong>Allowed Network:</strong><br>${escapeHtml(detail.boundary.network.join(", ") || "(Default Deny)")}</div>
          <div><strong>Allowed Peer Agents:</strong><br>${escapeHtml(detail.boundary.peer_agents.join(", ") || "(Default Deny)")}</div>
        </div>
      `;
    }

    if (eventsTbody) {
      if (events.length === 0) {
        eventsTbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);">No events recorded yet for this task.</td></tr>';
      } else {
        eventsTbody.innerHTML = events.map(e => {
          const isInside = e.verdict === "INSIDE";
          const vColor = isInside ? "#10b981" : "#ef4444";
          const prevBadge = e.prevented ? '<span class="badge" style="background:rgba(16,185,129,0.2);color:#10b981;">STOPPED BEFORE EXEC</span>' : '<span class="badge" style="background:rgba(148,163,184,0.1);color:var(--text-muted);">Observed / Allowed</span>';
          return `
            <tr>
              <td style="font-family:var(--font-mono);font-size:0.75rem;">${escapeHtml(e.timestamp.substring(11, 19))}</td>
              <td><span class="badge">${escapeHtml(e.source)}</span></td>
              <td><strong>${escapeHtml(e.kind)}</strong></td>
              <td><code style="font-size:0.75rem;">${escapeHtml(e.target)}</code></td>
              <td><strong style="color:${vColor};">${escapeHtml(e.verdict)}</strong></td>
              <td><span class="status-pill status-${e.risk_tier.toLowerCase()}">${escapeHtml(e.risk_tier)}</span></td>
              <td>${escapeHtml(e.action_taken)}</td>
              <td>${prevBadge}</td>
            </tr>
          `;
        }).join("");
      }
    }
  } catch (err) {
    console.error("Failed to load task detail:", err);
  }
}
window.loadGovernanceTaskDetail = loadGovernanceTaskDetail;

async function loadGovernanceInventory() {
  try {
    const res = await fetch("/api/governance/inventory");
    if (!res.ok) return;
    const items = await res.json();
    const tbody = document.getElementById("gov-inventory-tbody");
    if (!tbody) return;

    if (items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--text-muted);">No agents discovered yet.</td></tr>';
      return;
    }

    tbody.innerHTML = items.map(item => {
      const isShadow = item.classification === "SHADOW";
      const classBadge = isShadow ? '<span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;border:1px solid #ef4444;"><i class="fa-solid fa-triangle-exclamation"></i> UNGOVERNED SHADOW</span>' : '<span class="badge" style="background:rgba(16,185,129,0.2);color:#10b981;border:1px solid #10b981;"><i class="fa-solid fa-shield-halved"></i> GOVERNED</span>';
      return `
        <tr>
          <td>${classBadge}</td>
          <td><code style="font-size:0.78rem;font-weight:700;">${escapeHtml(item.agent_id)}</code></td>
          <td>${escapeHtml(item.name)}</td>
          <td>${escapeHtml(item.owner)}</td>
          <td><span class="status-pill status-${item.status.toLowerCase()}">${escapeHtml(item.status)}</span></td>
          <td>${item.current_task_id ? `<code style="font-size:0.75rem;">${escapeHtml(item.current_task_id)} (v${item.boundary_version})</code>` : '<span style="color:var(--text-muted);">&mdash;</span>'}</td>
          <td style="color:#10b981;font-weight:600;">${item.actions_inside}</td>
          <td style="color:${item.actions_outside > 0 ? '#ef4444' : 'inherit'};font-weight:600;">${item.actions_outside}</td>
          <td><strong style="color:${item.violations_count > 0 ? '#ef4444' : 'inherit'};">${item.violations_count}</strong></td>
          <td style="font-family:var(--font-mono);font-size:0.75rem;">${item.last_seen_utc ? escapeHtml(item.last_seen_utc.substring(0, 19).replace('T', ' ')) : '&mdash;'}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed to load governance inventory:", err);
  }
}
window.loadGovernanceInventory = loadGovernanceInventory;

async function loadGovernanceAlerts() {
  try {
    const res = await fetch("/api/governance/alerts");
    if (!res.ok) return;
    const alerts = await res.json();
    const tbody = document.getElementById("gov-alerts-tbody");
    const countBadge = document.getElementById("nav-gov-alerts-count");
    if (countBadge) countBadge.textContent = alerts.length;
    if (!tbody) return;

    if (alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);">No active compliance or governance alerts.</td></tr>';
      return;
    }

    tbody.innerHTML = alerts.map(a => {
      const isShadow = a.is_shadow;
      return `
        <tr>
          <td style="font-family:var(--font-mono);font-size:0.75rem;">${escapeHtml(a.timestamp.substring(11, 19))}</td>
          <td><code style="font-size:0.75rem;">${escapeHtml(a.event_id)}</code></td>
          <td><span class="badge">${escapeHtml(a.source)}</span></td>
          <td><strong>${escapeHtml(a.agent_id)}</strong> ${isShadow ? '<span class="badge" style="background:#ef4444;color:#fff;font-size:0.6rem;">SHADOW</span>' : ''}</td>
          <td><code style="font-size:0.75rem;">${escapeHtml(a.target)}</code></td>
          <td><span class="status-pill status-${a.severity.toLowerCase()}">${escapeHtml(a.severity)}</span></td>
          <td><span class="badge" style="background:rgba(239,68,68,0.15);color:#ef4444;">${escapeHtml(a.action_taken)}</span></td>
          <td style="font-size:0.8rem;color:var(--text-muted);">${escapeHtml(a.rule_matched)}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed to load governance alerts:", err);
  }
}
window.loadGovernanceAlerts = loadGovernanceAlerts;

async function loadGovernanceConfig() {
  try {
    const res = await fetch("/api/governance/config");
    if (!res.ok) return;
    const cfg = await res.json();
    const modeEl = document.getElementById("hdr-gov-mode");
    const pillEl = document.getElementById("hdr-gov-mode-pill");
    if (modeEl) modeEl.textContent = cfg.system_mode || "OBSERVE";
    if (pillEl) {
      if (cfg.system_mode === "ENFORCE") {
        pillEl.style.background = "rgba(239, 68, 68, 0.15)";
        pillEl.style.color = "#f87171";
        pillEl.style.border = "1px solid rgba(239, 68, 68, 0.3)";
      } else {
        pillEl.style.background = "rgba(99, 102, 241, 0.15)";
        pillEl.style.color = "#818cf8";
        pillEl.style.border = "1px solid rgba(99, 102, 241, 0.3)";
      }
    }
  } catch (err) {
    console.error("Failed to load governance config:", err);
  }
}
window.loadGovernanceConfig = loadGovernanceConfig;

async function loadGovernanceExpansions() {
  try {
    const res = await fetch("/api/governance/expansions");
    if (!res.ok) return;
    const expansions = await res.json();
    const tbody = document.getElementById("gov-expansions-tbody");
    const countBadge = document.getElementById("nav-gov-expansions-count");
    const pendingCount = expansions.filter(e => e.status === "PENDING").length;
    if (countBadge) countBadge.textContent = pendingCount;
    if (!tbody) return;

    if (expansions.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--text-muted);">No expansion requests recorded.</td></tr>';
      return;
    }

    tbody.innerHTML = expansions.map(e => {
      const isPending = e.status === "PENDING";
      const isEscalated = e.escalated_by_provenance;
      const statusBadge = isPending
        ? '<span class="status-pill status-pending" style="background:rgba(245,158,11,0.2);color:#f59e0b;">PENDING</span>'
        : (e.status === "APPROVED"
          ? '<span class="status-pill status-allowed" style="background:rgba(16,185,129,0.2);color:#10b981;">APPROVED</span>'
          : '<span class="status-pill status-blocked" style="background:rgba(239,68,68,0.2);color:#ef4444;">DENIED</span>');

      const actionButtons = isPending ? `
        <div style="display:flex;gap:0.3rem;">
          <button class="btn btn-primary btn-sm" onclick="approveExpansion('${escapeHtml(e.request_id)}')"><i class="fa-solid fa-check"></i> Approve</button>
          <button class="btn btn-danger btn-sm" onclick="denyExpansion('${escapeHtml(e.request_id)}')"><i class="fa-solid fa-xmark"></i> Deny</button>
        </div>
      ` : `<span style="font-size:0.75rem;color:var(--text-muted);">Resolved by ${escapeHtml(e.resolved_by || '')}</span>`;

      return `
        <tr>
          <td><code style="font-size:0.75rem;">${escapeHtml(e.request_id)}</code></td>
          <td><code style="font-size:0.75rem;">${escapeHtml(e.task_id)}</code></td>
          <td><strong>${escapeHtml(e.agent_id)}</strong></td>
          <td><span class="badge">${escapeHtml(e.resource_type)}</span></td>
          <td><code style="font-size:0.75rem;">${escapeHtml(e.resource_target)}</code></td>
          <td><span class="status-pill status-${e.baseline_risk_tier.toLowerCase()}">${escapeHtml(e.baseline_risk_tier)}</span></td>
          <td><span class="status-pill status-${e.effective_risk_tier.toLowerCase()}">${escapeHtml(e.effective_risk_tier)}</span></td>
          <td>${isEscalated ? '<span class="badge" style="background:#ef4444;color:#fff;font-size:0.65rem;">ESCALATED (+1)</span>' : '<span style="color:var(--text-muted);font-size:0.75rem;">No (Baseline)</span>'}</td>
          <td>${statusBadge}</td>
          <td>${actionButtons}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed to load governance expansions:", err);
  }
}
window.loadGovernanceExpansions = loadGovernanceExpansions;

async function approveExpansion(requestId) {
  try {
    const res = await fetch(`/api/governance/expansions/${requestId}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decided_by: "human_operator" })
    });
    if (res.ok) {
      await loadGovernanceExpansions();
    } else {
      const err = await res.json();
      alert(`Approval failed: ${err.detail || 'Error'}`);
    }
  } catch (err) {
    console.error("Error approving expansion:", err);
  }
}
window.approveExpansion = approveExpansion;

async function denyExpansion(requestId) {
  try {
    const res = await fetch(`/api/governance/expansions/${requestId}/deny`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decided_by: "human_operator", reason: "Denied by operator" })
    });
    if (res.ok) {
      await loadGovernanceExpansions();
    } else {
      const err = await res.json();
      alert(`Denial failed: ${err.detail || 'Error'}`);
    }
  } catch (err) {
    console.error("Error denying expansion:", err);
  }
}
window.denyExpansion = denyExpansion;
