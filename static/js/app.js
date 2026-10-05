
// ==============================================================================
// THEME CONTROLLER (Light / Dark Mode Dual Toggle)
// ==============================================================================
function initTheme() {
  const saved = localStorage.getItem('cgnat_theme') || 'light';
  applyTheme(saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('cgnat_theme', theme);
  const icon = document.getElementById('theme-icon');
  const label = document.getElementById('theme-label');
  if (icon) icon.textContent = theme === 'dark' ? '🌙' : '☀️';
  if (label) label.textContent = theme === 'dark' ? 'Dark' : 'Light';
}

// Auto-initialize theme on load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initTheme);
} else {
  initTheme();
}

// Global Fetch Interceptor for Authentication
const _nativeFetch = window.fetch;
window.fetch = async function (url, options = {}) {
  const token = authToken || localStorage.getItem("nat_ai_token");
  options = options || {};
  options.headers = options.headers || {};

  if (token) {
    if (options.headers instanceof Headers) {
      if (!options.headers.has("Authorization")) {
        options.headers.set("Authorization", "Bearer " + token);
      }
    } else if (Array.isArray(options.headers)) {
      if (!options.headers.some(h => h[0].toLowerCase() === "authorization")) {
        options.headers.push(["Authorization", "Bearer " + token]);
      }
    } else {
      if (!options.headers["Authorization"] && !options.headers["authorization"]) {
        options.headers["Authorization"] = "Bearer " + token;
      }
    }
  }

  const res = await _nativeFetch(url, options);
  if (res.status === 401 && !String(url).includes("/api/v1/auth/login")) {
    console.warn("Session expired or unauthorized request to:", url);
    const modal = document.getElementById("modal-login");
    if (modal && modal.style.display !== "flex") {
      openLoginModal();
    }
  }
  return res;
};

let authToken = localStorage.getItem("nat_ai_token");

    let currentUser = localStorage.getItem("nat_ai_user") || "admin";

    let currentUserRole = localStorage.getItem("nat_ai_role") || "admin";

    

    let currentView = "health";

    let refreshTimer = null;

    let refreshIntervalMs = 10000;

    let cachedSubscribers = [];

    let cachedUsers = [];



    // Active Telemetry Time State

    let activeTimeMode = "relative"; // "relative" or "absolute"

    let activeMinutes = 5;

    let activeStartTime = null;

    let activeEndTime = null;

    let activeRangeLabel = "Last 5 minutes";



    let resetTargetUser = "";





    // 15-Minute Inactivity Auto-Logout

    let inactivityTimer = null;

    const INACTIVITY_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes



    function resetInactivityTimer() {

      if (inactivityTimer) {

        clearTimeout(inactivityTimer);

        inactivityTimer = null;

      }

      if (!authToken) return;

      inactivityTimer = setTimeout(function() {

        if (authToken) {

          console.warn("Auto-logging out due to 15 minutes of inactivity");

          logout();

        }

      }, INACTIVITY_TIMEOUT_MS);

    }



    function setupInactivityListeners() {

      const events = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'];

      let lastReset = 0;

      events.forEach(function(evt) {

        window.addEventListener(evt, function() {

          const now = Date.now();

          if (now - lastReset > 2000) {

            lastReset = now;

            resetInactivityTimer();

          }

        }, { passive: true });

      });

      resetInactivityTimer();

    }



    window.onload = function() {
      setupInactivityListeners();
      loadRecentRanges();
      
      try {
        if (authToken) {
          const loginOverlay = document.getElementById("login-overlay");
          if (loginOverlay) loginOverlay.style.display = "none";
          const userDisplay = document.getElementById("user-display");
          if (userDisplay) userDisplay.innerText = currentUser;
          updateRoleVisibility();
          verifySession();
        } else {
          const loginOverlay = document.getElementById("login-overlay");
          if (loginOverlay) loginOverlay.style.display = "flex";
        }
      } catch (e) {
        console.error("Session check error:", e);
      }



      try {

        applyExportPreset('1h');

      } catch (e) {}



      try {

        loadRoutersList();

      } catch (e) {}



      loadTelemetry();

      setupRefreshTimer();



      // Close popover when clicking anywhere outside

      document.addEventListener("click", function(e) {

        const popover = document.getElementById("grafana-popover");

        const trigger = document.getElementById("time-picker-btn");

        if (popover && popover.classList.contains("open") && !popover.contains(e.target) && !trigger.contains(e.target)) {

          popover.classList.remove("open");

          trigger.classList.remove("active");

        }

      });

    };



    function toggleMobileMenu() {

      const sidebar = document.getElementById("app-sidebar");

      const backdrop = document.getElementById("sidebar-backdrop");

      sidebar.classList.toggle("open");

      backdrop.classList.toggle("open");

    }



    // Auto-refresh when tab comes back into focus

    document.addEventListener("visibilitychange", function() {

      if (document.visibilityState === "visible") {

        loadTelemetry();

        setupRefreshTimer();

      }

    });



    function setupRefreshTimer() {

      if (refreshTimer) {

        clearInterval(refreshTimer);

        refreshTimer = null;

      }

      if (refreshIntervalMs > 0) {

        refreshTimer = setInterval(function() {

          loadTelemetry();

        }, refreshIntervalMs);

      }

    }



    function changeRefreshInterval() {

      const selectEl = document.getElementById("refresh-interval");

      if (selectEl) {

        const val = parseInt(selectEl.value, 10);

        refreshIntervalMs = isNaN(val) ? 10000 : val;

        setupRefreshTimer();

      }

    }



    function updateRoleVisibility() {
      const isAdm = (currentUserRole === "admin");
      const isOp = (currentUserRole === "admin" || currentUserRole === "operator");
      
      const tabSystem = document.getElementById("tab-btn-system") || document.getElementById("tab-btn-users");
      if (tabSystem) tabSystem.style.display = isOp ? "flex" : "none";
      
      const btnSubUsers = document.getElementById("btn-sub-users");
      const btnSubAI = document.getElementById("btn-sub-aikeys");
      const btnSubRadius = document.getElementById("btn-sub-radius");
      const btnSubRouters = document.getElementById("btn-sub-routers");
      const btnSubDiscord = document.getElementById("btn-sub-discord");

      if (btnSubUsers) btnSubUsers.style.display = isAdm ? "inline-flex" : "none";
      if (btnSubAI) btnSubAI.style.display = isAdm ? "inline-flex" : "none";
      if (btnSubRadius) btnSubRadius.style.display = isAdm ? "inline-flex" : "none";
      if (btnSubRouters) btnSubRouters.style.display = isOp ? "inline-flex" : "none";
      if (btnSubDiscord) btnSubDiscord.style.display = isOp ? "inline-flex" : "none";

      const userRoleDisplay = document.getElementById("user-role-display");
      if (userRoleDisplay) userRoleDisplay.innerText = currentUserRole.toUpperCase();
      const badgeNavRole = document.getElementById("badge-nav-role");
      if (badgeNavRole) badgeNavRole.innerText = currentUserRole.toUpperCase();
    }



    function switchView(viewName) {

      currentView = viewName;

      const healthView = document.getElementById("view-health");
      const subsView = document.getElementById("view-subscribers");
      const exportView = document.getElementById("view-export");
      const threatsView = document.getElementById("view-threats");
      const systemView = document.getElementById("view-system") || document.getElementById("view-users");

      const healthBtn = document.getElementById("tab-btn-health");
      const subsBtn = document.getElementById("tab-btn-subscribers");
      const exportBtn = document.getElementById("tab-btn-export");
      const threatsBtn = document.getElementById("tab-btn-threats");
      const systemBtn = document.getElementById("tab-btn-system") || document.getElementById("tab-btn-users");



      const title = document.getElementById("view-title");



      if (healthBtn) healthBtn.classList.toggle("active", viewName === "health");

      if (subsBtn) subsBtn.classList.toggle("active", viewName === "subscribers");

      if (exportBtn) exportBtn.classList.toggle("active", viewName === "export");

      if (threatsBtn) threatsBtn.classList.toggle("active", viewName === "threats");

      if (systemBtn) systemBtn.classList.toggle("active", viewName === "system" || viewName === "users");



      if (healthView) healthView.classList.toggle("active", viewName === "health");

      if (subsView) subsView.classList.toggle("active", viewName === "subscribers");

      if (exportView) exportView.classList.toggle("active", viewName === "export");

      if (threatsView) threatsView.classList.toggle("active", viewName === "threats");

      if (systemView) systemView.classList.toggle("active", viewName === "system" || viewName === "users");



      // Close mobile drawer on navigation

      const sidebar = document.getElementById("app-sidebar");

      const backdrop = document.getElementById("sidebar-backdrop");

      if (sidebar) sidebar.classList.remove("open");

      if (backdrop) backdrop.classList.remove("open");



      if (viewName === "health") {

        title.innerHTML = "&#128202; Server &amp; Pipeline Telemetry Health";

        loadTelemetry();

      } else if (viewName === "subscribers") {

        title.innerHTML = "&#128101; Private Pool &amp; Heavy Subscribers Monitoring";

        loadTelemetry();

      } else if (viewName === "export") {

        title.innerHTML = "&#128229; Carrier-Grade Forensics Log Exporter";

      } else if (viewName === "threats") {

        title.innerHTML = "&#128737;&#65039; Multi-Vendor Threat Shield &amp; Fleet Blocker";

        loadRouters();

        loadThreatData();

            } else if (viewName === "system" || viewName === "users") {
        title.innerHTML = "&#9881;&#65039; System Configuration &amp; Administration";
        updateRoleVisibility();
        let defaultSub = window.activeSystemSubTab;
        if (currentUserRole !== "admin") {
          if (!defaultSub || defaultSub === "users" || defaultSub === "aikeys" || defaultSub === "radius") {
            defaultSub = "routers";
          }
        } else {
          if (!defaultSub) defaultSub = "users";
        }
        switchSystemSubTab(defaultSub);
      }

    }



    function switchTableTab(tab) {

      document.getElementById("btn-table-routers").classList.toggle("active", tab === "routers");

      document.getElementById("btn-table-nat").classList.toggle("active", tab === "nat");

      document.getElementById("btn-table-private").classList.toggle("active", tab === "private");



      document.getElementById("table-view-routers").style.display = (tab === "routers") ? "block" : "none";

      document.getElementById("table-view-nat").style.display = (tab === "nat") ? "block" : "none";

      document.getElementById("table-view-private").style.display = (tab === "private") ? "block" : "none";

    }



    /* ================= GRAFANA TIME PICKER LOGIC ================= */

    function toggleTimePicker(e) {

      if (e) e.stopPropagation();

      const popover = document.getElementById("grafana-popover");

      const btn = document.getElementById("time-picker-btn");

      popover.classList.toggle("open");

      btn.classList.toggle("active");

    }



    function selectQuickRange(minutes, label, el) {

      activeTimeMode = "relative";

      activeMinutes = minutes;

      activeStartTime = null;

      activeEndTime = null;

      activeRangeLabel = label;



      document.querySelectorAll(".quick-range-btn").forEach(b => b.classList.remove("active"));

      if (el) el.classList.add("active");



      document.getElementById("active-range-label").innerText = label;

      document.getElementById("health-window-text").innerText = label;

      document.getElementById("subs-window-text").innerText = label;

      

      toggleTimePicker();

      setupRefreshTimer();

      loadTelemetry();

    }



    function selectNamedRange(preset, label, el) {

      const now = new Date();

      let start = new Date();

      let end = new Date();



      if (preset === 'today') {

        start.setHours(0, 0, 0, 0);

      } else if (preset === 'yesterday') {

        start.setDate(start.getDate() - 1);

        start.setHours(0, 0, 0, 0);

        end.setDate(end.getDate() - 1);

        end.setHours(23, 59, 59, 999);

      }



      const stStr = toLocalISOString(start).replace('T', ' ');

      const etStr = toLocalISOString(end).replace('T', ' ');



      activeTimeMode = "absolute";

      activeStartTime = stStr;

      activeEndTime = etStr;

      activeRangeLabel = label;



      document.querySelectorAll(".quick-range-btn").forEach(b => b.classList.remove("active"));

      if (el) el.classList.add("active");



      document.getElementById("active-range-label").innerText = label;

      document.getElementById("health-window-text").innerText = `${label} (${stStr.slice(11,16)} - ${etStr.slice(11,16)})`;

      document.getElementById("subs-window-text").innerText = label;



      addRecentRange(stStr, etStr);

      toggleTimePicker();

      setupRefreshTimer();

      loadTelemetry();

    }



    function applyAbsoluteTimeRange() {

      let fromVal = document.getElementById("picker-from-input").value.trim();

      let toVal = document.getElementById("picker-to-input").value.trim();



      if (!fromVal) {

        alert("Please enter a valid From date/time (e.g. now-1h or YYYY-MM-DD HH:MM:SS)");

        return;

      }

      if (!toVal) toVal = "now";



      const now = new Date();

      let start = new Date();

      let end = new Date();



      // Parse From

      if (fromVal.startsWith("now-")) {

        const unit = fromVal.slice(4).trim();

        if (unit.endsWith("m")) start = new Date(now.getTime() - parseInt(unit, 10) * 60 * 1000);

        else if (unit.endsWith("h")) start = new Date(now.getTime() - parseInt(unit, 10) * 3600 * 1000);

        else if (unit.endsWith("d")) start = new Date(now.getTime() - parseInt(unit, 10) * 86400 * 1000);

      } else {

        start = new Date(fromVal.replace(' ', 'T'));

      }



      // Parse To

      if (toVal === "now") {

        end = now;

      } else if (toVal.startsWith("now-")) {

        const unit = toVal.slice(4).trim();

        if (unit.endsWith("m")) end = new Date(now.getTime() - parseInt(unit, 10) * 60 * 1000);

        else if (unit.endsWith("h")) end = new Date(now.getTime() - parseInt(unit, 10) * 3600 * 1000);

        else if (unit.endsWith("d")) end = new Date(now.getTime() - parseInt(unit, 10) * 86400 * 1000);

      } else {

        end = new Date(toVal.replace(' ', 'T'));

      }



      if (isNaN(start.getTime()) || isNaN(end.getTime())) {

        alert("Invalid Date format. Use YYYY-MM-DD HH:MM:SS (e.g. 2026-09-17 12:00:00)");

        return;

      }



      const stStr = toLocalISOString(start).replace('T', ' ');

      const etStr = toLocalISOString(end).replace('T', ' ');



      activeTimeMode = "absolute";

      activeStartTime = stStr;

      activeEndTime = etStr;

      activeRangeLabel = `${stStr.slice(5, 16)} to ${etStr.slice(5, 16)}`;



      document.querySelectorAll(".quick-range-btn").forEach(b => b.classList.remove("active"));

      document.getElementById("active-range-label").innerText = activeRangeLabel;

      document.getElementById("health-window-text").innerText = `${stStr} to ${etStr}`;

      document.getElementById("subs-window-text").innerText = `${stStr} to ${etStr}`;



      addRecentRange(stStr, etStr);

      toggleTimePicker();

      setupRefreshTimer();

      loadTelemetry();

    }



    function addRecentRange(st, et) {

      let recents = JSON.parse(localStorage.getItem("nat_ai_recent_ranges") || "[]");

      const entry = `${st} to ${et}`;

      recents = recents.filter(r => r !== entry);

      recents.unshift(entry);

      if (recents.length > 5) recents.pop();

      localStorage.setItem("nat_ai_recent_ranges", JSON.stringify(recents));

      loadRecentRanges();

    }



    function loadRecentRanges() {

      const recents = JSON.parse(localStorage.getItem("nat_ai_recent_ranges") || "[]");

      const container = document.getElementById("recent-ranges-container");

      if (recents.length === 0) {

        container.innerHTML = '<div style="font-size: 11px; color: #5f6672; padding: 4px;">No recent ranges</div>';

        return;

      }

      let html = "";

      recents.forEach(r => {

        html += `<div class="recent-range-item" onclick="applyRecentRangeString('${r}')">${r}</div>`;

      });

      container.innerHTML = html;

    }



    function applyRecentRangeString(str) {

      const parts = str.split(" to ");

      if (parts.length === 2) {

        document.getElementById("picker-from-input").value = parts[0];

        document.getElementById("picker-to-input").value = parts[1];

        applyAbsoluteTimeRange();

      }

    }



    function filterQuickRanges() {

      const q = (document.getElementById("quick-search-input").value || "").toLowerCase().trim();

      const buttons = document.querySelectorAll(".quick-range-btn");

      buttons.forEach(btn => {

        const text = btn.innerText.toLowerCase();

        btn.style.display = text.includes(q) ? "block" : "none";

      });

    }



    /* ================= USER MANAGEMENT & AUTH ================= */

    async function performLogin() {

      const u = document.getElementById("login-user").value.trim();

      const p = document.getElementById("login-pass").value;

      const errEl = document.getElementById("login-err");

      const btn = document.getElementById("btn-login");

      errEl.style.display = "none";



      if (!u || !p) {

        errEl.innerText = "Please enter both username and password";

        errEl.style.display = "block";

        return;

      }



      btn.disabled = true;

      btn.innerText = "Authenticating...";



      try {

        const res = await fetch("/api/v1/auth/login", {

          method: "POST",

          headers: {"Content-Type": "application/json"},

          body: JSON.stringify({username: u, password: p})

        });

        const data = await res.json();

        btn.disabled = false;

        btn.innerText = "Log In";



        if (res.ok) {

          authToken = data.token;

          currentUser = data.username;

          currentUserRole = data.role || "operator";

          

          localStorage.setItem("nat_ai_token", authToken);

          localStorage.setItem("nat_ai_user", currentUser);

          localStorage.setItem("nat_ai_role", currentUserRole);



          document.getElementById("login-overlay").style.display = "none";

          document.getElementById("user-display").innerText = currentUser;

          updateRoleVisibility();

          loadTelemetry();

          resetInactivityTimer();

        } else {

          errEl.innerText = data.detail || "Invalid username or password";

          errEl.style.display = "block";

        }

      } catch (e) {

        btn.disabled = false;

        btn.innerText = "Log In";

        errEl.innerText = "Network connection failed";

        errEl.style.display = "block";

      }

    }



    async function verifySession() {
      if (!authToken) {
        const loginOverlay = document.getElementById("login-overlay");
        if (loginOverlay) loginOverlay.style.display = "flex";
        return;
      }
      try {
        const res = await fetch("/api/v1/auth/me", {
          headers: {"Authorization": "Bearer " + authToken}
        });
        if (res.ok) {
          const data = await res.json();
          currentUser = data.username;
          currentUserRole = data.role || "operator";
          localStorage.setItem("nat_ai_user", currentUser);
          localStorage.setItem("nat_ai_role", currentUserRole);

          const loginOverlay = document.getElementById("login-overlay");
          if (loginOverlay) loginOverlay.style.display = "none";
          const userDisplay = document.getElementById("user-display");
          if (userDisplay) userDisplay.innerText = currentUser;
          updateRoleVisibility();
          resetInactivityTimer();
        } else if (res.status === 401) {
          localStorage.removeItem("nat_ai_token");
          localStorage.removeItem("nat_ai_user");
          localStorage.removeItem("nat_ai_role");
          const loginOverlay = document.getElementById("login-overlay");
          if (loginOverlay) loginOverlay.style.display = "flex";
        }
      } catch (e) {
        console.error("verifySession network error:", e);
      }
    }

    function logout() {

      localStorage.removeItem("nat_ai_token");

      localStorage.removeItem("nat_ai_user");

      localStorage.removeItem("nat_ai_role");

      location.reload();

    }



    function openPasswordModal() {

      document.getElementById("cp-current").value = "";

      document.getElementById("cp-new").value = "";

      document.getElementById("cp-confirm").value = "";

      document.getElementById("cp-status").style.display = "none";

      document.getElementById("modal-change-password").style.display = "flex";

    }



    function closePasswordModal() {

      document.getElementById("modal-change-password").style.display = "none";

    }



    async function submitPasswordChange() {

      const cur = document.getElementById("cp-current").value;

      const nw = document.getElementById("cp-new").value;

      const cf = document.getElementById("cp-confirm").value;

      const statusEl = document.getElementById("cp-status");



      if (!cur) {

        statusEl.innerHTML = '<span style="color: var(--danger);">&#9888; Please enter your current password</span>';

        statusEl.style.display = "block";

        return;

      }

      if (nw.length < 4) {

        statusEl.innerHTML = '<span style="color: var(--danger);">&#9888; New password must be at least 4 characters</span>';

        statusEl.style.display = "block";

        return;

      }

      if (nw !== cf) {

        statusEl.innerHTML = '<span style="color: var(--danger);">&#9888; Passwords do not match</span>';

        statusEl.style.display = "block";

        return;

      }



      try {

        const res = await fetch("/api/v1/auth/change-password", {

          method: "POST",

          headers: {

            "Content-Type": "application/json",

            "Authorization": "Bearer " + authToken

          },

          body: JSON.stringify({current_password: cur, new_password: nw})

        });

        const data = await res.json();

        if (res.ok) {

          statusEl.innerHTML = '<span style="color: var(--success); font-weight: 600;">&#10004; Password updated successfully!</span>';

          statusEl.style.display = "block";

          setTimeout(() => closePasswordModal(), 1200);

        } else {

          statusEl.innerHTML = `<span style="color: var(--danger);">&#9888; ${data.detail || "Password update failed"}</span>`;

          statusEl.style.display = "block";

        }

      } catch (e) {

        statusEl.innerHTML = '<span style="color: var(--danger);">&#9888; Network error</span>';

        statusEl.style.display = "block";

      }

    }



    async function loadUsersList() {
      if (currentUserRole !== "admin") return;
      try {
        const res = await fetch("/api/v1/users", {
          headers: {"Authorization": "Bearer " + authToken}
        });
        if (res.ok) {
          const data = await res.json();
          cachedUsers = data.users || [];
          
          let total = cachedUsers.length;
          let admins = 0, operators = 0;
          cachedUsers.forEach(u => {
            if (u.role === "admin") admins++;
            else operators++;
          });

          const elTotal = document.getElementById("kpi-user-total");
          const elAdmins = document.getElementById("kpi-user-admins");
          const elOps = document.getElementById("kpi-user-operators");
          const elBadge = document.getElementById("users-count-badge");

          if (elTotal) elTotal.innerText = total;
          if (elAdmins) elAdmins.innerText = admins;
          if (elOps) elOps.innerText = operators;
          if (elBadge) elBadge.innerText = `${total} Accounts`;

          let html = "";
          cachedUsers.forEach(u => {
            const isSelf = (u.username === currentUser);
            const isOnline = !!u.is_online;
            const dotStyle = isOnline
              ? "display: inline-block; vertical-align: middle; margin-right: 8px; width: 8px; height: 8px; background: var(--success); border-radius: 50%; box-shadow: 0 0 8px var(--success); animation: pulse 2s infinite;"
              : "display: inline-block; vertical-align: middle; margin-right: 8px; width: 8px; height: 8px; background: #ef4444; border-radius: 50%; box-shadow: 0 0 6px rgba(239, 68, 68, 0.6);";

            let roleHtml = "";
            if (u.username.toLowerCase() === "admin") {
              roleHtml = `<span class="badge-tag purple" style="font-weight: 600;" title="Primary Administrator account role is permanently locked">&#128274; ADMIN</span>`;
            } else {
              roleHtml = `
                <select class="form-control" style="display: inline-block; width: auto; min-width: 105px; padding: 3px 8px; font-size: 11px; height: 26px; background: var(--input-bg); border: 1px solid var(--border-light); color: ${u.role === 'admin' ? '#c084fc' : (u.role === 'operator' ? '#38bdf8' : '#4ade80')}; font-weight: 600; border-radius: 4px;" onchange="changeUserRole('${u.username}', this.value)">
                  <option value="operator" ${u.role === 'operator' ? 'selected' : ''} style="color: #38bdf8;">OPERATOR</option>
                  <option value="admin" ${u.role === 'admin' ? 'selected' : ''} style="color: #c084fc;">ADMIN</option>
                  <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''} style="color: #4ade80;">VIEWER</option>
                </select>
              `;
            }

            html += `
              <tr>
                <td><span style="${dotStyle}" title="${isOnline ? 'Online' : 'Offline'}"></span><strong style="color: var(--text-main);">${u.username}</strong> ${isSelf ? '<span style="color: var(--text-dim); font-size: 10px;">(You)</span>' : ''}</td>
                <td>${roleHtml}</td>
                <td style="color: var(--text-dim);">${u.created_at || "--"}</td>
                <td style="color: var(--text-muted);">${u.last_login || "Never"}</td>
                <td style="text-align: right;">
                  <button class="btn-table-action" onclick="openAdminResetModal('${u.username}')">&#128273; Reset</button>
                  ${!isSelf && u.username.toLowerCase() !== 'admin' ? `<button class="btn-table-action danger" onclick="deleteUser('${u.username}')">&#128465; Delete</button>` : ''}
                </td>
              </tr>
            `;
          });
          const tbody = document.getElementById("tbody-users");
          if (tbody) tbody.innerHTML = html || '<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 24px;">No users found</td></tr>';
        }
      } catch (e) {
        console.error("Failed to load users:", e);
      }
    }

    async function changeUserRole(username, newRole) {
      if (username.toLowerCase() === "admin") {
        alert("The primary admin account role cannot be changed.");
        loadUsersList();
        return;
      }
      try {
        const res = await fetch(`/api/v1/users/${encodeURIComponent(username)}/role`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + authToken
          },
          body: JSON.stringify({ role: newRole })
        });
        const data = await res.json();
        if (res.ok) {
          loadUsersList();
        } else {
          alert(data.detail || "Failed to update user role");
          loadUsersList();
        }
      } catch (e) {
        alert("Network error updating user role");
        loadUsersList();
      }
    }

    async function submitCreateUser() {
      const uEl = document.getElementById("new-user-username") || document.getElementById("new-user-name");
      const pEl = document.getElementById("new-user-password") || document.getElementById("new-user-pass");
      const rEl = document.getElementById("new-user-role");
      const cEl = document.getElementById("new-user-pass-confirm");

      const u = uEl ? uEl.value.trim() : "";
      const p = pEl ? pEl.value : "";
      const r = rEl ? rEl.value : "operator";
      const c = cEl ? cEl.value : p;
      const statusEl = document.getElementById("create-user-status");

      if (u.length < 3) {
        if (statusEl) {
          statusEl.innerHTML = '<span style="color: var(--danger);">&#9888; Username must be at least 3 characters</span>';
          statusEl.style.display = "block";
        }
        return;
      }
      if (p.length < 4) {
        if (statusEl) {
          statusEl.innerHTML = '<span style="color: var(--danger);">&#9888; Password must be at least 4 characters</span>';
          statusEl.style.display = "block";
        }
        return;
      }
      if (c && p !== c) {
        if (statusEl) {
          statusEl.innerHTML = '<span style="color: var(--danger);">&#9888; Passwords do not match</span>';
          statusEl.style.display = "block";
        }
        return;
      }

      try {
        const res = await fetch("/api/v1/users", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + authToken
          },
          body: JSON.stringify({username: u, password: p, role: r})
        });
        const data = await res.json();
        if (res.ok) {
          if (statusEl) {
            statusEl.innerHTML = `<span style="color: var(--success); font-weight: 600;">&#10004; ${data.message}</span>`;
            statusEl.style.display = "block";
          }
          if (uEl) uEl.value = "";
          if (pEl) pEl.value = "";
          if (cEl) cEl.value = "";
          loadUsersList();
          if (statusEl) setTimeout(() => { statusEl.style.display = "none"; }, 3000);
        } else {
          if (statusEl) {
            statusEl.innerHTML = `<span style="color: var(--danger);">&#9888; ${data.detail || "Creation failed"}</span>`;
            statusEl.style.display = "block";
          }
        }
      } catch (e) {
        if (statusEl) {
          statusEl.innerHTML = '<span style="color: var(--danger);">&#9888; Network error</span>';
          statusEl.style.display = "block";
        }
      }
    }

    function openAdminResetModal(targetUser) {

      resetTargetUser = targetUser;

      document.getElementById("admin-reset-target-user").innerText = targetUser;

      document.getElementById("admin-reset-new-pwd").value = "";

      document.getElementById("admin-reset-status").style.display = "none";

      document.getElementById("modal-admin-reset-pwd").style.display = "flex";

    }



    function closeAdminResetModal() {

      document.getElementById("modal-admin-reset-pwd").style.display = "none";

    }



    async function submitAdminResetPassword() {

      const pwd = document.getElementById("admin-reset-new-pwd").value;

      const statusEl = document.getElementById("admin-reset-status");



      if (pwd.length < 4) {

        statusEl.innerHTML = '<span style="color: var(--danger);">&#9888; New password must be at least 4 characters</span>';

        statusEl.style.display = "block";

        return;

      }



      try {

        const res = await fetch(`/api/v1/users/${resetTargetUser}/reset-password`, {

          method: "PUT",

          headers: {

            "Content-Type": "application/json",

            "Authorization": "Bearer " + authToken

          },

          body: JSON.stringify({new_password: pwd})

        });

        const data = await res.json();

        if (res.ok) {

          statusEl.innerHTML = `<span style="color: var(--success); font-weight: 600;">&#10004; ${data.message}</span>`;

          statusEl.style.display = "block";

          setTimeout(() => closeAdminResetModal(), 1200);

        } else {

          statusEl.innerHTML = `<span style="color: var(--danger);">&#9888; ${data.detail || "Reset failed"}</span>`;

          statusEl.style.display = "block";

        }

      } catch (e) {

        statusEl.innerHTML = '<span style="color: var(--danger);">&#9888; Network error</span>';

        statusEl.style.display = "block";

      }

    }



    async function deleteUser(username) {

      if (!confirm(`Are you sure you want to permanently delete account "${username}"?`)) return;

      try {

        const res = await fetch(`/api/v1/users/${username}`, {

          method: "DELETE",

          headers: {"Authorization": "Bearer " + authToken}

        });

        const data = await res.json();

        if (res.ok) {

          loadUsersList();

        } else {

          alert(data.detail || "Failed to delete user");

        }

      } catch (e) {

        alert("Network error");

      }

    }



    /* ================= TELEMETRY LOADING & DATA POPULATION ================= */

    function formatBytes(bytes, decimals = 1) {

      if (!bytes || bytes === 0) return '0 B';

      const k = 1024;

      const dm = decimals < 0 ? 0 : decimals;

      const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

      const i = Math.floor(Math.log(bytes) / Math.log(k));

      return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];

    }



    async function loadTelemetry() {

      try {

        let url = "/api/v1/telemetry";

        if (activeTimeMode === "relative") {

          url += `?minutes=${activeMinutes}`;

        } else if (activeTimeMode === "absolute" && activeStartTime && activeEndTime) {

          url += `?start_time=${encodeURIComponent(activeStartTime)}&end_time=${encodeURIComponent(activeEndTime)}`;

        }



        const res = await fetch(url);

        if (!res.ok) return;

        const data = await res.json();



        document.getElementById("health-last-updated").innerText = data.timestamp || new Date().toLocaleTimeString();



        // System Health

        const sys = data.system || {};

        const cpuLoad = sys.load_avg ? `${sys.load_avg['1m']}` : "--";

        const cpuPct = sys.load_pct || 0;

        document.getElementById("kpi-cpu-load").innerText = `${cpuLoad} (${cpuPct}%)`;

        document.getElementById("kpi-cpu-bar").style.width = `${Math.min(100, cpuPct)}%`;

        document.getElementById("kpi-cpu-cores").innerText = `${sys.cpu_cores || 32} vCPUs`;

        document.getElementById("kpi-uptime").innerText = sys.uptime || "--";



        // Memory

        const mem = sys.memory || {};

        document.getElementById("kpi-mem-used").innerText = `${formatBytes(mem.used_bytes, 1)} (${mem.pct}%)`;

        document.getElementById("kpi-mem-bar").style.width = `${mem.pct || 0}%`;

        document.getElementById("kpi-mem-total").innerText = formatBytes(mem.total_bytes, 1);

        document.getElementById("kpi-mem-free").innerText = formatBytes(mem.free_bytes, 1);



        // Disk

        const disk = sys.disk || {};

        document.getElementById("kpi-disk-free").innerText = `${formatBytes(disk.root_free, 1)} Free`;

        document.getElementById("kpi-disk-bar").style.width = `${disk.root_pct || 2}%`;

        document.getElementById("kpi-disk-used").innerText = `${formatBytes(disk.root_used, 1)} (${disk.root_pct}%)`;

        document.getElementById("kpi-disk-total").innerText = formatBytes(disk.root_total, 1);



        // Services

        const svcs = sys.services || {};

        updateServiceBadge("svc-clickhouse", svcs['clickhouse-server']);

        updateServiceBadge("svc-vector", svcs['vector']);


        updateServiceBadge("svc-agent", svcs['nat-ai-agent']);



        // Ingestion & Rates

        const ingest = data.ingestion || {};

        const currentEps = ingest.current_eps || 0;

        const windowEps = ingest.window_eps || 0;

        document.getElementById("kpi-eps").innerText = `~${Math.round(currentEps).toLocaleString()} eps`;

        document.getElementById("stat-fps").innerText = `~${Math.round(currentEps).toLocaleString()} eps`;

        document.getElementById("kpi-5m-rate").innerText = `~${Math.round(windowEps).toLocaleString()} eps`;

        document.getElementById("kpi-routers-count").innerText = `${ingest.active_routers_count || 0} Nodes`;

        document.getElementById("stat-routers").innerText = `${ingest.active_routers_count || 0} Online`;



        // Protocols

        const protocols = ingest.protocols || [];

        let tcpPct = 0, udpPct = 0;

        protocols.forEach(p => {

          if (p.protocol === "TCP") tcpPct = p.pct;

          if (p.protocol === "UDP") udpPct = p.pct;

        });

        document.getElementById("proto-tcp-pct").innerText = `${tcpPct}%`;

        document.getElementById("proto-tcp-bar").style.width = `${tcpPct}%`;

        document.getElementById("proto-udp-pct").innerText = `${udpPct}%`;

        document.getElementById("proto-udp-bar").style.width = `${udpPct}%`;



        // Top ports badges

        const topPorts = ingest.top_ports || [];

        const portBadgesHtml = topPorts.map(p => `<span class="badge-tag green">Port ${p.port} (${p.proto}): ${p.flows.toLocaleString()} flows</span>`).join("");

        document.getElementById("top-ports-badges").innerHTML = portBadgesHtml || '<span class="badge-tag green">Port 443 (HTTPS)</span>';



        // Storage

        const storage = data.storage || {};

        const totalRows = storage.total_rows || 0;

        const totalRowsStr = totalRows >= 1000000 ? (totalRows / 1000000).toFixed(2) + "M rows" : totalRows.toLocaleString() + " rows";

        document.getElementById("kpi-total-logs").innerText = totalRowsStr;

        document.getElementById("kpi-comp-ratio").innerText = `${storage.compression_ratio || 6.2}x Ratio`;

        document.getElementById("kpi-bytes-row").innerText = `${storage.bytes_per_row || 4.67} B/row`;



        // NAT Pools & Subscribers

        const nat = data.nat_pool || {};

        const priv = data.private_pool || {};

        document.getElementById("kpi-public-nat-count").innerText = `${nat.total_public_nat_ips || 0} Public IPs`;

        document.getElementById("kpi-nat-ips").innerText = `${nat.total_public_nat_ips || 0} IPs`;

        document.getElementById("kpi-priv-subs").innerText = `${(priv.total_private_subscribers || 0).toLocaleString()} Subs`;



        // Dedicated Subscriber KPIs

        const totalSubs = priv.total_private_subscribers || 0;

        const totalFlows = priv.total_flows || 0;

        document.getElementById("subs-kpi-total-subs").innerText = totalSubs.toLocaleString();

        document.getElementById("subs-kpi-sub-count").innerText = `${totalSubs.toLocaleString()} IPs`;

        document.getElementById("subs-kpi-total-flows").innerText = totalFlows >= 1000000 ? (totalFlows / 1000000).toFixed(2) + "M flows" : totalFlows.toLocaleString() + " flows";

        

        const winSec = (data.window && data.window.seconds) ? data.window.seconds : 300;

        document.getElementById("subs-kpi-flows-rate").innerText = `~${Math.round(totalFlows / winSec).toLocaleString()} eps`;



        cachedSubscribers = priv.top_subscribers || [];

        let heavyCount = 0, scannerCount = 0;

        cachedSubscribers.forEach(s => {

          if (s.behavior.includes("HEAVY")) heavyCount++;

          if (s.behavior.includes("SCANNER")) scannerCount++;

        });



        document.getElementById("subs-kpi-heavy-count").innerText = `${heavyCount} Subs`;

        document.getElementById("subs-kpi-heavy-pct").innerText = cachedSubscribers.length > 0 ? `${Math.round((heavyCount / cachedSubscribers.length) * 100)}%` : "0%";

        document.getElementById("subs-kpi-scanners-count").innerText = `${scannerCount} Threats`;



        // Table 1: Routers

        const routers = ingest.routers || [];

        let rHtml = "";

        routers.forEach(r => {

          rHtml += `

            <tr>

              <td><strong>${r.router_ip}</strong></td>

              <td><span style="color: var(--success); font-weight: 600;">${r.eps.toLocaleString()} eps</span></td>

              <td>${r.flows.toLocaleString()}</td>

              <td>${r.subscribers.toLocaleString()}</td>

              <td>${r.nat_ips}</td>

              <td style="color: var(--text-dim);">${r.last_seen}</td>

              <td><span class="badge-tag green">ACTIVE</span></td>

            </tr>

          `;

        });

        document.getElementById("tbody-routers").innerHTML = rHtml || '<tr><td colspan="7">No active routers streaming</td></tr>';



        // Table 2: Public NAT Pool

        cachedNatList = (nat.top_nat_ips || []).slice();

        renderNatPoolTable();



        // Table 3: Private Pool Preview

        let pHtml = "";

        cachedSubscribers.slice(0, 50).forEach(s => {

          const isScanner = s.behavior.includes("SCANNER");

          const isHeavy = s.behavior.includes("HEAVY");

          const tagClass = isScanner ? "red" : (isHeavy ? "yellow" : "green");

          pHtml += `

            <tr>

              <td><strong style="color: #93c5fd;">${s.src_ip}</strong></td>

              <td>${s.router_ip}</td>

              <td>${s.flows.toLocaleString()}</td>

              <td><span style="color: ${isScanner ? 'var(--danger)' : 'inherit'}; font-weight: ${isScanner ? 'bold' : 'normal'};">${s.distinct_dests.toLocaleString()}</span></td>

              <td>${s.distinct_ports.toLocaleString()}</td>

              <td>${s.assigned_nat_ip}</td>

              <td><span class="badge-tag ${tagClass}">${s.behavior}</span></td>

              <td><button class="btn-table-action" onclick="investigateSubscriber('${s.src_ip}')">&#128269; Forensics</button></td>

            </tr>

          `;

        });

        document.getElementById("tbody-private").innerHTML = pHtml || '<tr><td colspan="8">No subscribers recorded</td></tr>';



        filterSubscribersTable();



      } catch (e) {

        console.error("Telemetry load failed:", e);

      }

    }



    
    // Multi-Column Subscriber Sorting State (Default: distinct_ports DESC)
    let currentSubsSortColumn = 'distinct_ports';
    let currentSubsSortDir = 'desc';

    function sortSubscribersBy(column) {
      if (column === 'distinct_ports') {
        // Distinct Ports in descending order cannot be changed (always high to low)
        currentSubsSortColumn = 'distinct_ports';
        currentSubsSortDir = 'desc';
      } else {
        if (currentSubsSortColumn === column) {
          // Toggle direction for other columns
          currentSubsSortDir = (currentSubsSortDir === 'desc') ? 'asc' : 'desc';
        } else {
          currentSubsSortColumn = column;
          currentSubsSortDir = (column === 'src_ip' || column === 'router_ip' || column === 'assigned_nat_ip' || column === 'behavior') ? 'asc' : 'desc';
        }
      }
      updateSubsSortIcons();
      filterSubscribersTable();
    }

    function updateSubsSortIcons() {
      const columns = ['src_ip', 'router_ip', 'flows', 'distinct_dests', 'distinct_ports', 'assigned_nat_ip', 'behavior'];
      columns.forEach(col => {
        const iconEl = document.getElementById(`sort-icon-${col}`);
        const thEl = iconEl ? iconEl.closest('th') : null;
        if (!iconEl) return;

        if (col === currentSubsSortColumn) {
          iconEl.innerHTML = currentSubsSortDir === 'desc' ? ' &#9660;' : ' &#9650;';
          if (thEl) {
            thEl.style.color = 'var(--accent)';
            thEl.style.fontWeight = '700';
          }
        } else if (col === 'distinct_ports') {
          // Show persistent secondary sort indicator
          iconEl.innerHTML = ' <span style="font-size: 9px; opacity: 0.6;" title="Permanent secondary tie-breaker">&#9660;</span>';
          if (thEl) {
            thEl.style.color = '';
            thEl.style.fontWeight = '';
          }
        } else {
          iconEl.innerHTML = '';
          if (thEl) {
            thEl.style.color = '';
            thEl.style.fontWeight = '';
          }
        }
      });

      const badgeEl = document.getElementById("subs-active-sort-badge");
      if (badgeEl) {
        const colLabels = {
          distinct_ports: "Distinct Ports",
          flows: "Window Flows",
          distinct_dests: "Unique Targets",
          src_ip: "Subscriber IP",
          router_ip: "Router Ingress",
          assigned_nat_ip: "Public NAT IP",
          behavior: "Behavior Tag"
        };
        const activeLabel = colLabels[currentSubsSortColumn] || currentSubsSortColumn;
        const arrow = currentSubsSortDir === 'desc' ? '&darr;' : '&uarr;';
        if (currentSubsSortColumn === 'distinct_ports') {
          badgeEl.innerHTML = `&bull; Sorted: Distinct Ports ${arrow} (Fixed)`;
          badgeEl.className = "badge-tag cyan";
        } else {
          badgeEl.innerHTML = `&bull; Sorted: ${activeLabel} ${arrow} (2nd: Distinct Ports &darr;)`;
          badgeEl.className = "badge-tag orange";
        }
      }
    }

    function filterSubscribersTable() {

      const search = (document.getElementById("subs-search-input").value || "").toLowerCase().trim();

      const routerFilter = document.getElementById("subs-filter-router").value || "ALL";

      const behaviorFilter = document.getElementById("subs-filter-behavior").value || "ALL";

      const tbody = document.getElementById("tbody-full-subscribers");



      let filtered = cachedSubscribers.filter(s => {

        if (routerFilter !== "ALL" && s.router_ip !== routerFilter) return false;

        if (behaviorFilter !== "ALL" && !s.behavior.includes(behaviorFilter)) return false;

        if (search) {

          const matchIp = s.src_ip.toLowerCase().includes(search);

          const matchNat = (s.assigned_nat_ip || "").toLowerCase().includes(search);

          const matchRouter = s.router_ip.toLowerCase().includes(search);

          const matchBehavior = s.behavior.toLowerCase().includes(search);

          if (!matchIp && !matchNat && !matchRouter && !matchBehavior) return false;

        }

        return true;

      });



      if (filtered.length === 0) {

        tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-dim); padding: 30px;">&#9888;&#65039; No subscribers match filter criteria.</td></tr>`;

        return;

      }



      let html = "";

      filtered.forEach((s, idx) => {

        const isScanner = s.behavior.includes("SCANNER");

        const isHeavy = s.behavior.includes("HEAVY");

        const tagClass = isScanner ? "red" : (isHeavy ? "yellow" : "green");

        

        const radiusInfo = (isSubsRadiusEnabled && subscriberRadiusCache[s.src_ip]) ? subscriberRadiusCache[s.src_ip] : null;

        const userBadge = radiusInfo && radiusInfo.username && radiusInfo.username !== "N/A"

          ? `<div style="font-size: 11px; color: #a78bfa; margin-top: 2px;">👤 <strong>${radiusInfo.username}</strong>${radiusInfo.name && radiusInfo.name !== 'N/A' ? ` <span style="color: var(--text-dim);">(${radiusInfo.name})</span>` : ''}</div>`

          : (isSubsRadiusEnabled && !radiusInfo ? `<div style="font-size: 10px; color: var(--text-dim); margin-top: 2px;">Resolving...</div>` : '');



        html += `

          <tr>

            <td style="color: var(--text-dim); font-size: 11px;">#${idx + 1}</td>

            <td>

              <strong style="color: #93c5fd; font-size: 12.5px;">${s.src_ip}</strong>

              ${userBadge}

            </td>

            <td><span style="color: var(--text-muted);">${s.router_ip}</span></td>

            <td><strong style="color: var(--text-main);">${s.flows.toLocaleString()}</strong></td>

            <td><span style="color: ${isScanner ? 'var(--danger)' : '#cbd5e1'}; font-weight: ${isScanner ? 'bold' : 'normal'};">${s.distinct_dests.toLocaleString()}</span></td>

            <td>${s.distinct_ports.toLocaleString()}</td>

            <td><strong style="color: var(--cyan);">${s.assigned_nat_ip}</strong></td>

            <td><span class="badge-tag ${tagClass}">${s.behavior}</span></td>

            <td style="text-align: right;">

              <button class="btn-table-action" onclick="investigateSubscriber('${s.src_ip}')">&#128269; Forensics Search</button>

            </td>

          </tr>

        `;

      });

      tbody.innerHTML = html;

    }



    let subscriberRadiusCache = {};

    let isSubsRadiusEnabled = false;



    async function toggleSubsRadius() {

      const checkbox = document.getElementById("toggle-subs-radius");

      isSubsRadiusEnabled = checkbox ? checkbox.checked : false;



      if (isSubsRadiusEnabled) {

        renderSubscribersTable();

        const missingIps = (allSubscribersData || [])

          .map(s => s.src_ip)

          .filter(ip => ip && !subscriberRadiusCache[ip]);



        if (missingIps.length > 0) {

          try {

            const res = await fetch("/api/v1/subscribers/enrich-radius", {

              method: "POST",

              headers: {

                "Content-Type": "application/json",

                "Authorization": "Bearer " + (authToken || localStorage.getItem('nat_ai_token'))

              },

              body: JSON.stringify({ subscribers: missingIps.slice(0, 100) })

            });

            if (res.ok) {

              const data = await res.json();

              if (data.data) {

                Object.assign(subscriberRadiusCache, data.data);

              }

            }

          } catch (e) {

            console.error("Error fetching subscriber RADIUS data:", e);

          }

        }

      }

      renderSubscribersTable();

    }



    function resetSubsFilter() {

      document.getElementById("subs-search-input").value = "";

      document.getElementById("subs-filter-router").value = "ALL";

      document.getElementById("subs-filter-behavior").value = "ALL";

      filterSubscribersTable();

    }



    function updateServiceBadge(elementId, isActive) {

      const el = document.getElementById(elementId);

      if (!el) return;

      if (isActive) {

        el.className = "badge-status active";

        el.innerText = "ACTIVE RUNNING";

      } else {

        el.className = "badge-status inactive";

        el.innerText = "OFFLINE / STOPPED";

      }

    }



    async function loadRoutersList() {

      try {

        const token = authToken || localStorage.getItem("nat_ai_token");
        const res = await fetch("/api/v1/export/routers", { headers: token ? { "Authorization": "Bearer " + token } : {} });

        if (res.ok) {

          const data = await res.json();

          const routers = data.routers || [];

          

          const select = document.getElementById("filter-router");

          select.innerHTML = '<option value="ALL">All Connected Routers</option>';

          routers.forEach(r => { select.innerHTML += `<option value="${r}">${r}</option>`; });



          const subsRouterSelect = document.getElementById("subs-filter-router");

          subsRouterSelect.innerHTML = '<option value="ALL">All Router Nodes</option>';

          routers.forEach(r => { subsRouterSelect.innerHTML += `<option value="${r}">${r}</option>`; });

        }

      } catch (e) {}

    }



    function investigateSubscriber(ip) {

      switchView('export');

      applyExportPreset('15m');

      document.getElementById('filter-src-ip').value = ip;

      document.getElementById('filter-nat-ip').value = "";

      document.getElementById('filter-nat-port').value = "";

      document.getElementById('filter-src-port').value = "";

      document.getElementById('filter-dst-ip').value = "";

      document.getElementById('filter-dst-port').value = "";

      document.getElementById('filter-router').value = "ALL";

      document.getElementById('filter-protocol').value = "ALL";

      setTimeout(() => {

        previewLogs();

      }, 100);

    }



    /* ================= FORENSICS LOGIC ================= */

    function toLocalISOString(date) {

      const pad = (n) => String(n).padStart(2, '0');

      const y = date.getFullYear();

      const m = pad(date.getMonth() + 1);

      const d = pad(date.getDate());

      const hh = pad(date.getHours());

      const mm = pad(date.getMinutes());

      const ss = pad(date.getSeconds());

      return `${y}-${m}-${d}T${hh}:${mm}:${ss}`;

    }



    function applyExportPreset(preset, evt) {

      const now = new Date();

      let start = new Date();

      let end = new Date();



      document.querySelectorAll(".preset-chip").forEach(c => {

        c.classList.remove("active");

        if (!evt && c.getAttribute('onclick') && c.getAttribute('onclick').includes(`'${preset}'`)) {

          c.classList.add("active");

        }

      });

      if (evt && evt.target) evt.target.classList.add("active");



      if (preset === '15m') start = new Date(now.getTime() - 15 * 60 * 1000);

      else if (preset === '1h') start = new Date(now.getTime() - 60 * 60 * 1000);

      else if (preset === '6h') start = new Date(now.getTime() - 6 * 60 * 60 * 1000);

      else if (preset === '24h') start = new Date(now.getTime() - 24 * 60 * 60 * 1000);

      else if (preset === 'today') start.setHours(0, 0, 0, 0);

      else if (preset === 'yesterday') {

        start.setDate(start.getDate() - 1);

        start.setHours(0, 0, 0, 0);

        end.setDate(end.getDate() - 1);

        end.setHours(23, 59, 59, 999);

      }



      document.getElementById("filter-start-time").value = toLocalISOString(start);

      document.getElementById("filter-end-time").value = toLocalISOString(end);

    }



    function resetForensicFilters() {

      applyExportPreset('1h');

      document.getElementById("filter-router").value = "ALL";

      document.getElementById("filter-protocol").value = "ALL";

      document.getElementById("filter-nat-ip").value = "";

      document.getElementById("filter-nat-port").value = "";

      document.getElementById("filter-src-ip").value = "";

      document.getElementById("filter-src-port").value = "";

      document.getElementById("filter-dst-ip").value = "";

      document.getElementById("filter-dst-port").value = "";

      document.getElementById("filter-limit").value = "5000";

      document.getElementById("export-action-status").innerText = "Filters reset to defaults";

      document.getElementById("export-total-badge").innerText = "--";

      document.getElementById("export-latency-badge").innerText = "-- ms";

      document.getElementById("tbody-export-preview").innerHTML = `

        <tr>

          <td colspan="6" style="text-align: center; padding: 36px 0; color: var(--text-dim);">

            <div>&#128269; Select your filters above and click <strong>"Live Preview"</strong> or <strong>"Download Excel"</strong> to extract matching records.</div>

          </td>

        </tr>

      `;

    }



    function getFilterPayload() {

      const detectedTz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";

      return {

        start_time: document.getElementById("filter-start-time").value || null,

        end_time: document.getElementById("filter-end-time").value || null,

        router_ip: document.getElementById("filter-router").value || "ALL",

        protocol: document.getElementById("filter-protocol").value || "ALL",

        nat_src_ip: document.getElementById("filter-nat-ip").value.trim() || null,

        nat_src_port: parseInt(document.getElementById("filter-nat-port").value, 10) || null,

        src_ip: document.getElementById("filter-src-ip").value.trim() || null,

        src_port: parseInt(document.getElementById("filter-src-port").value, 10) || null,

        dst_ip: document.getElementById("filter-dst-ip").value.trim() || null,

        dst_port: parseInt(document.getElementById("filter-dst-port").value, 10) || null,

        timezone: detectedTz,

        limit: parseInt(document.getElementById("filter-limit").value, 10) || 5000

      };

    }



    async function previewLogs(withRadius = false) {

      const payload = getFilterPayload();

      payload.with_radius = Boolean(withRadius);

      const statusEl = document.getElementById("export-action-status");

      const tbody = document.getElementById("tbody-export-preview");

      const previewBtn = document.getElementById("btn-preview-export");

      const previewRadiusBtn = document.getElementById("btn-preview-radius-export");



      statusEl.innerText = withRadius ? "Querying ClickHouse & resolving RADIUS sessions..." : "Querying ClickHouse records...";

      if (previewBtn) previewBtn.disabled = true;

      if (previewRadiusBtn) previewRadiusBtn.disabled = true;

      tbody.innerHTML = `

        <tr>

          <td colspan="7" style="text-align: center; padding: 36px 0; color: var(--accent);">

            <div style="display: inline-block; animation: pulse 1s infinite;">&#9889; Scanning ClickHouse partitions (${payload.timezone})${withRadius ? ' & correlating RADIUS...' : ''}</div>

          </td>

        </tr>

      `;



      try {

        const res = await fetch("/api/v1/export/preview", {

          method: "POST",

          headers: {

            "Content-Type": "application/json",

            "Authorization": "Bearer " + authToken

          },

          body: JSON.stringify(payload)

        });



        if (previewBtn) previewBtn.disabled = false;

        if (previewRadiusBtn) previewRadiusBtn.disabled = false;



        if (res.ok) {

          const resp = await res.json();

          const data = resp.data || {};

          const rows = data.rows || [];

          const totalCount = data.total_count || 0;

          const latency = data.query_time_ms || 0;



          document.getElementById("export-total-badge").innerText = totalCount >= 1000000 ? (totalCount / 1000000).toFixed(2) + "M rows" : totalCount.toLocaleString() + " rows";

          document.getElementById("export-latency-badge").innerText = `${latency} ms`;

          statusEl.innerHTML = `<span style="color: var(--success); font-weight: 600;">&#10004; Query completed in ${latency}ms (${totalCount.toLocaleString()} matches)${withRadius ? ' with RADIUS usernames' : ''}</span>`;



          if (rows.length === 0) {

            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 36px 0; color: var(--warning);">&#9888;&#65039; No matching forensic translations found for selected criteria.</td></tr>`;

            return;

          }



          let html = "";

          rows.forEach(r => {

            const protoBadge = r.protocol === "TCP" ? "badge-tag" : "badge-tag purple";

            const userStr = r.username && r.username !== "--" && r.username !== "N/A"

              ? `<strong style="color: #c084fc;">👤 ${r.username}</strong>`

              : `<span style="color: var(--text-dim);">--</span>`;



            html += `

              <tr>

                <td style="color: #cbd5e1;">${r.timestamp}</td>

                <td><span style="color: var(--text-muted);">${r.router_ip}</span></td>

                <td><span class="${protoBadge}">${r.protocol}</span></td>

                <td><strong style="color: #93c5fd;">${r.subscriber}</strong></td>

                <td>${userStr}</td>

                <td><strong style="color: var(--cyan);">${r.public_nat}</strong></td>

                <td><span style="color: #a7f3d0;">${r.destination}</span></td>

              </tr>

            `;

          });

          tbody.innerHTML = html;



        } else {

          statusEl.innerText = "Query execution error";

          tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--danger);">Failed to execute preview query.</td></tr>`;

        }

      } catch (e) {

        if (previewBtn) previewBtn.disabled = false;

        if (previewRadiusBtn) previewRadiusBtn.disabled = false;

        statusEl.innerText = "Network connection failed";

        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--danger);">Error connecting to backend service.</td></tr>`;

      }

    }



    async function downloadLogs(format = 'xlsx', enriched = false) {

      const payload = getFilterPayload();

      payload.format = format;

      payload.enriched = Boolean(enriched);

      const statusEl = document.getElementById("export-action-status");

      const btn = enriched ? document.getElementById("btn-download-nta-xlsx") : document.getElementById("btn-download-xlsx");

      

      const originalText = btn ? btn.innerHTML : "";

      if (btn) {

        btn.disabled = true;

        btn.innerHTML = `<span>&#8987; Exporting ${enriched ? 'NTA 14-Col...' : `${payload.limit.toLocaleString()} rows...`}</span>`;

      }

      statusEl.innerHTML = `<span style="color: var(--accent);">&#9889; Generating ${enriched ? 'NTA Lawful Interception Report (with RADIUS)' : `${format.toUpperCase()} export file`} in memory...</span>`;



      try {

        const res = await fetch("/api/v1/export/download", {

          method: "POST",

          headers: {

            "Content-Type": "application/json",

            "Authorization": "Bearer " + authToken

          },

          body: JSON.stringify(payload)

        });



        if (btn) {

          btn.disabled = false;

          btn.innerHTML = originalText;

        }



        if (res.ok) {

          const blob = await res.blob();

          const contentDisposition = res.headers.get('Content-Disposition') || '';

          let filename = enriched 

            ? `NTA_Lawful_Interception_Report_${new Date().toISOString().slice(0,10)}.${format}`

            : `NAT_Forensic_Export_${new Date().toISOString().slice(0,10)}.${format}`;

          if (contentDisposition && contentDisposition.indexOf('filename=') !== -1) {

            const matches = /filename="?([^"]+)"?/.exec(contentDisposition);

            if (matches != null && matches[1]) filename = matches[1];

          }



          const url = window.URL.createObjectURL(blob);

          const a = document.createElement('a');

          a.style.display = 'none';

          a.href = url;

          a.download = filename;

          document.body.appendChild(a);

          a.click();

          window.URL.revokeObjectURL(url);

          document.body.removeChild(a);



          statusEl.innerHTML = `<span style="color: var(--success); font-weight: 600;">&#10004; Successfully downloaded ${filename} (${formatBytes(blob.size)})</span>`;

        } else {

          statusEl.innerHTML = `<span style="color: var(--danger);">&#9888;&#65039; Export error (${res.status}). Try reducing the record limit.</span>`;

        }

      } catch (e) {

        if (btn) {

          btn.disabled = false;

          btn.innerHTML = originalText;

        }

        statusEl.innerHTML = `<span style="color: var(--danger);">&#9888;&#65039; Download failed. Network connection interrupted.</span>`;

      }

    }

  

    // -------------------------------------------------------------

    // Threat Shield & MikroTik Synchronization UI Functions

    // -------------------------------------------------------------

    let currentThreatConfig = { min_ports: 1000, max_subscribers: 4, flood_min_flows: 10000, enabled: true };

    let currentSyncEnabled = true;



    function updateThreatThresholdLabels() {

      const minPorts = currentThreatConfig.min_ports || 1000;

      const maxSubs = currentThreatConfig.max_subscribers !== undefined ? currentThreatConfig.max_subscribers : 4;

      const subHosts = currentThreatConfig.subnet_min_hosts || 8;

      const subFlows = currentThreatConfig.subnet_min_flows || 20000;

      

      const headerLabel = document.getElementById("threat-header-label");

      if (headerLabel) {

        headerLabel.innerHTML = `MikroTik Scanner &amp; Flood Shield &bull; Router: <strong>192.0.2.1</strong> (List: <code>scanner</code> &bull; &ge;${minPorts} Ports, &le;${maxSubs} Subs)`;

      }

      const threshKpi = document.getElementById("kpi-threat-threshold-label");

      if (threshKpi) {

        threshKpi.innerText = `\u2265${minPorts} Ports \u2022 \u2264${maxSubs} Subs`;

      }

      const syncKpiSub = document.getElementById("kpi-sync-threshold-sub");

      if (syncKpiSub) {

        syncKpiSub.innerText = `\u2265${minPorts} ports, \u2264${maxSubs} subs`;

      }

    }



    let currentRouterFleet = [];

    let selectedThreatRouter = 'all';



    async function loadRouters() {

      try {

        const res = await fetch("/api/v1/routers", {

          headers: { "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}` }

        });

        if (res.ok) {

          const data = await res.json();

          currentRouterFleet = data.routers || [];

          

          // Populate Threat View Router Selector Dropdown

          const selectEl = document.getElementById("select-threat-router");

          if (selectEl) {

            let opts = '<option value="all">🌐 All Fleet Routers (Aggregated)</option>';

            currentRouterFleet.forEach(r => {

              const icon = r.vendor === 'juniper' ? '⚡' : '🛡️';

              const selected = r.router_id === selectedThreatRouter ? 'selected' : '';

              opts += `<option value="${r.router_id}" ${selected}>${icon} ${r.name} (${r.ip})</option>`;

            });

            selectEl.innerHTML = opts;

          }



          // Populate Add Threat Target Router Dropdown

          const addTargetEl = document.getElementById("add-threat-target-router");

          if (addTargetEl) {

            let addOpts = '<option value="all">🌐 All Enabled Fleet Routers</option>';

            currentRouterFleet.forEach(r => {

              const icon = r.vendor === 'juniper' ? '⚡' : '🛡️';

              addOpts += `<option value="${r.router_id}">${icon} ${r.name} (${r.ip})</option>`;

            });

            addTargetEl.innerHTML = addOpts;

          }



          renderRouterFleetTable(currentRouterFleet);

        }

      } catch (err) {

        console.error("Error loading router fleet:", err);

      }

    }



        
    function updateScopeVisuals(scope) {
      const selectEl = document.getElementById("select-enforcement-scope");
      const badgeEl = document.getElementById("active-scope-badge");
      if (!selectEl) return;

      if (selectEl.value !== scope) {
        selectEl.value = scope;
      }

      const scopeMeta = {
        fleet_wide: {
          color: "var(--accent)",
          borderColor: "rgba(59, 130, 246, 0.5)",
          badgeClass: "badge-tag cyan",
          label: "Fleet-Wide Active",
          title: "Active Policy: 🌐 All Fleet Routers (AS-Wide Autonomous Mitigation)"
        },
        originating_router: {
          color: "var(--success)",
          borderColor: "rgba(16, 185, 129, 0.5)",
          badgeClass: "badge-tag green",
          label: "Originating Active",
          title: "Active Policy: 🎯 Originating Router Only (Isolated Gateway Table)"
        },
        hybrid: {
          color: "var(--warning)",
          borderColor: "rgba(245, 158, 11, 0.5)",
          badgeClass: "badge-tag orange",
          label: "Hybrid Active",
          title: "Active Policy: ⚡ Smart Hybrid Mode (Local Scans on Originating, Large Sweeps Fleet-Wide)"
        }
      };

      const meta = scopeMeta[scope] || scopeMeta.fleet_wide;
      selectEl.style.color = meta.color;
      selectEl.style.borderColor = meta.borderColor;
      selectEl.title = meta.title;

      if (badgeEl) {
        badgeEl.className = meta.badgeClass;
        badgeEl.innerHTML = `&bull; ${meta.label}`;
      }
    }

    async function onEnforcementScopeChange() {
      const selectEl = document.getElementById("select-enforcement-scope");
      if (!selectEl) return;
      const newScope = selectEl.value;
      updateScopeVisuals(newScope);
      const statusEl = document.getElementById("threat-sync-status");

      try {
        const res = await fetch("/api/v1/threats/config", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}`
          },
          body: JSON.stringify({ enforcement_scope: newScope })
        });

        if (res.ok) {
          const data = await res.json();
          currentThreatConfig = data.config || currentThreatConfig;
          if (statusEl) {
            statusEl.style.display = "block";
            statusEl.style.background = "rgba(16, 185, 129, 0.15)";
            statusEl.style.color = "var(--success)";
            statusEl.style.border = "1px solid rgba(16, 185, 129, 0.3)";
            const labels = {
              fleet_wide: "🌐 All Fleet Routers (AS-Wide Perimeter Defense)",
              originating_router: "🎯 Originating Router Only (Localized Isolation)",
              hybrid: "⚡ Smart Hybrid Mode (Scans -> Local, Sweeps -> Fleet-Wide)"
            };
            statusEl.innerHTML = `&#10003; <strong>Enforcement Scope Updated:</strong> ${labels[newScope] || newScope}`;
            setTimeout(() => { statusEl.style.display = "none"; }, 5000);
          }
          updateThreatThresholdLabels();
        }
      } catch (err) {
        console.error("Error updating enforcement scope:", err);
      }
    }

    function onThreatRouterChange() {

      const selectEl = document.getElementById("select-threat-router");

      if (selectEl) {

        selectedThreatRouter = selectEl.value;

      }

      loadThreatData();

    }



    async function loadThreatData() {

      try {

        const [scannersRes, fleetRes, configRes] = await Promise.all([

          fetch("/api/v1/threats/scanners?minutes=15", {

            headers: { "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}` }

          }),

          fetch(`/api/v1/threats/fleet-list?router_id=${selectedThreatRouter}`, {

            headers: { "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}` }

          }),

          fetch("/api/v1/threats/config", {

            headers: { "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}` }

          })

        ]);



        if (scannersRes.status === 401 || fleetRes.status === 401 || configRes.status === 401) {

          logout();

          return;

        }



        const scannersData = await scannersRes.json();

        const fleetData = await fleetRes.json();

        if (configRes.ok) {

          const cfgData = await configRes.json();

          if (cfgData.config) {

            currentThreatConfig = cfgData.config;

          }

        }



        const minPorts = scannersData.min_ports_threshold || currentThreatConfig.min_ports || 1000;

        const maxSubs = scannersData.max_subscribers_threshold !== undefined ? scannersData.max_subscribers_threshold : (currentThreatConfig.max_subscribers !== undefined ? currentThreatConfig.max_subscribers : 4);



        // Update Sync Engine Toggle UI State

        const syncState = scannersData.sync_state || fleetData.sync_state || currentThreatConfig || { enabled: true };

        updateSyncUiState(syncState.enabled !== false, syncState);



        renderThreatCandidates(scannersData.candidates || []);

        renderMikrotikEntries(fleetData.entries || []);



        // Update Dynamic Header & KPI Labels

        updateThreatThresholdLabels();



        // Update KPIs

        const candidates = scannersData.candidates || [];

        const entries = fleetData.entries || [];

        const sweeps = candidates.filter(c => c.threat_type === "UDP_PORT_SWEEP" || c.threat_type === "SUBNET_SWEEP").length;

        const pending = candidates.filter(c => !c.is_blocked_in_mikrotik).length;



        document.getElementById("kpi-threat-candidates").innerText = candidates.length;

        document.getElementById("kpi-threat-sweeps").innerText = `${sweeps} sweeps`;

        document.getElementById("kpi-mikrotik-blocked").innerText = entries.length;

        document.getElementById("kpi-threat-pending").innerText = pending;

        document.getElementById("kpi-threat-pending-sub").innerText = pending > 0 ? `${pending} ready to block` : "All blocked";

        document.getElementById("badge-threat-count").innerText = pending > 0 ? `${pending} NEW` : "SYNCED";



      } catch (err) {

        console.error("Error loading threat data:", err);

      }

    }



    function updateSyncUiState(enabled, syncState) {
      currentSyncEnabled = enabled;
      const toggleBtn = document.getElementById("btn-toggle-sync");
      const dotEl = document.getElementById("dot-sync-status");
      const statusVal = document.getElementById("kpi-sync-status-val");
      const subDesc = document.getElementById("kpi-sync-sub-desc");
      const threshSub = document.getElementById("kpi-sync-threshold-sub");
      const syncCard = document.getElementById("kpi-card-sync-service");
      const syncIcon = document.getElementById("kpi-sync-icon");
      const statusBanner = document.getElementById("threat-sync-status");

      const hasAiKeys = (syncState && syncState.has_ai_keys !== undefined) ? !!syncState.has_ai_keys : (window.hasAiApiKeys !== undefined ? window.hasAiApiKeys : true);
      window.hasAiApiKeys = hasAiKeys;

      const minPorts = (syncState && (syncState.udp_sweep_min_ports || syncState.min_ports)) || (currentThreatConfig && currentThreatConfig.min_ports) || 1000;
      const maxSubs = (syncState && (syncState.max_subscribers_for_block || syncState.max_subscribers)) || (currentThreatConfig && currentThreatConfig.max_subscribers) || 4;

      if (threshSub) {
        threshSub.innerHTML = `&ge;${minPorts} ports, &le;${maxSubs} subs`;
      }

      if (!hasAiKeys) {
        // Strict guardrail: Automated sync is completely blocked without AI API keys
        if (toggleBtn) {
          toggleBtn.innerHTML = "&#128683; Threat Sync Blocked (No AI Keys)";
          toggleBtn.title = "Automated sync is blocked because no AI API keys are configured. You must add threat rules manually or configure an AI API key.";
          toggleBtn.style.color = "#fbbf24";
          toggleBtn.style.borderColor = "rgba(245, 158, 11, 0.4)";
          toggleBtn.style.background = "rgba(245, 158, 11, 0.1)";
        }
        if (dotEl) { dotEl.style.background = "#fbbf24"; }
        if (statusVal) { statusVal.innerText = "BLOCKED (No AI Keys)"; statusVal.style.color = "#fbbf24"; }
        if (subDesc) { subDesc.innerText = "Automated sync disabled. Add threat rules manually."; }
        if (syncIcon) { syncIcon.innerHTML = "&#9888;&#65039;"; }
        if (syncCard) { syncCard.className = "kpi-card warning"; }

        if (statusBanner) {
          statusBanner.style.display = "block";
          statusBanner.style.background = "rgba(245, 158, 11, 0.15)";
          statusBanner.style.color = "var(--warning)";
          statusBanner.style.border = "1px solid rgba(245, 158, 11, 0.35)";
          statusBanner.innerHTML = `<div style="display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;">
            <div>
              <strong>⚠️ Automated Threat Sync Strictly Blocked:</strong> No active Gemini AI API keys configured. Automated mitigation is disabled to prevent false-positive service disruptions.
            </div>
            <div style="display: flex; gap: 8px;">
              <button class="btn-refresh" onclick="openAddAddressModal()" style="padding: 4px 10px; font-size: 11px; font-weight: 600;">➕ Add Threat Rule Manually</button>
              <button class="btn-action primary" onclick="openAIKeysModal()" style="padding: 4px 10px; font-size: 11px; font-weight: 600;">🔑 Configure AI Keys</button>
            </div>
          </div>`;
        }
        return;
      }

      if (toggleBtn) {
        if (enabled) {
          toggleBtn.innerHTML = "&#9209; Stop Threat Shield";
          toggleBtn.title = "Pause AI Threat Reasoning & Prefix/Address-list Sync";
          toggleBtn.style.color = "#f87171";
          toggleBtn.style.borderColor = "rgba(239, 68, 68, 0.4)";
          toggleBtn.style.background = "rgba(239, 68, 68, 0.1)";
          if (dotEl) { dotEl.style.background = "var(--green)"; }
          if (statusVal) { statusVal.innerText = "Active (15m)"; statusVal.style.color = "var(--green)"; }
          if (subDesc) { subDesc.innerText = "AI reasoning & router sync ACTIVE"; }
          if (syncIcon) { syncIcon.innerHTML = "&#128994;"; }
          if (syncCard) { syncCard.className = "kpi-card cyan"; }
        } else {
          toggleBtn.innerHTML = "&#9654; Resume Threat Shield";
          toggleBtn.title = "Resume AI Threat Reasoning & Prefix/Address-list Sync";
          toggleBtn.style.color = "#34d399";
          toggleBtn.style.borderColor = "rgba(52, 211, 153, 0.4)";
          toggleBtn.style.background = "rgba(52, 211, 153, 0.1)";
          if (dotEl) { dotEl.style.background = "var(--danger)"; }
          if (statusVal) { statusVal.innerText = "STOPPED (Paused)"; statusVal.style.color = "var(--danger)"; }
          if (subDesc) { subDesc.innerText = "AI reasoning & router sync PAUSED"; }
          if (syncIcon) { syncIcon.innerHTML = "&#128308;"; }
          if (syncCard) { syncCard.className = "kpi-card danger"; }
        }
      }
    }

    async function toggleMikrotikSync() {
      if (window.hasAiApiKeys === false && !currentSyncEnabled) {
        alert("Cannot enable Automated Threat Sync: No active Gemini AI API keys configured.\n\nAutomated syncing is strictly blocked to prevent false-positive blocks without LLM reasoning.\n\nPlease add a Gemini API key in System Management > AI Keys first, or add threat rules manually using '+ Add Threat Rule'.");
        openAIKeysModal();
        return;
      }

      const newEnabled = !currentSyncEnabled;
      const toggleBtn = document.getElementById("btn-toggle-sync");
      if (toggleBtn) {
        toggleBtn.disabled = true;
        toggleBtn.innerText = newEnabled ? "Resuming..." : "Stopping...";
      }

      try {
        const res = await fetch("/api/v1/threats/sync/toggle", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}`
          },
          body: JSON.stringify({ enabled: newEnabled })
        });
        const data = await res.json();
        if (res.ok) {
          updateSyncUiState(newEnabled, data.sync_state);
          const statusBanner = document.getElementById("threat-sync-status");
          if (statusBanner) {
            statusBanner.style.display = "block";
            if (newEnabled) {
              statusBanner.style.background = "rgba(16, 185, 129, 0.15)";
              statusBanner.style.color = "var(--success)";
              statusBanner.style.border = "1px solid rgba(16, 185, 129, 0.3)";
              statusBanner.innerHTML = `&#10003; <strong>Threat Shield Resumed:</strong> AI threat reasoning and address-list / prefix-list sync are now <strong>ACTIVE</strong>.`;
            } else {
              statusBanner.style.background = "rgba(239, 68, 68, 0.15)";
              statusBanner.style.color = "var(--danger)";
              statusBanner.style.border = "1px solid rgba(239, 68, 68, 0.3)";
              statusBanner.innerHTML = `&#9888; <strong>Threat Shield Stopped:</strong> AI threat reasoning and address-list / prefix-list sync are now <strong>PAUSED</strong>.`;
            }
          }
        } else {
          alert(`Threat Shield: ${data.detail || data.message || 'Failed to update sync state'}`);
          if (data.detail && data.detail.includes("AI API keys")) {
            openAIKeysModal();
          }
        }
      } catch (err) {
        alert(`Error toggling sync: ${err.message}`);
      } finally {
        if (toggleBtn) toggleBtn.disabled = false;
        loadThreatData();
      }

    }



    function openThreatConfigModal() {

      document.getElementById("cfg-subnet-hosts").value = currentThreatConfig.subnet_min_hosts || 8;

      document.getElementById("cfg-subnet-ports").value = currentThreatConfig.subnet_min_ports || 100;

      document.getElementById("cfg-subnet-flows").value = currentThreatConfig.subnet_min_flows || 2000;

      document.getElementById("cfg-min-ports").value = currentThreatConfig.min_ports || 1000;

      document.getElementById("cfg-flood-flows").value = currentThreatConfig.flood_min_flows || 10000;

      document.getElementById("cfg-max-subs").value = currentThreatConfig.max_subscribers !== undefined ? currentThreatConfig.max_subscribers : 4;

      document.getElementById("cfg-sync-enabled").checked = currentThreatConfig.enabled !== false;

      document.getElementById("cfg-sub-flows").value = currentThreatConfig.private_ip_flow_threshold || 2500;

      document.getElementById("cfg-sub-targets").value = currentThreatConfig.private_ip_target_threshold || 400;

      document.getElementById("cfg-sub-ports").value = currentThreatConfig.private_ip_port_threshold || 1000;

      document.getElementById("cfg-nat-exhaustion").value = currentThreatConfig.port_exhaustion_threshold || 45000;

      document.getElementById("cfg-dest-spike").value = currentThreatConfig.destination_spike_flows || 150000;

      document.getElementById("cfg-status").style.display = "none";

      document.getElementById("modal-threat-config").style.display = "flex";

    }



    function closeThreatConfigModal() {

      document.getElementById("modal-threat-config").style.display = "none";

    }



    async function submitThreatConfig() {

      const subnetHosts = parseInt(document.getElementById("cfg-subnet-hosts").value, 10);

      const subnetPorts = parseInt(document.getElementById("cfg-subnet-ports").value, 10);

      const subnetFlows = parseInt(document.getElementById("cfg-subnet-flows").value, 10);

      const minPorts = parseInt(document.getElementById("cfg-min-ports").value, 10);

      const floodFlows = parseInt(document.getElementById("cfg-flood-flows").value, 10);

      const maxSubs = parseInt(document.getElementById("cfg-max-subs").value, 10);

      const enabled = document.getElementById("cfg-sync-enabled").checked;

      const subFlows = parseInt(document.getElementById("cfg-sub-flows").value, 10);

      const subTargets = parseInt(document.getElementById("cfg-sub-targets").value, 10);

      const subPorts = parseInt(document.getElementById("cfg-sub-ports").value, 10);

      const natExhaustion = parseInt(document.getElementById("cfg-nat-exhaustion").value, 10);

      const destSpike = parseInt(document.getElementById("cfg-dest-spike").value, 10);

      const statusEl = document.getElementById("cfg-status");



      if (isNaN(minPorts) || minPorts < 1) {

        statusEl.style.display = "block";

        statusEl.style.color = "var(--danger)";

        statusEl.innerText = "Please enter a valid minimum ports number.";

        return;

      }

      if (isNaN(maxSubs) || maxSubs < 0) {

        statusEl.style.display = "block";

        statusEl.style.color = "var(--danger)";

        statusEl.innerText = "Please enter a valid max subscribers number.";

        return;

      }



      statusEl.style.display = "block";

      statusEl.style.color = "var(--cyan)";

      statusEl.innerText = "Saving configuration...";



      try {

        const res = await fetch("/api/v1/threats/config", {

          method: "POST",

          headers: {

            "Content-Type": "application/json",

            "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}`

          },

          body: JSON.stringify({

            enabled: enabled,

            subnet_min_hosts: isNaN(subnetHosts) ? 8 : subnetHosts,

            subnet_min_ports: isNaN(subnetPorts) ? 100 : subnetPorts,

            subnet_min_flows: isNaN(subnetFlows) ? 2000 : subnetFlows,

            min_ports: minPorts,

            flood_min_flows: isNaN(floodFlows) ? 10000 : floodFlows,

            max_subscribers: maxSubs,

            private_ip_flow_threshold: isNaN(subFlows) ? 2500 : subFlows,

            private_ip_target_threshold: isNaN(subTargets) ? 400 : subTargets,

            private_ip_port_threshold: isNaN(subPorts) ? 1000 : subPorts,

            port_exhaustion_threshold: isNaN(natExhaustion) ? 45000 : natExhaustion,

            destination_spike_flows: isNaN(destSpike) ? 150000 : destSpike

          })

        });

        const data = await res.json();

        if (res.ok) {

          currentThreatConfig = data.config || currentThreatConfig;

          statusEl.style.color = "var(--success)";

          statusEl.innerHTML = "&#10003; <strong>Parameters Saved!</strong> Updated threat thresholds.";

          updateThreatThresholdLabels();

          setTimeout(() => {

            closeThreatConfigModal();

            loadThreatData();

          }, 800);

        } else {

          statusEl.style.color = "var(--danger)";

          statusEl.innerText = `Error: ${data.detail || data.message}`;

        }

      } catch (err) {

        statusEl.style.color = "var(--danger)";

        statusEl.innerText = `Error: ${err.message}`;

      }

    }





    function openAuditPruneModal() {

      document.getElementById("ap-min-ports").value = currentThreatConfig.min_ports || 1000;

      document.getElementById("ap-max-subs").value = currentThreatConfig.max_subscribers !== undefined ? currentThreatConfig.max_subscribers : 4;

      document.getElementById("ap-results-box").style.display = "none";

      document.getElementById("ap-status").style.display = "none";

      document.getElementById("modal-audit-prune").style.display = "flex";

    }



    function closeAuditPruneModal() {

      document.getElementById("modal-audit-prune").style.display = "none";

    }



    async function runAuditPrune(dryRun) {

      const minPortsVal = document.getElementById("ap-min-ports").value;

      const maxSubsVal = document.getElementById("ap-max-subs").value;

      const minPorts = minPortsVal ? parseInt(minPortsVal, 10) : null;

      const maxSubs = maxSubsVal ? parseInt(maxSubsVal, 10) : null;



      const btnDry = document.getElementById("btn-ap-dryrun");

      const btnExec = document.getElementById("btn-ap-execute");

      const statusEl = document.getElementById("ap-status");

      const resultsBox = document.getElementById("ap-results-box");

      const summaryEl = document.getElementById("ap-results-summary");

      const reasonsList = document.getElementById("ap-reasons-list");



      btnDry.disabled = true;

      btnExec.disabled = true;

      statusEl.style.display = "block";

      statusEl.style.color = "var(--cyan)";

      statusEl.innerText = dryRun ? "Auditing address list against thresholds..." : "Auditing and executing pruning on MikroTik...";



      try {

        const res = await fetch("/api/v1/threats/audit-prune", {

          method: "POST",

          headers: {

            "Content-Type": "application/json",

            "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}`

          },

          body: JSON.stringify({

            dry_run: dryRun,

            min_ports: minPorts,

            max_subscribers: maxSubs

          })

        });

        const data = await res.json();

        if (res.ok) {

          resultsBox.style.display = "block";

          statusEl.style.color = "var(--success)";

          statusEl.innerHTML = dryRun 

            ? `&#10003; <strong>Audit Complete (Dry-Run):</strong> Evaluated ${data.total_before} entries.` 

            : `&#10003; <strong>Pruning Complete:</strong> Removed ${data.removed_count} entries from MikroTik.`;



          summaryEl.innerHTML = `

            <div>Total Entries Before: <strong>${data.total_before}</strong> &bull; Compliant to Keep: <strong style="color: var(--success);">${data.to_keep_count}</strong> &bull; Non-Compliant: <strong style="color: var(--danger);">${data.to_remove_count}</strong></div>

            <div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">Applied Thresholds: Min Ports &ge; ${data.thresholds_applied.min_ports}, Max Subscribers &le; ${data.thresholds_applied.max_subscribers}</div>

          `;



          let reasonsHtml = "<div style='margin-top: 8px; font-weight: 600; color: var(--text-main);'>Removal Breakdown:</div><ul style='margin-left: 18px; margin-top: 4px;'>";

          for (const [rKey, rCount] of Object.entries(data.reasons_summary || {})) {

            reasonsHtml += `<li><strong>${rCount}</strong> &times; ${rKey}</li>`;

          }

          reasonsHtml += "</ul>";



          if (data.removed_entries && data.removed_entries.length > 0) {

            reasonsHtml += "<div style='margin-top: 8px; font-weight: 600; color: var(--text-main);'>Sample Evaluated Entries:</div>";

            data.removed_entries.slice(0, 10).forEach(x => {

              reasonsHtml += `<div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; margin-top: 2px; color: #f87171;">&bull; ${x.address} (${x.reason})</div>`;

            });

          }



          reasonsList.innerHTML = reasonsHtml;

          if (!dryRun) {

            loadThreatData();

          }

        } else {

          statusEl.style.color = "var(--danger)";

          statusEl.innerText = `Error: ${data.detail || data.message}`;

        }

      } catch (err) {

        statusEl.style.color = "var(--danger)";

        statusEl.innerText = `Error: ${err.message}`;

      } finally {

        btnDry.disabled = false;

        btnExec.disabled = false;

      }

    }





    function renderThreatCandidates(candidates) {

      const tbody = document.getElementById("tbody-threat-candidates");

      const countEl = document.getElementById("threat-candidate-count");

      countEl.innerText = `${candidates.length} detected targets in last 15m`;



      if (!candidates.length) {

        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 24px;">No active scanner or flood targets detected in last 15m.</td></tr>`;

        return;

      }



      let html = "";

      candidates.slice(0, 50).forEach(c => {

        const isBlocked = c.is_blocked_in_mikrotik;

        const statusBadge = isBlocked 

          ? `<span class="badge-tag green">&#10003; BLOCKED</span>`

          : `<span class="badge-tag danger">&#9888; UNBLOCKED</span>`;



        const typeBadge = (c.threat_type === "UDP_PORT_SWEEP")

          ? `<span class="badge-tag red">UDP SWEEP</span>`

          : (c.threat_type === "VERTICAL_PORT_SCAN" ? `<span class="badge-tag purple">PORT SCAN</span>` : `<span class="badge-tag orange">FLOOD</span>`);



        const blockBtn = isBlocked 

          ? `<button class="btn btn-secondary" style="padding: 3px 7px; font-size: 10px; opacity: 0.6;" disabled>Blocked</button>`

          : `<button class="btn btn-primary" style="padding: 3px 8px; font-size: 10px;" onclick="blockSingleIp('${c.dst_ip}', '${c.threat_type}')">+ Block</button>`;



        const drillBtn = `<button class="btn btn-secondary" style="padding: 3px 7px; font-size: 10px;" onclick="drilldownForensics('${c.dst_ip}')">&#128269; Forensics</button>`;



        html += `

          <tr>

            <td><strong style="color: var(--text-main); font-family: 'JetBrains Mono', monospace;">${c.dst_ip}</strong></td>

            <td>${typeBadge}</td>

            <td style="color: var(--cyan); font-weight: 600;">${c.distinct_ports.toLocaleString()} ports</td>

            <td>${c.total_flows.toLocaleString()} flows</td>

            <td>${c.subscriber_count} subs</td>

            <td>${statusBadge}</td>

            <td><div style="display: flex; gap: 4px;">${blockBtn} ${drillBtn}</div></td>

          </tr>

        `;

      });

      tbody.innerHTML = html;

    }



    function renderMikrotikEntries(entries) {

      const tbody = document.getElementById("tbody-mikrotik-entries");

      const countEl = document.getElementById("mikrotik-list-count");

      countEl.innerText = `${entries.length} active dropped rules`;



      if (!entries.length) {

        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 24px;">No active threat block rules on selected router / fleet.</td></tr>`;

        return;

      }



      let html = "";

      entries.forEach(item => {

        const addr = item.address || "";

        const comment = item.comment || item.list || "";

        const creation = item.creation_time || "--";

        const routerIp = item.router_ip || "Fleet";

        const vendor = item.vendor || "mikrotik";

        const vendorBadge = vendor === "juniper" ? `<span class="badge-tag purple" style="font-size: 10px; padding: 2px 6px;">⚡ Juniper Junos</span>` : `<span class="badge-tag cyan" style="font-size: 10px; padding: 2px 6px;">🛡️ MikroTik</span>`;



        html += `

          <tr>

            <td>

              <div style="display: flex; flex-direction: column; gap: 2px;">

                <span style="font-size: 11.5px; font-weight: 600; color: var(--text-main);">${routerIp}</span>

                ${vendorBadge}

              </div>

            </td>

            <td><strong style="color: var(--danger); font-family: 'JetBrains Mono', monospace;">${addr}</strong></td>

            <td style="font-size: 11px; color: var(--text-muted); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${comment}">${comment}</td>

            <td style="font-size: 11px; color: var(--text-dim);">${creation}</td>

            <td style="text-align: right;">

              <div style="display: flex; gap: 4px; justify-content: flex-end;">

                <button class="btn btn-secondary" style="padding: 2px 6px; font-size: 10px;" onclick="drilldownForensics('${addr.split('/')[0]}')">&#128269; Forensics</button>

                <button class="btn btn-secondary" style="padding: 2px 6px; font-size: 10px; color: var(--danger);" onclick="removeMikrotikEntry('${addr}', '${item.router_id || routerIp}')">&#10005; Remove</button>

              </div>

            </td>

          </tr>

        `;

      });

      tbody.innerHTML = html;

    }



    async function triggerManualSync() {

      const btn = document.getElementById("btn-sync-mikrotik");

      const statusEl = document.getElementById("threat-sync-status");

      btn.disabled = true;

      btn.innerText = "Syncing with Fleet...";



      try {

        const res = await fetch(`/api/v1/threats/fleet-sync?minutes=15&router_id=${selectedThreatRouter}`, {

          method: "POST",

          headers: { "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}` }

        });

        const data = await res.json();

        

        statusEl.style.display = "block";

        statusEl.style.background = "rgba(16, 185, 129, 0.15)";

        statusEl.style.color = "var(--success)";

        statusEl.style.border = "1px solid rgba(16, 185, 129, 0.3)";

        statusEl.innerHTML = `&#10003; <strong>Fleet Sync Complete:</strong> Scanned ${data.candidates_found || 0} candidates across ${data.target_routers ? data.target_routers.join(', ') : 'fleet'}.`;



        loadThreatData();

      } catch (err) {

        statusEl.style.display = "block";

        statusEl.style.background = "rgba(239, 68, 68, 0.15)";

        statusEl.style.color = "var(--danger)";

        statusEl.style.border = "1px solid rgba(239, 68, 68, 0.3)";

        statusEl.innerText = `Fleet Sync failed: ${err.message}`;

      } finally {

        btn.disabled = false;

        btn.innerText = "⚡ Sync to Fleet";

      }

    }



        function onThreatTargetRouterChange() {
      const routerSelect = document.getElementById("add-threat-target-router");
      const listSelect = document.getElementById("add-threat-list-name");
      const customGroup = document.getElementById("add-threat-custom-list-group");
      const customInput = document.getElementById("add-threat-custom-list");
      if (!routerSelect || !listSelect) return;

      const targetVal = routerSelect.value;
      let lists = [];

      if (targetVal === "all") {
        const listSet = new Set(["scanner"]);
        currentRouterFleet.forEach(r => {
          if (r.address_list) listSet.add(r.address_list);
          if (Array.isArray(r.supported_lists)) {
            r.supported_lists.forEach(l => listSet.add(l));
          }
        });
        lists = Array.from(listSet);
      } else {
        const matchedRouter = currentRouterFleet.find(r => r.router_id === targetVal || r.ip === targetVal);
        if (matchedRouter) {
          const listSet = new Set();
          if (matchedRouter.address_list) listSet.add(matchedRouter.address_list);
          if (Array.isArray(matchedRouter.supported_lists)) {
            matchedRouter.supported_lists.forEach(l => listSet.add(l));
          } else if (matchedRouter.vendor === 'juniper') {
            listSet.add('THREAT-SHIELD-PREFIXES');
          } else {
            listSet.add('scanner');
          }
          lists = Array.from(listSet);
        } else {
          lists = ["scanner"];
        }
      }

      let html = '';
      lists.forEach((l, idx) => {
        html += `<option value="${l}" ${idx === 0 ? 'selected' : ''}>${l} (Standard)</option>`;
      });
      html += '<option value="__custom__">➕ Custom List / Prefix-List...</option>';
      listSelect.innerHTML = html;

      if (customGroup) customGroup.style.display = "none";
      if (customInput) customInput.value = "";
    }

    function onThreatListNameChange() {
      const listSelect = document.getElementById("add-threat-list-name");
      const customGroup = document.getElementById("add-threat-custom-list-group");
      const customInput = document.getElementById("add-threat-custom-list");
      if (listSelect && customGroup) {
        if (listSelect.value === "__custom__") {
          customGroup.style.display = "block";
          if (customInput) customInput.focus();
        } else {
          customGroup.style.display = "none";
        }
      }
    }

    function openAddAddressModal(prefillIp, prefillReason, targetRouter) {
      document.getElementById("add-mt-address").value = prefillIp || "";
      document.getElementById("add-mt-comment").value = prefillReason || "";
      const statusEl = document.getElementById("add-mt-status");
      if (statusEl) statusEl.style.display = "none";

      const tout = document.getElementById("add-threat-timeout");
      if (tout) tout.value = "";

      const routerSelect = document.getElementById("add-threat-target-router");
      if (routerSelect) {
        if (targetRouter) {
          routerSelect.value = targetRouter;
        } else if (selectedThreatRouter && selectedThreatRouter !== "all") {
          routerSelect.value = selectedThreatRouter;
        } else {
          routerSelect.value = "all";
        }
      }

      document.getElementById("modal-add-address").style.display = "flex";
      loadRouters().then(() => {
        if (targetRouter && routerSelect) {
          routerSelect.value = targetRouter;
        }
        onThreatTargetRouterChange();
      });
    }

    function closeAddAddressModal() {
      document.getElementById("modal-add-address").style.display = "none";
    }

    async function submitAddAddress() {
      const addr = document.getElementById("add-mt-address").value.trim();
      const comment = document.getElementById("add-mt-comment").value.trim();
      const targetRouter = document.getElementById("add-threat-target-router").value;
      const listSelect = document.getElementById("add-threat-list-name");
      const customInput = document.getElementById("add-threat-custom-list");
      const timeoutSelect = document.getElementById("add-threat-timeout");
      const statusEl = document.getElementById("add-mt-status");
      const btn = document.getElementById("btn-submit-add-threat");

      let listName = listSelect ? listSelect.value : "scanner";
      if (listName === "__custom__" && customInput) {
        listName = customInput.value.trim();
        if (!listName) {
          statusEl.style.display = "block";
          statusEl.style.background = "rgba(239, 68, 68, 0.15)";
          statusEl.style.color = "var(--danger)";
          statusEl.innerText = "Please specify a custom address-list/prefix-list name";
          return;
        }
      }
      const timeout = timeoutSelect ? timeoutSelect.value : "";

      if (!addr) {
        statusEl.style.display = "block";
        statusEl.style.background = "rgba(239, 68, 68, 0.15)";
        statusEl.style.color = "var(--danger)";
        statusEl.innerText = "Please enter an IP address or CIDR subnet";
        return;
      }

      statusEl.style.display = "block";
      statusEl.style.background = "rgba(56, 189, 248, 0.15)";
      statusEl.style.color = "var(--cyan)";
      statusEl.innerText = "Applying block rule across target router(s)...";
      if (btn) btn.disabled = true;

      try {
        const res = await fetch(`/api/v1/threats/fleet-add?router_id=${targetRouter}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}`
          },
          body: JSON.stringify({ 
            address: addr, 
            comment: comment || "Manual fleet block",
            router_id: targetRouter,
            list_name: listName,
            timeout: timeout
          })
        });

        if (res.ok) {
          closeAddAddressModal();
          loadThreatData();
        } else {
          const err = await res.json();
          statusEl.style.display = "block";
          statusEl.style.background = "rgba(239, 68, 68, 0.15)";
          statusEl.style.color = "var(--danger)";
          statusEl.innerText = `Failed to add: ${err.detail || err.message}`;
        }
      } catch (err) {
        statusEl.style.display = "block";
        statusEl.style.background = "rgba(239, 68, 68, 0.15)";
        statusEl.style.color = "var(--danger)";
        statusEl.innerText = `Error: ${err.message}`;
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    async function blockSingleIp(ip, threatType) {
      openAddAddressModal(ip, `Manual block: ${threatType || 'Threat'}`, selectedThreatRouter);
    }

        function editRouterNode(routerId) {
      const r = currentRouterFleet.find(item => item.router_id === routerId);
      if (!r) return;
      document.getElementById("router-form-title").innerHTML = `✎ Edit Router Node: <strong>${r.name}</strong>`;
      document.getElementById("rf-router-id").value = r.router_id;
      document.getElementById("rf-name").value = r.name || '';
      document.getElementById("rf-vendor").value = r.vendor || 'mikrotik';
      document.getElementById("rf-ip").value = r.ip || '';
      document.getElementById("rf-port").value = r.port || 22;
      document.getElementById("rf-user").value = r.user || r.username || 'natlog';
      document.getElementById("rf-password").value = '';
      document.getElementById("rf-list").value = r.address_list || 'scanner';
      if (document.getElementById("rf-role")) document.getElementById("rf-role").value = r.role || 'cgnat';
      if (document.getElementById("rf-supported-lists")) {
        document.getElementById("rf-supported-lists").value = Array.isArray(r.supported_lists) ? r.supported_lists.join(', ') : (r.address_list || 'scanner');
      }
      document.getElementById("rf-sync-enabled").checked = r.sync_enabled !== false;
      document.getElementById("btn-cancel-router-edit").style.display = "inline-block";
      onVendorSelectChange();
    }

    function resetRouterForm() {
      document.getElementById("router-form-title").innerHTML = "&#10010; Add New Router Node";
      document.getElementById("rf-router-id").value = "";
      document.getElementById("rf-name").value = "";
      document.getElementById("rf-vendor").value = "mikrotik";
      document.getElementById("rf-ip").value = "";
      document.getElementById("rf-port").value = 22;
      document.getElementById("rf-user").value = "natlog";
      document.getElementById("rf-password").value = "";
      document.getElementById("rf-list").value = "scanner";
      if (document.getElementById("rf-role")) document.getElementById("rf-role").value = 'cgnat';
      if (document.getElementById("rf-supported-lists")) document.getElementById("rf-supported-lists").value = "scanner, drop-flood";
      document.getElementById("rf-sync-enabled").checked = true;
      document.getElementById("btn-cancel-router-edit").style.display = "none";
      document.getElementById("router-test-status").style.display = "none";
      onVendorSelectChange();
    }



        async function submitRouterForm() {
      const routerId = document.getElementById("rf-router-id").value.trim();
      const name = document.getElementById("rf-name").value.trim();
      const vendor = document.getElementById("rf-vendor").value;
      const ip = document.getElementById("rf-ip").value.trim();
      const port = parseInt(document.getElementById("rf-port").value) || 22;
      const user = document.getElementById("rf-user").value.trim() || 'natlog';
      const password = document.getElementById("rf-password").value;
      const addressList = document.getElementById("rf-list").value.trim() || 'scanner';
      const role = document.getElementById("rf-role") ? document.getElementById("rf-role").value : 'cgnat';
      const suppStr = document.getElementById("rf-supported-lists") ? document.getElementById("rf-supported-lists").value : '';
      const supportedLists = suppStr.split(',').map(s => s.trim()).filter(s => s.length > 0);
      const syncEnabled = document.getElementById("rf-sync-enabled").checked;

      if (!name || !ip) {
        alert("Router Name and Management IP are required.");
        return;
      }

      const payload = {
        name: name,
        vendor: vendor,
        ip: ip,
        port: port,
        user: user,
        username: user,
        address_list: addressList,
        supported_lists: supportedLists.length > 0 ? supportedLists : [addressList],
        role: role,
        sync_enabled: syncEnabled
      };

      if (password) {
        payload.password = password;
      }



      const isEdit = !!routerId;

      const url = isEdit ? `/api/v1/routers/${routerId}` : "/api/v1/routers";

      const method = isEdit ? "PUT" : "POST";



      try {

        const res = await fetch(url, {

          method: method,

          headers: {

            "Content-Type": "application/json",

            "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}`

          },

          body: JSON.stringify(payload)

        });

        const data = await res.json();

        if (res.ok) {

          resetRouterForm();

          loadRouters();

          loadThreatData();

        } else {

          alert(`Error saving router: ${data.detail || data.message}`);

        }

      } catch (err) {

        alert(`Request failed: ${err.message}`);

      }

    }



    async function deleteRouterNode(routerId, name) {

      if (!confirm(`Are you sure you want to remove router '${name}' (${routerId}) from the fleet?`)) return;

      try {

        const res = await fetch(`/api/v1/routers/${routerId}`, {

          method: "DELETE",

          headers: { "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}` }

        });

        const data = await res.json();

        if (res.ok) {

          loadRouters();

          loadThreatData();

        } else {

          alert(`Error deleting router: ${data.detail || data.message}`);

        }

      } catch (err) {

        alert(`Request failed: ${err.message}`);

      }

    }



    // --- RADIUS & BILLING API INTEGRATION FUNCTIONS ---

    async function openRadiusConfigModal() {

      const modal = document.getElementById("modal-radius-config");

      modal.style.display = "flex";

      document.getElementById("rc-status").style.display = "none";

      document.getElementById("rc-test-results").style.display = "none";

      document.getElementById("rc-api-token").value = "";



      try {

        const res = await fetch("/api/v1/vault/config", {

          headers: { "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}` }

        });

        if (res.ok) {

          const data = await res.json();

          const cfg = data.config || {};

          document.getElementById("rc-api-url").value = cfg.RADIUS_API_URL || "";

          document.getElementById("rc-auth-type").value = cfg.RADIUS_AUTH_TYPE || "bearer";

          document.getElementById("rc-auth-header").value = cfg.RADIUS_AUTH_HEADER || "Authorization";

          document.getElementById("rc-http-method").value = cfg.RADIUS_HTTP_METHOD || "GET";

          document.getElementById("rc-field-username").value = cfg.RADIUS_FIELD_USERNAME || "session.username";

          document.getElementById("rc-field-name").value = cfg.RADIUS_FIELD_NAME || "customer.name";

          document.getElementById("rc-field-phone").value = cfg.RADIUS_FIELD_PHONE || "customer.contact.primary";

          document.getElementById("rc-field-address").value = cfg.RADIUS_FIELD_ADDRESS || "customer.address";

          document.getElementById("rc-field-code").value = cfg.RADIUS_FIELD_CODE || "customer.customer_code";

        }

      } catch (err) {

        console.warn("Could not load vault config:", err);

      }

    }



    function closeRadiusConfigModal() {

      document.getElementById("modal-radius-config").style.display = "none";

    }



    async function submitRadiusConfig() {

      const apiUrl = document.getElementById("rc-api-url").value.trim();

      const authType = document.getElementById("rc-auth-type").value;

      const authHeader = document.getElementById("rc-auth-header").value.trim() || "Authorization";

      const httpMethod = document.getElementById("rc-http-method").value;

      const apiToken = document.getElementById("rc-api-token").value.trim();

      const fUsername = document.getElementById("rc-field-username").value.trim() || "session.username";

      const fName = document.getElementById("rc-field-name").value.trim() || "customer.name";

      const fPhone = document.getElementById("rc-field-phone").value.trim() || "customer.contact.primary";

      const fAddress = document.getElementById("rc-field-address").value.trim() || "customer.address";

      const fCode = document.getElementById("rc-field-code").value.trim() || "customer.customer_code";



      const statusEl = document.getElementById("rc-status");

      statusEl.style.display = "block";

      statusEl.style.color = "var(--cyan)";

      statusEl.innerText = "Encrypting parameters and saving to appliance vault...";



      const updates = [

        { key: "RADIUS_API_URL", value: apiUrl },

        { key: "RADIUS_AUTH_TYPE", value: authType },

        { key: "RADIUS_AUTH_HEADER", value: authHeader },

        { key: "RADIUS_HTTP_METHOD", value: httpMethod },

        { key: "RADIUS_FIELD_USERNAME", value: fUsername },

        { key: "RADIUS_FIELD_NAME", value: fName },

        { key: "RADIUS_FIELD_PHONE", value: fPhone },

        { key: "RADIUS_FIELD_ADDRESS", value: fAddress },

        { key: "RADIUS_FIELD_CODE", value: fCode }

      ];

      if (apiToken) {

        updates.push({ key: "RADIUS_API_TOKEN", value: apiToken });

      }



      try {

        for (const item of updates) {

          await fetch("/api/v1/vault/update", {

            method: "POST",

            headers: {

              "Content-Type": "application/json",

              "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}`

            },

            body: JSON.stringify(item)

          });

        }

        statusEl.style.color = "var(--success)";

        statusEl.innerHTML = "✓ <strong>Saved!</strong> RADIUS & billing integration parameters safely vaulted.";

        setTimeout(() => {

          closeRadiusConfigModal();

        }, 1000);

      } catch (err) {

        statusEl.style.color = "var(--danger)";

        statusEl.innerText = `Save error: ${err.message}`;

      }

    }



    async function testRadiusLookupLive() {

      const testIp = document.getElementById("rc-test-ip").value.trim();

      if (!testIp) {

        alert("Please enter a subscriber IP address (e.g. 100.64.10.50) to test lookup.");

        return;

      }

      const resultsEl = document.getElementById("rc-test-results");

      resultsEl.style.display = "block";

      resultsEl.style.color = "var(--cyan)";

      resultsEl.innerText = `Querying billing API for subscriber ${testIp}...`;



      try {

        const res = await fetch("/api/v1/radius/test", {

          method: "POST",

          headers: {

            "Content-Type": "application/json",

            "Authorization": `Bearer ${authToken || localStorage.getItem('nat_ai_token')}`

          },

          body: JSON.stringify({ ip: testIp })

        });

        const data = await res.json();

        if (res.ok && data.result) {

          resultsEl.style.color = "var(--success)";

          resultsEl.innerHTML = `<div style="color: #38bdf8; margin-bottom: 4px;">✓ Response from ${data.api_url}:</div><pre style="margin: 0; color: #a7f3d0;">${JSON.stringify(data.result, null, 2)}</pre>`;

        } else {

          resultsEl.style.color = "var(--danger)";

          resultsEl.innerHTML = `<div style="color: #f87171;">Lookup returned no subscriber data (or error):</div><pre style="margin: 0;">${JSON.stringify(data, null, 2)}</pre>`;

        }

      } catch (err) {

        resultsEl.style.color = "var(--danger)";

        resultsEl.innerText = `Test request failed: ${err.message}`;

      }

    }



    function drilldownForensics(dstIp) {

      switchView('export');

      applyExportPreset('15m');

      document.getElementById("filter-src-ip").value = "";

      document.getElementById("filter-src-port").value = "";

      document.getElementById("filter-nat-ip").value = "";

      document.getElementById("filter-nat-port").value = "";

      document.getElementById("filter-dst-ip").value = dstIp;

      document.getElementById("filter-dst-port").value = "";

      document.getElementById("filter-router").value = "ALL";

      document.getElementById("filter-protocol").value = "ALL";

      // Trigger instant forensics query

      setTimeout(() => {

        previewLogs();

      }, 150);

    }



  

    // Public NAT Pool Interactive Sorting & Search

    let cachedNatList = [];

    let currentNatSortField = 'active_ports';

    let currentNatSortAsc = false;



    function sortNatPool(field) {

      if (currentNatSortField === field) {

        currentNatSortAsc = !currentNatSortAsc;

      } else {

        currentNatSortField = field;

        currentNatSortAsc = (field === 'nat_src_ip' || field === 'router_ip');

      }

      renderNatPoolTable();

    }



    function filterNatPoolTable() {

      renderNatPoolTable();

    }



    function renderNatPoolTable() {

      if (!document.getElementById("tbody-nat")) return;

      const searchInput = document.getElementById("nat-pool-search");

      const query = searchInput ? searchInput.value.trim().toLowerCase() : "";



      let list = [...cachedNatList];

      if (query) {

        list = list.filter(n => 

          (n.nat_src_ip && n.nat_src_ip.toLowerCase().includes(query)) ||

          (n.router_ip && n.router_ip.toLowerCase().includes(query)) ||

          (n.status && n.status.toLowerCase().includes(query))

        );

      }



      list.sort((a, b) => {

        let vA = a[currentNatSortField];

        let vB = b[currentNatSortField];

        if (typeof vA === 'string') {

          return currentNatSortAsc ? vA.localeCompare(vB) : vB.localeCompare(vA);

        }

        return currentNatSortAsc ? ((vA || 0) - (vB || 0)) : ((vB || 0) - (vA || 0));

      });



      // Update sort indicators

      const fields = ['nat_src_ip', 'router_ip', 'active_ports', 'util_pct', 'active_subscribers', 'total_flows', 'status'];

      fields.forEach(f => {

        const iconEl = document.getElementById(`sort-icon-${f}`);

        if (iconEl) {

          if (f === currentNatSortField) {

            iconEl.innerText = currentNatSortAsc ? '▲' : '▼';

            iconEl.style.color = 'var(--cyan)';

            iconEl.style.opacity = '1';

          } else {

            iconEl.innerText = '↕';

            iconEl.style.color = 'inherit';

            iconEl.style.opacity = '0.5';

          }

        }

      });



      const summaryEl = document.getElementById("nat-pool-summary-text");

      if (summaryEl) {

        const fieldName = currentNatSortField.replace('_', ' ').toUpperCase();

        summaryEl.innerText = `Showing ${list.length} of ${cachedNatList.length} Public NAT IPs (Sorted by ${fieldName}: ${currentNatSortAsc ? 'Ascending' : 'High to Low (Top Usage First)'}).`;

      }



      let nHtml = "";

      list.forEach(n => {

        const badgeClass = n.status === "CRITICAL" ? "red" : (n.status === "WARNING" ? "yellow" : "green");

        nHtml += `

          <tr>

            <td><strong style="color: var(--cyan);">${n.nat_src_ip}</strong></td>

            <td>${n.router_ip}</td>

            <td><strong style="color: var(--text-main);">${Number(n.active_ports || 0).toLocaleString()}</strong> <span style="color: var(--text-dim); font-size: 11px;">/ 64.5k</span></td>

            <td>

              <div style="display: flex; align-items: center; gap: 8px;">

                <div class="progress-bar-container" style="width: 80px; margin: 0; background: rgba(255,255,255,0.08);">

                  <div class="progress-bar ${badgeClass}" style="width: ${Math.min(100, n.util_pct || 0)}%;"></div>

                </div>

                <strong style="color: ${n.util_pct >= 70 ? 'var(--danger)' : 'inherit'};">${n.util_pct}%</strong>

              </div>

            </td>

            <td>${Number(n.active_subscribers || 0).toLocaleString()}</td>

            <td>${Number(n.total_flows || 0).toLocaleString()}</td>

            <td><span class="badge-tag ${badgeClass}">${n.status}</span></td>

          </tr>

        `;

      });



      document.getElementById("tbody-nat").innerHTML = nHtml || '<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 18px;">No public NAT IPs matching query</td></tr>';

    }



    function downloadNatPoolCSV() {

      if (!cachedNatList || cachedNatList.length === 0) return;

      let csv = "Public NAT IP,Router,Active Ports,Port Utilization %,Bound Subscribers,Total Flows,Pool Status\n";

      // Export in current sorted order

      let list = [...cachedNatList];

      list.sort((a, b) => (b.active_ports || 0) - (a.active_ports || 0));

      list.forEach(n => {

        csv += `"${n.nat_src_ip}","${n.router_ip}",${n.active_ports},${n.util_pct},${n.active_subscribers},${n.total_flows},"${n.status}"\n`;

      });

      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });

      const link = document.createElement("a");

      link.href = URL.createObjectURL(blob);

      link.setAttribute("download", `NAT_Port_Utilization_${new Date().toISOString().slice(0,10)}.csv`);

      document.body.appendChild(link);

      link.click();

      document.body.removeChild(link);

    }

    // =========================================================================
    // AI KEY VAULT & REAL-TIME AI THREAT STREAM FUNCTIONS
    // =========================================================================

    function openAIKeysModal() {
      const modal = document.getElementById("modal-ai-keys");
      if (modal) {
        modal.style.display = "flex";
        modal.style.zIndex = "99999";
        loadAIKeys();
      }
    }

    function closeAIKeysModal() {
      const modal = document.getElementById("modal-ai-keys");
      if (modal) {
        modal.style.display = "none";
      }
    }

    async function loadAIKeys() {
      const tbody = document.getElementById("tbody-ai-keys");
      const badgeCount = document.getElementById("badge-aikeys-count");
      if (!tbody) return;
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-dim); padding:16px;">Loading encrypted keys...</td></tr>';
      
      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/ai/keys", {
          headers: token ? { "Authorization": `Bearer ${token}` } : {}
        });
        const data = await res.json();
        const keys = data.keys || [];
        window.hasAiApiKeys = (keys.length > 0);

        if (badgeCount) {
          badgeCount.innerText = `${keys.length} POOLED`;
        }

        if (keys.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-dim); padding:20px;">No Gemini keys in vault. Click "+ Add Key" below.</td></tr>';
          return;
        }

        tbody.innerHTML = keys.map((k, idx) => {
          const isFirst = idx === 0;
          const isLast = idx === keys.length - 1;
          const upDisabled = isFirst ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : '';
          const downDisabled = isLast ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : '';

          return `
            <tr>
              <td style="text-align:center; font-weight:700; color:var(--cyan);">#${k.priority}</td>
              <td>
                <span style="font-weight:600;" id="key-name-${k.id}">${k.name}</span>
                <button class="btn-refresh" onclick="renameAIKey('${k.id}', '${k.name.replace(/'/g, "\\'")}')" style="padding:1px 6px; font-size:10px; margin-left:6px;" title="Rename Key">&#9998;</button>
              </td>
              <td><code style="font-size:12px; color:var(--text-muted);">${k.key}</code></td>
              <td style="text-align:center;">
                <span class="badge-tag green" id="badge-key-status-${k.id}">Active</span>
              </td>
              <td style="text-align:right; white-space:nowrap;">
                <button class="btn-refresh" onclick="moveAIKey('${k.id}', 'up')" ${upDisabled} title="Move Up in Priority">&#128314;</button>
                <button class="btn-refresh" onclick="moveAIKey('${k.id}', 'down')" ${downDisabled} title="Move Down in Priority">&#128315;</button>
                <button class="btn-refresh" onclick="testAIKey('${k.id}')" title="Test Live Auth" style="padding:3px 8px; font-size:11px;">&#128260; Test</button>
                <button class="btn-refresh" onclick="deleteAIKey('${k.id}', '${k.name.replace(/'/g, "\\'")}')" title="Delete Key" style="color:#f87171; padding:3px 7px; font-size:11px;">&#128465;</button>
              </td>
            </tr>
          `;
        }).join("");
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--danger); padding:16px;">Failed to load keys: ${err.message}</td></tr>`;
      }
    }

    async function moveAIKey(keyId, direction) {
      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch(`/api/v1/ai/keys/${keyId}`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { "Authorization": `Bearer ${token}` } : {})
          },
          body: JSON.stringify({ direction: direction })
        });
        if (res.ok) {
          loadAIKeys();
        } else {
          const err = await res.json();
          alert(`Error moving key: ${err.detail || 'Failed'}`);
        }
      } catch (err) {
        alert(`Request failed: ${err.message}`);
      }
    }

    async function renameAIKey(keyId, currentName) {
      const newName = prompt("Enter new friendly name for this Gemini Key/Account:", currentName);
      if (!newName || newName.trim() === "" || newName.trim() === currentName) return;

      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch(`/api/v1/ai/keys/${keyId}`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { "Authorization": `Bearer ${token}` } : {})
          },
          body: JSON.stringify({ name: newName.trim() })
        });
        if (res.ok) {
          loadAIKeys();
        } else {
          const err = await res.json();
          alert(`Error renaming key: ${err.detail || 'Failed'}`);
        }
      } catch (err) {
        alert(`Request failed: ${err.message}`);
      }
    }

    async function submitAddNewAIKey() {
      const nameInput = document.getElementById("input-new-key-name");
      const tokenInput = document.getElementById("input-new-key-token");
      const name = nameInput ? nameInput.value.trim() : "";
      const token = tokenInput ? tokenInput.value.trim() : "";

      if (!token) {
        alert("Please paste the Gemini API Key token.");
        return;
      }

      try {
        const authTok = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/ai/keys", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(authTok ? { "Authorization": `Bearer ${authTok}` } : {})
          },
          body: JSON.stringify({ name: name || "New Account Key", key: token })
        });
        if (res.ok) {
          if (nameInput) nameInput.value = "";
          if (tokenInput) tokenInput.value = "";
          loadAIKeys();
          if (typeof loadThreatData === 'function') loadThreatData();
          alert("Key added to encrypted vault successfully!");
        } else {
          const err = await res.json();
          alert(`Error adding key: ${err.detail || 'Failed'}`);
        }
      } catch (err) {
        alert(`Request failed: ${err.message}`);
      }
    }

    async function testAIKey(keyId) {
      const badge = document.getElementById(`badge-key-status-${keyId}`);
      if (badge) {
        badge.className = "badge-tag warning";
        badge.innerText = "Testing...";
      }

      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/ai/keys/test", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { "Authorization": `Bearer ${token}` } : {})
          },
          body: JSON.stringify({ key_id: keyId })
        });
        const data = await res.json();
        if (badge) {
          if (data.success) {
            badge.className = "badge-tag green";
            badge.innerText = "200 OK";
          } else {
            badge.className = "badge-tag danger";
            badge.innerText = "Failed";
            alert(`Key test result: ${data.message}`);
          }
        }
      } catch (err) {
        if (badge) {
          badge.className = "badge-tag danger";
          badge.innerText = "Error";
        }
      }
    }

    async function testAllAIKeys() {
      const token = authToken || localStorage.getItem('nat_ai_token');
      const res = await fetch("/api/v1/ai/keys", {
        headers: token ? { "Authorization": `Bearer ${token}` } : {}
      });
      const data = await res.json();
      const keys = data.keys || [];
      for (const k of keys) {
        await testAIKey(k.id);
      }
    }

    async function deleteAIKey(keyId, name) {
      if (!confirm(`Are you sure you want to delete '${name}' from the encrypted key vault?`)) return;

      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch(`/api/v1/ai/keys/${keyId}`, {
          method: "DELETE",
          headers: token ? { "Authorization": `Bearer ${token}` } : {}
        });
        if (res.ok) {
          loadAIKeys();
          if (typeof loadThreatData === 'function') loadThreatData();
        } else {
          const err = await res.json();
          alert(`Error deleting key: ${err.detail || 'Failed'}`);
        }
      } catch (err) {
        alert(`Request failed: ${err.message}`);
      }
    }

    async function triggerManualAIScan() {
      if (window.hasAiApiKeys === false) {
        alert("Cannot run AI Threat Scan: No active Gemini AI API keys configured.\n\nCloud AI reasoning requires at least one API key.\nPlease add an AI key in System Management > AI Keys, or add threat rules manually using '+ Add Threat Rule'.");
        openAIKeysModal();
        return;
      }

      const btn = document.getElementById("btn-sync-mikrotik");
      if (btn) {
        btn.disabled = true;
        btn.innerText = "Running AI Scan...";
      }
      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/threats/sync/daily?hours=24", {
          method: "POST",
          headers: token ? { "Authorization": `Bearer ${token}` } : {}
        });
        const data = await res.json();
        if (res.ok) {
          alert("AI Threat Scan completed successfully! Refreshing dashboard.");
          loadThreatData();
        } else {
          alert(`AI scan: ${data.detail || 'Execution failed'}`);
          if (data.detail && data.detail.includes("AI API keys")) {
            openAIKeysModal();
          }
        }
      } catch (err) {
        alert(`AI scan error: ${err.message}`);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = "&#9889; Run AI Scan Now";
        }
      }
    }

    // Expose functions globally on window
    window.openAIKeysModal = openAIKeysModal;
    window.closeAIKeysModal = closeAIKeysModal;
    window.loadAIKeys = loadAIKeys;
    window.moveAIKey = moveAIKey;
    window.renameAIKey = renameAIKey;
    window.submitAddNewAIKey = submitAddNewAIKey;
    window.testAIKey = testAIKey;
    window.testAllAIKeys = testAllAIKeys;
    window.deleteAIKey = deleteAIKey;
    window.triggerManualAIScan = triggerManualAIScan;

    // Attach backdrop and escape key listeners for modal-ai-keys
    document.addEventListener("DOMContentLoaded", function() {
      const m = document.getElementById("modal-ai-keys");
      if (m) {
        m.addEventListener("click", function(e) {
          if (e.target === m) closeAIKeysModal();
        });
      }
    });
    document.addEventListener("keydown", function(e) {
      if (e.key === "Escape") {
        closeAIKeysModal();
      }
    });



    // =========================================================================
    // UNIFIED SYSTEM MANAGEMENT SUB-MODULE CONTROLLER
    // =========================================================================

    window.activeSystemSubTab = "users";

    function switchSystemSubTab(subTab) {
      if (currentUserRole !== "admin" && (subTab === "users" || subTab === "aikeys" || subTab === "radius")) {
        subTab = "routers";
      }
      window.activeSystemSubTab = subTab;
      const subTabs = ["users", "aikeys", "routers", "radius", "discord"];
      
      subTabs.forEach(t => {
        const sec = document.getElementById(`sec-sys-${t}`);
        const btn = document.getElementById(`btn-sub-${t}`);
        if (sec) sec.style.display = (t === subTab) ? "block" : "none";
        if (btn) {
          if (t === subTab) {
            btn.classList.add("active");
            btn.style.color = "var(--cyan)";
            btn.style.borderColor = "var(--cyan)";
          } else {
            btn.classList.remove("active");
            btn.style.color = "";
            btn.style.borderColor = "";
          }
        }
      });

      if (subTab === "users" && currentUserRole === "admin") loadUsersList();
      else if (subTab === "aikeys" && currentUserRole === "admin") loadAIKeys();
      else if (subTab === "routers") loadRoutersFleet();
      else if (subTab === "radius" && currentUserRole === "admin") loadRadiusSettings();
      else if (subTab === "discord") loadDiscordSettings();
    }

    // -------------------------------------------------------------------------
    // 1. ROUTERS FLEET MANAGEMENT
    // -------------------------------------------------------------------------

    async function loadRoutersFleet() {
      const tbody = document.getElementById("tbody-routers-fleet");
      if (!tbody) return;
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-dim); padding:20px;">Loading router fleet...</td></tr>';

      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/routers", {
          headers: token ? { "Authorization": `Bearer ${token}` } : {}
        });
        const data = await res.json();
        const routers = data.routers || [];

        if (routers.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-dim); padding:24px;">No routers in fleet. Use the form on the right to add your first edge router.</td></tr>';
          return;
        }

        tbody.innerHTML = routers.map(r => {
          const routerIp = r.router_ip || r.ip || "";
          const isOnline = r.status === "online" || r.status === "active";
          const statusBadge = isOnline ? '<span class="badge-tag green">Online</span>' : '<span class="badge-tag danger">Offline</span>';
          const syncBadge = r.sync_enabled !== false ? '<span class="badge-tag green" style="font-size:9px; padding:2px 5px;">SYNC ON</span>' : '<span class="badge-tag" style="background:rgba(255,255,255,0.06); color:var(--text-dim); font-size:9px; padding:2px 5px;">SYNC OFF</span>';
          const vendorTag = (r.vendor || 'mikrotik').toLowerCase();
          let vendorBadgeClass = "badge-tag purple";
          if (vendorTag === "juniper") vendorBadgeClass = "badge-tag cyan";
          else if (vendorTag === "cisco") vendorBadgeClass = "badge-tag green";
          else if (vendorTag === "huawei") vendorBadgeClass = "badge-tag orange";
          
          const routerDisplayName = r.name || `${vendorTag.toUpperCase()} Core (${r.router_ip})`;

          return `
            <tr>
              <td>
                <strong style="color:var(--text-bright); font-size:13px;">${routerDisplayName}</strong><br>
                <span style="color:var(--text-dim); font-size:11px; font-family:monospace;">${routerIp}</span>
              </td>
              <td><span class="${vendorBadgeClass}">${vendorTag.toUpperCase()}</span></td>
              <td><code>${r.port || 22}</code></td>
              <td>${r.username || 'natlog'}</td>
              <td><span class="badge-tag cyan">${r.address_list || 'scanner'}</span></td>
              <td>${syncBadge}</td>
              <td>${statusBadge}</td>
              <td style="text-align:right; white-space:nowrap;">
                <button class="btn-refresh" onclick="testRouterConnection('${routerIp}')" style="padding:3px 8px; font-size:11px;" title="Test Live SSH">&#9889; Test</button>
                <button class="btn-refresh" onclick="editRouterEntry('${routerIp}', '${escape(r.name || '')}', '${r.vendor || 'mikrotik'}', ${r.port || 22}, '${r.username || 'natlog'}', '${r.address_list || 'scanner'}', ${r.sync_enabled !== false})" style="padding:3px 7px; font-size:11px;" title="Edit Router">&#9998;</button>
                <button class="btn-refresh" onclick="deleteRouterEntry('${routerIp}')" style="color:#f87171; padding:3px 7px; font-size:11px;" title="Delete Router">&#128465;</button>
              </td>
            </tr>
          `;
        }).join("");
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--danger); padding:20px;">Failed to load fleet: ${err.message}</td></tr>`;
      }
    }

    async function submitSaveRouter() {
      const name = document.getElementById("input-router-name") ? document.getElementById("input-router-name").value.trim() : "";
      const ip = document.getElementById("input-router-ip").value.trim();
      const vendor = document.getElementById("select-router-vendor").value;
      const port = parseInt(document.getElementById("input-router-port").value.trim()) || 22;
      const user = document.getElementById("input-router-user").value.trim();
      const pass = document.getElementById("input-router-pass").value.trim();
      const list = document.getElementById("input-router-list").value.trim() || "scanner";
      const syncEnabled = document.getElementById("input-router-sync") ? document.getElementById("input-router-sync").checked : true;
      const statusEl = document.getElementById("router-add-status");

      if (!ip) {
        alert("Please enter a valid Router IP.");
        return;
      }

      if (statusEl) {
        statusEl.style.display = "block";
        statusEl.style.color = "var(--cyan)";
        statusEl.innerText = "Saving router configuration...";
      }

      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/routers", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { "Authorization": `Bearer ${token}` } : {})
          },
          body: JSON.stringify({
            name: name || `${vendor.toUpperCase()} Core (${ip})`,
            router_ip: ip,
            vendor: vendor,
            port: port,
            username: user,
            password: pass,
            address_list: list,
            sync_enabled: syncEnabled
          })
        });

        if (res.ok) {
          if (statusEl) {
            statusEl.style.color = "var(--green)";
            statusEl.innerText = "Router saved to fleet successfully!";
            setTimeout(() => { statusEl.style.display = "none"; }, 3000);
          }
          if (document.getElementById("input-router-name")) document.getElementById("input-router-name").value = "";
          document.getElementById("input-router-ip").value = "";
          document.getElementById("input-router-pass").value = "";
          const title = document.getElementById("router-form-title");
          if (title) title.innerText = "➕ Add Router to Fleet";
          const btnText = document.getElementById("btn-save-router-text");
          if (btnText) btnText.innerText = "➕ Save Router to Fleet";
          loadRoutersFleet();
        } else {
          const err = await res.json();
          if (statusEl) {
            statusEl.style.color = "var(--danger)";
            statusEl.innerText = `Error: ${err.detail || 'Failed'}`;
          }
        }
      } catch (e) {
        if (statusEl) {
          statusEl.style.color = "var(--danger)";
          statusEl.innerText = `Request error: ${e.message}`;
        }
      }
    }

    async function testRouterConnection(routerIp) {
      alert(`Testing live SSH connection to router ${routerIp}...`);
      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch(`/api/v1/routers/${routerIp}/test`, {
          method: "POST",
          headers: token ? { "Authorization": `Bearer ${token}` } : {}
        });
        const data = await res.json();
        alert(data.message || (data.status === 'ok' ? 'Connection Successful!' : 'Connection Failed'));
        loadRoutersFleet();
      } catch (err) {
        alert(`Test error: ${err.message}`);
      }
    }

    function editRouterEntry(ip, nameEscaped, vendor, port, user, list, syncEnabled) {
      if (document.getElementById("input-router-name")) document.getElementById("input-router-name").value = unescape(nameEscaped || "");
      document.getElementById("input-router-ip").value = ip;
      document.getElementById("select-router-vendor").value = vendor;
      document.getElementById("input-router-port").value = port;
      document.getElementById("input-router-user").value = user;
      document.getElementById("input-router-list").value = list;
      if (document.getElementById("input-router-sync")) document.getElementById("input-router-sync").checked = (syncEnabled !== false);
      const title = document.getElementById("router-form-title");
      if (title) title.innerText = `✏️ Edit Router (${ip})`;
      const btnText = document.getElementById("btn-save-router-text");
      if (btnText) btnText.innerText = "💾 Update Router in Fleet";
    }

    async function deleteRouterEntry(routerIp) {
      if (!confirm(`Are you sure you want to remove router ${routerIp} from the appliance fleet?`)) return;
      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch(`/api/v1/routers/${routerIp}`, {
          method: "DELETE",
          headers: token ? { "Authorization": `Bearer ${token}` } : {}
        });
        if (res.ok) {
          loadRoutersFleet();
        } else {
          const err = await res.json();
          alert(`Error: ${err.detail || 'Delete failed'}`);
        }
      } catch (e) {
        alert(`Request failed: ${e.message}`);
      }
    }

    // -------------------------------------------------------------------------
    // 2. RADIUS MANAGEMENT
    // -------------------------------------------------------------------------

    async function loadRadiusSettings() {
      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/vault/config", {
          headers: token ? { "Authorization": `Bearer ${token}` } : {}
        });
        if (res.ok) {
          const data = await res.json();
          const cfg = data.config || {};
          if (document.getElementById("rad-api-url")) document.getElementById("rad-api-url").value = cfg.RADIUS_API_URL || "";
          if (document.getElementById("rad-api-token")) document.getElementById("rad-api-token").value = cfg.RADIUS_API_TOKEN || "";
          if (document.getElementById("rad-auth-header")) document.getElementById("rad-auth-header").value = cfg.RADIUS_AUTH_HEADER || "Authorization";
          if (document.getElementById("rad-auth-type")) document.getElementById("rad-auth-type").value = cfg.RADIUS_AUTH_TYPE || "bearer";
          if (document.getElementById("rad-http-method")) document.getElementById("rad-http-method").value = cfg.RADIUS_HTTP_METHOD || "GET";
          if (document.getElementById("rad-field-username")) document.getElementById("rad-field-username").value = cfg.RADIUS_FIELD_USERNAME || "session.username";
          if (document.getElementById("rad-field-name")) document.getElementById("rad-field-name").value = cfg.RADIUS_FIELD_NAME || "customer.name";
          if (document.getElementById("rad-field-code")) document.getElementById("rad-field-code").value = cfg.RADIUS_FIELD_CODE || "customer.customer_code";
          if (document.getElementById("rad-field-phone")) document.getElementById("rad-field-phone").value = cfg.RADIUS_FIELD_PHONE || "customer.contact.primary";
        }
      } catch (err) {
        console.warn("Could not load RADIUS vault config:", err);
      }
    }

    async function saveRadiusSettings() {
      const statusEl = document.getElementById("rad-save-status");
      const settings = {
        RADIUS_API_URL: document.getElementById("rad-api-url").value.trim(),
        RADIUS_API_TOKEN: document.getElementById("rad-api-token").value.trim(),
        RADIUS_AUTH_HEADER: document.getElementById("rad-auth-header").value.trim(),
        RADIUS_AUTH_TYPE: document.getElementById("rad-auth-type").value,
        RADIUS_HTTP_METHOD: document.getElementById("rad-http-method").value,
        RADIUS_FIELD_USERNAME: document.getElementById("rad-field-username").value.trim(),
        RADIUS_FIELD_NAME: document.getElementById("rad-field-name").value.trim(),
        RADIUS_FIELD_CODE: document.getElementById("rad-field-code").value.trim(),
        RADIUS_FIELD_PHONE: document.getElementById("rad-field-phone").value.trim()
      };

      if (statusEl) {
        statusEl.style.display = "block";
        statusEl.style.color = "var(--cyan)";
        statusEl.innerText = "Encrypting and saving RADIUS settings to appliance vault...";
      }

      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/vault/bulk-update", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { "Authorization": `Bearer ${token}` } : {})
          },
          body: JSON.stringify({ settings: settings })
        });

        if (res.ok) {
          if (statusEl) {
            statusEl.style.color = "var(--green)";
            statusEl.innerText = "RADIUS settings safely encrypted & saved!";
            setTimeout(() => { statusEl.style.display = "none"; }, 3000);
          }
        } else {
          const err = await res.json();
          if (statusEl) {
            statusEl.style.color = "var(--danger)";
            statusEl.innerText = `Save error: ${err.detail || 'Failed'}`;
          }
        }
      } catch (e) {
        if (statusEl) {
          statusEl.style.color = "var(--danger)";
          statusEl.innerText = `Request error: ${e.message}`;
        }
      }
    }

    async function testRadiusLookupFromForm() {
      const ip = document.getElementById("test-rad-ip").value.trim();
      const ts = document.getElementById("test-rad-ts").value.trim();
      const output = document.getElementById("test-rad-output");

      if (!ip) {
        alert("Please enter a subscriber IP to test (e.g. 100.64.0.15).");
        return;
      }

      if (output) output.innerText = "Executing live RADIUS API lookup query...";

      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/radius/test", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { "Authorization": `Bearer ${token}` } : {})
          },
          body: JSON.stringify({ ip: ip, timestamp: ts || null })
        });
        const data = await res.json();
        if (output) {
          output.innerText = JSON.stringify(data, null, 2);
        }
      } catch (err) {
        if (output) output.innerText = `Lookup Error: ${err.message}`;
      }
    }

    // -------------------------------------------------------------------------
    // 3. DISCORD CHANNEL MANAGEMENT
    // -------------------------------------------------------------------------

    async function loadDiscordSettings() {
      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/vault/config", {
          headers: token ? { "Authorization": `Bearer ${token}` } : {}
        });
        if (res.ok) {
          const data = await res.json();
          const cfg = data.config || {};
          if (document.getElementById("disc-webhook-url")) document.getElementById("disc-webhook-url").value = cfg.DISCORD_WEBHOOK_URL || "";
        }
      } catch (err) {
        console.warn("Could not load Discord config:", err);
      }
    }

    async function saveDiscordSettings() {
      const statusEl = document.getElementById("disc-save-status");
      const url = document.getElementById("disc-webhook-url").value.trim();
      const settings = { DISCORD_WEBHOOK_URL: url };

      if (statusEl) {
        statusEl.style.display = "block";
        statusEl.style.color = "var(--cyan)";
        statusEl.innerText = "Saving Discord webhook to encrypted vault...";
      }

      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/vault/bulk-update", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { "Authorization": `Bearer ${token}` } : {})
          },
          body: JSON.stringify({ settings: settings })
        });

        if (res.ok) {
          if (statusEl) {
            statusEl.style.color = "var(--green)";
            statusEl.innerText = "Discord Webhook saved successfully!";
            setTimeout(() => { statusEl.style.display = "none"; }, 3000);
          }
        } else {
          const err = await res.json();
          if (statusEl) {
            statusEl.style.color = "var(--danger)";
            statusEl.innerText = `Save error: ${err.detail || 'Failed'}`;
          }
        }
      } catch (e) {
        if (statusEl) {
          statusEl.style.color = "var(--danger)";
          statusEl.innerText = `Request error: ${e.message}`;
        }
      }
    }

    async function testDiscordWebhookFromForm() {
      const statusEl = document.getElementById("disc-test-status");
      const url = document.getElementById("disc-webhook-url").value.trim();

      if (statusEl) {
        statusEl.style.display = "block";
        statusEl.style.color = "var(--cyan)";
        statusEl.innerText = "Sending test embed to Discord channel...";
      }

      try {
        const token = authToken || localStorage.getItem('nat_ai_token');
        const res = await fetch("/api/v1/discord/test", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { "Authorization": `Bearer ${token}` } : {})
          },
          body: JSON.stringify({ webhook_url: url || null })
        });

        const data = await res.json();
        if (res.ok && data.status === "ok") {
          if (statusEl) {
            statusEl.style.color = "var(--green)";
            statusEl.innerText = "Test Alert sent! Check your Discord channel.";
          }
        } else {
          if (statusEl) {
            statusEl.style.color = "var(--danger)";
            statusEl.innerText = `Test failed: ${data.message || data.detail || 'Error'}`;
          }
        }
      } catch (e) {
        if (statusEl) {
          statusEl.style.color = "var(--danger)";
          statusEl.innerText = `Connection failed: ${e.message}`;
        }
      }
    }

    // Expose all System Management functions globally
    window.switchSystemSubTab = switchSystemSubTab;
    window.loadRoutersFleet = loadRoutersFleet;
    window.submitSaveRouter = submitSaveRouter;
    window.testRouterConnection = testRouterConnection;
    window.editRouterEntry = editRouterEntry;
    window.deleteRouterEntry = deleteRouterEntry;
    window.loadRadiusSettings = loadRadiusSettings;
    window.saveRadiusSettings = saveRadiusSettings;
    window.testRadiusLookupFromForm = testRadiusLookupFromForm;
    window.loadDiscordSettings = loadDiscordSettings;
    window.saveDiscordSettings = saveDiscordSettings;
    window.testDiscordWebhookFromForm = testDiscordWebhookFromForm;
