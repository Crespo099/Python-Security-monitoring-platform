const $ = (id) => document.getElementById(id);
let mode = "login";
let token = sessionStorage.getItem("swam-token");

function setMode(next) {
  mode = next;
  $("login-tab").classList.toggle("active", mode === "login");
  $("register-tab").classList.toggle("active", mode === "register");
  $("name-wrap").classList.toggle("hidden", mode !== "register");
  $("display-name").required = mode === "register";
  $("password").autocomplete = mode === "login" ? "current-password" : "new-password";
  $("password").minLength = mode === "login" ? 1 : 12;
  $("submit-auth").textContent = mode === "login" ? "Sign in" : "Create account";
  $("auth-error").textContent = "";
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && typeof options.body === "string" && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    if (response.status === 401) signOut();
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

function signOut() {
  token = null;
  sessionStorage.removeItem("swam-token");
  $("dashboard").classList.add("hidden");
  $("auth-panel").classList.remove("hidden");
  $("identity").textContent = "";
}

const formatDate = (value) => new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });

async function loadDashboard() {
  try {
    const [me, summary, alerts, events] = await Promise.all([
      api("/api/auth/me"), api("/api/summary"), api("/api/alerts?limit=30"), api("/api/events?limit=30")
    ]);
    $("auth-panel").classList.add("hidden");
    $("dashboard").classList.remove("hidden");
    $("identity").textContent = me.display_name;
    $("events-count").textContent = summary.events_7d.toLocaleString();
    $("alerts-count").textContent = summary.open_alerts.toLocaleString();
    renderAlerts(alerts);
    renderEvents(events);
    $("load-error").textContent = "";
  } catch (error) {
    if (!token) return;
    $("load-error").textContent = error.message;
  }
}

function renderAlerts(alerts) {
  const host = $("alerts-list");
  if (!alerts.length) { host.innerHTML = '<p class="empty">No alerts yet. New signals will appear here.</p>'; return; }
  host.replaceChildren(...alerts.map((alert) => {
    const card = document.createElement("article"); card.className = "alert";
    const top = document.createElement("div"); top.className = "alert-top";
    const title = document.createElement("span"); title.className = "alert-title"; title.textContent = alert.title;
    const badge = document.createElement("span"); badge.className = `badge ${alert.severity}`; badge.textContent = alert.severity;
    top.append(title, badge);
    const description = document.createElement("p"); description.textContent = alert.description;
    const time = document.createElement("time"); time.textContent = formatDate(alert.created_at);
    card.append(top, description, time);
    if (!alert.is_acknowledged) {
      const ack = document.createElement("button"); ack.className = "ack"; ack.textContent = "Acknowledge";
      ack.addEventListener("click", async () => { await api(`/api/alerts/${alert.id}/acknowledge`, { method: "POST" }); await loadDashboard(); });
      card.append(ack);
    }
    return card;
  }));
}

function renderEvents(events) {
  const body = $("events-list");
  if (!events.length) { body.innerHTML = '<tr><td colspan="3" class="empty">No activity has been recorded.</td></tr>'; return; }
  body.replaceChildren(...events.map((event) => {
    const row = document.createElement("tr");
    for (const text of [event.event_type, event.domain || "—", formatDate(event.occurred_at)]) {
      const cell = document.createElement("td"); cell.textContent = text; row.append(cell);
    }
    return row;
  }));
}

$("login-tab").addEventListener("click", () => setMode("login"));
$("register-tab").addEventListener("click", () => setMode("register"));
$("auth-form").addEventListener("submit", async (event) => {
  event.preventDefault(); $("auth-error").textContent = "";
  const email = $("email").value; const password = $("password").value;
  try {
    if (mode === "register") {
      await api("/api/auth/register", { method: "POST", body: JSON.stringify({ email, password, display_name: $("display-name").value }) });
      setMode("login");
      $("auth-error").textContent = "Account created. Sign in to continue.";
      return;
    }
    const credentials = new URLSearchParams({ username: email, password });
    const result = await api("/api/auth/login", { method: "POST", body: credentials });
    token = result.access_token; sessionStorage.setItem("swam-token", token); await loadDashboard();
  } catch (error) { $("auth-error").textContent = error.message; }
});
$("logout").addEventListener("click", signOut);
$("refresh").addEventListener("click", loadDashboard);
if (token) loadDashboard();
