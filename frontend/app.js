const devicesTable = document.querySelector("#devicesTable");
const rulesTable = document.querySelector("#rulesTable");
const checksGrid = document.querySelector("#checksGrid");

document.querySelector("#refreshButton").addEventListener("click", loadDashboard);

async function getJson(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

async function loadDashboard() {
  const [devices, rules, checks] = await Promise.all([
    getJson("/devices"),
    getJson("/firewall-rules"),
    getJson("/cis-results"),
  ]);

  renderDevices(devices);
  renderRules(rules);
  renderChecks(checks);
  document.querySelector("#deviceCount").textContent = devices.length;
  document.querySelector("#ruleCount").textContent = rules.length;
  document.querySelector("#passedCount").textContent = checks.filter((item) => item.status === "pass").length;
  document.querySelector("#failedCount").textContent = checks.filter((item) => item.status === "fail").length;
}

function renderDevices(devices) {
  if (!devices.length) {
    devicesTable.innerHTML = `<tr><td colspan="4" class="empty">No scan data yet. Run the scanner to populate this table.</td></tr>`;
    return;
  }
  devicesTable.innerHTML = devices
    .map((device) => {
      const ports = device.open_ports
        .map((item) => `<span class="pill" title="${escapeHtml(item.banner || "No banner")}">${item.port}/${escapeHtml(item.service)}</span>`)
        .join("");
      return `<tr>
        <td>${escapeHtml(device.ip)}</td>
        <td>${escapeHtml(device.hostname || "-")}</td>
        <td>${escapeHtml(device.mac_vendor || device.mac || "-")}</td>
        <td>${ports || "-"}</td>
      </tr>`;
    })
    .join("");
}

function renderRules(rules) {
  if (!rules.length) {
    rulesTable.innerHTML = `<tr><td colspan="6" class="empty">No firewall rules loaded.</td></tr>`;
    return;
  }
  rulesTable.innerHTML = rules
    .map(
      (rule) => `<tr>
        <td>${escapeHtml(rule.direction)}</td>
        <td>${escapeHtml(rule.source)}</td>
        <td>${escapeHtml(rule.destination)}</td>
        <td>${escapeHtml(rule.protocol)}</td>
        <td>${escapeHtml(String(rule.port))}</td>
        <td>${escapeHtml(rule.action)}</td>
      </tr>`,
    )
    .join("");
}

function renderChecks(checks) {
  if (!checks.length) {
    checksGrid.innerHTML = `<div class="empty">No benchmark results loaded.</div>`;
    return;
  }
  checksGrid.innerHTML = checks
    .map(
      (check) => `<article class="check ${check.status === "fail" ? "fail" : ""}">
        <div class="check-header">
          <h3>${escapeHtml(check.check_id)}: ${escapeHtml(check.title)}</h3>
          <span class="status">${escapeHtml(check.status)}</span>
        </div>
        <p>${escapeHtml(check.cis_control)}</p>
        <ul class="evidence">
          ${check.evidence.slice(0, 4).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
        </ul>
        <p>${escapeHtml(check.recommendation)}</p>
      </article>`,
    )
    .join("");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

loadDashboard().catch((error) => {
  checksGrid.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
});
