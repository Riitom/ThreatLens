"use strict";
/* ThreatLens front end. Every value from the API is inserted with textContent,
   never innerHTML, because scan results contain text taken from hostile pages. */

const $ = (sel, root = document) => root.querySelector(sel);

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const form = $("#scan-form");
const urlInput = $("#url");
const btn = $("#scan-btn");
const progress = $("#progress");
const errorBox = $("#error");
const resultEl = $("#result");
let lastResult = null;

const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Note" };
const GRADE_TEXT = {
  "A+": "Strong configuration with additional safeguards.",
  A: "Strong configuration.", B: "Good, with minor gaps.", C: "Several gaps worth fixing.",
  D: "Weak configuration.", F: "Poorly configured.",
};
const ENGINE_NAME = {
  url: "Address analysis", content: "Page analysis", certificate: "Certificate check",
  security: "Security headers", intel: "Community intelligence", safe_browsing: "Google Safe Browsing",
  exposure: "Exposed-file check",
};
const CATEGORY_LABEL = {
  phishing: "Phishing page", malware: "Malware or fake download", fake_recruitment: "Fake job offer",
  payment_scam: "Payment scam", impersonation: "Impersonates an organisation", other: "Something else",
};

function setBusy(busy) {
  btn.disabled = busy;
  btn.textContent = busy ? "Scanning" : "Scan link";
  progress.hidden = !busy;
  form.setAttribute("aria-busy", String(busy));
  document.querySelectorAll(".chip").forEach((chip) => { chip.disabled = busy; });
  if (busy) { resultEl.hidden = true; lastResult = null; }
}
function showError(msg, invalid = false) {
  errorBox.textContent = msg || "";
  errorBox.hidden = !msg;
  urlInput.setAttribute("aria-invalid", String(invalid));
}

async function api(path, options) {
  let res;
  try {
    res = await fetch(path, { ...options, signal: AbortSignal.timeout(120000) });
  } catch {
    throw new Error("Could not reach the ThreatLens server. Check your connection and try again.");
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error body */ }
  if (!res.ok) {
    const error = new Error((data && data.error) || `The server answered with an error (${res.status}).`);
    error.status = res.status;
    throw error;
  }
  if (!data) throw new Error("The server returned an unreadable response. Please try again.");
  return data;
}

/* ---------- address specimen: splits the URL so the real domain stands out ---------- */
function specimen(r) {
  const f = r.features || {};
  let u;
  try { u = new URL(r.url); } catch { return null; }
  const host = u.hostname;
  const reg = f.registered_domain && host.endsWith(f.registered_domain) ? f.registered_domain : host;
  const sub = host.slice(0, host.length - reg.length);
  const rest = (u.port ? ":" + u.port : "") + u.pathname + u.search;
  const bad = r.verdict.level === "danger" || r.verdict.level === "high";
  const parts = [];
  parts.push(["scheme", u.protocol + "//", u.protocol === "https:" ? "" : "Not encrypted", u.protocol === "https:" ? "" : "warn"]);
  if (sub) parts.push(["sub", sub, "Decoration. Anyone can put any words here.", ""]);
  parts.push(["reg", reg, "The real site", bad && f.impersonated_brand ? "warn" : ""]);
  if (rest && rest !== "/") parts.push(["path", rest.length > 90 ? rest.slice(0, 90) + "…" : rest, "Page on that site", ""]);
  const wrap = h("div", { class: "url-parts", "aria-hidden": "true" });
  parts.forEach(([kind, text, cap, mod], i) => {
    const part = h("div", { class: `part ${kind} ${mod}`.trim() },
      h("span", { class: "text", text }), h("span", { class: "rule" }), cap ? h("span", { class: "cap", text: cap }) : null);
    part.style.setProperty("--i", i);
    wrap.append(part);
  });
  const note = f.impersonated_brand
    ? `This address imitates ${f.impersonated_brand}. The part in bold is the site you would actually be visiting.`
    : f.known_brand
      ? `The registered domain belongs to ${f.known_brand}.`
      : "The part in bold is the site you would actually be visiting.";
  const el = h("figure", { class: "specimen" },
    h("figcaption", { class: "sr-only", text: `Address breakdown. Real site: ${reg}` }), wrap, h("p", { class: "note", text: note }));
  requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add("drawn")));
  return el;
}

/* ---------- verdict ---------- */
function meter(score) {
  return h("div", { class: "meter-block" },
    h("div", { class: "meter-label" }, h("span", { text: "Threat score" }), h("strong", { text: `${score} / 100` })),
    h("div", { class: "meter", role: "img", "aria-label": `Threat score ${score} out of 100` },
      h("span", { class: "b1" }), h("span", { class: "b2" }), h("span", { class: "b3" }), h("span", { class: "b4" }),
      (() => { const m = h("i", { class: "marker" }); m.style.left = Math.min(100, Math.max(0, score)) + "%"; return m; })()),
    h("div", { class: "meter-scale", "aria-hidden": "true" }, h("span", { text: "Low" }), h("span", { text: "Dangerous" })));
}

function verdictBlock(r) {
  const v = r.verdict;
  const grade = r.posture.grade;
  const left = h("div", {},
    h("h2", { class: "verdict-word", text: v.label }),
    h("p", { class: "verdict-summary", text: v.summary }),
    v.advice.length ? h("ul", { class: "advice" }, v.advice.map((a) => h("li", { text: a }))) : null,
    h("div", { class: "actions" },
      h("button", { type: "button", class: "quiet", text: "Report this site", onclick: () => selectTab("community", true) }),
      h("button", { type: "button", class: "quiet", text: "Download JSON", onclick: downloadJson })));
  const right = h("div", { class: "scores" },
    meter(v.threat_score),
    h("div", {},
      h("div", { class: "meter-label" }, h("span", { text: "Site hardening" })),
      h("div", { class: "grade-row" },
        h("span", { class: `grade ${grade ? "grade-" + grade : "grade-na"}`, text: grade || "–" }),
        h("span", { class: "grade-text", text: grade ? GRADE_TEXT[grade] : "Not measured. The site did not answer." }))),
    h("p", { class: "fine", text: `Confidence: ${v.confidence}. Hardening is separate from the threat score because a scam page can be well configured.` }));
  return h("div", { class: `verdict level-${v.level}` }, left, right);
}

/* ---------- findings ---------- */
function findingItem(f) {
  return h("li", { class: "finding" },
    h("span", { class: `sev sev-${f.severity}`, text: SEV_LABEL[f.severity] || f.severity }),
    h("div", {},
      h("h4", { text: f.title }),
      f.detail ? h("p", { text: f.detail }) : null,
      f.advice ? h("p", { class: "todo", text: f.advice }) : null));
}
function group(title, sub, items, emptyText) {
  return h("div", { class: "group" },
    h("h3", { text: title }), sub ? h("p", { class: "sub", text: sub }) : null,
    items.length ? h("ul", { class: "findings" }, items.map(findingItem)) : h("p", { class: "empty", text: emptyText }));
}

function summaryPanel(r) {
  const threats = r.findings.filter((f) => (f.axis === "threat" || f.axis === "both") && f.severity !== "info");
  const posture = r.findings.filter((f) => f.axis === "posture" && f.severity !== "info");
  return h("div", {},
    group("Signs of fraud or malware", "Evidence about who runs the site and what it does with your data.", threats,
      "Nothing in the address, page, certificate or community reports pointed to fraud."),
    group("Configuration weaknesses", "Hygiene problems. They say how carefully the site is run, not whether it is honest.", posture,
      r.posture.grade ? "No configuration weaknesses were found." : "The site did not answer, so its configuration could not be checked."));
}

function row(k, v, cls) { return [h("dt", { text: k }), h("dd", { class: cls || "" }, v)]; }
function fmtDate(iso) { try { return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }); } catch { return iso; } }

function certPanel(r) {
  const c = r.certificate;
  const certFindings = r.findings.filter((f) => f.engine === "certificate");
  if (!c) {
    const cov = r.coverage.find((x) => x.engine === "certificate");
    return h("div", {}, h("p", { class: "empty", text: cov && cov.note ? `No certificate was read. ${cov.note}` : "No certificate was read for this link." }),
      certFindings.length ? h("ul", { class: "findings" }, certFindings.map(findingItem)) : null);
  }
  const t = c.transparency || {};
  const ct = t.embedded_scts > 0 ? `${t.embedded_scts} embedded SCT(s); signatures not verified` : "No embedded SCT";
  const ctExtra = t.crtsh === "found" ? " · found in crt.sh" : t.crtsh === "not_found" ? " · not in crt.sh" : t.crtsh === "unavailable" ? " · crt.sh unreachable" : "";
  
  const isIncident = certFindings.some((f) => f.id === "cert.issuer_watch" || f.id.includes("issuer_watch") || f.id === "cert.blocked_key");
  const incidentBanner = isIncident ? h("div", { class: "incident-banner" },
    h("h3", { text: "⚠️ Certificate Authority Under Distrust Review / Incident" }),
    h("p", { text: "This certificate chain contains a CA under public incident scrutiny (such as the eMudhra Global TLS weak key generation incident or root distrust blocklist). Certificates relying on affected intermediates risk being rejected or revoked by modern web browsers." })
  ) : null;

  let cryptoStatus = "No tested structural weakness detected; key entropy is not proven.";
  if (certFindings.some((f) => f.id === "cert.close_primes")) cryptoStatus = "CRITICAL: Factors with Fermat's method (close primes p ≈ q)";
  else if (certFindings.some((f) => f.id === "cert.roca_vulnerable")) cryptoStatus = "CRITICAL: Vulnerable to ROCA (CVE-2017-15361)";
  else if (certFindings.some((f) => f.id === "cert.shared_prime")) cryptoStatus = "CRITICAL: Shares RSA prime with another certificate (Batch GCD)";
  else if (certFindings.some((f) => f.id === "cert.weak_rsa_size")) cryptoStatus = "HIGH: RSA key size under 2048 bits";

  const facts = h("dl", { class: "facts" },
    row("Trust", c.trusted ? "Chain is trusted" : `Not trusted${c.trust_error ? ": " + c.trust_error : ""}`, `trust ${c.trusted ? "yes" : "no"}`),
    row("Issued to", c.subject_cn || "(none)"), row("Issued by", c.issuer || "(unknown)"),
    row("Valid", `${fmtDate(c.not_before)} to ${fmtDate(c.not_after)} (${c.days_left >= 0 ? c.days_left + " days left" : "expired"})`),
    row("Public key", c.key),
    row("Cryptographic Health", cryptoStatus, cryptoStatus.includes("CRITICAL") ? "mono st-fail" : cryptoStatus.includes("HIGH") ? "mono st-warn" : "mono st-pass"),
    row("Signature", c.signature.toUpperCase()),
    row("Connection", [c.protocol, c.cipher].filter(Boolean).join(" · ")),
    row("Transparency", ct + ctExtra),
    row("Names covered", (c.san || []).join(", ") || "(none)"),
    row("Fingerprint", c.sha256, "mono"));
  const chain = h("div", { class: "table-wrap" }, h("table", {},
    h("caption", { class: "sr-only", text: "Certificate chain, leaf first" }),
    h("thead", {}, h("tr", {}, ["Role", "Subject", "Issuer", "Key", "Expires"].map((x) => h("th", { scope: "col", text: x })))),
    h("tbody", {}, c.chain.map((x) => h("tr", {}, h("td", { text: x.role }), h("td", { text: x.subject }), h("td", { text: x.issuer }),
      h("td", { text: x.key }), h("td", { text: x.not_after }))))));
  return h("div", {}, incidentBanner, facts, h("h3", { text: "Chain presented by the server" }), chain,
    h("h3", { text: "Findings" }),
    certFindings.length ? h("ul", { class: "findings" }, certFindings.map(findingItem)) : h("p", { class: "empty", text: "No certificate problems were found." }));
}

function pagePanel(r) {
  const items = r.findings.filter((f) => f.engine === "content" || f.engine === "url");
  const p = r.page;
  const facts = p ? h("dl", { class: "facts" },
    row("Page title", p.title || "(none)"), row("Forms", String(p.forms)), row("Password fields", String(p.password_fields)),
    row("Hidden or embedded frames", String(p.iframes)), row("Scripts", String(p.scripts)),
    row("Final address", r.http.final_url || r.url, "mono"),
    r.http.redirects.length ? row("Redirects", r.http.redirects.map((x) => `${x.status} → ${x.to}`).join("  |  "), "mono") : null) : null;
  return h("div", {}, facts,
    p ? null : h("p", { class: "empty", text: r.http.error ? `The page could not be read. ${r.http.error}` : "The response was not an HTML page, so only the address was analysed." }),
    h("h3", { text: "Findings" }),
    items.length ? h("ul", { class: "findings" }, items.map(findingItem)) : h("p", { class: "empty", text: "Nothing suspicious in the address or the page." }));
}

function headersPanel(r) {
  if (!r.headers.length) return h("p", { class: "empty", text: "The site did not answer, so its headers could not be checked." });
  const sec = r.findings.filter((f) => f.engine === "security");
  const lbl = { pass: "Present", warn: "Weak", fail: "Missing", info: "Not applicable" };
  const table = h("div", { class: "table-wrap" }, h("table", {},
    h("caption", { class: "sr-only", text: "Security headers" }),
    h("thead", {}, h("tr", {}, ["Header", "Status", "Value or note"].map((x) => h("th", { scope: "col", text: x })))),
    h("tbody", {}, r.headers.map((x) => h("tr", {}, h("td", { text: x.name }),
      h("td", { class: `st-${x.status}`, text: lbl[x.status] || x.status }), h("td", { class: "mono", text: x.value || x.note || "" }))))));
  return h("div", {}, table, h("h3", { text: "Findings" }),
    sec.length ? h("ul", { class: "findings" }, sec.map(findingItem)) : h("p", { class: "empty", text: "No weaknesses were found." }));
}

/* ---------- community ---------- */
function communityPanel(r) {
  if (r.demo) return h("div", { class: "demo-notice" },
    h("h3", { text: "Demonstration evidence" }),
    h("p", { text: "This scenario is synthetic. Reports and votes are disabled to keep example data out of the live community feed. Scan a real address to contribute." }));
  const c = r.community;
  const level = c ? (c.effective_level || c.level) : "none";
  const text = { none: "No community reports for this site yet.", weak: "One report exists and nobody has backed it up.",
    reported: "Several people have reported this site.", confirmed: "Independent reports confirm this site is harmful." }[level];
  const facts = c ? h("dl", { class: "facts" },
    row("Status", text), row("Reports", String(c.reports)), row("Independent reporters", String(c.unique_reporters)),
    row("Confirmations / disputes", `${c.confirmations} / ${c.disputes}`),
    Object.keys(c.categories || {}).length ? row("Reported as", Object.entries(c.categories).map(([k, v]) => `${CATEGORY_LABEL[k] || k} (${v})`).join(", ")) : null,
    c.note ? row("Note", c.note) : null) : h("p", { class: "empty", text: "Community data is not available on this server." });

  const select = h("select", { id: "rep-cat", name: "category" },
    Object.entries(CATEGORY_LABEL).map(([k, v]) => h("option", { value: k, text: v })));
  const comment = h("textarea", { id: "rep-comment", maxlength: "500", placeholder: "What did the page ask you to do? (optional)" });
  const status = h("p", { class: "status-msg", role: "status" });
  const send = async (fn) => {
    status.textContent = "Sending";
    reportForm.querySelectorAll("button").forEach((b) => { b.disabled = true; });
    try {
      status.textContent = await fn();
      const rep = await api("/api/reputation?url=" + encodeURIComponent(r.host));
      r.community = rep;
      const refreshed = communityPanel(r);
      refreshed.querySelector(".status-msg").textContent = status.textContent;
      $("#panel-community").replaceChildren(refreshed);
      loadThreatFeed();
    } catch (e) { status.textContent = e.message; }
    finally { reportForm.querySelectorAll("button").forEach((b) => { b.disabled = false; }); }
  };
  const post = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const reportForm = h("form", { class: "report-form", novalidate: true, onsubmit: (e) => {
    e.preventDefault();
    send(async () => {
      const out = await post("/api/report", { url: r.url, category: select.value, comment: comment.value });
      return out.status === "duplicate" ? "You already reported this site. Thank you." : "Report added. Thank you for warning others.";
    });
  } },
    h("div", {}, h("label", { for: "rep-cat", text: "What kind of problem is it?" }), select),
    h("div", {}, h("label", { for: "rep-comment", text: "Details" }), comment),
    h("p", { class: "hint", text: "We store the address without its query string, and only a one-way hash of your network address." }),
    h("div", { class: "row" },
      h("button", { type: "submit", class: "primary", text: "Send report" }),
      h("button", { type: "button", class: "quiet", text: "This site is harmful", onclick: () => send(async () => { await post("/api/vote", { url: r.url, vote: "confirm" }); return "Vote recorded."; }) }),
      h("button", { type: "button", class: "quiet", text: "This site is safe", onclick: () => send(async () => { await post("/api/vote", { url: r.url, vote: "dispute" }); return "Vote recorded."; }) })),
    status);
  return h("div", {}, facts, h("h3", { text: "Tell others what you saw" }), reportForm);
}

function coveragePanel(r) {
  return h("div", {},
    h("p", { class: "sub", text: "Which checks ran for this scan, and which could not." }),
    h("ul", { class: "cov" }, r.coverage.map((c) => h("li", {},
      h("span", { text: ENGINE_NAME[c.engine] || c.engine }),
      h("span", { class: c.status === "ok" ? "st-pass" : c.status === "failed" || c.status === "blocked" ? "st-fail" : "st-info", text: { ok: "Ran", failed: "Failed", blocked: "Blocked", skipped: "Skipped", partial: "Partial" }[c.status] || c.status }),
      h("span", { class: "note", text: c.note || "" })))),
    r.notes.length ? h("ul", { class: "notes" }, r.notes.map((n) => h("li", { text: n }))) : null,
    h("p", { class: "fine", text: `Scanned ${new Date(r.scanned_at).toLocaleString()} in ${(r.duration_ms / 1000).toFixed(1)} s.` }));
}

/* ---------- tabs ---------- */
let tabButtons = [];
function selectTab(id, focusPanel) {
  tabButtons.forEach((b) => {
    const on = b.dataset.tab === id;
    b.setAttribute("aria-selected", on ? "true" : "false");
    b.tabIndex = on ? 0 : -1;
    $("#panel-" + b.dataset.tab).hidden = !on;
  });
  if (focusPanel) { const p = $("#panel-" + id); p.scrollIntoView({ block: "start" }); p.focus({ preventScroll: true }); }
}
function tabs(r) {
  const defs = [["summary", "Summary", summaryPanel], ["certificate", "Certificate", certPanel], ["page", "Page", pagePanel],
    ["headers", "Headers", headersPanel], ["community", "Community", communityPanel], ["coverage", "Coverage", coveragePanel]];
  const list = h("div", { role: "tablist", "aria-label": "Scan details" });
  const wrap = h("div", { class: "tabs" }, list);
  tabButtons = defs.map(([id, label]) => {
    const b = h("button", { role: "tab", type: "button", id: "tab-" + id, "data-tab": id, "aria-controls": "panel-" + id, text: label,
      onclick: () => selectTab(id), onkeydown: (e) => {
        const i = tabButtons.indexOf(b);
        const next = e.key === "ArrowRight" ? i + 1 : e.key === "ArrowLeft" ? i - 1 : e.key === "Home" ? 0 : e.key === "End" ? tabButtons.length - 1 : null;
        if (next === null) return;
        e.preventDefault();
        const t = tabButtons[(next + tabButtons.length) % tabButtons.length];
        selectTab(t.dataset.tab); t.focus();
      } });
    list.append(b);
    return b;
  });
  defs.forEach(([id, , render]) => wrap.append(h("div", { role: "tabpanel", id: "panel-" + id, "aria-labelledby": "tab-" + id, tabindex: "0", hidden: true }, render(r))));
  queueMicrotask(() => selectTab("summary"));
  return wrap;
}

function downloadJson() {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
  const a = h("a", { href: URL.createObjectURL(blob), download: `threatlens-${lastResult.host || "scan"}.json` });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

function render(r) {
  lastResult = r;
  resultEl.replaceChildren(h("div", { class: "result-inner" },
    h("div", { class: r.demo ? "demo-notice" : "scan-meta", role: "status", text: r.demo
      ? "Demonstration · Synthetic example, not a live scan. No requests were sent to this domain."
      : `Live inspection · ${new Date(r.scanned_at).toLocaleString()} · ${(r.duration_ms / 1000).toFixed(1)} s` }),
    specimen(r), verdictBlock(r), tabs(r)));
  resultEl.hidden = false;
  resultEl.scrollIntoView({ block: "start", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
  resultEl.focus({ preventScroll: true });
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  showError("");
  if (!url) { showError("Enter a link to check.", true); urlInput.focus(); return; }
  const deep = $("#deep").checked, authorized = $("#authorized").checked;
  if (deep && !authorized) { showError("Confirm that you own this site or have permission before running the exposed-file check."); return; }
  setBusy(true);
  try {
    render(await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, deep, authorized }) }));
  } catch (err) {
    showError(err.message, err.status === 400);
  } finally {
    setBusy(false);
  }
});

const preset = new URLSearchParams(location.search).get("url");
if (preset) { urlInput.value = preset; form.requestSubmit(); }

/* ---------- demonstration scenario presets ---------- */
const presetsContainer = $("#presets-container");
if (presetsContainer) {
  presetsContainer.addEventListener("click", async (e) => {
    const chip = e.target.closest(".chip");
    if (!chip) return;
    const scenario = chip.dataset.scenario;
    if (!scenario) return;
    showError("");
    setBusy(true);
    try {
      const data = await api("/api/demo/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario })
      });
      urlInput.value = data.url || "";
      render(data);
    } catch (err) {
      showError(err.message);
    } finally {
      setBusy(false);
    }
  });
}

/* ---------- collaborative threat intelligence feed explorer ---------- */
let allFeedEntries = [];
let currentFeedCategory = "all";

async function loadThreatFeed() {
  const container = $("#feed-table-container");
  if (!container) return;
  try {
    const res = await api("/api/feed?limit=500");
    allFeedEntries = res.entries || [];
    renderFeedTable();
  } catch (err) {
    container.replaceChildren(h("p", { class: "empty", text: "Could not load feed: " + err.message }));
  }
}

function renderFeedTable() {
  const container = $("#feed-table-container");
  if (!container) return;
  const q = ($("#feed-search") ? $("#feed-search").value.trim().toLowerCase() : "");
  const filtered = allFeedEntries.filter((entry) => {
    const matchCat = currentFeedCategory === "all" || entry.category === currentFeedCategory;
    const matchQ = !q || entry.host.toLowerCase().includes(q) || (entry.category && entry.category.toLowerCase().includes(q));
    return matchCat && matchQ;
  });

  if (!filtered.length) {
    container.replaceChildren(h("div", { class: "empty-state" },
      h("h3", { text: allFeedEntries.length ? "No matching indicators" : "No corroborated reports yet" }),
      h("p", { text: allFeedEntries.length ? "Try another category or domain search." : "Indicators appear after at least three independent reporters corroborate a host. Scan a real link and open Community to submit a report. Demonstrations do not populate this feed." })));
    return;
  }

  const table = h("table", {},
    h("thead", {}, h("tr", {}, [
      h("th", { scope: "col", text: "Target Host / Domain" }),
      h("th", { scope: "col", text: "Threat Category" }),
      h("th", { scope: "col", text: "Reputation Score" }),
      h("th", { scope: "col", text: "Independent Reporters" }),
      h("th", { scope: "col", text: "Action" })
    ])),
    h("tbody", {}, filtered.map((item) => {
      return h("tr", {},
        h("td", { class: "mono", text: item.host }),
        h("td", { text: CATEGORY_LABEL[item.category] || item.category }),
        h("td", { class: "st-fail", text: String(item.score) }),
        h("td", { text: String(item.reporters) }),
        h("td", {}, h("button", {
          type: "button",
          class: "quiet",
          text: "Scan Now",
          onclick: () => {
            urlInput.value = "https://" + item.host;
            form.requestSubmit();
            window.scrollTo({ top: 0, behavior: "smooth" });
          }
        }))
      );
    }))
  );
  container.replaceChildren(table);
}

const feedSearchInput = $("#feed-search");
if (feedSearchInput) {
  feedSearchInput.addEventListener("input", () => renderFeedTable());
}

const filterBtns = document.querySelectorAll(".filter-btn");
filterBtns.forEach((b) => {
  b.addEventListener("click", () => {
    filterBtns.forEach((x) => x.classList.remove("active"));
    filterBtns.forEach((x) => x.setAttribute("aria-pressed", "false"));
    b.classList.add("active");
    b.setAttribute("aria-pressed", "true");
    currentFeedCategory = b.dataset.cat || "all";
    renderFeedTable();
  });
});

const feedRefreshBtn = $("#feed-refresh-btn");
if (feedRefreshBtn) {
  feedRefreshBtn.addEventListener("click", () => loadThreatFeed());
}

/* ---------- certificate & cryptography lab ---------- */
const labHostBtn = $("#lab-host-btn");
const labPemBtn = $("#lab-pem-btn");
const labHostInput = $("#lab-host-input");
const labPemInput = $("#lab-pem-input");
const labSampleBtn = $("#lab-load-sample-btn");
const labClearBtn = $("#lab-clear-btn");
const labResult = $("#lab-result");

async function auditCert(payload) {
  if (!labResult) return;
  labResult.hidden = false;
  labResult.replaceChildren(h("p", { class: "empty", text: "Running cryptographic and trust chain audit..." }));
  [labHostBtn, labPemBtn, labSampleBtn, labClearBtn].forEach((b) => { b.disabled = true; });
  labResult.setAttribute("aria-busy", "true");
  try {
    const res = await api("/api/cert/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    renderLabResult(res);
  } catch (err) {
    labResult.replaceChildren(h("p", { class: "error", text: "Audit failed: " + err.message }));
  } finally {
    [labHostBtn, labPemBtn, labSampleBtn, labClearBtn].forEach((b) => { b.disabled = false; });
    labResult.setAttribute("aria-busy", "false");
  }
}

function renderLabResult(res) {
  const c = res.certificate;
  if (!c) throw new Error("No certificate was returned for this address.");
  const findings = res.findings || [];
  const certFindings = findings.filter((f) => f.engine === "certificate");

  const isIncident = certFindings.some((f) => f.id === "cert.issuer_watch" || f.id.includes("issuer_watch") || f.id === "cert.blocked_key");
  const banner = isIncident ? h("div", { class: "incident-banner" },
    h("h3", { text: "⚠️ Intermediate Certificate Authority Flagged Under Distrust Review" }),
    h("p", { text: "A CA watchlist or blocked-key rule matched this chain. Review the finding: an issuer-name match alone does not prove a compromised key." })
  ) : null;

  let cryptoStatus = "No tested structural weakness detected; key entropy is not proven.";
  if (certFindings.some((f) => f.id === "cert.close_primes")) cryptoStatus = "CRITICAL: Modulus factors with Fermat's method (close primes p ≈ q)";
  else if (certFindings.some((f) => f.id === "cert.roca_vulnerable")) cryptoStatus = "CRITICAL: Vulnerable to ROCA (CVE-2017-15361 / Infineon flawed library)";
  else if (certFindings.some((f) => f.id === "cert.shared_prime")) cryptoStatus = "CRITICAL: Shares RSA prime with another scanned certificate (Batch GCD)";
  else if (certFindings.some((f) => f.id === "cert.weak_rsa_size")) cryptoStatus = "HIGH: RSA key size under 2048 bits";

  const facts = h("dl", { class: "facts" },
    row("Trust Status", c.trusted ? "Chain Verified" : `Untrusted (${c.trust_error || "Unverified"})`, `trust ${c.trusted ? "yes" : "no"}`),
    row("Subject CN", c.subject_cn || "(none)"),
    row("Issuer", c.issuer || "(unknown)"),
    row("Public Key", c.key),
    row("Cryptographic Health", cryptoStatus, cryptoStatus.includes("CRITICAL") ? "mono st-fail" : cryptoStatus.includes("HIGH") ? "mono st-warn" : "mono st-pass"),
    row("Certificate Transparency", c.transparency ? `${c.transparency.embedded_scts} embedded SCT(s); signatures not verified` : "Not measured"),
    row("Validity Range", `${fmtDate(c.not_before)} to ${fmtDate(c.not_after)} (${c.days_left >= 0 ? c.days_left + " days left" : "expired"})`),
    row("SHA-256 Fingerprint", c.sha256, "mono")
  );

  const chainTable = c.chain && c.chain.length ? h("div", { class: "table-wrap" },
    h("h4", { text: "Certificate Chain (Leaf to Root)" }),
    h("table", {},
      h("thead", {}, h("tr", {}, ["Role", "Subject", "Issuer", "Public Key", "Expires"].map((t) => h("th", { scope: "col", text: t })))),
      h("tbody", {}, c.chain.map((x) => h("tr", {},
        h("td", { text: x.role }),
        h("td", { text: x.subject }),
        h("td", { text: x.issuer }),
        h("td", { text: x.key }),
        h("td", { text: x.not_after })
      )))
    )
  ) : null;

  const findingsList = certFindings.length ? h("div", {},
    h("h4", { text: "Cryptographic Findings & Policy Diagnostics" }),
    h("ul", { class: "findings" }, certFindings.map(findingItem))
  ) : h("p", { class: "empty", text: "No cryptographic or structural key issues found." });

  labResult.replaceChildren(...[
    banner,
    h("h3", { text: `Audit Results: ${c.subject_cn || c.host || "Certificate"}` }),
    facts,
    chainTable,
    findingsList
  ].filter(Boolean));
}

if (labHostBtn && labHostInput) {
  labHostBtn.addEventListener("click", () => {
    const host = labHostInput.value.trim();
    if (!host) { labResult.hidden = false; labResult.replaceChildren(h("p", { class: "error", role: "alert", text: "Enter a host to inspect." })); labHostInput.focus(); return; }
    auditCert({ host });
  });
}

if (labPemBtn && labPemInput) {
  labPemBtn.addEventListener("click", () => {
    const pem = labPemInput.value.trim();
    if (!pem) { labResult.hidden = false; labResult.replaceChildren(h("p", { class: "error", role: "alert", text: "Paste a PEM certificate or load the sample first." })); labPemInput.focus(); return; }
    auditCert({ pem });
  });
}

if (labSampleBtn && labPemInput) {
  labSampleBtn.addEventListener("click", async () => {
    labSampleBtn.disabled = true;
    try {
      const sample = await api("/api/demo/certificate");
      labPemInput.value = sample.pem;
      await auditCert({ pem: sample.pem });
    } catch (err) {
      labResult.hidden = false;
      labResult.replaceChildren(h("p", { class: "error", role: "alert", text: err.message }));
    } finally { labSampleBtn.disabled = false; }
  });
}

if (labClearBtn && labPemInput && labHostInput) {
  labClearBtn.addEventListener("click", () => {
    labPemInput.value = "";
    labHostInput.value = "";
    if (labResult) labResult.hidden = true;
  });
}

// Initialise threat feed
loadThreatFeed();

api("/api/health").then((health) => {
  const indicator = $("#service-status");
  indicator.textContent = "Analysis server online";
  indicator.classList.add("online");
  if (health.storage && !health.storage.durable) {
    $("#storage-notice").hidden = false;
    $("#storage-notice").textContent = health.storage.note;
  }
}).catch(() => { $("#service-status").textContent = "Server unavailable · try again shortly"; });

labHostInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") { event.preventDefault(); if (!labHostBtn.disabled) labHostBtn.click(); }
});
