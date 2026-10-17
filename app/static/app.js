const $app = document.getElementById("app");
const state = { view: "overview", health: null, me: null, mounts: null };

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}

const getToken = () => sessionStorage.getItem("vault_token");

async function api(path, opts = {}) {
  const res = await fetch(`/api${path}`, {
    method: opts.method || "GET",
    headers: {
      "X-Vault-Token": getToken() || "",
      ...(opts.body ? { "Content-Type": "application/json" } : {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const d = (await res.json()).detail;
      msg = typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => x.msg).join("; ") : msg;
    } catch {}
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

const q = (obj) => new URLSearchParams(obj).toString();
const fmtDate = (s) => (s ? new Date(s).toLocaleString() : "never");
const fmtTtl = (sec) => {
  if (!sec) return "no expiry";
  const d = Math.floor(sec / 86400), hr = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return [d && `${d}d`, hr && `${hr}h`, !d && m && `${m}m`].filter(Boolean).join(" ") || `${sec}s`;
};
const errorBox = (e) => h("div", { class: "error" }, e.message);

function copy(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const old = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => (btn.textContent = old), 1200);
  });
}

// ---------- Login ----------
async function renderLogin(error) {
  let health;
  try { health = await api("/health"); } catch { health = { reachable: false, addr: "?" }; }
  const input = h("input", { type: "password", placeholder: "Vault token", autofocus: true, required: true });
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault();
    sessionStorage.setItem("vault_token", input.value);
    try {
      await boot();
    } catch (err) {
      sessionStorage.removeItem("vault_token");
      renderLogin(err.status === 403 || err.status === 401 ? "Invalid or expired token" : err.message);
    }
  } },
    error && h("div", { class: "error" }, error),
    input,
    h("button", { class: "btn primary", type: "submit" }, "Sign in"),
  );
  $app.replaceChildren(h("div", { class: "login" }, h("div", { class: "box" },
    h("div", { class: "brand" }, h("span", { class: "logo" }, "V"), "Vault Dashboard"),
    h("div", { class: "card" }, form),
    h("p", { class: "hint" }, health.reachable
      ? `Connected to ${health.addr}${health.sealed ? " (sealed!)" : ""}`
      : `Cannot reach Vault at ${health.addr}. Set VAULT_ADDR and restart.`),
  )));
}

// ---------- Shell ----------
const NAV = [["overview", "Overview"], ["secrets", "Secrets"], ["policies", "Policies"],
  ["auth", "Auth methods"], ["leases", "Leases"], ["audit", "Audit"]];

function shell(content) {
  const nav = NAV.map(([k, label]) =>
    h("button", { class: `nav-item ${state.view === k ? "active" : ""}`, onclick: () => go(k) }, label));
  return h("div", { class: "layout" },
    h("aside", { class: "sidebar" },
      h("div", { class: "brand" }, h("span", { class: "logo" }, "V"), "Vault"),
      nav,
      h("div", { class: "spacer" }),
      h("div", { class: "conn" }, state.health.addr, h("br"), `v${state.health.version || "?"}`),
      h("button", { class: "nav-item", onclick: logout }, "Sign out"),
    ),
    h("main", {}, content));
}

function go(view) {
  state.view = view;
  render();
}

function logout() {
  sessionStorage.removeItem("vault_token");
  renderLogin();
}

async function render() {
  const holder = h("div", {}, h("p", { class: "empty" }, "Loading…"));
  $app.replaceChildren(shell(holder));
  try {
    const content = await views[state.view]();
    holder.replaceChildren(content);
  } catch (e) {
    if (e.status === 403 && state.view === "overview") return logout();
    holder.replaceChildren(errorBox(e));
  }
}

// ---------- Views ----------
const views = {
  async overview() {
    const { me, health, mounts } = state;
    const ttl = me.ttl;
    const policies = me.policies || [];
    return h("div", {},
      h("h2", {}, "Overview"),
      h("div", { class: "grid" },
        stat("Status", health.sealed ? "Sealed" : "Unsealed", health.sealed ? "bad" : "ok"),
        stat("Version", health.version || "?"),
        stat("Cluster", health.cluster_name || "-"),
        stat("Secret engines", Object.keys(mounts.secret).length),
        stat("Auth methods", Object.keys(mounts.auth).length)),
      h("div", { class: "card" },
        h("h3", {}, "Your token"),
        h("table", {}, h("tbody", {},
          row("Display name", me.display_name),
          row("Policies", h("div", { class: "caps" }, policies.map((p) =>
            h("span", { class: `badge ${p === "root" ? "bad" : ""}` }, p)))),
          row("Expires", ttl ? `in ${fmtTtl(ttl)} (${fmtDate(me.expire_time)})` : "never"),
          row("Renewable", me.renewable ? "yes" : "no"),
        )),
        policies.includes("root") && h("p", { class: "hint" },
          "You are using a root token. Prefer a scoped token for daily use.")));
  },

  async secrets() {
    const kvMounts = Object.entries(state.mounts.secret)
      .filter(([, m]) => m.type === "kv" || m.type === "generic");
    if (!kvMounts.length) return h("div", { class: "card empty" }, "No KV secret engines found.");
    const selected = state.kvMount && kvMounts.find(([k]) => k === state.kvMount) ? state.kvMount : kvMounts[0][0];
    state.kvMount = selected;
    const path = state.kvPath || "";
    const root = h("div", {});
    root.append(h("h2", {}, "Secrets"),
      h("div", { class: "row", style: "margin-bottom:14px" },
        kvMounts.map(([k, m]) => h("button", {
          class: `btn ${k === selected ? "primary" : ""}`,
          onclick: () => { state.kvMount = k; state.kvPath = ""; state.kvSearch = ""; state.kvForm = null; render(); },
        }, `${k} (v${(m.options && m.options.version) || 1})`))),
      secretToolbar(selected, path),
      crumbs(selected, path));
    const isFile = path && !path.endsWith("/");
    if (state.kvForm) root.append(await secretForm(selected, path));
    else if (state.kvSearch) root.append(await secretSearch(selected));
    else if (isFile) root.append(await secretDetail(selected, path));
    else root.append(await secretList(selected, path));
    return root;
  },

  async policies() {
    const { policies } = await api("/policies");
    const selected = state.policy;
    const root = h("div", {}, h("h2", {}, "Policies"));
    const list = h("div", { class: "card" }, h("div", { class: "caps" }, policies.map((p) =>
      h("button", { class: `btn ${p === selected ? "primary" : ""}`,
        onclick: () => { state.policy = p; render(); } }, p))));
    root.append(list);
    if (selected) {
      try {
        const data = await api(`/policies/${encodeURIComponent(selected)}`);
        const risky = data.rules.filter((r) => r.risky).length;
        root.append(h("div", { class: "card" },
          h("div", { class: "row between" }, h("h3", {}, `Rules in "${data.name}"`),
            risky ? h("span", { class: "badge warn" }, `${risky} broad rule${risky > 1 ? "s" : ""}`) : null),
          data.rules.length ? data.rules.map((r) => h("div", { class: "rule" },
            h("code", { class: "p" }, r.path),
            h("div", { class: "caps" }, r.capabilities.map((c) =>
              h("span", { class: `badge ${c === "sudo" ? "bad" : ""}` }, c))),
            r.risky && h("span", { class: "badge warn" }, "broad"))) : h("p", { class: "empty" }, "No path rules."),
        ), h("div", { class: "card" }, h("h3", {}, "HCL"), h("pre", {}, data.policy)));
      } catch (e) { root.append(errorBox(e)); }
    }
    return root;
  },

  async auth() {
    const entries = Object.entries(state.mounts.auth);
    return h("div", {}, h("h2", {}, "Auth methods"),
      h("div", { class: "card" }, entries.length ? h("table", {},
        h("thead", {}, h("tr", {}, ["Path", "Type", "Description"].map((c) => h("th", {}, c)))),
        h("tbody", {}, entries.map(([path, m]) => h("tr", {},
          h("td", {}, h("code", {}, path)), h("td", {}, m.type), h("td", {}, m.description || "")))))
        : h("p", { class: "empty" }, "No auth methods visible to this token.")));
  },

  async leases() {
    const prefix = state.leasePrefix || "";
    const { keys } = await api(`/leases?${q({ prefix })}`);
    const parts = prefix.split("/").filter(Boolean);
    const crumb = h("div", { class: "crumbs" },
      h("a", { onclick: () => { state.leasePrefix = ""; render(); } }, "leases"),
      parts.map((p, i) => [" / ", h("a", { onclick: () => {
        state.leasePrefix = parts.slice(0, i + 1).join("/") + "/"; render(); } }, p)]));
    const root = h("div", {}, h("h2", {}, "Leases"), crumb);
    if (state.leaseInfo) root.append(h("div", { class: "card" },
      h("div", { class: "row between" }, h("h3", {}, "Lease"),
        h("button", { class: "btn", onclick: () => { state.leaseInfo = null; render(); } }, "Close")),
      h("table", {}, h("tbody", {},
        row("ID", h("code", {}, state.leaseInfo.id)),
        row("Issued", fmtDate(state.leaseInfo.issue_time)),
        row("Expires", fmtDate(state.leaseInfo.expire_time)),
        row("TTL", fmtTtl(state.leaseInfo.ttl)),
        row("Renewable", state.leaseInfo.renewable ? "yes" : "no")))));
    root.append(h("div", { class: "card" }, keys.length ? h("table", {}, h("tbody", {}, keys.map((k) =>
      h("tr", { class: "click", onclick: async () => {
        if (k.endsWith("/")) { state.leasePrefix = prefix + k; render(); return; }
        try { state.leaseInfo = await api(`/leases/info?${q({ lease_id: prefix + k })}`); } catch (e) { alert(e.message); return; }
        render();
      } }, h("td", {}, k.endsWith("/") ? "📁 " : "🔑 ", h("code", {}, k)))))) :
      h("p", { class: "empty" }, "No leases at this level.")));
    return root;
  },
  async audit() {
    const days = state.staleDays || 90;
    const r = await api(`/audit?${q({ stale_days: days })}`);
    const counts = { high: 0, medium: 0, low: 0 };
    r.findings.forEach((f) => counts[f.severity]++);
    const tone = { high: "bad", medium: "warn", low: "" };
    const select = h("select", { onchange: (e) => { state.staleDays = Number(e.target.value); render(); } },
      [30, 90, 180, 365].map((d) => h("option", { value: d, selected: d === days }, `${d} days`)));
    return h("div", {},
      h("div", { class: "row between" }, h("h2", {}, "Audit"),
        h("label", { class: "row", style: "color:var(--muted)" }, "Stale after", select)),
      h("div", { class: "grid" },
        stat("High", counts.high, counts.high ? "bad" : "ok"),
        stat("Medium", counts.medium, counts.medium ? "warn" : "ok"),
        stat("Low", counts.low),
        stat("Checked", `${r.stats.policies} policies · ${r.stats.tokens} tokens · ${r.stats.secrets} secrets`)),
      r.notes.map((n) => h("div", { class: "card", style: "color:var(--muted)" }, "ℹ ", n)),
      h("div", { class: "card" }, r.findings.length ? h("table", {},
        h("thead", {}, h("tr", {}, ["Severity", "Area", "Finding", "Details"].map((c) => h("th", {}, c)))),
        h("tbody", {}, r.findings.map((f) => h("tr", {},
          h("td", {}, h("span", { class: `badge ${tone[f.severity]}` }, f.severity)),
          h("td", {}, f.category), h("td", {}, h("strong", {}, f.title)),
          h("td", { style: "color:var(--muted)" }, f.detail)))))
        : h("p", { class: "empty" }, "No issues found. 🎉")));
  },
};

function stat(label, value, tone) {
  return h("div", { class: "stat" }, h("small", {}, label),
    h("strong", { class: tone ? `badge ${tone}` : "" , style: tone ? "font-size:16px" : "" }, value));
}
function row(label, value) {
  return h("tr", {}, h("td", { style: "width:160px;color:var(--muted)" }, label), h("td", {}, value));
}

function crumbs(mount, path) {
  const parts = path.split("/").filter(Boolean);
  return h("div", { class: "crumbs" },
    h("a", { onclick: () => { state.kvPath = ""; state.kvForm = null; state.kvSearch = ""; render(); } }, mount),
    parts.map((p, i) => {
      const last = i === parts.length - 1 && !path.endsWith("/");
      const target = parts.slice(0, i + 1).join("/") + (last ? "" : "/");
      return [" / ", h("a", { onclick: () => { state.kvPath = target; state.kvForm = null; state.kvSearch = ""; render(); } }, p)];
    }));
}

async function secretList(mount, path) {
  const { keys } = await api(`/kv/list?${q({ mount, path })}`);
  if (!keys.length) return h("div", { class: "card empty" }, "Nothing here.");
  return h("div", { class: "card" }, h("table", {}, h("tbody", {}, keys.map((k) =>
    h("tr", { class: "click", onclick: () => { state.kvPath = path + k; render(); } },
      h("td", {}, k.endsWith("/") ? "📁 " : "🔑 ", h("code", {}, k)))))));
}

function dirOf(path) {
  const i = path.lastIndexOf("/");
  return i === -1 ? "" : path.slice(0, i + 1);
}

function secretToolbar(mount, path) {
  const input = h("input", { placeholder: "Search paths in this mount…", value: state.kvSearch || "" });
  const form = h("form", { class: "row", style: "flex:1", onsubmit: (e) => {
    e.preventDefault();
    state.kvSearch = input.value.trim();
    state.kvForm = null;
    render();
  } }, input, h("button", { class: "btn", type: "submit" }, "Search"),
    state.kvSearch && h("button", { class: "btn", type: "button",
      onclick: () => { state.kvSearch = ""; render(); } }, "Clear"));
  const newBtn = !state.health.readonly && h("button", { class: "btn primary", onclick: () => {
    state.kvSearch = "";
    state.kvForm = { mode: "new", dir: dirOf(path), data: {} };
    render();
  } }, "+ New secret");
  return h("div", { class: "row", style: "margin-bottom:14px" }, form, newBtn);
}

async function secretSearch(mount) {
  const r = await api(`/kv/search?${q({ mount, q: state.kvSearch })}`);
  return h("div", { class: "card" },
    h("h3", {}, `${r.results.length} match${r.results.length === 1 ? "" : "es"} for "${state.kvSearch}"`),
    r.truncated && h("p", { class: "hint" }, `Only the first ${r.scanned} secrets were scanned.`),
    r.results.length ? h("table", {}, h("tbody", {}, r.results.map((p) =>
      h("tr", { class: "click", onclick: () => { state.kvSearch = ""; state.kvPath = p; render(); } },
        h("td", {}, "🔑 ", h("code", {}, p))))))
      : h("p", { class: "empty" }, "No matching secrets."));
}

async function secretForm(mount, path) {
  const f = state.kvForm;
  const isNew = f.mode === "new";
  const originals = f.data;
  const pathInput = h("input", { value: isNew ? f.dir : path, placeholder: "folder/secret-name",
    disabled: isNew ? null : "disabled" });
  const rowsEl = h("div", { style: "display:flex;flex-direction:column;gap:8px;width:100%" });
  const addRow = (k = "", v = "") => {
    const text = typeof v === "string" ? v : JSON.stringify(v);
    const kInput = h("input", { placeholder: "key", value: k, class: "mono" });
    const vInput = h("input", { placeholder: "value", value: text, class: "mono" });
    const row = h("div", { class: "row" }, kInput, vInput,
      h("button", { class: "btn", type: "button", onclick: () => row.remove() }, "✕"));
    row.getKV = () => [kInput.value.trim(), vInput.value, k];
    rowsEl.append(row);
  };
  Object.entries(originals).forEach(([k, v]) => addRow(k, v));
  if (!Object.keys(originals).length) addRow();
  const errBox = h("div", {});

  const save = async (e) => {
    e.preventDefault();
    errBox.replaceChildren();
    const data = {};
    try {
      for (const row of rowsEl.children) {
        const [k, v, origKey] = row.getKV();
        if (!k) continue;
        if (k in data) throw new Error(`Duplicate key "${k}"`);
        // Keep non-string values (numbers, objects) typed as they were.
        data[k] = origKey && typeof originals[origKey] !== "string" && originals[origKey] !== undefined
          ? JSON.parse(v) : v;
      }
      const target = pathInput.value.trim();
      await api("/kv/write", { method: "POST", body: { mount, path: target, data } });
      state.kvForm = null;
      state.kvPath = target;
      render();
    } catch (err) {
      errBox.replaceChildren(errorBox(err));
    }
  };

  return h("form", { class: "card", style: "display:block", onsubmit: save },
    h("h3", {}, isNew ? "New secret" : "Edit secret (saves a new version)"),
    errBox,
    h("label", { style: "display:block;margin-bottom:12px;color:var(--muted)" }, "Path", pathInput),
    rowsEl,
    h("div", { class: "row", style: "margin-top:14px" },
      h("button", { class: "btn", type: "button", onclick: () => addRow() }, "+ Add key"),
      h("div", { style: "flex:1" }),
      h("button", { class: "btn", type: "button", onclick: () => { state.kvForm = null; render(); } }, "Cancel"),
      h("button", { class: "btn primary", type: "submit" }, "Save")));
}

async function secretDetail(mount, path) {
  const s = await api(`/kv/read?${q({ mount, path })}`);
  const entries = Object.entries(s.data || {});
  const wrap = h("div", {});
  if (!state.health.readonly) {
    const v2 = s.kv_version === 2;
    wrap.append(h("div", { class: "row", style: "margin-bottom:14px" },
      h("button", { class: "btn", onclick: () => { state.kvForm = { mode: "edit", data: s.data || {} }; render(); } }, "Edit"),
      h("button", { class: "btn", style: "color:var(--bad)", onclick: async () => {
        const msg = v2 ? `Delete the latest version of "${path}"? It can be undeleted in Vault.`
          : `Permanently delete "${path}"? This cannot be undone.`;
        if (!confirm(msg)) return;
        try {
          await api(`/kv/delete?${q({ mount, path })}`, { method: "DELETE" });
          state.kvPath = dirOf(path);
          render();
        } catch (e) { alert(e.message); }
      } }, "Delete")));
  }
  wrap.append(h("div", { class: "card" }, h("h3", {}, "Data"),
    entries.length ? h("table", {}, h("tbody", {}, entries.map(([k, v]) => {
      const text = typeof v === "string" ? v : JSON.stringify(v);
      const mask = h("span", { class: "mono mask" }, "••••••••");
      const val = h("span", { class: "mono", style: "display:none;word-break:break-all" }, text);
      const toggle = h("button", { class: "btn", onclick: () => {
        const hidden = val.style.display === "none";
        val.style.display = hidden ? "" : "none";
        mask.style.display = hidden ? "none" : "";
        toggle.textContent = hidden ? "Hide" : "Reveal";
      } }, "Reveal");
      const cp = h("button", { class: "btn", onclick: () => copy(text, cp) }, "Copy");
      return h("tr", {}, h("td", { class: "mono", style: "width:220px" }, k),
        h("td", {}, h("div", { class: "secret-val" }, mask, val)),
        h("td", { style: "width:150px;text-align:right" }, toggle, " ", cp));
    }))) : h("p", { class: "empty" }, "Empty secret.")));
  if (s.versions && s.versions.length) wrap.append(h("div", { class: "card" }, h("h3", {}, "Versions"),
    h("table", {}, h("tbody", {}, s.versions.map((v) => h("tr", {},
      h("td", {}, `v${v.version}`), h("td", {}, fmtDate(v.created_time)),
      h("td", {}, v.destroyed ? h("span", { class: "badge bad" }, "destroyed")
        : v.deleted ? h("span", { class: "badge warn" }, "deleted")
        : v.version === (s.metadata && s.metadata.version) ? h("span", { class: "badge ok" }, "current") : "")))))));
  return wrap;
}

// ---------- Boot ----------
async function boot() {
  state.health = await api("/health");
  state.me = await api("/me");
  state.mounts = await api("/mounts");
  render();
}

if (getToken()) boot().catch(() => renderLogin("Session expired, sign in again"));
else renderLogin();
