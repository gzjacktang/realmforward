function detectBase() {
  if (typeof window.XFP_BASE === "string") {
    return window.XFP_BASE.replace(/\/$/, "") || "";
  }
  let p = location.pathname || "/";
  p = p.replace(/\/index\.html$/i, "").replace(/\/$/, "");
  if (!p || p === "/") return "";
  return p;
}
const BASE = detectBase();
const API = BASE + "/api";

function panelURL(basePath) {
  let b = (basePath || "/").trim() || "/";
  if (!b.startsWith("/")) b = "/" + b;
  b = b.replace(/\/+$/, "");
  if (!b) b = "";
  return location.origin + (b || "") + "/";
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(window.__tt);
  window.__tt = setTimeout(() => t.classList.remove("show"), 2200);
}

function showApp(on) {
  document.getElementById("view-login").classList.toggle("active", !on);
  document.getElementById("view-app").classList.toggle("active", on);
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = document.getElementById("login-err");
  err.textContent = "";
  try {
    await api("/login", {
      method: "POST",
      body: JSON.stringify({
        username: document.getElementById("login-user").value,
        password: document.getElementById("login-pass").value,
      }),
    });
    showApp(true);
    goPage("dash");
  } catch (ex) {
    err.textContent = ex.message;
  }
});

document.getElementById("btn-logout").onclick = async () => {
  try { await api("/logout", { method: "POST" }); } catch (_) {}
  showApp(false);
};

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => goPage(btn.dataset.page, btn));
});

function goPage(id, el) {
  document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
  document.getElementById("page-" + id).classList.add("active");
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));
  (el || document.querySelector(`.nav-item[data-page="${id}"]`))?.classList.add("active");
  loadPage(id);
}

async function loadPage(id) {
  const el = document.getElementById("page-" + id);
  el.innerHTML = `<p class="empty">加载中…</p>`;
  try {
    if (id === "dash") await renderDash(el);
    if (id === "fwd") await renderFwd(el);
    if (id === "ports") await renderPorts(el);
    if (id === "tg") await renderTG(el);
    if (id === "logs") await renderLogs(el);
    if (id === "settings") await renderSettings(el);
  } catch (ex) {
    if (String(ex.message).includes("unauthorized")) {
      showApp(false);
      return;
    }
    el.innerHTML = `<p class="empty">${ex.message}</p>`;
  }
}

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}

async function renderDash(el) {
  const [st, fwds] = await Promise.all([api("/status"), api("/forwards")]);
  document.getElementById("nav-ver").textContent = "v" + (st.panel_version || "0.2.2");
  const list = Array.isArray(fwds) ? fwds : [];
  const enabled = list.filter((r) => r.enabled).length;
  el.innerHTML = `
    <div class="page-head"><div><h2>仪表盘</h2><p class="sub">主机状态、XDP 模式与流量概览</p></div>
      <button class="btn btn-ghost btn-sm" onclick="goPage('dash')">刷新</button></div>
    <div class="banner warn"><strong>⚠</strong><div>${st.warning || ""}</div></div>
    <div class="grid grid-4" style="margin-bottom:16px">
      <div class="stat"><div class="label">XDP 模式</div><div class="value" style="color:var(--accent)">${st.xdp?.mode || (st.xdp?.loaded ? "on" : "off")}</div>
        <div class="meta">${st.xdp?.iface || "-"} · ${st.xdp?.loaded ? "已加载" : (st.xdp?.error || "未加载")}</div></div>
      <div class="stat"><div class="label">转发规则</div><div class="value">${list.length}</div><div class="meta">${enabled} 启用</div></div>
      <div class="stat"><div class="label">防火墙</div><div class="value" style="font-size:1.1rem">${st.firewall}</div><div class="meta">监听 ${st.listen}</div></div>
      <div class="stat"><div class="label">SNAT 保留</div><div class="value" style="font-size:1.1rem">${st.snat}</div><div class="meta">不打开防火墙</div></div>
    </div>
    <div class="panel"><div class="panel-h"><h3>转发规则</h3></div>
      <table><thead><tr><th>规则</th><th>协议</th><th>包</th><th>字节</th></tr></thead>
      <tbody>${list.map((r) => `<tr>
        <td class="mono">:${r.local_port} → ${r.dest_ip}:${r.dest_port}</td>
        <td><span class="tag tag-ok">${r.proto}</span></td>
        <td class="mono">${r.packets || 0}</td>
        <td class="mono">${fmtBytes(r.bytes || 0)}</td></tr>`).join("") || `<tr><td colspan="4" class="empty">暂无规则</td></tr>`}
      </tbody></table></div>`;
}

function protoLabel(p) {
  if (p === "both") return "tcp+udp";
  return p;
}

async function renderFwd(el) {
  const raw = await api("/forwards");
  const rules = Array.isArray(raw) ? raw : [];
  el.innerHTML = `
    <div class="page-head"><div><h2>转发规则</h2><p class="sub">XDP DNAT+SNAT · IPv4 · 支持 tcp / udp / tcp+udp</p></div>
      <button class="btn btn-primary" id="btn-add-fwd">＋ 添加规则</button></div>
    <div class="banner info"><strong>ℹ</strong><div>添加/修改后自动放行对应防火墙端口。XDP 在 netfilter 前执行。</div></div>
    <div class="panel"><table>
      <thead><tr><th>ID</th><th>本地</th><th>目标</th><th>协议</th><th>状态</th><th>统计</th><th></th></tr></thead>
      <tbody>${rules.map((r) => `<tr>
        <td class="mono">#${r.id}</td><td class="mono">${r.local_port}</td>
        <td class="mono">${r.dest_ip}:${r.dest_port}</td>
        <td><span class="tag tag-info">${protoLabel(r.proto)}</span></td>
        <td><span class="tag ${r.enabled ? "tag-ok" : "tag-off"}">${r.enabled ? "enabled" : "disabled"}</span></td>
        <td class="mono">${r.packets || 0} / ${fmtBytes(r.bytes || 0)}</td>
        <td>
          <button class="btn btn-ghost btn-sm" data-edit="${r.id}"
            data-lport="${r.local_port}" data-dip="${r.dest_ip}" data-dport="${r.dest_port}" data-proto="${r.proto}">编辑</button>
          <button class="btn btn-ghost btn-sm" data-toggle="${r.id}" data-en="${r.enabled ? 0 : 1}">${r.enabled ? "停用" : "启用"}</button>
          <button class="btn btn-ghost btn-sm" data-del="${r.id}">删除</button>
        </td></tr>`).join("") || `<tr><td colspan="7" class="empty">暂无</td></tr>`}
      </tbody></table></div>
    <div id="fwd-form" class="panel" style="margin-top:14px;display:none">
      <div class="panel-h"><h3 id="fwd-form-title">添加规则</h3></div>
      <input type="hidden" id="f-id" value="" />
      <div class="form-box form-row">
        <div class="field"><label>本地端口</label><input id="f-lport" class="mono" /></div>
        <div class="field"><label>协议</label>
          <select id="f-proto">
            <option value="both">tcp+udp</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
          </select></div>
        <div class="field"><label>目标 IP</label><input id="f-dip" class="mono" /></div>
        <div class="field"><label>目标端口</label><input id="f-dport" class="mono" /></div>
      </div>
      <div class="form-box" style="padding-top:0">
        <button class="btn btn-primary" id="f-save">保存</button>
        <button class="btn btn-ghost" id="f-cancel">取消</button>
      </div>
    </div>`;

  const showForm = (rule) => {
    document.getElementById("fwd-form").style.display = "block";
    document.getElementById("fwd-form-title").textContent = rule ? "编辑规则 #" + rule.id : "添加规则";
    document.getElementById("f-id").value = rule ? rule.id : "";
    document.getElementById("f-lport").value = rule ? rule.local_port : "";
    document.getElementById("f-dip").value = rule ? rule.dest_ip : "";
    document.getElementById("f-dport").value = rule ? rule.dest_port : "";
    document.getElementById("f-proto").value = rule ? (rule.proto === "both" ? "both" : rule.proto) : "both";
  };

  document.getElementById("btn-add-fwd").onclick = () => showForm(null);
  document.getElementById("f-cancel").onclick = () => {
    document.getElementById("fwd-form").style.display = "none";
  };
  document.getElementById("f-save").onclick = async () => {
    const id = document.getElementById("f-id").value;
    const body = {
      local_port: +document.getElementById("f-lport").value,
      dest_ip: document.getElementById("f-dip").value,
      dest_port: +document.getElementById("f-dport").value,
      proto: document.getElementById("f-proto").value,
    };
    try {
      if (id) {
        await api("/forwards/" + id, { method: "PUT", body: JSON.stringify(body) });
        toast("已更新 #" + id);
      } else {
        await api("/forwards", { method: "POST", body: JSON.stringify(body) });
        toast("已添加");
      }
      goPage("fwd");
    } catch (ex) {
      toast("保存失败: " + ex.message);
    }
  };
  el.querySelectorAll("[data-edit]").forEach((b) => {
    b.onclick = () => showForm({
      id: +b.dataset.edit,
      local_port: +b.dataset.lport,
      dest_ip: b.dataset.dip,
      dest_port: +b.dataset.dport,
      proto: b.dataset.proto,
    });
  });
  el.querySelectorAll("[data-del]").forEach((b) => {
    b.onclick = async () => {
      if (!confirm("删除转发 #" + b.dataset.del + "？")) return;
      try {
        await api("/forwards/" + b.dataset.del, { method: "DELETE" });
        toast("已删除");
        goPage("fwd");
      } catch (ex) { toast(ex.message); }
    };
  });
  el.querySelectorAll("[data-toggle]").forEach((b) => {
    b.onclick = async () => {
      await api("/forwards/" + b.dataset.toggle + "/enable", {
        method: "POST",
        body: JSON.stringify({ enabled: b.dataset.en === "1" }),
      });
      goPage("fwd");
    };
  });
}

async function renderPorts(el, page) {
  const data = await api("/ports");
  const all = Array.isArray(data.ports) ? data.ports : [];
  const pageSize = data.page_size || 20;
  const total = all.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  let cur = Math.max(1, Math.min(pages, page || window.__portsPage || 1));
  window.__portsPage = cur;
  const slice = all.slice((cur - 1) * pageSize, cur * pageSize);

  const fwActive = !!data.fw_active;
  el.innerHTML = `
    <div class="page-head"><div><h2>防火墙端口</h2>
      <p class="sub">三层状态 · 后端 ${data.backend}${fwActive ? " · 已启用默认拒绝" : " · 未加固"} · 共 ${total} 条 · 每页 ${pageSize}</p></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-ghost" id="btn-harden-fw">一键开启防火墙</button>
        <button class="btn btn-primary" id="btn-open-port">打开端口</button>
      </div></div>
    <div class="banner warn"><strong>⚠</strong><div>「一键开启防火墙」会启用默认拒绝入站，仅保留 SSH（${data.ssh_port}）、面板、本机监听与 XDP 转发端口；其余已放行端口会关闭。关闭受保护端口需二次确认。</div></div>
    <div class="panel"><table>
      <thead><tr><th>端口</th><th>协议</th><th>防火墙</th><th>监听</th><th>XDP</th><th></th></tr></thead>
      <tbody>${slice.map((p) => `<tr>
        <td class="mono">${p.port}${p.protected ? ' <span class="tag tag-warn">保护</span>' : ""}</td>
        <td><span class="tag tag-info">${protoLabel(p.proto)}</span></td>
        <td><span class="tag ${p.firewall === "open" ? "tag-ok" : (p.firewall === "partial" ? "tag-warn" : "tag-off")}">${p.firewall}</span></td>
        <td>${p.listening}</td>
        <td><span class="tag ${p.xdp !== "—" ? "tag-xdp" : "tag-off"}">${p.xdp}</span></td>
        <td style="white-space:nowrap">
          <button class="btn btn-ghost btn-sm" data-edit-port="${p.port}" data-proto="${p.proto}"
            data-fw="${p.firewall}" data-prot="${p.protected ? 1 : 0}" data-xdp="${p.xdp || ""}">修改</button>
          ${(p.firewall === "open" || p.firewall === "partial")
          ? `<button class="btn btn-ghost btn-sm" data-close="${p.port}" data-proto="${p.proto}" data-prot="${p.protected ? 1 : 0}">关闭</button>`
          : `<button class="btn btn-ghost btn-sm" data-open="${p.port}" data-proto="${p.proto}">打开</button>`}
        </td></tr>`).join("") || `<tr><td colspan="6" class="empty">暂无端口</td></tr>`}
      </tbody></table>
      <div class="form-box" style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap">
        <span class="hint" style="margin:0">第 ${cur} / ${pages} 页</span>
        <div style="display:flex;gap:8px">
          <button class="btn btn-ghost btn-sm" id="ports-prev" ${cur <= 1 ? "disabled" : ""}>上一页</button>
          <button class="btn btn-ghost btn-sm" id="ports-next" ${cur >= pages ? "disabled" : ""}>下一页</button>
        </div>
      </div>
    </div>`;

  document.getElementById("ports-prev").onclick = () => renderPorts(el, cur - 1);
  document.getElementById("ports-next").onclick = () => renderPorts(el, cur + 1);

  document.getElementById("btn-harden-fw").onclick = async () => {
    if (!confirm("将开启防火墙（默认拒绝入站），并关闭所有无业务监听 / 无 XDP 转发的已放行端口。\n\n会保留：SSH、面板、本机监听、已启用转发端口。\n确认继续？")) {
      return;
    }
    try {
      const res = await api("/ports/harden", { method: "POST", body: "{}" });
      const closedN = (res.closed || []).length;
      const keptN = (res.kept || []).length;
      toast(`防火墙已开启（${res.backend}）：保留 ${keptN} · 关闭 ${closedN}`);
      window.__portsPage = 1;
      renderPorts(el, 1);
    } catch (ex) {
      toast("开启失败: " + ex.message);
    }
  };

  document.getElementById("btn-open-port").onclick = async () => {
    const port = prompt("端口号");
    if (!port) return;
    const proto = prompt("协议: tcp / udp / both", "both") || "both";
    try {
      await api("/ports/open", { method: "POST", body: JSON.stringify({ port: +port, proto }) });
      toast("防火墙已放行 " + port + "/" + protoLabel(proto));
      window.__portsPage = 1;
      renderPorts(el, 1);
    } catch (ex) {
      toast("打开失败: " + ex.message);
    }
  };
  el.querySelectorAll("[data-close]").forEach((b) => {
    b.onclick = async () => {
      let confirmFlag = true;
      if (b.dataset.prot === "1") {
        confirmFlag = confirm("这是受保护端口，确认关闭？");
        if (!confirmFlag) return;
      }
      await api("/ports/close", {
        method: "POST",
        body: JSON.stringify({ port: +b.dataset.close, proto: b.dataset.proto, confirm: !!confirmFlag }),
      });
      toast("已关闭（无业务端口已移出列表）");
      renderPorts(el, window.__portsPage || 1);
    };
  });
  el.querySelectorAll("[data-open]").forEach((b) => {
    b.onclick = async () => {
      await api("/ports/open", {
        method: "POST",
        body: JSON.stringify({ port: +b.dataset.open, proto: b.dataset.proto }),
      });
      renderPorts(el, window.__portsPage || 1);
    };
  });
  el.querySelectorAll("[data-edit-port]").forEach((b) => {
    b.onclick = async () => {
      const oldPort = +b.dataset.editPort;
      const oldProto = b.dataset.proto || "tcp";
      const wasOpen = b.dataset.fw === "open" || b.dataset.fw === "partial";
      const portStr = prompt("端口号", String(oldPort));
      if (portStr === null) return;
      const newPort = +portStr;
      if (!newPort || newPort < 1 || newPort > 65535) {
        toast("端口无效");
        return;
      }
      const newProto = (prompt("协议: tcp / udp / both", oldProto === "both" ? "both" : oldProto) || oldProto).toLowerCase();
      if (!["tcp", "udp", "both"].includes(newProto)) {
        toast("协议无效");
        return;
      }
      if (newPort === oldPort && newProto === oldProto) {
        toast("未更改");
        return;
      }
      if (b.dataset.xdp && b.dataset.xdp !== "—" && newPort !== oldPort) {
        if (!confirm("该端口绑定了 XDP 转发 " + b.dataset.xdp + "。修改防火墙端口不会改转发规则，是否继续？")) return;
      }
      try {
        if (wasOpen) {
          if (b.dataset.prot === "1") {
            if (!confirm("将关闭受保护端口 " + oldPort + "，确认？")) return;
          }
          await api("/ports/close", {
            method: "POST",
            body: JSON.stringify({ port: oldPort, proto: oldProto, confirm: true }),
          });
        }
        await api("/ports/open", {
          method: "POST",
          body: JSON.stringify({ port: newPort, proto: newProto }),
        });
        toast("已修改为 " + newPort + "/" + protoLabel(newProto));
        renderPorts(el, window.__portsPage || 1);
      } catch (ex) {
        toast("修改失败: " + ex.message);
      }
    };
  });
}

async function renderTG(el) {
  const tg = await api("/tg");
  el.innerHTML = `
    <div class="page-head"><div><h2>Telegram</h2><p class="sub">仅白名单管理员</p></div></div>
    <div class="panel"><div class="form-box">
      <div class="field"><label>Bot Token</label><input id="tg-token" type="password" placeholder="${tg.token_set ? "已配置（留空不改）" : "粘贴 token"}" /></div>
      <div class="field"><label>管理员 ID（逗号分隔）</label><input id="tg-admins" class="mono" value="${(tg.admin_ids || []).join(",")}" /></div>
      <div class="field"><label>启用</label>
        <button type="button" class="toggle ${tg.enabled ? "on" : ""}" id="tg-en"></button></div>
      <button class="btn btn-primary" id="tg-save">保存</button>
    </div></div>`;
  document.getElementById("tg-en").onclick = function () { this.classList.toggle("on"); };
  document.getElementById("tg-save").onclick = async () => {
    const ids = document.getElementById("tg-admins").value.split(",").map((s) => s.trim()).filter(Boolean).map(Number);
    const body = { enabled: document.getElementById("tg-en").classList.contains("on"), admin_ids: ids };
    const tok = document.getElementById("tg-token").value;
    if (tok) body.token = tok;
    await api("/tg", { method: "POST", body: JSON.stringify(body) });
    toast("已保存");
  };
}

async function renderLogs(el) {
  const raw = await api("/logs");
  const logs = Array.isArray(raw) ? raw : [];
  el.innerHTML = `
    <div class="page-head"><div><h2>操作日志</h2><p class="sub">Web / Telegram</p></div></div>
    <div class="panel"><table>
      <thead><tr><th>时间</th><th>来源</th><th>操作者</th><th>动作</th><th>结果</th></tr></thead>
      <tbody>${logs.map((l) => `<tr>
        <td class="mono">${l.ts}</td><td>${l.source}</td><td>${l.actor}</td>
        <td class="mono">${l.action}</td><td>${l.result}</td></tr>`).join("") || `<tr><td colspan="5" class="empty">暂无</td></tr>`}
      </tbody></table></div>`;
}

async function renderSettings(el) {
  const s = await api("/settings");
  el.innerHTML = `
    <div class="page-head"><div><h2>面板设置</h2><p class="sub">更新 · 证书 · 账号 · 卸载 · VPS 命令 <span class="mono">xdp</span></p></div></div>
    <div class="grid grid-2">
      <div class="panel"><div class="panel-h"><h3>版本与更新</h3></div><div class="form-box">
        <div class="ver-row"><div><div class="name">面板</div><div class="ver">v${s.panel_version}</div></div></div>
        <div class="ver-row"><div><div class="name">转发内核 BPF</div><div class="ver">v${s.bpf_version} · ${s.xdp?.loaded ? s.xdp.mode : "未加载"}</div></div>
        <div class="field"><label>自动更新</label>
          <button type="button" class="toggle ${s.auto_update ? "on" : ""}" id="au"></button></div>
        <div class="field"><label>更新地址</label><input id="upd" class="mono" value="${s.update_url || "https://github.com/gzjacktang/xdpforward/releases/latest"}" /></div>
        <div style="display:flex;flex-wrap:wrap;gap:8px">
          <button class="btn btn-primary" id="do-update">立即更新</button>
          <button class="btn btn-warn" id="restart">重启面板</button>
        </div>
        <p class="hint">也可在 VPS 执行 <span class="mono">xdp update</span></p>
      </div></div>
      <div class="panel"><div class="panel-h"><h3>访问</h3></div><div class="form-box">
        <div class="field"><label>端口</label><input id="lp" class="mono" value="${s.listen_port}" /></div>
        <div class="field"><label>路径前缀</label><input id="bp" class="mono" value="${s.base_path || "/"}" /></div>
        <div class="field"><label>绑定</label><input id="la" class="mono" value="${s.listen_addr}" /></div>
        <div class="field"><label>网卡</label><input id="ifc" class="mono" value="${s.iface || ""}" /></div>
        <div class="field"><label>SNAT 段</label><div class="form-row">
          <input id="smin" class="mono" value="${s.snat_min}" /><input id="smax" class="mono" value="${s.snat_max}" /></div>
          <p class="hint">仅保留内核端口，不打开防火墙。</p></div>
        <div class="field"><label>公网域名</label><input id="ph" class="mono" value="${s.public_host || ""}" /></div>
        <button class="btn btn-primary" id="sv">保存设置</button>
        <p class="hint">改端口/绑定后请「保存」再「重启面板」。</p>
      </div></div>
    </div>
    <div class="panel" style="margin-top:14px"><div class="panel-h"><h3>证书</h3></div><div class="form-box">
      <p class="hint">当前: <strong>${s.tls_mode || "selfsigned"}</strong> · ${s.tls || "-"}</p>
      <div class="form-row">
        <div class="field"><label>域名</label><input id="tls-domain" class="mono" value="${s.public_host || ""}" placeholder="panel.example.com" /></div>
        <div class="field"><label>ACME 邮箱（LE）</label><input id="tls-email" class="mono" value="${s.acme_email || ""}" /></div>
        <div class="field"><label>模式</label>
          <select id="tls-mode">
            <option value="selfsigned" ${!["letsencrypt","le","zerossl","zero"].includes(s.tls_mode) ? "selected" : ""}>自签</option>
            <option value="letsencrypt" ${s.tls_mode === "letsencrypt" || s.tls_mode === "le" ? "selected" : ""}>Let's Encrypt</option>
            <option value="zerossl" ${s.tls_mode === "zerossl" || s.tls_mode === "zero" ? "selected" : ""}>ZeroSSL</option>
          </select></div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:8px">
        <button class="btn btn-primary" id="tls-issue">安装 / 更换证书</button>
        <button class="btn btn-ghost" id="regen">仅重生成自签</button>
      </div>
      <p class="hint">Let's Encrypt 需要域名解析到本机且 <span class="mono">80</span> 可用。VPS: <span class="mono">xdp cert</span></p>
    </div></div>
    <div class="panel" style="margin-top:14px"><div class="panel-h"><h3>账号</h3></div><div class="form-box">
      <div class="form-row">
        <div class="field"><label>用户名</label><input id="un" value="${s.username || "admin"}" /></div>
        <div class="field"><label>当前密码（改密必填）</label><input id="op" type="password" autocomplete="current-password" /></div>
        <div class="field"><label>新密码（至少 8 位，留空不改）</label><input id="np" type="password" autocomplete="new-password" /></div>
      </div>
      <button class="btn btn-primary" id="acc">保存账号</button>
      <p class="hint" id="acc-hint">可只改用户名；改密码需当前密码 + 新密码。VPS: <span class="mono">xdp passwd</span></p>
    </div></div>
    <div class="panel" style="margin-top:14px"><div class="panel-h"><h3>危险操作</h3></div><div class="form-box">
      <p class="hint">卸载将停止服务并删除程序文件；可选是否删除数据目录。</p>
      <div class="field"><label>确认语（请输入 UNINSTALL）</label><input id="uninst-confirm" class="mono" placeholder="UNINSTALL" /></div>
      <div class="field"><label>同时删除数据</label>
        <button type="button" class="toggle" id="uninst-wipe"></button></div>
      <button class="btn btn-warn" id="do-uninstall">卸载面板</button>
    </div></div>`;
  document.getElementById("au").onclick = function () { this.classList.toggle("on"); };
  document.getElementById("uninst-wipe").onclick = function () { this.classList.toggle("on"); };
  document.getElementById("sv").onclick = async () => {
    try {
      const newBase = document.getElementById("bp").value;
      await api("/settings", {
        method: "POST",
        body: JSON.stringify({
          listen_port: +document.getElementById("lp").value,
          base_path: newBase,
          listen_addr: document.getElementById("la").value,
          iface: document.getElementById("ifc").value,
          public_host: document.getElementById("ph").value,
          snat_min: +document.getElementById("smin").value,
          snat_max: +document.getElementById("smax").value,
          update_url: document.getElementById("upd").value,
          auto_update: document.getElementById("au").classList.contains("on"),
        }),
      });
      try { localStorage.setItem("xfp_next_url", panelURL(newBase)); } catch (_) {}
      toast("设置已保存。改端口/路径后请点「重启面板」");
    } catch (ex) {
      toast("保存失败: " + ex.message);
    }
  };
  document.getElementById("restart").onclick = async () => {
    if (!confirm("确认重启面板？将自动跳转到新访问路径。")) return;
    const next = (() => {
      try { return localStorage.getItem("xfp_next_url") || panelURL(document.getElementById("bp").value); }
      catch (_) { return panelURL(document.getElementById("bp").value); }
    })();
    try {
      await api("/settings/restart", { method: "POST" });
      toast("正在重启并跳转…");
      setTimeout(() => { location.href = next; }, 2800);
    } catch (ex) {
      toast("重启失败: " + ex.message);
    }
  };
  document.getElementById("do-update").onclick = async () => {
    if (!confirm("从 GitHub 拉取并更新？服务会短暂中断。")) return;
    try {
      await api("/settings", {
        method: "POST",
        body: JSON.stringify({ update_url: document.getElementById("upd").value }),
      });
      await api("/settings/update", { method: "POST" });
      toast("已开始更新，约 1–3 分钟后刷新页面");
    } catch (ex) {
      toast("更新失败: " + ex.message);
    }
  };
  document.getElementById("tls-issue").onclick = async () => {
    const mode = document.getElementById("tls-mode").value;
    const domain = document.getElementById("tls-domain").value.trim();
    if ((mode === "letsencrypt" || mode === "zerossl") && !domain) {
      toast("公共 CA 需要域名");
      return;
    }
    if (mode === "zerossl" && !document.getElementById("tls-email").value.trim()) {
      toast("ZeroSSL 需要填写邮箱");
      return;
    }
    if (!confirm("确认申请/更换证书？（公共 CA 需占用 80 端口）")) return;
    try {
      await api("/settings/tls/issue", {
        method: "POST",
        body: JSON.stringify({
          mode,
          domain,
          email: document.getElementById("tls-email").value.trim(),
        }),
      });
      toast("证书任务已启动，完成后会自动重启");
    } catch (ex) {
      toast(ex.message);
    }
  };
  document.getElementById("regen").onclick = async () => {
    try {
      await api("/settings/tls/regen", { method: "POST" });
      toast("自签证书已重生，请重启面板后生效");
    } catch (ex) {
      toast("失败: " + ex.message);
    }
  };
  document.getElementById("acc").onclick = async () => {
    const hint = document.getElementById("acc-hint");
    try {
      const res = await api("/settings/account", {
        method: "POST",
        body: JSON.stringify({
          username: document.getElementById("un").value.trim(),
          old_password: document.getElementById("op").value,
          new_password: document.getElementById("np").value,
        }),
      });
      const what = (res.changed || []).join("+") || "ok";
      toast("账号已更新: " + what);
      hint.textContent = "保存成功（" + what + "）。若改了密码请用新密码重新登录。";
      document.getElementById("op").value = "";
      document.getElementById("np").value = "";
    } catch (ex) {
      toast("账号保存失败: " + ex.message);
      hint.textContent = "失败: " + ex.message;
    }
  };
  document.getElementById("do-uninstall").onclick = async () => {
    const confirmWord = document.getElementById("uninst-confirm").value.trim();
    if (confirmWord !== "UNINSTALL") {
      toast("请输入 UNINSTALL 确认");
      return;
    }
    const wipe = document.getElementById("uninst-wipe").classList.contains("on");
    if (!confirm(wipe ? "将卸载并删除全部数据，不可恢复！" : "确认卸载面板？（保留数据目录）")) return;
    try {
      await api("/settings/uninstall", {
        method: "POST",
        body: JSON.stringify({ confirm: "UNINSTALL", wipe_data: wipe }),
      });
      toast("正在卸载…");
    } catch (ex) {
      toast(ex.message);
    }
  };
}

// try session
api("/status").then(() => { showApp(true); goPage("dash"); }).catch(() => showApp(false));
