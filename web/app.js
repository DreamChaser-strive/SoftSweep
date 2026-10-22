(() => {
  "use strict";

  const params = new URLSearchParams(location.search);
  let token = params.get("t") || sessionStorage.getItem("softsweep.token") || "";
  if (params.get("t")) {
    sessionStorage.setItem("softsweep.token", params.get("t"));
    history.replaceState(null, "", location.pathname);
  }

  const $ = (id) => document.getElementById(id);
  const state = {
    apps: [],
    categories: [],
    notices: [],
    version: "",
    isAdmin: false,
    scanStatus: "idle",
    scanPhase: "",
    scanError: "",
    pendingSizes: 0,
    startedAt: null,
    finishedAt: null,
    filters: {
      category: "all",
      source: "all",
      query: "",
      showProtected: false,
      sort: "name",
    },
    drawerAppId: null,
    drawerOpen: false,
    dialogOpen: false,
    dialogKind: null,
    modalConfirm: null,
    job: null,
    jobModalOpen: false,
    jobSelection: new Set(),
    jobLeftoverSig: null,
    jobCleanupMode: null,
    cleanupSubmitting: false,
    trackedJobId: null,
    jobRenderSig: null,
    history: [],
    dead: false,
    pollTimer: null,
    started: false,
    lastStateErrorAt: 0,
    searchTimer: null,
  };

  const ICONS = {
    folder: "i-folder",
    shortcut: "i-link",
    registry: "i-reg",
    registry_value: "i-reg",
    trash: "i-trash",
    shield: "i-shield",
    alert: "i-alert",
    check: "i-check",
    checkCircle: "i-check-circle",
    package: "i-package",
    scan: "i-scan",
  };

  const collator = new Intl.Collator("zh-CN", { numeric: true, sensitivity: "base" });

  // ------------------------------------------------------------------ utils
  const esc = (value) =>
    String(value == null ? "" : value).replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[ch]));

  const safeColor = (value) =>
    /^#[0-9a-fA-F]{6}$/.test(String(value || "")) ? value : "#5b7165";

  function icon(name, className = "ico") {
    return `<svg class="${className}" aria-hidden="true"><use href="#${name}"></use></svg>`;
  }

  function humanSize(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n < 0) return "—";
    if (n < 1024) return `${Math.round(n)} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let value = n / 1024;
    let index = 0;
    while (value >= 1024 && index < units.length - 1) {
      value /= 1024;
      index += 1;
    }
    const digits = value >= 100 || index === 0 ? 0 : 1;
    return `${value.toFixed(digits)} ${units[index]}`;
  }

  function timeText(ts) {
    if (!ts) return "";
    const d = new Date(Number(ts) * 1000);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" });
  }

  function dateTimeText(ts) {
    if (!ts) return "";
    const d = new Date(Number(ts) * 1000);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleString("zh-CN", {
      month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
    });
  }

  function shortDate(value) {
    if (!value) return "—";
    return String(value).replace(/-/g, ".");
  }

  function firstChar(name) {
    const chars = Array.from(String(name || "").trim());
    return chars.length ? chars[0].toUpperCase() : "?";
  }

  function appCategory(app) {
    return state.categories.find((c) => c.key === app.category) ||
      { key: app.category || "other", label: app.category_label || "其他", color: app.category_color || "#7c8790" };
  }

  function iconUrl(app) {
    if (!app || !app.id || !app.icon_version) return "";
    return `/api/icon/${encodeURIComponent(app.id)}?v=${encodeURIComponent(app.icon_version)}&t=${encodeURIComponent(token)}`;
  }

  function avatarHtml(app, className = "app-avatar") {
    const value = app || {};
    const color = safeColor(appCategory(value).color);
    const src = iconUrl(value);
    const letter = `<span class="avatar-letter">${esc(firstChar(value.name))}</span>`;
    const image = src
      ? `<img class="app-icon-img" src="${esc(src)}" alt="" loading="lazy" decoding="async">`
      : "";
    return `<span class="${className} avatar-tile ${src ? "with-icon" : ""}" style="--cat:${color}" aria-hidden="true">${letter}${image}</span>`;
  }

  function jobAvatar(job, className = "job-app-icon") {
    const app = job && job.app ? job.app : {};
    const merged = {
      ...app,
      id: app.id || (job && job.app_id) || "",
      name: (job && job.app_name) || app.name || "",
      icon_version: app.icon_version || "",
    };
    return avatarHtml(merged, className);
  }

  function getApp(id) {
    return state.apps.find((a) => a.id === id) || null;
  }

  function toast(message, kind = "") {
    const node = document.createElement("div");
    node.className = `toast ${kind}`;
    node.textContent = message;
    $("toastRoot").appendChild(node);
    setTimeout(() => {
      node.style.opacity = "0";
      node.style.transform = "translateY(5px)";
      node.style.transition = "opacity .2s, transform .2s";
      setTimeout(() => node.remove(), 220);
    }, 4400);
  }

  function brandMark() {
    return `<span class="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 32 32"><path d="M7.5 21.5c5.8 2.8 12.2 1.6 16.4-3.1" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/><path d="M9 9.2h13M9 14.2h9" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/><circle cx="23.6" cy="9.2" r="1.6" fill="currentColor"/></svg>
    </span>`;
  }

  function fatal(title, message, hint = "") {
    state.dead = true;
    clearTimeout(state.pollTimer);
    document.body.innerHTML = `<div class="fatal"><div class="fatal-card">
      ${brandMark()}
      <h1>${esc(title)}</h1>
      <p>${esc(message)}</p>
      ${hint ? `<code>${esc(hint)}</code>` : ""}
    </div></div>`;
  }

  // -------------------------------------------------------------------- api
  async function api(path, options = {}) {
    if (state.dead) throw new Error("会话已结束");
    const init = {
      method: options.method || "GET",
      headers: { "X-Token": token },
      cache: "no-store",
    };
    if (options.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    let response;
    try {
      response = await fetch(path, init);
    } catch (err) {
      throw new Error("无法连接本地服务，请确认 SoftSweep 仍在运行");
    }
    let data = null;
    try {
      data = await response.json();
    } catch (err) {
      data = null;
    }
    if (response.status === 401) {
      fatal(
        "访问令牌已失效",
        "请关闭当前页面，从 SoftSweep 启动窗口重新打开界面。为保护本机软件信息，所有接口都需要本次会话的令牌。",
        "data/session.json"
      );
      const error = new Error("访问令牌无效");
      error.handled = true;
      throw error;
    }
    if (!response.ok) {
      const message = (data && data.error) || `请求失败（HTTP ${response.status}）`;
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function normalizeCategories(raw) {
    if (!Array.isArray(raw)) return [];
    return raw.map((item) => {
      if (Array.isArray(item)) return { key: item[0], label: item[1], color: item[2] };
      return {
        key: item.key,
        label: item.label || item.key,
        color: item.color || "#7c8790",
      };
    });
  }

  async function startScan() {
    try {
      await api("/api/scan", { method: "POST", body: {} });
      state.scanStatus = "scanning";
      state.scanError = "";
      renderScanState();
      schedule(800);
    } catch (err) {
      if (!err.handled) toast(err.message, "error");
    }
  }

  async function loadState() {
    const data = await api("/api/state");
    if (state.dead) return;
    state.apps = (data.apps || []).map((app) => ({
      ...app,
      size: app.size || {},
    }));
    state.categories = normalizeCategories(data.categories);
    state.notices = Array.isArray(data.notices) ? data.notices : [];
    state.version = data.version || "";
    state.isAdmin = Boolean(data.is_admin);
    state.scanStatus = data.status || "idle";
    state.scanPhase = data.phase || "";
    state.scanError = data.error || "";
    state.pendingSizes = Number(data.pending_sizes || 0);
    state.startedAt = data.started_at || null;
    state.finishedAt = data.finished_at || null;
    state.history = Array.isArray(data.jobs_history) ? data.jobs_history : [];
    if (!state.trackedJobId && data.jobs_active && data.jobs_active.id) {
      state.trackedJobId = data.jobs_active.id;
    }
    if (state.startedAt === null && state.scanStatus === "idle" && !state.started) {
      state.started = true;
      await startScan();
    }
    renderAll();
    if (state.trackedJobId) await loadJob(state.trackedJobId);
  }

  function schedule(ms) {
    clearTimeout(state.pollTimer);
    if (state.dead) return;
    state.pollTimer = setTimeout(tick, ms);
  }

  async function tick() {
    if (state.dead) return;
    let fast = false;
    try {
      if (document.hidden) {
        schedule(4500);
        return;
      }
      await loadState();
      fast = state.scanStatus === "scanning" || state.pendingSizes > 0 ||
        Boolean(state.trackedJobId && state.job && state.job.active);
    } catch (err) {
      if (!err.handled) {
        const now = Date.now();
        if (now - state.lastStateErrorAt > 12000) {
          state.lastStateErrorAt = now;
          toast(err.message, "error");
        }
      }
    }
    schedule(fast ? 1300 : 9000);
  }

  // ------------------------------------------------------------- rendering
  function renderAll() {
    renderAdmin();
    renderScanState();
    renderNotices();
    renderCategories();
    renderList();
    renderMiniJob();
    if (state.drawerOpen && state.drawerAppId) renderDrawer(state.drawerAppId, false);
    if (state.dialogOpen && state.dialogKind === "history") renderHistoryModal();
    const version = $("versionText");
    if (version) version.textContent = state.version ? `SoftSweep v${state.version}` : "";
  }

  function renderAdmin() {
    const badge = $("adminBadge");
    badge.textContent = state.isAdmin ? "管理员模式" : "普通权限";
    badge.classList.toggle("no-admin", !state.isAdmin);
    badge.title = state.isAdmin
      ? "已获取管理员权限，可以读取和清理系统级项目"
      : "未获取管理员权限，部分系统级项目不可读写";
    $("adminBanner").hidden = state.isAdmin;
  }

  function renderScanState() {
    const scanning = state.scanStatus === "scanning";
    $("scanBanner").hidden = !scanning;
    $("scanPhase").textContent = state.scanPhase || "正在扫描…";
    $("scanDetail").textContent = scanning
      ? "读取注册表、Microsoft Store 应用及安装目录信息"
      : "";
    $("pendingSizes").textContent = state.pendingSizes > 0 ? `正在统计 ${state.pendingSizes} 个大小` : "";
    const refresh = $("refreshBtn");
    refresh.disabled = scanning;
    const label = refresh.querySelector("span");
    if (label) label.textContent = scanning ? "扫描中…" : "重新扫描";
  }

  function renderNotices() {
    const box = $("noticeBox");
    const notices = [];
    if (state.scanError) notices.push(`扫描出错：${state.scanError}`);
    for (const item of state.notices.slice(0, 4)) {
      if (item && !notices.includes(item)) notices.push(item);
    }
    box.hidden = notices.length === 0;
    if (notices.length) {
      box.innerHTML = `<ul>${notices.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>`;
    }
  }

  function baseFilteredApps({ ignoreCategory = false } = {}) {
    const f = state.filters;
    const query = f.query.trim().toLowerCase();
    let list = state.apps;
    if (!f.showProtected) list = list.filter((a) => a.primary);
    if (f.source !== "all") list = list.filter((a) => a.source === f.source);
    if (!ignoreCategory && f.category !== "all") {
      list = list.filter((a) => a.category === f.category);
    }
    if (query) {
      list = list.filter((a) => {
        const hay = [
          a.name, a.publisher, a.install_location, a.install_location_display,
          a.package_name, a.category_label, a.source_label,
        ].join(" ").toLowerCase();
        return hay.includes(query);
      });
    }
    return list;
  }

  function sortApps(list) {
    const mode = state.filters.sort;
    const categoryOrder = new Map(state.categories.map((c, i) => [c.key, i]));
    const arr = list.slice();
    arr.sort((a, b) => {
      if (mode === "size") {
        const av = Number(a.size && a.size.bytes);
        const bv = Number(b.size && b.size.bytes);
        const an = Number.isFinite(av) ? av : -1;
        const bn = Number.isFinite(bv) ? bv : -1;
        if (an !== bn) return bn - an;
      } else if (mode === "date") {
        const ad = a.install_date || "";
        const bd = b.install_date || "";
        if (ad !== bd) {
          if (!ad) return 1;
          if (!bd) return -1;
          return bd.localeCompare(ad);
        }
      } else if (mode === "category") {
        const ac = categoryOrder.has(a.category) ? categoryOrder.get(a.category) : 99;
        const bc = categoryOrder.has(b.category) ? categoryOrder.get(b.category) : 99;
        if (ac !== bc) return ac - bc;
      }
      return collator.compare(a.name || "", b.name || "");
    });
    return arr;
  }

  function renderCategories() {
    const f = state.filters;
    const pool = baseFilteredApps({ ignoreCategory: true });
    const counts = new Map();
    for (const app of pool) counts.set(app.category, (counts.get(app.category) || 0) + 1);
    const total = pool.length;
    const allActive = f.category === "all";
    let html = `<button type="button" class="cat-item ${allActive ? "active" : ""}" data-cat="all">
      <span class="cat-dot" style="--cat:#226d58"></span>
      <span class="cat-name">全部软件</span><span class="cat-count">${total}</span>
    </button>`;
    for (const category of state.categories) {
      const count = counts.get(category.key) || 0;
      html += `<button type="button" class="cat-item ${f.category === category.key ? "active" : ""}" data-cat="${esc(category.key)}" title="${esc(category.label)}">
        <span class="cat-dot" style="--cat:${safeColor(category.color)}"></span>
        <span class="cat-name">${esc(category.label)}</span><span class="cat-count">${count}</span>
      </button>`;
    }
    $("categoryNav").innerHTML = html;
    const totalPrimary = state.apps.filter((a) => a.primary).length;
    const protectedCount = state.apps.filter((a) => a.protected).length;
    $("showProtected").checked = f.showProtected;
    const current = state.categories.find((c) => c.key === f.category);
    $("listTitle").textContent = f.category === "all" ? "全部软件" : (current ? current.label : "软件");
    const scanned = state.finishedAt ? `最近扫描 ${timeText(state.finishedAt)}` : "扫描进行中";
    const scope = f.showProtected ? "含受保护组件" : "仅显示可管理软件";
    $("listSummary").textContent =
      `${state.apps.length} 款软件 · 可管理 ${totalPrimary} · 受保护 ${protectedCount} · ${scope} · ${scanned}`;
  }

  function sizeText(app) {
    const size = app.size || {};
    if (size.bytes != null && Number(size.bytes) >= 0) {
      const approximate = size.estimated && !size.exact ? "约 " : "";
      let sub = "";
      if (size.computing) sub = "，继续统计中";
      else if (size.partial) sub = "，估算";
      else if (size.estimated) sub = "，安装器估算";
      return `${approximate}${humanSize(size.bytes)}${sub}`;
    }
    if (size.computing) return "计算中…";
    if (app.kind === "uwp") return "商店应用，未统计";
    if (app.protected) return "受保护，未统计";
    return "未知";
  }

  function sizeCell(app) {
    const size = app.size || {};
    if (size.bytes != null && Number(size.bytes) >= 0) {
      const approximate = size.estimated && !size.exact ? "约 " : "";
      let sub = "";
      if (size.computing) sub = "继续统计中";
      else if (size.exact) sub = "已统计";
      else if (size.partial) sub = "文件较多，估算";
      else if (size.estimated) sub = "安装器估算";
      return `<div class="size-main">${approximate}${humanSize(size.bytes)}</div>${sub ? `<div class="size-sub">${sub}</div>` : ""}`;
    }
    if (size.computing) return `<div class="size-main size-unknown">计算中…</div>`;
    if (app.kind === "uwp") return `<div class="size-main size-unknown">—</div><div class="size-sub">商店应用</div>`;
    if (app.protected) return `<div class="size-main size-unknown">—</div><div class="size-sub">受保护</div>`;
    return `<div class="size-main size-unknown">—</div><div class="size-sub">未知</div>`;
  }

  function appRow(app) {
    const category = appCategory(app);
    const location = app.install_location_display || app.install_location || "";
    const publisher = app.publisher || "未知发布商";
    const version = app.version || "";
    const sub = `${esc(publisher)}${version ? ` <span class="sep">·</span> <span>${esc(version)}</span>` : ""}`;
    const tags = [`<span class="tag tag-source">${esc(app.source_label || "未知来源")}</span>`];
    if (app.source === "store") tags.push(`<span class="tag tag-store">商店</span>`);
    if (app.protected) tags.push(`<span class="tag tag-protected">${icon("i-shield", "ico")}受保护</span>`);
    const warningTag = !app.protected && (app.warnings || []).length
      ? `<span class="tag">${app.warnings.length} 条提示</span>` : "";
    return `<div class="app-row ${app.protected ? "is-protected" : ""}" role="button" tabindex="0"
      data-app-id="${esc(app.id)}" aria-label="查看 ${esc(app.name)} 详情">
      <div class="app-software">
        ${avatarHtml(app)}
        <div class="app-copy">
          <div class="app-name"><span>${esc(app.name)}</span></div>
          <div class="app-sub"><span class="publisher" title="${esc(publisher)}">${sub}</span></div>
          <div class="app-tags">${tags.join("")}${warningTag}</div>
        </div>
      </div>
      <div class="app-kind">${esc(app.category_label || category.label)}</div>
      <div class="app-location ${location ? "" : "is-empty"}" title="${esc(location)}">${location ? esc(location) : "未登记安装位置"}</div>
      <div class="app-size">${sizeCell(app)}</div>
      <div class="row-arrow">${icon("i-chevron")}</div>
    </div>`;
  }

  function skeletonRows() {
    return Array.from({ length: 7 }, () => `<div class="app-row skeleton-row" aria-hidden="true">
      <div class="app-software">
        <span class="skeleton sk-avatar"></span>
        <div class="app-copy"><span class="skeleton sk-line w60"></span><span class="skeleton sk-line w40"></span><span class="skeleton sk-line w20"></span></div>
      </div>
      <span class="skeleton sk-line w75"></span>
      <span class="skeleton sk-line w60"></span>
      <span class="skeleton sk-line w40"></span>
      <span></span>
    </div>`).join("");
  }

  function renderList() {
    const list = sortApps(baseFilteredApps());
    const container = $("appList");
    const empty = $("emptyState");
    if (state.scanStatus === "scanning" && !state.apps.length) {
      container.innerHTML = skeletonRows();
      empty.hidden = true;
      return;
    }
    if (!list.length) {
      container.innerHTML = "";
      empty.hidden = false;
      const title = empty.querySelector("h2");
      const text = empty.querySelector("p");
      if (state.apps.length && state.filters.query) {
        title.textContent = "没有匹配的软件";
        text.textContent = `没有找到包含「${state.filters.query}」的软件，试试更短的关键词。`;
      } else if (state.apps.length) {
        title.textContent = "当前筛选下没有软件";
        text.textContent = "切换分类或来源，或开启左侧的受保护组件显示。";
      } else if (state.scanStatus === "error") {
        title.textContent = "扫描没有完成";
        text.textContent = "请查看上方错误信息，或点击“重新扫描”再试一次。";
      } else {
        title.textContent = "还没有软件列表";
        text.textContent = "正在等待扫描结果，请稍候。";
      }
      return;
    }
    empty.hidden = true;
    container.innerHTML = list.map(appRow).join("");
  }

  // ----------------------------------------------------------------- drawer
  function updateBodyLock() {
    const locked = Boolean(state.drawerOpen || state.dialogOpen || state.jobModalOpen);
    document.body.style.overflow = locked ? "hidden" : "";
  }

  function openDrawer(appId) {
    const app = getApp(appId);
    if (!app) return;
    state.drawerAppId = appId;
    state.drawerOpen = true;
    const drawer = $("appDrawer");
    const overlay = $("overlay");
    drawer.hidden = false;
    overlay.hidden = false;
    drawer.setAttribute("aria-hidden", "false");
    updateBodyLock();
    renderDrawer(appId);
    drawer.querySelector(".drawer-close")?.focus();
  }

  function closeDrawer() {
    state.drawerOpen = false;
    state.drawerAppId = null;
    $("appDrawer").hidden = true;
    $("appDrawer").setAttribute("aria-hidden", "true");
    if (!state.dialogOpen && !state.jobModalOpen) $("overlay").hidden = true;
    updateBodyLock();
  }

  function renderDrawer(appId, focus = true) {
    const app = getApp(appId);
    if (!app) return closeDrawer();
    const category = appCategory(app);
    const warnings = Array.isArray(app.warnings) ? app.warnings : [];
    const location = app.install_location || "";
    const locationDisplay = app.install_location_display || location;
    const isUwp = app.kind === "uwp";
    const canUninstall = Boolean(app.can_uninstall) && !app.protected;
    const canForce = Boolean(app.can_force) && !app.protected;
    const requiresAdmin = Boolean(app.requires_admin);
    const protectedBox = app.protected ? `<div class="protected-box">
      ${icon("i-shield")}
      <strong>受保护的项目</strong>
      ${esc(app.protected_reason || "系统组件、驱动或运行库，卸载可能影响系统或其他软件。")}
    </div>` : "";
    const warningHtml = warnings.length ? `<div class="drawer-section-title">${icon("i-alert")}注意事项</div>
      <div class="warning-list">${warnings.map((w) => `<div class="warning-item">${icon("i-alert")}<span>${esc(w)}</span></div>`).join("")}</div>` : "";
    const adminWarning = !state.isAdmin ? `<div class="warning-item">${icon("i-alert")}<span>当前为普通权限。${requiresAdmin ? "此软件的卸载和清理可能需要管理员权限；" : ""}注册表系统项可能无法修改或备份。</span></div>` : "";
    let actions = "";
    if (app.protected) {
      actions = `<div class="action-row"><button class="btn btn-ghost btn-wide" disabled type="button">${icon("i-shield")}此项目受保护</button></div>
        <p class="drawer-danger-note">受保护项目不提供自动卸载或清理。</p>`;
    } else if (canUninstall) {
      actions = `<div class="action-row">
          <button class="btn btn-primary" data-drawer-act="uninstall" type="button">${icon("i-trash")}${isUwp ? "卸载并清理应用数据" : "卸载并深度清理"}</button>
        </div>
        <p class="action-hint">先启动官方卸载程序，结束后自动扫描残留；不会直接删除任何文件。</p>
        ${canForce ? `<button class="force-link" data-drawer-act="force" type="button">卸载程序损坏或无响应？改为仅清理残留</button>` : ""}`;
    } else if (canForce) {
      actions = `<div class="action-row">
          <button class="btn btn-primary" data-drawer-act="force" type="button">${icon("i-scan")}扫描并清理残留</button>
        </div>
        <p class="action-hint">该软件没有可用的官方卸载命令。清理前会再次扫描，由你确认文件列表。</p>`;
    } else {
      actions = `<div class="action-row"><button class="btn btn-ghost btn-wide" disabled type="button">暂不可自动清理</button></div>`;
    }
    const tech = `<details class="tech-box"><summary>技术信息 ${icon("i-chevron", "ico")}</summary>
      ${app.uninstall_string ? `<div class="detail-row">卸载命令<code>${esc(app.uninstall_string)}</code></div>` : ""}
      ${app.uninstall_key ? `<div class="detail-row">卸载注册项<code>${esc(app.uninstall_key)}</code></div>` : ""}
      ${app.package_full_name ? `<div class="detail-row">应用包<code>${esc(app.package_full_name)}</code></div>` : ""}
      ${!app.uninstall_string && !app.uninstall_key && !app.package_full_name ? `<div class="detail-row">没有可展示的卸载技术信息。</div>` : ""}
    </details>`;
    const drawer = $("appDrawer");
    drawer.innerHTML = `<div class="drawer-head">
      ${avatarHtml(app, "drawer-icon app-avatar")}
      <div class="drawer-title-wrap">
        <div class="drawer-kicker">${isUwp ? "Microsoft Store 应用" : app.category_label || "桌面软件"}</div>
        <h2 class="drawer-title" id="drawerTitle">${esc(app.name)}</h2>
        <div class="drawer-meta">${esc(app.publisher || "未知发布商")}${app.version ? ` · v${esc(app.version)}` : ""}</div>
      </div>
      <button class="icon-btn drawer-close" data-drawer-close type="button" aria-label="关闭详情">${icon("i-x")}</button>
    </div>
    <div class="drawer-body">
      <div class="meta-grid">
        <div class="meta-item"><div class="meta-label">分类</div><div class="meta-value">${esc(app.category_label || category.label)}</div></div>
        <div class="meta-item"><div class="meta-label">来源</div><div class="meta-value">${esc(app.source_label || "未知")}</div></div>
        <div class="meta-item"><div class="meta-label">安装日期</div><div class="meta-value">${esc(shortDate(app.install_date))}</div></div>
        <div class="meta-item"><div class="meta-label">占用空间</div><div class="meta-value">${esc(sizeText(app))}</div></div>
        <div class="meta-item"><div class="meta-label">权限要求</div><div class="meta-value">${app.requires_admin ? "可能需要管理员" : "当前用户"}</div></div>
        <div class="meta-item"><div class="meta-label">软件类型</div><div class="meta-value">${isUwp ? "商店应用" : "Win32 桌面程序"}</div></div>
      </div>
      <div class="path-box"><span class="path-label">安装位置</span>${locationDisplay ? esc(locationDisplay) : "注册表中未记录安装位置"}</div>
      ${protectedBox}
      ${warningHtml}
      ${!app.protected && (adminWarning || warnings.length === 0) ? `<div class="drawer-section-title">${icon("i-shield")}清理说明</div><div class="warning-list">${adminWarning}</div>` : ""}
      <p class="drawer-note"><strong>清理流程：</strong>${canUninstall
        ? "启动官方卸载程序 → 等待卸载完成 → 扫描安装目录、AppData、快捷方式和注册表 → 你确认后清理。"
        : "扫描安装目录、AppData、快捷方式和注册表 → 你确认后清理。"}所选文件默认<strong>移入回收站</strong>，注册表修改会先导出备份；文档、下载和图片目录不会被扫描。</p>
      ${tech}
    </div>
    <div class="drawer-actions">${actions}</div>`;
    if (focus) drawer.querySelector(".drawer-close")?.focus();
  }

  // ------------------------------------------------------------------ dialog
  function closeSimpleModal() {
    state.dialogOpen = false;
    state.dialogKind = null;
    state.modalConfirm = null;
    const root = $("dialogRoot");
    root.hidden = true;
    root.innerHTML = "";
    updateBodyLock();
  }

  function openSimpleModal({ title, subtitle = "", body = "", confirm = "确定", cancel = "取消", danger = false, wide = "", onConfirm = null, hideCancel = false, confirmId = "" }) {
    state.dialogOpen = true;
    state.dialogKind = "simple";
    state.modalConfirm = onConfirm;
    const root = $("dialogRoot");
    root.hidden = false;
    root.innerHTML = `<div class="modal ${wide}" role="dialog" aria-modal="true" aria-labelledby="simpleModalTitle">
      <div class="modal-head">
        <div class="modal-title-wrap">
          <h2 class="modal-title" id="simpleModalTitle">${esc(title)}</h2>
          ${subtitle ? `<p class="modal-sub">${esc(subtitle)}</p>` : ""}
        </div>
        <button class="icon-btn modal-close" data-simple-close type="button" aria-label="关闭">${icon("i-x")}</button>
      </div>
      <div class="modal-body">${body}</div>
      <div class="modal-foot">
        ${hideCancel ? "" : `<button class="btn btn-ghost" data-simple-close type="button">${esc(cancel)}</button>`}
        <button class="btn ${danger ? "btn-danger" : "btn-primary"}" data-simple-confirm="${esc(confirmId)}" type="button">${esc(confirm)}</button>
      </div>
    </div>`;
    updateBodyLock();
    setTimeout(() => {
      const target = root.querySelector("[data-simple-confirm]");
      if (target) target.focus();
    }, 40);
  }

  async function runSimpleConfirm(button) {
    const handler = state.modalConfirm;
    if (!handler) return;
    button.disabled = true;
    const original = button.textContent;
    button.textContent = "处理中…";
    try {
      const outcome = await handler();
      if (outcome === "handled" || outcome === false) {
        button.disabled = false;
        button.textContent = original;
        return;
      }
      state.modalConfirm = null;
      closeSimpleModal();
    } catch (err) {
      button.disabled = false;
      button.textContent = original;
      if (!err.handled) toast(err.message || "操作失败", "error");
    }
  }

  function openAdminHelp() {
    openSimpleModal({
      title: "如何获得管理员权限",
      subtitle: "普通权限会漏掉一部分系统级软件和注册表信息",
      wide: "history-modal",
      body: `<ul class="confirm-list">
        <li><span class="num">1</span><span>保存好当前工作，关闭 SoftSweep 窗口。</span></li>
        <li><span class="num">2</span><span>在文件资源管理器中找到 <code>启动.bat</code>。</span></li>
        <li><span class="num">3</span><span>右键点击它，选择“以管理员身份运行”。</span></li>
        <li><span class="num">4</span><span>在系统弹出的用户账户控制窗口中点击“是”。</span></li>
      </ul>
      <div class="confirm-warning">启动脚本也会尝试自动请求管理员权限。若你拒绝了 UAC，工具仍可使用，但 HKLM 注册表项、系统级软件信息和部分 Program Files 目录将无法读取或清理。</div>`,
      confirm: "我知道了",
      hideCancel: true,
    });
  }

  function openQuitDialog() {
    const job = state.job;
    let warning = "";
    if (job && job.status === "cleaning") {
      toast("清理正在进行，请等待完成后再退出", "error");
      return;
    }
    if (job && job.active) {
      warning = `<div class="confirm-warning danger">当前任务仍在进行：${esc(job.status_label || job.status)}。退出会停止跟踪任务，但已经打开的官方卸载程序不会被关闭。</div>`;
    }
    openSimpleModal({
      title: "退出 SoftSweep？",
      subtitle: "退出后重新运行 SoftSweep.exe 或 启动.bat 即可继续使用",
      body: `${warning}<p class="confirm-warning">正在进行的文件清理会被中断，未完成的项目可能留在原处。建议先完成任务。</p>`,
      confirm: "退出工具",
      danger: true,
      onConfirm: async () => {
        try {
          await api("/api/quit", { method: "POST", body: {} });
        } catch (err) {
          // The server may close the socket before replying; treat as success.
        }
        state.dead = true;
        $("dialogRoot").hidden = true;
        window.setTimeout(() => window.close(), 80);
        window.setTimeout(() => {
          document.body.innerHTML = `<div class="fatal"><div class="fatal-card">
          ${brandMark()}
          <h1>SoftSweep 已退出</h1>
          <p>本地服务已关闭，可以安全关闭这个窗口。需要再次使用时，请运行 SoftSweep.exe 或 启动.bat。</p>
        </div></div>`;
        }, 260);
        return "handled";
      },
    });
  }

  // -------------------------------------------------------------- start job
  function openStartDialog(appId, mode) {
    const app = getApp(appId);
    if (!app) return;
    const isForce = mode === "force";
    const adminHint = !state.isAdmin && app.requires_admin
      ? `<div class="confirm-warning">当前没有管理员权限，卸载程序可能无法运行，或在清理注册表时失败。建议以管理员身份重新启动工具。</div>` : "";
    const body = `<div class="confirm-visual">
        ${avatarHtml(app)}
        <div><div class="cv-name">${esc(app.name)}</div><div class="cv-sub">${esc(app.publisher || "")}${app.version ? ` · v${esc(app.version)}` : ""}</div></div>
      </div>
      ${isForce ? `<p class="confirm-warning">这里不会调用官方卸载程序。它适合卸载程序损坏、软件已卸载但注册表仍有残留的情况。若软件仍能正常使用，请优先选择“卸载并深度清理”。</p>` : `<ul class="confirm-list">
        <li><span class="num">1</span><span>启动该软件自带的卸载程序，需要你在弹出窗口中完成操作。</span></li>
        <li><span class="num">2</span><span>卸载结束后重新扫描安装目录、AppData、快捷方式和注册表。</span></li>
        <li><span class="num">3</span><span>展示残留清单，由你勾选确认后才会删除；默认移入回收站。</span></li>
      </ul>`}
      ${adminHint}
      ${isForce ? `<div class="field"><label for="forceConfirmName">输入软件名称以继续</label>
        <input class="input" id="forceConfirmName" type="text" autocomplete="off" spellcheck="false" placeholder="${esc(app.name)}">
        <p class="field-hint">请输入 <code>${esc(app.name)}</code>，确认你了解这不会启动官方卸载程序。</p>
      </div>` : ""}`;
    openSimpleModal({
      title: isForce ? "仅清理残留文件" : "卸载并深度清理",
      subtitle: isForce ? "不会启动官方卸载程序，清理前仍会再次扫描" : (app.kind === "uwp" ? "将通过 Windows 移除商店应用" : "官方卸载程序会单独弹出"),
      wide: isForce ? "" : "history-modal",
      body,
      confirm: isForce ? "开始扫描残留" : "开始卸载",
      danger: false,
      onConfirm: async () => {
        if (isForce) {
          const input = $("forceConfirmName");
          if (!input || input.value.trim() !== String(app.name).trim()) {
            toast("请输入完整的软件名称", "error");
            return false;
          }
        }
        const result = await api("/api/jobs", {
          method: "POST",
          body: {
            app_id: app.id,
            mode,
            confirm_name: isForce ? (($("forceConfirmName") || {}).value || "") : "",
          },
        });
        if (!result.job) throw new Error("任务创建失败");
        closeSimpleModal();
        state.job = result.job;
        state.jobModalOpen = true;
        state.trackedJobId = result.job.id;
        state.jobSelection = new Set();
        state.jobLeftoverSig = null;
        state.jobCleanupMode = null;
        state.jobRenderSig = null;
        closeDrawer();
        renderJobModal();
        schedule(600);
        return "handled";
      },
    });
    if (isForce) {
      const input = $("forceConfirmName");
      const button = $("dialogRoot").querySelector("[data-simple-confirm]");
      if (input && button) {
        button.disabled = true;
        input.addEventListener("input", () => {
          button.disabled = input.value.trim() !== String(app.name).trim();
        });
        setTimeout(() => input.focus(), 60);
      }
    }
  }

  // ------------------------------------------------------------------- jobs
  async function loadJob(jobId) {
    if (!jobId) return;
    let data;
    try {
      data = await api(`/api/jobs/${encodeURIComponent(jobId)}`);
    } catch (err) {
      if (err.status === 404) {
        state.trackedJobId = null;
        state.job = null;
        state.jobModalOpen = false;
        state.jobRenderSig = null;
        $("modalRoot").hidden = true;
        $("modalRoot").innerHTML = "";
        $("miniJob").hidden = true;
        updateBodyLock();
      }
      if (!err.handled) throw err;
      return;
    }
    const job = data.job;
    if (!job) return;
    const previous = state.job;
    const previousStatus = previous && previous.status;
    const leftoverSig = job.leftover ? `${job.leftover.scanned_at}|${(job.leftover.items || []).length}` : "";
    if (job.leftover && leftoverSig !== state.jobLeftoverSig) {
      state.jobLeftoverSig = leftoverSig;
      const items = job.leftover.items || [];
      state.jobSelection = new Set(items.filter((item) => item.default_selected).map((item) => item.id));
    }
    if (job.status !== "awaiting_cleanup") {
      state.jobCleanupMode = null;
    }
    state.job = job;
    if (previousStatus && previousStatus !== job.status) {
      const scanned = job.status === "completed" || job.status === "failed" || job.status === "cancelled";
      if (scanned) loadState().catch(() => {});
      if (job.status === "awaiting_cleanup") {
        toast("残留扫描完成，请确认要清理的项目", "ok");
      }
      if (job.status === "failed") toast(job.message || "任务失败", "error");
    }
    if (state.jobModalOpen) {
      const sig = jobRenderSignature(job);
      if (sig !== state.jobRenderSig) {
        renderJobModal(true);
      } else {
        renderMiniJob();
      }
    } else {
      renderMiniJob();
    }
    if (!state.dialogOpen && !state.jobModalOpen && job.active) {
      $("miniJob").hidden = false;
    }
  }

  function jobRenderSignature(job) {
    return [
      job.status,
      job.phase,
      job.message,
      job.still_installed,
      job.leftover ? `${job.leftover.scanned_at}|${(job.leftover.items || []).length}` : "",
      job.cleanup ? `${job.cleanup.total}|${job.cleanup.failed}|${job.cleanup.removed_bytes}` : "",
      job.app ? `${job.app.icon_version || ""}` : "",
      state.jobCleanupMode || "",
      state.cleanupSubmitting ? "submitting" : "",
    ].join("|");
  }

  function jobSteps(job) {
    const force = job.mode === "force";
    const labels = force
      ? ["准备清理", "扫描残留", "确认清理", "完成"]
      : ["启动卸载", "等待完成", "扫描残留", "确认清理", "完成"];
    let active = 0;
    const status = job.status;
    if (force) {
      if (status === "starting") active = 0;
      else if (status === "scanning") active = 1;
      else if (status === "awaiting_cleanup" || status === "cleaning") active = 2;
      else if (status === "completed") active = 3;
      else if (status === "failed" || status === "cancelled") active = -1;
    } else {
      if (status === "starting") active = 0;
      else if (status === "uninstalling" || status === "waiting") active = 1;
      else if (status === "scanning") active = 2;
      else if (status === "awaiting_cleanup" || status === "cleaning") active = 3;
      else if (status === "completed") active = 4;
      else if (status === "failed" || status === "cancelled") active = -1;
    }
    const doneAll = status === "completed";
    return labels.map((label, index) => {
      const done = doneAll || index < active;
      const isActive = !doneAll && index === active;
      return `<div class="job-step ${done ? "done" : ""} ${isActive ? "active" : ""}">
        <span class="step-dot">${done ? icon("i-check") : String(index + 1)}</span>
        <span class="step-label">${esc(label)}</span>
      </div>`;
    }).join("");
  }

  function statusPill(job) {
    let cls = "";
    if (job.status === "completed") cls = "";
    else if (job.status === "failed" || job.status === "cancelled") cls = "danger";
    else if (job.status === "awaiting_cleanup") cls = "warn";
    else if (job.status === "cleaning" || job.status === "scanning" || job.status === "starting") cls = "neutral";
    return `<span class="status-pill ${cls}">${esc(job.status_label || job.status)}</span>`;
  }

  function jobHead(job) {
    const closeAct = job.active ? "minimize-job" : "close-job";
    return `<div class="job-head">
      ${jobAvatar(job, "job-app-icon app-avatar")}
      <div class="job-head-copy">
        <div class="job-kicker">${statusPill(job)}<span>${job.mode === "force" ? "仅清理残留" : "卸载与深度清理"}</span><span>#${esc(String(job.id || "").slice(1, 9))}</span></div>
        <h2 class="job-title">${esc(job.app_name || "清理任务")}</h2>
        <p class="job-subtitle">${esc(job.phase || "")}${job.elevated ? " · 已请求管理员权限" : ""}</p>
      </div>
      <button class="icon-btn modal-close" data-act="${closeAct}" type="button" aria-label="${job.active ? "收起任务" : "关闭"}">${icon("i-x")}</button>
    </div>`;
  }

  function jobLogs(job, open = false) {
    const logs = Array.isArray(job.logs) ? job.logs : [];
    return `<details class="job-logs" ${open ? "open" : ""}><summary>${icon("i-history")}运行日志（${logs.length} 条）</summary>
      <div class="log-list">${logs.map((entry) => `<div class="log-line ${entry.level === "error" ? "error" : entry.level === "warn" ? "warn" : ""}">
        <span class="log-time">${esc((entry.time || "").slice(11))}</span><span>${esc(entry.message)}</span>
      </div>`).join("")}</div>
    </details>`;
  }

  function heroView(job) {
    const status = job.status;
    let title = job.phase || "正在处理";
    let sub = job.message || "";
    if (status === "uninstalling" || status === "waiting") {
      title = "卸载程序已打开";
      sub = job.message || "请在弹出的卸载窗口中完成操作。卸载结束后会自动继续扫描残留；如果没有反应，可以点击“重新检查”。";
    } else if (status === "scanning") {
      title = "正在扫描残留";
      sub = "正在检查安装目录、AppData、开始菜单快捷方式和卸载注册项。文件较多时需要一些时间。";
    } else if (status === "cleaning") {
      title = "正在清理选中的项目";
      sub = "文件正在移入回收站，大目录可能需要一些时间。请保持工具和页面运行。";
    } else if (status === "starting") {
      title = "正在准备任务";
      sub = job.message || "即将启动卸载程序。";
    }
    const actions = [];
    if (status === "uninstalling" || status === "waiting") {
      actions.push(`<button class="btn btn-ghost" data-act="recheck" type="button">${icon("i-refresh")}重新检查</button>`);
      actions.push(`<button class="btn btn-danger-quiet" data-act="cancel-job" type="button">取消任务</button>`);
    } else if (status === "starting") {
      actions.push(`<button class="btn btn-ghost" data-act="cancel-job" type="button">取消任务</button>`);
    }
    const facts = [
      `<span class="fact">模式：${job.mode === "force" ? "仅清理残留" : "官方卸载 + 深度清理"}</span>`,
      `<span class="fact">权限：${job.is_admin ? "管理员" : "当前用户"}${job.elevated ? "（卸载程序已提权）" : ""}</span>`,
      job.pid ? `<span class="fact">进程 PID <code>${esc(job.pid)}</code></span>` : "",
    ].filter(Boolean).join("");
    return `<div class="job-hero">
      <div class="hero-spinner" aria-hidden="true"></div>
      <h3>${esc(title)}</h3>
      <p>${esc(sub)}</p>
      ${actions.length ? `<div class="job-actions">${actions.join("")}</div>` : ""}
      <div class="job-facts">${facts}</div>
      ${jobLogs(job)}
    </div>`;
  }

  function sectionList(job) {
    const leftover = job.leftover || {};
    const defs = Array.isArray(leftover.sections) && leftover.sections.length ? leftover.sections : [
      { key: "install", label: "程序文件", hint: "" },
      { key: "userdata", label: "用户数据", hint: "" },
      { key: "publicdata", label: "公共数据", hint: "" },
      { key: "shortcuts", label: "快捷方式", hint: "" },
      { key: "registry", label: "注册表项", hint: "" },
    ];
    const items = Array.isArray(leftover.items) ? leftover.items : [];
    const order = new Map(defs.map((d, i) => [d.key, i]));
    const groups = new Map();
    for (const item of items) {
      if (!groups.has(item.section)) groups.set(item.section, []);
      groups.get(item.section).push(item);
    }
    return [...groups.entries()]
      .sort((a, b) => (order.has(a[0]) ? order.get(a[0]) : 99) - (order.has(b[0]) ? order.get(b[0]) : 99))
      .map(([key, groupItems]) => ({
        def: defs.find((d) => d.key === key) || { key, label: key, hint: "" },
        items: groupItems,
      }));
  }

  function itemIcon(kind) {
    if (kind === "dir") return "i-folder";
    if (kind === "shortcut") return "i-link";
    return "i-reg";
  }

  function riskTag(risk) {
    if (risk === "high") return `<span class="risk high">请确认</span>`;
    if (risk === "caution") return `<span class="risk caution">谨慎</span>`;
    return `<span class="risk normal">常规</span>`;
  }

  function cleanupItemRow(item) {
    const selected = state.jobSelection.has(item.id);
    const size = item.bytes != null ? humanSize(item.bytes) : "—";
    const conf = item.confidence === "high" ? "高置信度" : item.confidence === "medium" ? "名称推断" : "";
    const kindLabel = item.kind === "dir" ? "目录" : item.kind === "shortcut" ? "快捷方式" : item.kind === "registry_value" ? "启动项" : "注册表";
    return `<div class="leftover-row ${selected ? "selected" : ""}" data-item-row="${esc(item.id)}">
      <label class="checkline" aria-label="选择 ${esc(item.label)}">
        <input type="checkbox" data-item-check="${esc(item.id)}" ${selected ? "checked" : ""}>
      </label>
      <span class="leftover-kind">${icon(itemIcon(item.kind))}</span>
      <div class="leftover-copy">
        <div class="leftover-title-line">
          <span class="leftover-label">${esc(item.label || kindLabel)}</span>
          ${riskTag(item.risk)}
          ${conf ? `<span class="tag tag-conf">${conf}</span>` : ""}
          ${item.kind === "registry" || item.kind === "registry_value" ? `<span class="tag tag-backup">自动备份</span>` : ""}
        </div>
        <div class="leftover-path">${esc(item.display_path || item.path || "")}</div>
        ${item.note ? `<div class="leftover-note">${esc(item.note)}</div>` : ""}
      </div>
      <span class="leftover-size">${size}</span>
    </div>`;
  }

  function leftoverView(job) {
    const leftover = job.leftover || { items: [], notice: [] };
    const items = Array.isArray(leftover.items) ? leftover.items : [];
    const groups = sectionList(job);
    const selected = items.filter((item) => state.jobSelection.has(item.id));
    const selectedBytes = selected.reduce((sum, item) => sum + (Number(item.bytes) || 0), 0);
    if (!items.length) {
      return `<div class="job-empty"><strong>没有发现可安全清理的残留</strong><span>软件可能已完成卸载并自行清理了文件。个人文档、下载目录不会被扫描。</span></div>
        ${jobLogs(job)}`;
    }
    const stillWarning = job.still_installed ? `<div class="job-message warn">${icon("i-alert")}<span>${
      job.mode === "force"
        ? "“仅清理残留”模式不会移除卸载注册项，软件仍会出现在已安装列表中。为避免误删正在使用的程序，所有项目默认未勾选；请只选择确认无用的残留。"
        : "软件仍在已安装列表中。它可能还没有完成卸载，所有项目已默认取消勾选；请先确认卸载完成，或只选择明确无用的项目。"
    }</span></div>` : "";
    const notices = Array.isArray(leftover.notice) ? leftover.notice : [];
    const topNotice = notices.length
      ? `<p class="job-notice">${notices.map((n) => esc(n)).join(" · ")}</p>` : "";
    return `${stillWarning}
      ${job.message ? `<div class="job-message ${job.status === "waiting" ? "warn" : ""}">${icon("i-scan")}<span>${esc(job.message)}</span></div>` : ""}
      <div class="leftover-overview">
        <div><h3 class="overview-title">发现 ${items.length} 项关联内容</h3>
          <span class="overview-sub">共 ${humanSize(leftover.all_bytes || 0)} · 默认勾选 ${items.filter((i) => i.default_selected).length} 项</span></div>
        <div class="overview-actions">
          <button class="mini-link" data-act="select-default" type="button">推荐项</button>
          <button class="mini-link" data-act="select-all" type="button">全选</button>
          <button class="mini-link" data-act="select-none" type="button">清空</button>
        </div>
      </div>
      ${topNotice}
      ${groups.map(({ def, items: groupItems }) => {
        const allSelected = groupItems.every((i) => state.jobSelection.has(i.id));
        const someSelected = groupItems.some((i) => state.jobSelection.has(i.id));
        const groupSize = groupItems.reduce((sum, i) => sum + (Number(i.bytes) || 0), 0);
        return `<section class="leftover-section">
          <div class="section-head">
            <label class="checkline"><input type="checkbox" data-section-check="${esc(def.key)}" ${allSelected ? "checked" : ""} data-indeterminate="${!allSelected && someSelected ? "1" : "0"}"><span class="section-name">${esc(def.label)}</span></label>
            <span class="section-hint">${esc(def.hint || "")}</span>
            <span class="section-size">${groupSize ? humanSize(groupSize) : ""}</span>
          </div>
          ${groupItems.map(cleanupItemRow).join("")}
        </section>`;
      }).join("")}
      <p class="job-notice">删除方式由你选择：默认移入回收站，可在恢复前撤销；注册表项会先导出 .reg 备份。文档、下载、图片等个人目录不在此列表中。</p>
      ${jobLogs(job)}`;
  }

  function selectionBar(job) {
    const items = (job.leftover && job.leftover.items) || [];
    const selected = items.filter((item) => state.jobSelection.has(item.id));
    const selectedBytes = selected.reduce((sum, item) => sum + (Number(item.bytes) || 0), 0);
    const amount = !selected.length ? "尚未选择项目" : selectedBytes ? humanSize(selectedBytes) : "仅注册表项";
    return `<div class="selection-bar">
      <div class="selection-info">
        <strong>已选 ${selected.length} 项</strong>
        <span>${amount} · ${state.job.still_installed ? "软件仍在使用，请谨慎" : "移入回收站可撤销"}</span>
      </div>
      <div class="selection-actions">
        <button class="mini-link" data-act="cancel-job" type="button">放弃清理</button>
        <button class="btn btn-danger-quiet" data-act="cleanup-permanent" type="button" ${selected.length ? "" : "disabled"}>${icon("i-trash")}永久删除…</button>
        <button class="btn btn-primary" data-act="cleanup-recycle" type="button" ${selected.length ? "" : "disabled"}>${icon("i-check")}移入回收站</button>
      </div>
    </div>`;
  }

  function cleanupConfirmView(job) {
    const permanent = state.jobCleanupMode === "permanent";
    const items = (job.leftover && job.leftover.items) || [];
    const selected = items.filter((item) => state.jobSelection.has(item.id));
    const bytes = selected.reduce((sum, item) => sum + (Number(item.bytes) || 0), 0);
    const preview = selected.slice(0, 6).map((item) => `<li class="result-item">${icon("i-check")}<div><div>${esc(item.label)}</div><div class="res-path">${esc(item.display_path || item.path || "")}</div></div></li>`).join("");
    const more = selected.length > 6 ? `<li class="result-item">还有 ${selected.length - 6} 项…</li>` : "";
    return `<div class="confirm-visual">
        ${jobAvatar(job, "app-avatar")}
        <div><div class="cv-name">${esc(job.app_name)}</div><div class="cv-sub">已选 ${selected.length} 项${bytes ? ` · ${humanSize(bytes)}` : ""}</div></div>
      </div>
      ${permanent
        ? `<div class="confirm-warning danger"><strong>永久删除不可恢复。</strong>所选目录和文件将直接绕过回收站删除，无法撤销。请只在确认这些内容不再需要时继续。</div>
           <div class="field"><label for="permanentNameInput">输入软件名称以确认</label>
             <input class="input" id="permanentNameInput" type="text" autocomplete="off" spellcheck="false" placeholder="${esc(job.app_name)}">
             <p class="field-hint">请输入 <code>${esc(job.app_name)}</code>。注册表项也会先备份，但文件不会进入回收站。</p>
           </div>`
        : `<div class="confirm-warning">这些项目将移动到 Windows 回收站，必要时可以恢复。仍建议确认列表中没有需要的聊天记录、浏览器配置或项目文件。</div>`}
      <ul class="result-list">${preview}${more}</ul>`;
  }

  function jobFooter(job) {
    if (state.jobCleanupMode) {
      const permanent = state.jobCleanupMode === "permanent";
      return `<div class="modal-foot job-modal-foot">
        <button class="btn btn-ghost" data-act="cleanup-back" type="button" ${state.cleanupSubmitting ? "disabled" : ""}>返回列表</button>
        <button class="btn ${permanent ? "btn-danger" : "btn-primary"}" data-act="cleanup-confirm" type="button" ${state.cleanupSubmitting ? "disabled" : ""}>
          ${state.cleanupSubmitting ? "正在清理…" : permanent ? "确认永久删除" : "确认移入回收站"}
        </button>
      </div>`;
    }
    if (job.status === "awaiting_cleanup" && (job.leftover && (job.leftover.items || []).length)) {
      return selectionBar(job);
    }
    return "";
  }

  function jobSummary(job) {
    const cleanup = job.cleanup || {};
    const results = Array.isArray(cleanup.items) ? cleanup.items : [];
    const failed = results.filter((r) => !r.ok);
    const title = failed.length ? "清理完成，但有项目未处理" : "清理完成";
    const sub = job.still_installed
      ? "软件仍在已安装列表中，建议确认清理范围是否确实无用。"
      : job.mode === "force"
        ? "仅清理残留模式已完成。文档、下载和图片目录未被触碰。"
        : "官方卸载过程已结束。文档、下载和图片目录未被触碰。";
    return `<div class="job-summary">
      <div class="summary-hero">
        <span class="summary-icon">${icon(failed.length ? "i-alert" : "i-check-circle")}</span>
        <div><h3>${title}</h3><p>${esc(sub)}</p></div>
      </div>
      <div class="summary-grid">
        <div class="summary-card"><div class="summary-value">${cleanup.total || 0}</div><div class="summary-label">处理项目</div></div>
        <div class="summary-card"><div class="summary-value">${cleanup.removed_bytes ? humanSize(cleanup.removed_bytes) : "0 B"}</div><div class="summary-label">处理数据量</div></div>
        <div class="summary-card"><div class="summary-value ${failed.length ? "danger" : ""}">${failed.length}</div><div class="summary-label">失败项目</div></div>
      </div>
      ${results.length ? `<ul class="result-list">${results.map((r) => `<li class="result-item ${r.ok ? "" : "failed"}">
        ${icon(r.ok ? "i-check" : "i-alert")}<div><div>${esc(r.label || r.path)}${r.ok ? "" : `：${esc(r.error || "失败")}`}</div><div class="res-path">${esc(r.path || "")}</div></div>
      </li>`).join("")}</ul>` : ""}
      ${cleanup.backup_dir ? `<p class="job-notice">注册表备份已保存到：<code>${esc(cleanup.backup_dir)}</code></p>` : ""}
      <div class="job-facts" style="justify-content:flex-start;margin-top:15px">
        <button class="btn btn-ghost btn-small" data-act="download-report" type="button">${icon("i-package")}下载报告</button>
        <button class="btn btn-ghost btn-small" data-act="open-report-folder" type="button">${icon("i-folder")}打开报告文件夹</button>
        <button class="btn btn-soft btn-small" data-act="close-job" type="button">${icon("i-check")}完成</button>
      </div>
      ${jobLogs(job, failed.length > 0)}
    </div>`;
  }

  function renderJobModal(preserveScroll = false) {
    const job = state.job;
    if (!job) return;
    state.jobModalOpen = true;
    const root = $("modalRoot");
    const scrollTop = preserveScroll ? (root.querySelector(".job-body")?.scrollTop || 0) : 0;
    root.hidden = false;
    updateBodyLock();
    let body = "";
    let footer = "";
    if (state.jobCleanupMode) {
      body = cleanupConfirmView(job);
      footer = jobFooter(job);
    } else if (job.status === "awaiting_cleanup") {
      body = leftoverView(job);
      footer = jobFooter(job);
    } else if (job.status === "completed") {
      body = jobSummary(job);
    } else if (job.status === "failed" || job.status === "cancelled") {
      body = `<div class="job-message danger">${icon("i-alert")}<span>${esc(job.message || job.phase || "任务未完成")}</span></div>
        <div class="job-hero">
          <h3>${job.status === "cancelled" ? "任务已取消" : "任务没有完成"}</h3>
          <p>${job.status === "cancelled"
            ? (job.mode === "force" ? "未执行任何文件清理。" : "未执行进一步的文件操作。已打开的官方卸载程序不会被强制关闭。")
            : "已经执行的步骤记录在下方日志中。你可以关闭任务后重新选择软件，或改用“仅清理残留”。"}</p>
          <div class="job-actions"><button class="btn btn-ghost" data-act="close-job" type="button">关闭任务</button></div>
          ${jobLogs(job, true)}
        </div>`;
    } else {
      body = heroView(job);
    }
    root.innerHTML = `<div class="modal job-modal" role="dialog" aria-modal="true" aria-labelledby="jobTitle">
      ${jobHead(job)}
      <div class="job-steps">${jobSteps(job)}</div>
      <div class="job-body">${body}</div>
      ${footer}
    </div>`;
    const bodyEl = root.querySelector(".job-body");
    if (bodyEl && preserveScroll) bodyEl.scrollTop = scrollTop;
    const heading = root.querySelector(".job-title");
    if (heading) heading.id = "jobTitle";
    const indeterminate = root.querySelectorAll('input[data-indeterminate="1"]');
    indeterminate.forEach((el) => { el.indeterminate = true; });
    state.jobRenderSig = jobRenderSignature(job);
    const permanentInput = $("permanentNameInput");
    if (permanentInput) {
      const confirmButton = root.querySelector('[data-act="cleanup-confirm"]');
      if (confirmButton) confirmButton.disabled = true;
      permanentInput.addEventListener("input", () => {
        if (confirmButton) {
          confirmButton.disabled = permanentInput.value.trim() !== String(job.app_name || "").trim();
        }
      });
      setTimeout(() => permanentInput.focus(), 60);
    }
    renderMiniJob();
  }

  function minimizeJob() {
    state.jobModalOpen = false;
    $("modalRoot").hidden = true;
    $("modalRoot").innerHTML = "";
    updateBodyLock();
    renderMiniJob();
  }

  function closeJobView() {
    if (state.job && state.job.active) {
      if (state.job.status === "awaiting_cleanup") {
        toast("请先确认清理或点击“放弃清理”结束任务", "error");
        return;
      }
      minimizeJob();
      return;
    }
    state.jobModalOpen = false;
    state.job = null;
    state.trackedJobId = null;
    state.jobSelection = new Set();
    state.jobLeftoverSig = null;
    state.jobRenderSig = null;
    $("modalRoot").hidden = true;
    $("modalRoot").innerHTML = "";
    $("miniJob").hidden = true;
    updateBodyLock();
    loadState().catch(() => {});
  }

  function renderMiniJob() {
    const job = state.job;
    const node = $("miniJob");
    if (!job || !state.trackedJobId || !job.active || state.jobModalOpen) {
      node.hidden = true;
      return;
    }
    node.hidden = false;
    $("miniJobTitle").textContent = job.app_name || "清理任务";
    $("miniJobStatus").textContent = job.status === "awaiting_cleanup"
      ? "等待确认清理项目"
      : job.status_label || job.phase || "正在处理";
    const spinner = node.querySelector(".mini-spinner");
    if (spinner) spinner.style.display = job.status === "awaiting_cleanup" ? "none" : "";
  }

  async function doCleanup(permanent) {
    if (state.cleanupSubmitting) return;
    const job = state.job;
    if (!job) return;
    const items = (job.leftover && job.leftover.items) || [];
    const ids = items.filter((item) => state.jobSelection.has(item.id)).map((item) => item.id);
    if (!ids.length) return toast("请至少选择一个项目", "error");
    if (permanent) {
      const input = $("permanentNameInput");
      if (!input || input.value.trim() !== String(job.app_name || "").trim()) {
        return toast("请完整输入软件名称", "error");
      }
    }
    state.cleanupSubmitting = true;
    renderJobModal(true);
    try {
      const result = await api(`/api/jobs/${encodeURIComponent(job.id)}/cleanup`, {
        method: "POST",
        body: {
          item_ids: ids,
          permanent: Boolean(permanent),
          confirm_name: permanent ? (($("permanentNameInput") || {}).value || "") : "",
        },
      });
      state.cleanupSubmitting = false;
      state.jobCleanupMode = null;
      if (result.job) {
        state.job = result.job;
        if (result.job.cleanup) {
          toast(`清理完成：${result.job.cleanup.total} 项，失败 ${result.job.cleanup.failed} 项`,
            result.job.cleanup.failed ? "error" : "ok");
        }
      }
      state.jobRenderSig = null;
      renderJobModal();
      loadState().catch(() => {});
    } catch (err) {
      state.cleanupSubmitting = false;
      renderJobModal(true);
      if (!err.handled) toast(err.message || "清理失败", "error");
    }
  }

  async function jobAction(act, target) {
    const job = state.job;
    if (!job) return;
    if (act === "minimize-job") return minimizeJob();
    if (act === "close-job") return closeJobView();
    if (act === "recheck") {
      target.disabled = true;
      try {
        await api(`/api/jobs/${encodeURIComponent(job.id)}/recheck`, { method: "POST", body: {} });
        toast("已请求重新检查，请稍候", "ok");
        schedule(700);
      } catch (err) {
        if (!err.handled) toast(err.message, "error");
      } finally {
        target.disabled = false;
      }
      return;
    }
    if (act === "cancel-job") {
      const msg = job.status === "awaiting_cleanup"
        ? "放弃清理并结束任务？已发现的残留不会删除。"
        : "取消任务？已经打开的官方卸载程序不会被关闭，之后也不会自动清理文件。";
      openSimpleModal({
        title: "取消清理任务",
        subtitle: "不会删除任何尚未确认的文件",
        body: `<p class="confirm-warning danger">${esc(msg)}</p>`,
        confirm: "取消任务",
        danger: true,
        onConfirm: async () => {
          try {
            const result = await api(`/api/jobs/${encodeURIComponent(job.id)}/cancel`, { method: "POST", body: {} });
            if (result.job) state.job = result.job;
            state.jobRenderSig = null;
            closeSimpleModal();
            renderJobModal();
            schedule(500);
            return "handled";
          } catch (err) {
            if (!err.handled) toast(err.message, "error");
            return false;
          }
        },
      });
      return;
    }
    if (act === "select-all" || act === "select-none" || act === "select-default") {
      const items = (job.leftover && job.leftover.items) || [];
      if (act === "select-all") state.jobSelection = new Set(items.map((item) => item.id));
      else if (act === "select-none") state.jobSelection = new Set();
      else state.jobSelection = new Set(items.filter((item) => item.default_selected).map((item) => item.id));
      renderJobModal(true);
      return;
    }
    if (act === "cleanup-recycle") {
      state.jobCleanupMode = "recycle";
      renderJobModal();
      return;
    }
    if (act === "cleanup-permanent") {
      state.jobCleanupMode = "permanent";
      renderJobModal();
      return;
    }
    if (act === "cleanup-back") {
      state.jobCleanupMode = null;
      renderJobModal(true);
      return;
    }
    if (act === "cleanup-confirm") {
      return doCleanup(state.jobCleanupMode === "permanent");
    }
    if (act === "download-report") return downloadReport(job);
    if (act === "open-report-folder") {
      try {
        await api("/api/open-report-folder", { method: "POST", body: { job_id: job.id } });
        toast("已打开报告所在文件夹", "ok");
      } catch (err) {
        if (!err.handled) toast(err.message, "error");
      }
    }
  }

  async function downloadReport(job) {
    try {
      const response = await fetch(`/api/jobs/${encodeURIComponent(job.id)}/report`, {
        headers: { "X-Token": token },
        cache: "no-store",
      });
      if (!response.ok) {
        let message = "报告尚未生成";
        try { const data = await response.json(); message = data.error || message; } catch (err) {}
        throw new Error(message);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      const safeName = String(job.app_name || "软件").replace(/[\\/:*?"<>|]+/g, "_");
      anchor.href = url;
      anchor.download = `SoftSweep_${safeName}_报告.txt`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
    } catch (err) {
      if (!err.handled) toast(err.message || "下载报告失败", "error");
    }
  }

  // ---------------------------------------------------------------- history
  function openHistoryModal() {
    state.dialogOpen = true;
    state.dialogKind = "history";
    $("dialogRoot").hidden = false;
    updateBodyLock();
    renderHistoryModal();
  }

  function renderHistoryModal() {
    const jobs = state.history || [];
    const body = jobs.length ? `<div class="history-list">${jobs.map((job) => {
      const active = job.active;
      const label = job.status_label || job.status;
      const cls = job.status === "completed" ? "" : job.status === "failed" || job.status === "cancelled" ? "danger" : active ? "warn" : "neutral";
      return `<button class="history-row" data-history-id="${esc(job.id)}" type="button">
        ${jobAvatar(job, "app-avatar history-avatar")}
        <span class="history-main">
          <div class="history-name">${esc(job.app_name || "未命名任务")}</div>
          <div class="history-sub">${dateTimeText(job.created_at)} · ${job.mode === "force" ? "仅清理残留" : "官方卸载 + 清理"}</div>
        </span>
        <span class="status-pill ${cls} history-badge">${esc(label)}</span>
        <span class="row-arrow">${icon("i-chevron")}</span>
      </button>`;
    }).join("")}</div>` : `<div class="history-empty">还没有任务记录。选择一个软件开始清理后，记录会出现在这里。</div>`;
    $("dialogRoot").innerHTML = `<div class="modal history-modal" role="dialog" aria-modal="true">
      <div class="modal-head">
        <div class="modal-title-wrap"><h2 class="modal-title">任务记录</h2><p class="modal-sub">最近的卸载和清理任务；报告文件保存在 data/logs 目录。</p></div>
        <button class="icon-btn modal-close" data-simple-close type="button" aria-label="关闭">${icon("i-x")}</button>
      </div>
      <div class="modal-body">${body}</div>
      <div class="modal-foot"><button class="btn btn-ghost" data-simple-close type="button">关闭</button></div>
    </div>`;
  }

  async function openHistoryJob(jobId) {
    try {
      const data = await api(`/api/jobs/${encodeURIComponent(jobId)}`);
      if (!data.job) return;
      closeSimpleModal();
      state.trackedJobId = data.job.id;
      state.job = data.job;
      state.jobModalOpen = true;
      state.jobCleanupMode = null;
      state.jobLeftoverSig = data.job.leftover ? `${data.job.leftover.scanned_at}|${(data.job.leftover.items || []).length}` : null;
      state.jobSelection = new Set((data.job.leftover?.items || []).filter((item) => item.default_selected).map((item) => item.id));
      renderJobModal();
    } catch (err) {
      if (!err.handled) toast(err.message, "error");
    }
  }

  // ----------------------------------------------------------------- events
  function updateSelectionUI() {
    const job = state.job;
    if (!job) return;
    const root = $("modalRoot");
    const items = (job.leftover && job.leftover.items) || [];
    items.forEach((item) => {
      const row = root.querySelector(`[data-item-row="${item.id}"]`);
      const box = root.querySelector(`[data-item-check="${item.id}"]`);
      const selected = state.jobSelection.has(item.id);
      if (row) row.classList.toggle("selected", selected);
      if (box) box.checked = selected;
    });
    root.querySelectorAll("[data-section-check]").forEach((box) => {
      const key = box.getAttribute("data-section-check");
      const group = items.filter((item) => item.section === key);
      const selectedCount = group.filter((item) => state.jobSelection.has(item.id)).length;
      box.checked = group.length > 0 && selectedCount === group.length;
      box.indeterminate = selectedCount > 0 && selectedCount < group.length;
    });
    const selected = items.filter((item) => state.jobSelection.has(item.id));
    const bytes = selected.reduce((sum, item) => sum + (Number(item.bytes) || 0), 0);
    const info = root.querySelector(".selection-info");
    if (info) {
      const amount = !selected.length ? "尚未选择项目" : bytes ? humanSize(bytes) : "仅注册表项";
      info.innerHTML = `<strong>已选 ${selected.length} 项</strong><span>${amount} · ${job.still_installed ? "软件仍在使用，请谨慎" : "移入回收站可撤销"}</span>`;
    }
    root.querySelectorAll('[data-act="cleanup-recycle"], [data-act="cleanup-permanent"]').forEach((button) => {
      button.disabled = selected.length === 0;
    });
  }

  function bindEvents() {
    document.addEventListener("error", (event) => {
      const image = event.target;
      if (!image || image.tagName !== "IMG" || !image.classList.contains("app-icon-img")) return;
      const tile = image.parentElement;
      if (tile) tile.classList.remove("with-icon");
      image.remove();
    }, true);

    $("searchInput").addEventListener("input", (event) => {
      clearTimeout(state.searchTimer);
      const value = event.target.value;
      state.searchTimer = setTimeout(() => {
        state.filters.query = value;
        renderCategories();
        renderList();
      }, 120);
    });

    $("sourceFilter").addEventListener("change", (event) => {
      state.filters.source = event.target.value;
      renderCategories();
      renderList();
    });
    $("sortSelect").addEventListener("change", (event) => {
      state.filters.sort = event.target.value;
      renderList();
    });
    $("showProtected").addEventListener("change", (event) => {
      state.filters.showProtected = event.target.checked;
      if (state.filters.category !== "all" && !state.filters.showProtected) {
        const stillVisible = state.apps.some((a) => a.category === state.filters.category && a.primary);
        if (!stillVisible) state.filters.category = "all";
      }
      renderCategories();
      renderList();
    });

    $("refreshBtn").addEventListener("click", () => {
      if (state.scanStatus === "scanning") return;
      state.started = true;
      startScan();
    });
    $("historyBtn").addEventListener("click", openHistoryModal);
    $("quitBtn").addEventListener("click", openQuitDialog);
    $("adminHelpBtn").addEventListener("click", openAdminHelp);

    $("categoryNav").addEventListener("click", (event) => {
      const button = event.target.closest("[data-cat]");
      if (!button) return;
      state.filters.category = button.getAttribute("data-cat");
      renderCategories();
      renderList();
    });

    $("appList").addEventListener("click", (event) => {
      const row = event.target.closest(".app-row[data-app-id]");
      if (row) openDrawer(row.getAttribute("data-app-id"));
    });
    $("appList").addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      const row = event.target.closest(".app-row[data-app-id]");
      if (!row) return;
      event.preventDefault();
      openDrawer(row.getAttribute("data-app-id"));
    });

    $("overlay").addEventListener("click", closeDrawer);
    $("appDrawer").addEventListener("click", (event) => {
      if (event.target.closest("[data-drawer-close]")) return closeDrawer();
      const action = event.target.closest("[data-drawer-act]");
      if (action) {
        const appId = state.drawerAppId;
        const mode = action.getAttribute("data-drawer-act");
        if (!appId) return;
        openStartDialog(appId, mode);
      }
    });

    $("miniJobOpen").addEventListener("click", () => {
      if (!state.job) return;
      state.jobModalOpen = true;
      renderJobModal();
    });

    $("dialogRoot").addEventListener("click", (event) => {
      if (event.target === $("dialogRoot")) {
        closeSimpleModal();
        return;
      }
      if (event.target.closest("[data-simple-close]")) {
        closeSimpleModal();
        return;
      }
      const confirmBtn = event.target.closest("[data-simple-confirm]");
      if (confirmBtn) {
        runSimpleConfirm(confirmBtn);
        return;
      }
      const historyRow = event.target.closest("[data-history-id]");
      if (historyRow) {
        openHistoryJob(historyRow.getAttribute("data-history-id"));
      }
    });

    $("modalRoot").addEventListener("click", (event) => {
      const actionNode = event.target.closest("[data-act]");
      if (actionNode) {
        jobAction(actionNode.getAttribute("data-act"), actionNode);
      }
    });

    $("modalRoot").addEventListener("change", (event) => {
      const checkbox = event.target;
      if (checkbox.matches("[data-item-check]")) {
        const id = checkbox.getAttribute("data-item-check");
        if (checkbox.checked) state.jobSelection.add(id);
        else state.jobSelection.delete(id);
        updateSelectionUI();
        return;
      }
      if (checkbox.matches("[data-section-check]")) {
        const key = checkbox.getAttribute("data-section-check");
        const items = (state.job?.leftover?.items || []).filter((item) => item.section === key);
        items.forEach((item) => {
          if (checkbox.checked) state.jobSelection.add(item.id);
          else state.jobSelection.delete(item.id);
        });
        updateSelectionUI();
      }
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        if (state.dialogOpen) {
          closeSimpleModal();
        } else if (state.jobModalOpen) {
          if (state.jobCleanupMode) {
            state.jobCleanupMode = null;
            renderJobModal(true);
          } else if (state.job && state.job.status === "awaiting_cleanup") {
            toast("请先确认清理或放弃清理", "error");
          } else {
            minimizeJob();
          }
        } else if (state.drawerOpen) {
          closeDrawer();
        }
        return;
      }
      if (event.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) {
        event.preventDefault();
        $("searchInput").focus();
      }
    });
  }

  // ------------------------------------------------------------------- boot
  function init() {
    if (!token) {
      fatal(
        "请从启动器打开",
        "缺少本次会话的访问令牌。为保护本机软件信息，SoftSweep 的接口只接受由启动器生成的页面。请关闭本页，运行 启动.bat。",
        "启动.bat"
      );
      return;
    }
    bindEvents();
    if ("scrollRestoration" in history) history.scrollRestoration = "manual";
    loadState()
      .then(() => {
        schedule(900);
      })
      .catch((err) => {
        if (err.handled) return;
        fatal(
          "无法连接 SoftSweep",
          err.message || "本地服务没有响应，请确认工具仍在运行。",
          "data/logs/server.log"
        );
      });
  }

  init();
})();
