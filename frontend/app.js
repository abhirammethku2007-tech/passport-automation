const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function msg(text, type = "success", target = "#message") {
  const element = $(target);
  if (!element) return;
  element.textContent = text;
  element.className = `message show ${type}`;
}

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers
    }
  });
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("The local server returned an unexpected response. Restart it and try again.");
  }
  if (!response.ok) {
    const error = new Error(data.error || "The request could not be completed.");
    error.status = response.status;
    throw error;
  }
  return data;
}

async function getSession() {
  return api("/api/session");
}

function readLegacyArray(key) {
  const saved = localStorage.getItem(key);
  if (saved === null) return [];
  let value;
  try {
    value = JSON.parse(saved);
  } catch {
    throw new Error(`Your older browser data in ${key} could not be read. It has been left unchanged.`);
  }
  if (!Array.isArray(value)) {
    throw new Error(`Your older browser data in ${key} has an unexpected format. It has been left unchanged.`);
  }
  return value;
}

async function migrateLegacyBrowserData() {
  if (localStorage.getItem("pa_users") === null && localStorage.getItem("pa_apps") === null) return false;
  const users = readLegacyArray("pa_users");
  const applications = readLegacyArray("pa_apps");
  if (users.length === 0 && applications.length > 0) {
    throw new Error("Saved applications were found without their account records. The old browser data has been left unchanged.");
  }

  const migratedApplicationIds = new Set();
  for (const user of users) {
    if (!user || typeof user.email !== "string") {
      throw new Error("An older applicant account is missing its email address. The old browser data has been left unchanged.");
    }
    const email = user.email.trim().toLowerCase();
    const ownedApplications = applications.filter(application => {
      const ownerEmail = typeof application?.userEmail === "string"
        ? application.userEmail.trim().toLowerCase()
        : "";
      return ownerEmail === email;
    });
    for (const application of ownedApplications) {
      if (typeof application.id === "string") migratedApplicationIds.add(application.id);
    }
    await api("/api/migrate-legacy", {
      method: "POST",
      body: JSON.stringify({ user, applications: ownedApplications })
    });
  }
  if (migratedApplicationIds.size !== applications.length) {
    throw new Error("Some older applications do not match a saved account. The old browser data has been left unchanged.");
  }

  const oldSession = sessionStorage.getItem("pa_current");
  if (oldSession) {
    let previousUser;
    try {
      previousUser = JSON.parse(oldSession);
    } catch {
      throw new Error("Your previous sign-in could not be restored. The old browser data has been left unchanged.");
    }
    const returningUser = users.find(user =>
      user.email.toLowerCase() === String(previousUser.email || "").toLowerCase()
    );
    if (returningUser) {
      await api("/api/login", {
        method: "POST",
        body: JSON.stringify({ email: returningUser.email, password: returningUser.password })
      });
    }
  }

  localStorage.removeItem("pa_users");
  localStorage.removeItem("pa_apps");
  sessionStorage.removeItem("pa_current");
  return users.length > 0 || applications.length > 0;
}

function showFailure(error) {
  console.error(error);
  const message = error.message || "The request could not be completed.";
  if ($("#message")) {
    msg(message, "error");
    return;
  }
  const main = $("main");
  if (!main) return;
  let notice = $("#serverError");
  if (!notice) {
    notice = document.createElement("div");
    notice.id = "serverError";
    notice.className = "notice";
    main.prepend(notice);
  }
  notice.textContent = message;
}

function showMigrationNotice() {
  const main = $("main");
  if (!main) return;
  const notice = document.createElement("div");
  notice.id = "migrationNotice";
  notice.className = "notice migration-notice";
  notice.setAttribute("role", "status");
  notice.textContent = "Your previous demo account and applications have been saved in the database.";
  main.prepend(notice);
}

function statusClass(status) {
  return status.replace(/\s+/g, "-");
}

function setupNavigation(user) {
  const userNavigation = $("#userNav");
  const navigation = $(".nav");
  if (user && navigation) {
    const allowedPages = user.role === "admin"
      ? new Set(["index.html", "officer-dashboard.html"])
      : new Set(["index.html", "applicant-dashboard.html", "my-applications.html", "apply.html", "track.html"]);
    navigation.querySelectorAll("a").forEach(link => {
      const page = new URL(link.href, location.href).pathname.split("/").pop();
      if (link.id !== "logoutLink" && !allowedPages.has(page)) link.remove();
    });

    const dashboard = document.createElement("a");
    dashboard.href = user.role === "admin" ? "officer-dashboard.html" : "applicant-dashboard.html";
    dashboard.textContent = user.role === "admin" ? "Officer dashboard" : "Dashboard";
    if (!Array.from(navigation.querySelectorAll("a")).some(link => link.href === dashboard.href)) {
      navigation.insertBefore(dashboard, userNavigation || null);
    }
    if (userNavigation) {
      const pill = document.createElement("span");
      pill.className = "pill";
      pill.textContent = `Hello, ${user.name || user.email}`;
      userNavigation.replaceChildren(pill);
    }
    if (!$("#logoutLink")) {
      const logout = document.createElement("a");
      logout.id = "logoutLink";
      logout.href = "#";
      logout.textContent = "Logout";
      (userNavigation || navigation.lastElementChild).after(logout);
    }
  }

  $$("#logoutLink").forEach(link => {
    link.addEventListener("click", async event => {
      event.preventDefault();
      try {
        await api("/api/logout", { method: "POST" });
        location.href = "index.html";
      } catch (error) {
        showFailure(error);
      }
    });
  });
}

function initRegister() {
  const form = $("#registerForm");
  if (!form) return;
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    try {
      await api("/api/register", { method: "POST", body: JSON.stringify(data) });
      msg("Account created. You can now sign in with this email and password.");
      form.reset();
      setTimeout(() => { location.href = "login.html"; }, 900);
    } catch (error) {
      showFailure(error);
    }
  });
}

function initLogin() {
  const form = $("#loginForm");
  if (!form) return;
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    try {
      await api("/api/login", { method: "POST", body: JSON.stringify(data) });
      location.href = "applicant-dashboard.html";
    } catch (error) {
      showFailure(error);
    }
  });
}

function initAdminLogin() {
  const form = $("#adminLoginForm");
  if (!form) return;
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    try {
      await api("/api/admin/login", { method: "POST", body: JSON.stringify(data) });
      location.href = "officer-dashboard.html";
    } catch (error) {
      showFailure(error);
    }
  });
}

function initApply(user) {
  const form = $("#applyForm");
  if (!form) return;
  if (!user || user.role !== "applicant") {
    location.href = user?.role === "admin" ? "officer-dashboard.html" : "login.html";
    return;
  }
  const email = $("#email");
  if (email) {
    email.value = user.email;
    email.readOnly = true;
  }
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form));
    data.documentName = $("#documentFile")?.files?.[0]?.name || "Not uploaded";
    try {
      const application = await api("/api/applications", {
        method: "POST",
        body: JSON.stringify(data)
      });
      sessionStorage.setItem("pa_last_app", application.id);
      location.href = `payment.html?id=${encodeURIComponent(application.id)}`;
    } catch (error) {
      showFailure(error);
    }
  });
}

function initPayment(user) {
  const box = $("#paymentDetails");
  if (!box) return;
  if (!user || user.role !== "applicant") {
    location.href = user?.role === "admin" ? "officer-dashboard.html" : "login.html";
    return;
  }

  const requestedId = new URLSearchParams(location.search).get("id")
    || sessionStorage.getItem("pa_last_app");
  const loadApplication = requestedId
    ? api(`/api/my/applications/${encodeURIComponent(requestedId)}`)
    : api("/api/my/applications/latest");

  loadApplication.then(application => {
    if (!application) {
      box.innerHTML = '<p>No application found for this account. <a href="apply.html">Submit an application</a> first.</p>';
      return;
    }
    const id = application.id;
    box.innerHTML = `
      <p><strong>Application ID:</strong> ${escapeHtml(id)}</p>
      <p><strong>Applicant:</strong> ${escapeHtml(application.fullName)}</p>
      <p><strong>Demo fee:</strong> ₹1,500</p>
      <p><strong>Payment status:</strong> ${escapeHtml(application.payment)}</p>`;

    const button = $("#payButton");
    if (button && application.payment === "Unpaid") {
      button.addEventListener("click", async () => {
        button.disabled = true;
        try {
          await api(`/api/my/applications/${encodeURIComponent(id)}/payment`, { method: "POST" });
          box.innerHTML = `
            <div class="notice">Demo payment successful. No real money was charged.</div>
            <p><strong>Application ID:</strong> ${escapeHtml(id)}</p>
            <p>Save this ID to track your application.</p>
            <a class="btn" href="track.html?id=${encodeURIComponent(id)}">Track Application</a>`;
          button.hidden = true;
        } catch (error) {
          button.disabled = false;
          showFailure(error);
        }
      });
    } else if (button) {
      button.hidden = true;
      box.insertAdjacentHTML("beforeend",
        `<p><a class="btn" href="track.html?id=${encodeURIComponent(id)}">Track Application</a></p>`);
    }
  }).catch(showFailure);
}

function renderTrack(application, target) {
  if (!application) {
    target.innerHTML = '<div class="notice">No application found. Check the ID and try again.</div>';
    return;
  }
  const date = new Date(application.created);
  const submitted = Number.isNaN(date.getTime()) ? application.created : date.toLocaleString();
  target.innerHTML = `
    <div class="panel">
      <h3>Application Details</h3>
      <p><strong>Application ID:</strong> ${escapeHtml(application.id)}</p>
      <p><strong>Submitted:</strong> ${escapeHtml(submitted)}</p>
      <p><strong>Payment:</strong> ${escapeHtml(application.payment)}</p>
      <p><strong>Status:</strong> <span class="status ${statusClass(application.status)}">${escapeHtml(application.status)}</span></p>
      <p><strong>Officer remarks:</strong> ${escapeHtml(application.remarks || "No remarks added.")}</p>
    </div>`;
}

function initTrack() {
  const form = $("#trackForm");
  if (!form) return;
  const output = $("#trackResult");
  const query = new URLSearchParams(location.search).get("id");
  if (query) $("#applicationId").value = query;

  form.addEventListener("submit", async event => {
    event.preventDefault();
    const id = $("#applicationId").value.trim().toUpperCase();
    try {
      renderTrack(await api(`/api/applications/${encodeURIComponent(id)}`), output);
    } catch (error) {
      if (error.status === 404) {
        renderTrack(null, output);
      } else {
        showFailure(error);
      }
    }
  });
  if (query) form.requestSubmit();
}

function initMyApplications(user) {
  const list = $("#myApplications");
  if (!list) return;
  if (!user || user.role !== "applicant") {
    location.href = user?.role === "admin" ? "officer-dashboard.html" : "login.html";
    return;
  }

  api("/api/my/applications").then(applications => {
    if (!applications.length) {
      list.innerHTML = `
        <div class="empty-state">
          <span class="card-number">01</span>
          <h2>No applications yet</h2>
          <p>Your applications will appear here after you submit one.</p>
          <a class="btn" href="apply.html">Start an application</a>
        </div>`;
      return;
    }
    list.innerHTML = applications.map(application => {
      const date = new Date(application.created);
      const submitted = Number.isNaN(date.getTime()) ? application.created : date.toLocaleDateString();
      const paymentLink = application.payment === "Unpaid"
        ? `<a class="btn small" href="payment.html?id=${encodeURIComponent(application.id)}">Complete demo payment</a>`
        : "";
      return `
        <article class="application-item">
          <div class="application-item-heading">
            <div>
              <p class="eyebrow">Application ${escapeHtml(application.id)}</p>
              <h2>${escapeHtml(application.applicationType)}</h2>
            </div>
            <span class="status ${statusClass(application.status)}">${escapeHtml(application.status)}</span>
          </div>
          <p class="sub">Submitted ${escapeHtml(submitted)} · Payment: ${escapeHtml(application.payment)}</p>
          <div class="actions">
            ${paymentLink}
            <a class="btn secondary small" href="track.html?id=${encodeURIComponent(application.id)}">View tracking</a>
          </div>
        </article>`;
    }).join("");
  }).catch(showFailure);
}

function initApplicantDashboard(user) {
  const summary = $("#applicantSummary");
  if (!summary) return;
  if (!user || user.role !== "applicant") {
    location.href = user?.role === "admin" ? "officer-dashboard.html" : "login.html";
    return;
  }

  api("/api/my/applications").then(applications => {
    const inProgress = applications.filter(application =>
      !["Approved", "Rejected"].includes(application.status)
    ).length;
    const approved = applications.filter(application => application.status === "Approved").length;
    const needsPayment = applications.filter(application => application.payment === "Unpaid").length;
    summary.innerHTML = `
      <article class="summary-card"><span>Total applications</span><strong>${applications.length}</strong></article>
      <article class="summary-card"><span>In progress</span><strong>${inProgress}</strong></article>
      <article class="summary-card"><span>Approved</span><strong>${approved}</strong></article>
      <article class="summary-card"><span>Awaiting demo payment</span><strong>${needsPayment}</strong></article>`;

    const recent = $("#recentApplications");
    if (!recent) return;
    recent.innerHTML = applications.length
      ? applications.slice(0, 3).map(application => `
        <article class="application-item">
          <div class="application-item-heading">
            <div>
              <p class="eyebrow">Application ${escapeHtml(application.id)}</p>
              <h2>${escapeHtml(application.applicationType)}</h2>
            </div>
            <span class="status ${statusClass(application.status)}">${escapeHtml(application.status)}</span>
          </div>
          <p class="sub">Payment: ${escapeHtml(application.payment)}</p>
          <a class="btn secondary small" href="track.html?id=${encodeURIComponent(application.id)}">View status</a>
        </article>`).join("")
      : `<div class="empty-state">
          <span class="card-number">01</span>
          <h2>No applications yet</h2>
          <p>Your submitted applications and their progress will appear here.</p>
          <a class="btn" href="apply.html">Start an application</a>
        </div>`;
  }).catch(showFailure);
}

function initAdmin(user) {
  const table = $("#applicationsTable");
  if (!table) return;
  if (!user || user.role !== "admin") {
    location.href = "admin-login.html";
    return;
  }

  let applications = [];
  function draw() {
    $("#totalCount").textContent = applications.length;
    $("#pendingCount").textContent = applications.filter(app => !["Approved", "Rejected"].includes(app.status)).length;
    $("#approvedCount").textContent = applications.filter(app => app.status === "Approved").length;
    table.innerHTML = applications.length ? applications.map(app => `
      <tr>
        <td>${escapeHtml(app.id)}</td>
        <td>${escapeHtml(app.fullName)}</td>
        <td>${escapeHtml(app.userEmail)}</td>
        <td><span class="status ${statusClass(app.status)}">${escapeHtml(app.status)}</span></td>
        <td>${escapeHtml(app.payment)}</td>
        <td>
          <select data-status="${escapeHtml(app.id)}" aria-label="Status for ${escapeHtml(app.id)}">
            ${["Submitted", "Under Review", "Approved", "Rejected"].map(status =>
              `<option value="${status}" ${app.status === status ? "selected" : ""}>${status}</option>`
            ).join("")}
          </select>
          <input data-remarks="${escapeHtml(app.id)}" placeholder="Officer remarks" maxlength="500" value="${escapeHtml(app.remarks || "")}">
          <button class="btn small" type="button" data-save="${escapeHtml(app.id)}">Save</button>
        </td>
      </tr>`).join("") : '<tr><td colspan="6" class="empty">No applications have been submitted yet.</td></tr>';
  }

  async function loadApplications() {
    applications = await api("/api/admin/applications");
    draw();
  }

  table.addEventListener("click", async event => {
    const button = event.target.closest("[data-save]");
    if (!button) return;
    const id = button.dataset.save;
    const status = $(`[data-status="${id}"]`, table).value;
    const remarks = $(`[data-remarks="${id}"]`, table).value.trim();
    button.disabled = true;
    try {
      await api(`/api/admin/applications/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: JSON.stringify({ status, remarks })
      });
      await loadApplications();
      msg("Application updated successfully.");
    } catch (error) {
      button.disabled = false;
      showFailure(error);
    }
  });

  $("#searchInput")?.addEventListener("input", event => {
    const query = event.target.value.toLowerCase();
    $$("tbody tr", table).forEach(row => {
      row.classList.toggle("hidden", !row.textContent.toLowerCase().includes(query));
    });
  });
  $("#exportButton")?.addEventListener("click", () => {
    const file = new Blob([JSON.stringify(applications, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(file);
    link.download = "passport-applications-demo.json";
    link.click();
    URL.revokeObjectURL(link.href);
  });
  loadApplications().catch(showFailure);
}

document.addEventListener("DOMContentLoaded", async () => {
  let migrated = false;
  try {
    migrated = await migrateLegacyBrowserData();
  } catch (error) {
    showFailure(error);
  }
  try {
    const user = await getSession();
    setupNavigation(user);
    initRegister();
    initLogin();
    initAdminLogin();
    initApply(user);
    initPayment(user);
    initTrack();
    initMyApplications(user);
    initApplicantDashboard(user);
    initAdmin(user);
    if (migrated) showMigrationNotice();
  } catch (error) {
    showFailure(error);
  }
});
