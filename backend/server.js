const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const FRONTEND_ROOT = path.join(PROJECT_ROOT, "frontend");
const PORT = Number.parseInt(process.env.PORT || "8000", 10);
const HOST = process.env.HOST || "127.0.0.1";
const DATABASE_PATH = process.env.DATABASE_PATH || path.join(PROJECT_ROOT, "database", "passport-demo.sqlite");
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@passport.demo").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin123!";
const SESSION_LIFETIME = 24 * 60 * 60;
const MAX_BODY_SIZE = 1024 * 1024;
const STATUSES = new Set(["Submitted", "Under Review", "Approved", "Rejected"]);

fs.mkdirSync(path.dirname(DATABASE_PATH), { recursive: true });
const database = new DatabaseSync(DATABASE_PATH);
database.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    full_name TEXT NOT NULL,
    dob TEXT NOT NULL,
    gender TEXT NOT NULL,
    phone TEXT NOT NULL,
    application_type TEXT NOT NULL,
    address TEXT NOT NULL,
    document_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Submitted',
    payment TEXT NOT NULL DEFAULT 'Unpaid',
    remarks TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS applications_user_created
    ON applications(user_id, created_at DESC);
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('applicant', 'admin')),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
`);
database.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(Math.floor(Date.now() / 1000));

const adminSalt = crypto.randomBytes(16).toString("hex");
const adminHash = crypto.scryptSync(ADMIN_PASSWORD, adminSalt, 64);
const dummySalt = crypto.randomBytes(16).toString("hex");
const dummyHash = crypto.scryptSync("invalid-login-padding", dummySalt, 64);

function sendJson(response, status, data, headers = {}) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...headers
  });
  response.end(JSON.stringify(data));
}

function publicUser(user) {
  return { name: user.name, email: user.email, role: user.role };
}

function getSession(request) {
  const cookie = request.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)pa_session=([a-f0-9]{64})(?:;|$)/);
  if (!match) return null;
  const session = database.prepare(`
    SELECT user_id AS userId, role, name, email, expires_at AS expiresAt
    FROM sessions WHERE token_hash = ?
  `).get(crypto.createHash("sha256").update(match[1]).digest("hex"));
  if (!session) return null;
  if (session.expiresAt <= Math.floor(Date.now() / 1000)) {
    database.prepare("DELETE FROM sessions WHERE token_hash = ?")
      .run(crypto.createHash("sha256").update(match[1]).digest("hex"));
    return null;
  }
  return session;
}

function requireRole(session, role) {
  return Boolean(session && session.role === role);
}

function setSession(response, user, role) {
  const token = crypto.randomBytes(32).toString("hex");
  database.prepare(`
    INSERT INTO sessions (token_hash, user_id, role, name, email, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    crypto.createHash("sha256").update(token).digest("hex"),
    user.id ?? null,
    role,
    user.name,
    user.email,
    Math.floor(Date.now() / 1000) + SESSION_LIFETIME
  );
  response.setHeader(
    "Set-Cookie",
    `pa_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_LIFETIME}`
  );
}

function clearSession(response) {
  response.setHeader("Set-Cookie", "pa_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", chunk => {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_BODY_SIZE) {
        reject(Object.assign(new Error("Request body is too large."), { status: 413 }));
        request.destroy();
      }
    });
    request.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(Object.assign(new Error("Request body must be valid JSON."), { status: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function requireString(value, label, maxLength = 300) {
  if (typeof value !== "string" || !value.trim() || value.trim().length > maxLength) {
    throw Object.assign(new Error(`${label} is required and must be at most ${maxLength} characters.`), { status: 400 });
  }
  return value.trim();
}

function serializeApplication(row) {
  return {
    id: row.id,
    userEmail: row.userEmail,
    fullName: row.fullName,
    dob: row.dob,
    gender: row.gender,
    phone: row.phone,
    applicationType: row.applicationType,
    address: row.address,
    documentName: row.documentName,
    created: row.created,
    status: row.status,
    payment: row.payment,
    remarks: row.remarks
  };
}

const applicationColumns = `
  applications.id, users.email AS userEmail, applications.full_name AS fullName,
  applications.dob, applications.gender, applications.phone,
  applications.application_type AS applicationType, applications.address,
  applications.document_name AS documentName, applications.created_at AS created,
  applications.status, applications.payment, applications.remarks
`;

function lookupApplication(id) {
  return database.prepare(`
    SELECT ${applicationColumns}
    FROM applications JOIN users ON users.id = applications.user_id
    WHERE applications.id = ?
  `).get(id);
}

function validateEmail(email) {
  return typeof email === "string" && email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

async function handleApi(request, response, url) {
  const method = request.method;
  const route = url.pathname;
  const session = getSession(request);

  if (route === "/api/session" && method === "GET") {
    return sendJson(response, 200, session ? publicUser(session) : null);
  }

  if (route === "/api/migrate-legacy" && method === "POST") {
    const body = await readJson(request);
    const legacyUser = body.user;
    const name = requireString(legacyUser?.name, "Full name", 100);
    const email = requireString(legacyUser?.email, "Email address", 254).toLowerCase();
    const phone = requireString(legacyUser?.phone, "Phone number", 30);
    const password = legacyUser?.password;
    if (!validateEmail(email)) throw Object.assign(new Error("An existing account has an invalid email address."), { status: 400 });
    if (!/^[0-9+() -]{7,30}$/.test(phone)) throw Object.assign(new Error("An existing account has an invalid phone number."), { status: 400 });
    if (typeof password !== "string" || password.length < 6 || password.length > 128) {
      throw Object.assign(new Error("An existing account password could not be migrated. Please create a new account."), { status: 400 });
    }
    if (email === ADMIN_EMAIL) {
      throw Object.assign(new Error("The officer account cannot be migrated as an applicant account."), { status: 409 });
    }
    if (!Array.isArray(body.applications)) {
      throw Object.assign(new Error("Existing applications could not be read."), { status: 400 });
    }

    const applications = body.applications;
    const existingUser = database.prepare(`
      SELECT id, password_hash AS passwordHash, password_salt AS passwordSalt
      FROM users WHERE email = ? COLLATE NOCASE
    `).get(email);
    const salt = existingUser ? existingUser.passwordSalt : crypto.randomBytes(16).toString("hex");
    const expectedHash = existingUser ? Buffer.from(existingUser.passwordHash, "hex") : null;
    const suppliedHash = crypto.scryptSync(password, salt, 64);
    if (existingUser && !crypto.timingSafeEqual(suppliedHash, expectedHash)) {
      throw Object.assign(new Error("An account with this email already exists with a different password."), { status: 409 });
    }

    database.exec("BEGIN IMMEDIATE");
    try {
      let userId = existingUser?.id;
      if (!existingUser) {
        const passwordHash = suppliedHash.toString("hex");
        const result = database.prepare(`
          INSERT INTO users (name, email, phone, password_hash, password_salt, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(name, email, phone, passwordHash, salt, new Date().toISOString());
        userId = Number(result.lastInsertRowid);
      }

      for (const application of applications) {
        const applicationEmail = typeof application.userEmail === "string"
          ? application.userEmail.trim().toLowerCase()
          : email;
        if (applicationEmail !== email) {
          throw Object.assign(new Error("An existing application belongs to a different account."), { status: 400 });
        }
        const id = requireString(application.id, "Application ID", 20).toUpperCase();
        if (!/^PA[A-Z0-9]{4,18}$/.test(id)) {
          throw Object.assign(new Error("An existing application has an invalid ID."), { status: 400 });
        }
        const previous = database.prepare("SELECT user_id AS userId FROM applications WHERE id = ?").get(id);
        if (previous) {
          if (previous.userId !== userId) {
            throw Object.assign(new Error("An application ID is already associated with a different account."), { status: 409 });
          }
          continue;
        }
        const fullName = requireString(application.fullName, "Applicant name", 100);
        const dob = requireString(application.dob, "Date of birth", 10);
        const gender = requireString(application.gender, "Gender", 40);
        const applicationPhone = requireString(application.phone || phone, "Phone number", 30);
        const applicationType = requireString(application.applicationType, "Application type", 50);
        const address = requireString(application.address, "Address", 500);
        const documentName = path.basename(typeof application.documentName === "string"
          ? application.documentName
          : "Not uploaded").slice(0, 255);
        const payment = application.payment === "Paid (Demo)" ? "Paid (Demo)" : "Unpaid";
        const status = STATUSES.has(application.status) ? application.status : "Submitted";
        const remarks = typeof application.remarks === "string" ? application.remarks.trim().slice(0, 500) : "";
        const parsedCreated = Date.parse(application.created);
        const created = Number.isNaN(parsedCreated) ? new Date().toISOString() : new Date(parsedCreated).toISOString();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(dob) ||
          !["Female", "Male", "Other", "Prefer not to say"].includes(gender) ||
          !["Fresh Passport", "Passport Renewal"].includes(applicationType)) {
          throw Object.assign(new Error("An existing application contains invalid details."), { status: 400 });
        }
        database.prepare(`
          INSERT INTO applications
            (id, user_id, full_name, dob, gender, phone, application_type, address,
             document_name, created_at, status, payment, remarks)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          id, userId, fullName, dob, gender, applicationPhone, applicationType,
          address, documentName, created, status, payment, remarks
        );
      }
      database.exec("COMMIT");
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
    return sendJson(response, 200, { message: "Existing account and applications migrated." });
  }

  if (route === "/api/register" && method === "POST") {
    const body = await readJson(request);
    const name = requireString(body.name, "Full name", 100);
    const email = requireString(body.email, "Email address", 254).toLowerCase();
    const phone = requireString(body.phone, "Phone number", 30);
    const password = body.password;
    if (!validateEmail(email)) throw Object.assign(new Error("Enter a valid email address."), { status: 400 });
    if (!/^[0-9+() -]{7,30}$/.test(phone)) throw Object.assign(new Error("Enter a valid phone number."), { status: 400 });
    if (typeof password !== "string" || password.length < 8 || password.length > 128) {
      throw Object.assign(new Error("Password must contain between 8 and 128 characters."), { status: 400 });
    }
    if (email === ADMIN_EMAIL) {
      throw Object.assign(new Error("That email address is reserved for the officer account."), { status: 409 });
    }
    const salt = crypto.randomBytes(16).toString("hex");
    const passwordHash = crypto.scryptSync(password, salt, 64).toString("hex");
    try {
      database.prepare(`
        INSERT INTO users (name, email, phone, password_hash, password_salt, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(name, email, phone, passwordHash, salt, new Date().toISOString());
    } catch (error) {
      if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
        throw Object.assign(new Error("An account with this email already exists. Please sign in instead."), { status: 409 });
      }
      throw error;
    }
    return sendJson(response, 201, { message: "Account created. Sign in with your new account to continue." });
  }

  if ((route === "/api/login" || route === "/api/admin/login") && method === "POST") {
    const isAdmin = route === "/api/admin/login";
    const body = await readJson(request);
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (password.length > 128) throw Object.assign(new Error("Invalid email or password."), { status: 401 });

    if (isAdmin) {
      const suppliedHash = crypto.scryptSync(password, adminSalt, 64);
      const emailMatches = email === ADMIN_EMAIL;
      if (!emailMatches || !crypto.timingSafeEqual(suppliedHash, adminHash)) {
        throw Object.assign(new Error("Invalid officer email or password."), { status: 401 });
      }
      const admin = { name: "Passport Officer", email: ADMIN_EMAIL };
      setSession(response, admin, "admin");
      return sendJson(response, 200, publicUser({ ...admin, role: "admin" }));
    }

    const user = database.prepare(`
      SELECT id, name, email, password_hash AS passwordHash, password_salt AS passwordSalt
      FROM users WHERE email = ? COLLATE NOCASE
    `).get(email);
    const salt = user ? user.passwordSalt : dummySalt;
    const expectedHash = user ? Buffer.from(user.passwordHash, "hex") : dummyHash;
    const suppliedHash = crypto.scryptSync(password, salt, 64);
    if (!user || !crypto.timingSafeEqual(suppliedHash, expectedHash)) {
      throw Object.assign(new Error("Invalid email or password."), { status: 401 });
    }
    setSession(response, user, "applicant");
    return sendJson(response, 200, publicUser({ ...user, role: "applicant" }));
  }

  if (route === "/api/logout" && method === "POST") {
    const cookie = request.headers.cookie || "";
    const match = cookie.match(/(?:^|;\s*)pa_session=([a-f0-9]{64})(?:;|$)/);
    if (match) {
      database.prepare("DELETE FROM sessions WHERE token_hash = ?")
        .run(crypto.createHash("sha256").update(match[1]).digest("hex"));
    }
    clearSession(response);
    return sendJson(response, 200, { message: "Signed out." });
  }

  if (route === "/api/applications" && method === "POST") {
    if (!requireRole(session, "applicant")) throw Object.assign(new Error("Please sign in as an applicant."), { status: 401 });
    const body = await readJson(request);
    const fullName = requireString(body.fullName, "Full name", 100);
    const dob = requireString(body.dob, "Date of birth", 10);
    const gender = requireString(body.gender, "Gender", 40);
    const phone = requireString(body.phone, "Phone number", 30);
    const applicationType = requireString(body.applicationType, "Application type", 50);
    const address = requireString(body.address, "Address", 500);
    const documentName = path.basename(typeof body.documentName === "string" ? body.documentName : "Not uploaded").slice(0, 255);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dob) || Number.isNaN(Date.parse(`${dob}T00:00:00.000Z`))) {
      throw Object.assign(new Error("Enter a valid date of birth."), { status: 400 });
    }
    if (!["Female", "Male", "Other", "Prefer not to say"].includes(gender)) {
      throw Object.assign(new Error("Select a valid gender option."), { status: 400 });
    }
    if (!["Fresh Passport", "Passport Renewal"].includes(applicationType)) {
      throw Object.assign(new Error("Select a valid application type."), { status: 400 });
    }
    const id = `PA${crypto.randomBytes(5).toString("hex").toUpperCase()}`;
    const created = new Date().toISOString();
    database.prepare(`
      INSERT INTO applications
        (id, user_id, full_name, dob, gender, phone, application_type, address, document_name, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, session.userId, fullName, dob, gender, phone, applicationType, address, documentName, created);
    return sendJson(response, 201, { id });
  }

  if (route === "/api/my/applications/latest" && method === "GET") {
    if (!requireRole(session, "applicant")) throw Object.assign(new Error("Please sign in as an applicant."), { status: 401 });
    const row = database.prepare(`
      SELECT ${applicationColumns}
      FROM applications JOIN users ON users.id = applications.user_id
      WHERE applications.user_id = ?
      ORDER BY applications.created_at DESC LIMIT 1
    `).get(session.userId);
    return sendJson(response, 200, row ? serializeApplication(row) : null);
  }

  if (route === "/api/my/applications" && method === "GET") {
    if (!requireRole(session, "applicant")) throw Object.assign(new Error("Please sign in as an applicant."), { status: 401 });
    const rows = database.prepare(`
      SELECT id, full_name AS fullName, application_type AS applicationType,
        created_at AS created, status, payment, remarks
      FROM applications WHERE user_id = ?
      ORDER BY created_at DESC
    `).all(session.userId);
    return sendJson(response, 200, rows);
  }

  const ownedApplicationMatch = route.match(/^\/api\/my\/applications\/([A-Z0-9]+)$/i);
  if (ownedApplicationMatch && method === "GET") {
    if (!requireRole(session, "applicant")) throw Object.assign(new Error("Please sign in as an applicant."), { status: 401 });
    const row = database.prepare(`
      SELECT ${applicationColumns}
      FROM applications JOIN users ON users.id = applications.user_id
      WHERE applications.id = ? AND applications.user_id = ?
    `).get(ownedApplicationMatch[1].toUpperCase(), session.userId);
    if (!row) throw Object.assign(new Error("Application not found for this account."), { status: 404 });
    return sendJson(response, 200, serializeApplication(row));
  }

  const paymentMatch = route.match(/^\/api\/my\/applications\/([A-Z0-9]+)\/payment$/i);
  if (paymentMatch && method === "POST") {
    if (!requireRole(session, "applicant")) throw Object.assign(new Error("Please sign in as an applicant."), { status: 401 });
    const id = paymentMatch[1].toUpperCase();
    const result = database.prepare(`
      UPDATE applications SET payment = 'Paid (Demo)', status = 'Under Review'
      WHERE id = ? AND user_id = ? AND payment = 'Unpaid'
    `).run(id, session.userId);
    if (result.changes === 0) {
      const app = database.prepare("SELECT payment FROM applications WHERE id = ? AND user_id = ?").get(id, session.userId);
      if (!app) throw Object.assign(new Error("Application not found for this account."), { status: 404 });
      if (app.payment !== "Unpaid") throw Object.assign(new Error("This application has already been paid."), { status: 409 });
    }
    return sendJson(response, 200, { message: "Demo payment successful.", id });
  }

  if (route === "/api/admin/applications" && method === "GET") {
    if (!requireRole(session, "admin")) throw Object.assign(new Error("Officer sign-in is required."), { status: 401 });
    const rows = database.prepare(`
      SELECT ${applicationColumns}
      FROM applications JOIN users ON users.id = applications.user_id
      ORDER BY applications.created_at DESC
    `).all();
    return sendJson(response, 200, rows.map(serializeApplication));
  }

  const adminApplicationMatch = route.match(/^\/api\/admin\/applications\/([A-Z0-9]+)$/i);
  if (adminApplicationMatch && method === "PATCH") {
    if (!requireRole(session, "admin")) throw Object.assign(new Error("Officer sign-in is required."), { status: 401 });
    const body = await readJson(request);
    if (!STATUSES.has(body.status)) {
      throw Object.assign(new Error("Select a valid application status."), { status: 400 });
    }
    const remarks = typeof body.remarks === "string" ? body.remarks.trim() : "";
    if (remarks.length > 500) throw Object.assign(new Error("Officer remarks must be at most 500 characters."), { status: 400 });
    const result = database.prepare(`
      UPDATE applications SET status = ?, remarks = ? WHERE id = ?
    `).run(body.status, remarks, adminApplicationMatch[1].toUpperCase());
    if (result.changes === 0) throw Object.assign(new Error("Application not found."), { status: 404 });
    return sendJson(response, 200, { message: "Application updated successfully." });
  }

  const publicApplicationMatch = route.match(/^\/api\/applications\/([A-Z0-9]+)$/i);
  if (publicApplicationMatch && method === "GET") {
    const row = database.prepare(`
      SELECT id, created_at AS created, status, payment, remarks
      FROM applications WHERE id = ?
    `).get(publicApplicationMatch[1].toUpperCase());
    if (!row) throw Object.assign(new Error("No application found. Check the ID and try again."), { status: 404 });
    return sendJson(response, 200, row);
  }

  sendJson(response, 404, { error: "API endpoint not found." });
}

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8"
};
const publicFiles = new Set([
  "admin-login.html",
  "admin.html",
  "applicant-dashboard.html",
  "app.js",
  "apply.html",
  "index.html",
  "login.html",
  "my-applications.html",
  "officer-dashboard.html",
  "payment.html",
  "register.html",
  "style.css",
  "track.html"
]);

function serveStatic(request, response, url) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return sendJson(response, 405, { error: "Method not allowed." }, { Allow: "GET, HEAD" });
  }
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return sendJson(response, 400, { error: "Invalid URL path." });
  }
  if (pathname.includes("\0")) return sendJson(response, 400, { error: "Invalid URL path." });
  const relativePath = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  if (!publicFiles.has(relativePath)) return sendJson(response, 404, { error: "File not found." });
  const resolvedPath = path.resolve(FRONTEND_ROOT, relativePath);
  if (!resolvedPath.startsWith(`${FRONTEND_ROOT}${path.sep}`)) {
    return sendJson(response, 403, { error: "Access denied." });
  }
  let file;
  try {
    file = fs.readFileSync(resolvedPath);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "EISDIR") {
      return sendJson(response, 404, { error: "File not found." });
    }
    throw error;
  }
  response.writeHead(200, {
    "Content-Type": contentTypes[path.extname(resolvedPath)] || "application/octet-stream",
    "Cache-Control": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer"
  });
  response.end(request.method === "HEAD" ? undefined : file);
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    if (url.pathname.startsWith("/api/")) {
      await handleApi(request, response, url);
    } else {
      serveStatic(request, response, url);
    }
  } catch (error) {
    console.error(`[${new Date().toISOString()}] ${request.method} ${request.url}:`, error);
    if (!response.headersSent) {
      sendJson(response, error.status || 500, {
        error: error.status ? error.message : "The server encountered an unexpected error. Check its console output."
      });
    } else {
      response.destroy(error);
    }
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Passport demo is running at http://${HOST}:${PORT}/`);
  console.log(`SQLite database: ${DATABASE_PATH}`);
  console.log(`Officer account: ${ADMIN_EMAIL} (set ADMIN_PASSWORD to override its demo password)`);
});
