"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const { createClient } = require("@libsql/client");

const SESSION_LIFETIME = 24 * 60 * 60;
const MAX_BODY_SIZE = 1024 * 1024;
const STATUSES = new Set(["Submitted", "Under Review", "Approved", "Rejected"]);
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@passport.demo").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD ||
  (process.env.NODE_ENV === "production" ? "" : "Admin123!");
const adminSalt = crypto.randomBytes(16).toString("hex");
const adminHash = ADMIN_PASSWORD ? crypto.scryptSync(ADMIN_PASSWORD, adminSalt, 64) : null;
const dummySalt = crypto.randomBytes(16).toString("hex");
const dummyHash = crypto.scryptSync("invalid-login-padding", dummySalt, 64);
let database;
let initialized;

function configurationError() {
  if (!process.env.TURSO_DATABASE_URL) {
    return Object.assign(new Error("The hosted database is not configured."), { status: 503 });
  }
  if (process.env.NODE_ENV === "production" &&
      (ADMIN_PASSWORD.length < 12 || ADMIN_PASSWORD === "Admin123!")) {
    return Object.assign(new Error("Set a unique officer password of at least 12 characters in the deployment environment."), { status: 503 });
  }
  return null;
}

async function getDatabase() {
  const error = configurationError();
  if (error) throw error;
  if (!database) {
    const options = { url: process.env.TURSO_DATABASE_URL };
    if (process.env.TURSO_AUTH_TOKEN) options.authToken = process.env.TURSO_AUTH_TOKEN;
    database = createClient(options);
  }
  if (!initialized) {
    initialized = (async () => {
      const statements = [
        `CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          phone TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          password_salt TEXT NOT NULL,
          created_at TEXT NOT NULL
        )`,
        `CREATE TABLE IF NOT EXISTS applications (
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
        )`,
        `CREATE INDEX IF NOT EXISTS applications_user_created
          ON applications(user_id, created_at DESC)`,
        `CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          role TEXT NOT NULL CHECK(role IN ('applicant', 'admin')),
          name TEXT NOT NULL,
          email TEXT NOT NULL,
          expires_at INTEGER NOT NULL
        )`
      ];
      for (const sql of statements) await database.execute(sql);
      await database.execute({
        sql: "DELETE FROM sessions WHERE expires_at <= ?",
        args: [Math.floor(Date.now() / 1000)]
      });
    })();
  }
  await initialized;
  return database;
}

function sendJson(response, status, data) {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.end(JSON.stringify(data));
}

function readJson(request) {
  if (request.body !== undefined) {
    if (request.body && typeof request.body === "object" && !Buffer.isBuffer(request.body)) {
      return Promise.resolve(request.body);
    }
    try {
      return Promise.resolve(JSON.parse(Buffer.isBuffer(request.body)
        ? request.body.toString("utf8")
        : request.body || "{}"));
    } catch {
      return Promise.reject(Object.assign(new Error("Request body must be valid JSON."), { status: 400 }));
    }
  }
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

function validateEmail(email) {
  return typeof email === "string" && email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function publicUser(user) {
  return { name: user.name, email: user.email, role: user.role };
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

function sessionToken(request) {
  const match = (request.headers.cookie || "").match(/(?:^|;\s*)pa_session=([a-f0-9]{64})(?:;|$)/);
  return match ? match[1] : null;
}

async function getSession(database, request) {
  const token = sessionToken(request);
  if (!token) return null;
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const result = await database.execute({
    sql: `SELECT user_id AS userId, role, name, email, expires_at AS expiresAt
      FROM sessions WHERE token_hash = ?`,
    args: [tokenHash]
  });
  const session = result.rows[0];
  if (!session) return null;
  if (Number(session.expiresAt) <= Math.floor(Date.now() / 1000)) {
    await database.execute({ sql: "DELETE FROM sessions WHERE token_hash = ?", args: [tokenHash] });
    return null;
  }
  return session;
}

function requireRole(session, role) {
  return Boolean(session && session.role === role);
}

async function setSession(database, response, user, role) {
  const token = crypto.randomBytes(32).toString("hex");
  await database.execute({
    sql: `INSERT INTO sessions (token_hash, user_id, role, name, email, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)`,
    args: [
      crypto.createHash("sha256").update(token).digest("hex"),
      user.id ?? null,
      role,
      user.name,
      user.email,
      Math.floor(Date.now() / 1000) + SESSION_LIFETIME
    ]
  });
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `pa_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_LIFETIME}${secure}`
  );
}

function clearSession(response) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader("Set-Cookie", `pa_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
}

function fail(message, status) {
  return Object.assign(new Error(message), { status });
}

async function handleApi(request, response, url, database, session) {
  const { method } = request;
  const route = url.pathname;

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
    if (!validateEmail(email)) throw fail("An existing account has an invalid email address.", 400);
    if (!/^[0-9+() -]{7,30}$/.test(phone)) throw fail("An existing account has an invalid phone number.", 400);
    if (typeof password !== "string" || password.length < 6 || password.length > 128) {
      throw fail("An existing account password could not be migrated. Please create a new account.", 400);
    }
    if (email === ADMIN_EMAIL) throw fail("The officer account cannot be migrated as an applicant account.", 409);
    if (!Array.isArray(body.applications)) throw fail("Existing applications could not be read.", 400);
    const existingResult = await database.execute({
      sql: `SELECT id, password_hash AS passwordHash, password_salt AS passwordSalt
        FROM users WHERE email = ?`,
      args: [email]
    });
    const existingUser = existingResult.rows[0];
    const salt = existingUser ? existingUser.passwordSalt : crypto.randomBytes(16).toString("hex");
    const expectedHash = existingUser ? Buffer.from(existingUser.passwordHash, "hex") : null;
    const suppliedHash = crypto.scryptSync(password, salt, 64);
    if (existingUser && !crypto.timingSafeEqual(suppliedHash, expectedHash)) {
      throw fail("An account with this email already exists with a different password.", 409);
    }

    const transaction = await database.transaction("write");
    try {
      let userId = existingUser?.id;
      if (!existingUser) {
        const insert = await transaction.execute({
          sql: `INSERT INTO users (name, email, phone, password_hash, password_salt, created_at)
            VALUES (?, ?, ?, ?, ?, ?)`,
          args: [name, email, phone, suppliedHash.toString("hex"), salt, new Date().toISOString()]
        });
        userId = Number(insert.lastInsertRowid);
      }
      for (const application of body.applications) {
        const applicationEmail = typeof application.userEmail === "string"
          ? application.userEmail.trim().toLowerCase()
          : email;
        if (applicationEmail !== email) throw fail("An existing application belongs to a different account.", 400);
        const id = requireString(application.id, "Application ID", 20).toUpperCase();
        if (!/^PA[A-Z0-9]{4,18}$/.test(id)) throw fail("An existing application has an invalid ID.", 400);
        const previous = await transaction.execute({
          sql: "SELECT user_id AS userId FROM applications WHERE id = ?",
          args: [id]
        });
        if (previous.rows[0]) {
          if (Number(previous.rows[0].userId) !== Number(userId)) {
            throw fail("An application ID is already associated with a different account.", 409);
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
          throw fail("An existing application contains invalid details.", 400);
        }
        await transaction.execute({
          sql: `INSERT INTO applications
            (id, user_id, full_name, dob, gender, phone, application_type, address,
             document_name, created_at, status, payment, remarks)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          args: [
            id, userId, fullName, dob, gender, applicationPhone, applicationType,
            address, documentName, created, status, payment, remarks
          ]
        });
      }
      await transaction.commit();
    } catch (error) {
      await transaction.rollback();
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
    if (!validateEmail(email)) throw fail("Enter a valid email address.", 400);
    if (!/^[0-9+() -]{7,30}$/.test(phone)) throw fail("Enter a valid phone number.", 400);
    if (typeof password !== "string" || password.length < 8 || password.length > 128) {
      throw fail("Password must contain between 8 and 128 characters.", 400);
    }
    if (email === ADMIN_EMAIL) throw fail("That email address is reserved for the officer account.", 409);
    const salt = crypto.randomBytes(16).toString("hex");
    const passwordHash = crypto.scryptSync(password, salt, 64).toString("hex");
    try {
      await database.execute({
        sql: `INSERT INTO users (name, email, phone, password_hash, password_salt, created_at)
          VALUES (?, ?, ?, ?, ?, ?)`,
        args: [name, email, phone, passwordHash, salt, new Date().toISOString()]
      });
    } catch (error) {
      if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
        throw fail("An account with this email already exists. Please sign in instead.", 409);
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
    if (password.length > 128) throw fail("Invalid email or password.", 401);
    if (isAdmin) {
      if (!adminHash) throw fail("Officer sign-in is not configured.", 503);
      const suppliedHash = crypto.scryptSync(password, adminSalt, 64);
      if (email !== ADMIN_EMAIL || !crypto.timingSafeEqual(suppliedHash, adminHash)) {
        throw fail("Invalid officer email or password.", 401);
      }
      const admin = { name: "Passport Officer", email: ADMIN_EMAIL };
      await setSession(database, response, admin, "admin");
      return sendJson(response, 200, publicUser({ ...admin, role: "admin" }));
    }
    const result = await database.execute({
      sql: `SELECT id, name, email, password_hash AS passwordHash, password_salt AS passwordSalt
        FROM users WHERE email = ?`,
      args: [email]
    });
    const user = result.rows[0];
    const salt = user ? user.passwordSalt : dummySalt;
    const expectedHash = user ? Buffer.from(user.passwordHash, "hex") : dummyHash;
    const suppliedHash = crypto.scryptSync(password, salt, 64);
    if (!user || !crypto.timingSafeEqual(suppliedHash, expectedHash)) {
      throw fail("Invalid email or password.", 401);
    }
    await setSession(database, response, user, "applicant");
    return sendJson(response, 200, publicUser({ ...user, role: "applicant" }));
  }

  if (route === "/api/logout" && method === "POST") {
    const token = sessionToken(request);
    if (token) {
      await database.execute({
        sql: "DELETE FROM sessions WHERE token_hash = ?",
        args: [crypto.createHash("sha256").update(token).digest("hex")]
      });
    }
    clearSession(response);
    return sendJson(response, 200, { message: "Signed out." });
  }

  if (route === "/api/applications" && method === "POST") {
    if (!requireRole(session, "applicant")) throw fail("Please sign in as an applicant.", 401);
    const body = await readJson(request);
    const fullName = requireString(body.fullName, "Full name", 100);
    const dob = requireString(body.dob, "Date of birth", 10);
    const gender = requireString(body.gender, "Gender", 40);
    const phone = requireString(body.phone, "Phone number", 30);
    const applicationType = requireString(body.applicationType, "Application type", 50);
    const address = requireString(body.address, "Address", 500);
    const documentName = path.basename(typeof body.documentName === "string" ? body.documentName : "Not uploaded").slice(0, 255);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dob) || Number.isNaN(Date.parse(`${dob}T00:00:00.000Z`))) {
      throw fail("Enter a valid date of birth.", 400);
    }
    if (!["Female", "Male", "Other", "Prefer not to say"].includes(gender)) throw fail("Select a valid gender option.", 400);
    if (!["Fresh Passport", "Passport Renewal"].includes(applicationType)) throw fail("Select a valid application type.", 400);
    const id = `PA${crypto.randomBytes(5).toString("hex").toUpperCase()}`;
    await database.execute({
      sql: `INSERT INTO applications
        (id, user_id, full_name, dob, gender, phone, application_type, address, document_name, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [id, session.userId, fullName, dob, gender, phone, applicationType, address, documentName, new Date().toISOString()]
    });
    return sendJson(response, 201, { id });
  }

  if (route === "/api/my/applications/latest" && method === "GET") {
    if (!requireRole(session, "applicant")) throw fail("Please sign in as an applicant.", 401);
    const result = await database.execute({
      sql: `SELECT ${applicationColumns}
        FROM applications JOIN users ON users.id = applications.user_id
        WHERE applications.user_id = ? ORDER BY applications.created_at DESC LIMIT 1`,
      args: [session.userId]
    });
    return sendJson(response, 200, result.rows[0] ? serializeApplication(result.rows[0]) : null);
  }

  if (route === "/api/my/applications" && method === "GET") {
    if (!requireRole(session, "applicant")) throw fail("Please sign in as an applicant.", 401);
    const result = await database.execute({
      sql: `SELECT id, full_name AS fullName, application_type AS applicationType,
        created_at AS created, status, payment, remarks
        FROM applications WHERE user_id = ? ORDER BY created_at DESC`,
      args: [session.userId]
    });
    return sendJson(response, 200, result.rows);
  }

  const ownedApplicationMatch = route.match(/^\/api\/my\/applications\/([A-Z0-9]+)$/i);
  if (ownedApplicationMatch && method === "GET") {
    if (!requireRole(session, "applicant")) throw fail("Please sign in as an applicant.", 401);
    const result = await database.execute({
      sql: `SELECT ${applicationColumns}
        FROM applications JOIN users ON users.id = applications.user_id
        WHERE applications.id = ? AND applications.user_id = ?`,
      args: [ownedApplicationMatch[1].toUpperCase(), session.userId]
    });
    if (!result.rows[0]) throw fail("Application not found for this account.", 404);
    return sendJson(response, 200, serializeApplication(result.rows[0]));
  }

  const paymentMatch = route.match(/^\/api\/my\/applications\/([A-Z0-9]+)\/payment$/i);
  if (paymentMatch && method === "POST") {
    if (!requireRole(session, "applicant")) throw fail("Please sign in as an applicant.", 401);
    const id = paymentMatch[1].toUpperCase();
    const result = await database.execute({
      sql: `UPDATE applications SET payment = 'Paid (Demo)', status = 'Under Review'
        WHERE id = ? AND user_id = ? AND payment = 'Unpaid'`,
      args: [id, session.userId]
    });
    if (result.rowsAffected === 0) {
      const app = await database.execute({
        sql: "SELECT payment FROM applications WHERE id = ? AND user_id = ?",
        args: [id, session.userId]
      });
      if (!app.rows[0]) throw fail("Application not found for this account.", 404);
      if (app.rows[0].payment !== "Unpaid") throw fail("This application has already been paid.", 409);
    }
    return sendJson(response, 200, { message: "Demo payment successful.", id });
  }

  if (route === "/api/admin/applications" && method === "GET") {
    if (!requireRole(session, "admin")) throw fail("Officer sign-in is required.", 401);
    const result = await database.execute({
      sql: `SELECT ${applicationColumns}
        FROM applications JOIN users ON users.id = applications.user_id
        ORDER BY applications.created_at DESC`
    });
    return sendJson(response, 200, result.rows.map(serializeApplication));
  }

  const adminApplicationMatch = route.match(/^\/api\/admin\/applications\/([A-Z0-9]+)$/i);
  if (adminApplicationMatch && method === "PATCH") {
    if (!requireRole(session, "admin")) throw fail("Officer sign-in is required.", 401);
    const body = await readJson(request);
    if (!STATUSES.has(body.status)) throw fail("Select a valid application status.", 400);
    const remarks = typeof body.remarks === "string" ? body.remarks.trim() : "";
    if (remarks.length > 500) throw fail("Officer remarks must be at most 500 characters.", 400);
    const result = await database.execute({
      sql: "UPDATE applications SET status = ?, remarks = ? WHERE id = ?",
      args: [body.status, remarks, adminApplicationMatch[1].toUpperCase()]
    });
    if (result.rowsAffected === 0) throw fail("Application not found.", 404);
    return sendJson(response, 200, { message: "Application updated successfully." });
  }

  const publicApplicationMatch = route.match(/^\/api\/applications\/([A-Z0-9]+)$/i);
  if (publicApplicationMatch && method === "GET") {
    const result = await database.execute({
      sql: `SELECT id, created_at AS created, status, payment, remarks
        FROM applications WHERE id = ?`,
      args: [publicApplicationMatch[1].toUpperCase()]
    });
    if (!result.rows[0]) throw fail("No application found. Check the ID and try again.", 404);
    return sendJson(response, 200, result.rows[0]);
  }

  return sendJson(response, 404, { error: "API endpoint not found." });
}

module.exports = async function vercelApi(request, response) {
  try {
    const url = new URL(request.url, `https://${request.headers.host || "localhost"}`);
    if (!url.pathname.startsWith("/api/")) return sendJson(response, 404, { error: "API endpoint not found." });
    const database = await getDatabase();
    const session = await getSession(database, request);
    await handleApi(request, response, url, database, session);
  } catch (error) {
    console.error(`[${new Date().toISOString()}] ${request.method} ${request.url}:`, error);
    if (!response.headersSent) {
      sendJson(response, error.status || 500, {
        error: error.status ? error.message : "The server encountered an unexpected error. Check its function logs."
      });
    } else {
      response.end();
    }
  }
};
