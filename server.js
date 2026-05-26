import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import { query } from "./db.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

function publicUser(row) {
  if (!row || typeof row !== "object") {
    return null;
  }
  const safe = { ...row };
  delete safe.password_hash;
  delete safe.PASSWORD_HASH;
  return safe;
}

const accountRoles = ["Front Desk", "Dispatch", "Dealer", "Technician", "Customer"];
const accountCreatorRoles = ["Admin", "Front Desk"];

function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

function normalizeMobileValue(mobile) {
  return typeof mobile === "string" ? mobile.replace(/\D/g, "") : "";
}

/** Express 4: async route errors must be passed to next() or the process can crash (no DB = dead server). */
function asyncRoute(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

app.get("/ping", (_req, res) => {
  res.json({ ok: true, message: "API is running (no database check)" });
});

app.get("/health", async (_req, res) => {
  try {
    const result = await query("SELECT NOW() AS time");
    res.json({ ok: true, database: "mysql", databaseTime: result.rows[0].time });
  } catch (err) {
    console.error("GET /health database error:", err?.message || err);
    res.status(503).json({
      ok: false,
      database: "mysql",
      error: err?.code || err?.message || "database_unreachable",
      hint: "Server is reachable; fix MySQL host, VPN/firewall, or allow this PC IP on the database server."
    });
  }
});

app.post("/auth/login", asyncRoute(async (req, res) => {
  const lid = typeof req.body.loginId === "string" ? req.body.loginId.trim() : "";
  let rawEmail =
    typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  let rawMobile =
    typeof req.body.mobile === "string" ? String(req.body.mobile).replace(/\D/g, "") : "";
  const password = req.body.password;
  const { role } = req.body;

  if (lid) {
    if (lid.includes("@")) {
      rawEmail = lid.toLowerCase();
    } else {
      const digitsOnly = lid.replace(/\D/g, "");
      if (digitsOnly.length >= 10) {
        rawMobile = digitsOnly;
      } else {
        rawEmail = lid.toLowerCase();
      }
    }
  } else if (rawEmail) {
    rawEmail = rawEmail.toLowerCase();
  }

  if (!role || (!rawEmail && !rawMobile)) {
    return res.status(400).json({
      error:
        "role is required plus login ID: use loginId (email or mobile) or legacy email/mobile fields.",
    });
  }
  if (password === undefined || password === null) {
    return res.status(400).json({ error: "password is required" });
  }

  const result = rawEmail
    ? await query(
        "SELECT * FROM users WHERE LOWER(TRIM(COALESCE(email,''))) = LOWER(?) AND role = ? LIMIT 1",
        [rawEmail, role]
      )
    : await query("SELECT * FROM users WHERE mobile = ? AND role = ? LIMIT 1", [rawMobile, role]);
  if (!result.rowCount) {
    return res.status(404).json({ error: "User not found" });
  }
  const userRow = result.rows[0];
  const storedHash = userRow.password_hash;
  if (!storedHash) {
    return res.status(401).json({ error: "Password not set for this account." });
  }
  if (storedHash !== hashPassword(String(password))) {
    return res.status(401).json({ error: "Invalid user ID or password" });
  }

  let customer = null;
  let technician = null;
  if (role === "Customer") {
    const cr = await query("SELECT * FROM customers WHERE user_id = ? LIMIT 1", [userRow.id]);
    if (cr.rowCount) customer = cr.rows[0];
  }
  if (role === "Technician") {
    const tr = await query("SELECT * FROM technicians WHERE user_id = ? LIMIT 1", [userRow.id]);
    if (tr.rowCount) technician = tr.rows[0];
  }

  res.json({
    user: publicUser(userRow),
    customer,
    technician
  });
}));

/** Customer / Technician: logged-in profile — change login password after verifying old one. */
app.post("/auth/change-password", asyncRoute(async (req, res) => {
  const { userId, role, email, oldPassword, newPassword } = req.body;
  const emailTrim = typeof email === "string" ? email.trim().toLowerCase() : "";

  if (!userId || !role || !emailTrim || typeof oldPassword !== "string") {
    return res.status(400).json({
      error: "userId, role, email, and oldPassword are required",
    });
  }
  if (!newPassword || String(newPassword).length < 8) {
    return res.status(400).json({
      error: "New password must be at least 8 characters.",
    });
  }

  const result = await query(
    "SELECT * FROM users WHERE id = ? AND role = ? AND LOWER(TRIM(COALESCE(email,''))) = ? LIMIT 1",
    [userId, role, emailTrim.toLowerCase()]
  );
  if (!result.rowCount) {
    return res.status(404).json({ error: "Account not found for this login." });
  }
  const row = result.rows[0];
  if (!row.password_hash) {
    return res.status(400).json({ error: "No password set for this account." });
  }
  if (row.password_hash !== hashPassword(oldPassword)) {
    return res.status(401).json({ error: "Current password is incorrect." });
  }

  await query("UPDATE users SET password_hash = ? WHERE id = ?", [hashPassword(String(newPassword)), userId]);

  res.json({ ok: true });
}));

app.get("/accounts", asyncRoute(async (_req, res) => {
  const result = await query(
    "SELECT id, role, name, mobile, email, status, created_at FROM users ORDER BY created_at DESC LIMIT 500"
  );
  res.json({ accounts: result.rows });
}));

app.delete("/accounts/:id", asyncRoute(async (req, res) => {
  const requesterRole = typeof req.body?.requesterRole === "string" ? req.body.requesterRole.trim() : "";
  const accountId = typeof req.params.id === "string" ? req.params.id.trim() : "";

  if (requesterRole !== "Admin") {
    return res.status(403).json({ error: "Only Admin can delete login accounts." });
  }
  if (!accountId) {
    return res.status(400).json({ error: "Account id is required." });
  }

  const existing = await query("SELECT id, role, name, mobile, email FROM users WHERE id = ? LIMIT 1", [accountId]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Account not found." });
  }

  const account = existing.rows[0];
  if (account.role === "Admin") {
    return res.status(400).json({ error: "Admin account cannot be deleted from this screen." });
  }

  const deleted = {
    customers: 0,
    technicians: 0,
    dealers: 0,
    users: 0
  };

  if (account.role === "Customer") {
    const result = await query("DELETE FROM customers WHERE user_id = ? OR mobile = ?", [account.id, account.mobile]);
    deleted.customers = result.affectedRows;
  }

  if (account.role === "Technician") {
    const result = await query("DELETE FROM technicians WHERE user_id = ? OR mobile = ?", [account.id, account.mobile]);
    deleted.technicians = result.affectedRows;
  }

  if (account.role === "Dealer") {
    const result = await query("DELETE FROM dealers WHERE mobile = ?", [account.mobile]);
    deleted.dealers = result.affectedRows;
  }

  const userDelete = await query("DELETE FROM users WHERE id = ?", [account.id]);
  deleted.users = userDelete.affectedRows;

  res.json({ ok: true, deletedAccount: publicUser(account), deleted });
}));

app.post("/accounts", asyncRoute(async (req, res) => {
  const {
    role,
    name,
    mobile,
    email,
    password,
    status,
    createdByRole,
    city,
    state,
    address,
    pincode,
    serviceAreas,
    dealerNo,
    contactPerson
  } = req.body;

  const cleanRole = typeof role === "string" ? role.trim() : "";
  const cleanName = typeof name === "string" ? name.trim() : "";
  const cleanMobile = normalizeMobileValue(mobile);
  const cleanEmail = normalizeEmail(email);
  const cleanCreatedByRole = typeof createdByRole === "string" ? createdByRole.trim() : "";
  const cleanPassword = typeof password === "string" ? password : "";

  if (!accountCreatorRoles.includes(cleanCreatedByRole)) {
    return res.status(403).json({ error: "Only Admin or Front Desk can create login accounts." });
  }
  if (!accountRoles.includes(cleanRole)) {
    return res.status(400).json({ error: "Select a valid role." });
  }
  if (!cleanName || !cleanMobile || !cleanEmail || !cleanPassword) {
    return res.status(400).json({ error: "name, mobile, email, and password are required." });
  }
  if (cleanMobile.length < 10) {
    return res.status(400).json({ error: "Enter a valid mobile number." });
  }
  if (cleanPassword.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters." });
  }

  const existingMobile = await query("SELECT id FROM users WHERE mobile = ? LIMIT 1", [cleanMobile]);
  if (existingMobile.rowCount) {
    return res.status(409).json({ error: "This mobile number already has a login account." });
  }
  const existingEmail = await query(
    "SELECT id FROM users WHERE LOWER(TRIM(COALESCE(email,''))) = ? AND role = ? LIMIT 1",
    [cleanEmail, cleanRole]
  );
  if (existingEmail.rowCount) {
    return res.status(409).json({ error: "This login ID already exists for the selected role." });
  }

  await query(
    "INSERT INTO users (role, name, mobile, email, password_hash, status) VALUES (?, ?, ?, ?, ?, ?)",
    [cleanRole, cleanName, cleanMobile, cleanEmail, hashPassword(cleanPassword), status || "Active"]
  );
  const user = await query("SELECT * FROM users WHERE mobile = ? AND role = ? LIMIT 1", [cleanMobile, cleanRole]);
  const userId = user.rows[0].id;

  let customer = null;
  let technician = null;
  let dealer = null;

  if (cleanRole === "Customer") {
    await query(
      "INSERT INTO customers (user_id, name, mobile, address, city, state, pincode) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [userId, cleanName, cleanMobile, address || null, city || null, state || null, pincode || null]
    );
    const result = await query("SELECT * FROM customers WHERE user_id = ? LIMIT 1", [userId]);
    customer = result.rows[0] || null;
  }

  if (cleanRole === "Technician") {
    await query(
      "INSERT INTO technicians (user_id, name, mobile, city, service_areas, approval_status) VALUES (?, ?, ?, ?, ?, 'Pending')",
      [userId, cleanName, cleanMobile, city || null, serviceAreas || null]
    );
    const result = await query("SELECT * FROM technicians WHERE user_id = ? LIMIT 1", [userId]);
    technician = result.rows[0] || null;
  }

  if (cleanRole === "Dealer" && dealerNo) {
    await query(
      "INSERT INTO dealers (dealer_no, name, contact_person, mobile, address, city, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [dealerNo, cleanName, contactPerson || null, cleanMobile, address || null, city || null, state || null]
    );
    const result = await query("SELECT * FROM dealers WHERE dealer_no = ? LIMIT 1", [dealerNo]);
    dealer = result.rows[0] || null;
  }

  res.status(201).json({
    user: publicUser(user.rows[0]),
    customer,
    technician,
    dealer
  });
}));

app.post("/customers", asyncRoute(async (req, res) => {
  const { name, mobile, email, password, address, city, state, pincode } = req.body;
  if (!name || !mobile) {
    return res.status(400).json({ error: "name and mobile are required" });
  }

  await query(
    "INSERT INTO users (role, name, mobile, email, password_hash) VALUES ('Customer', ?, ?, ?, ?)",
    [name, mobile, email ? String(email).trim().toLowerCase() || null : null, password ? hashPassword(password) : null]
  );
  const user = await query("SELECT * FROM users WHERE mobile = ? AND role = 'Customer' LIMIT 1", [mobile]);
  await query(
    "INSERT INTO customers (user_id, name, mobile, address, city, state, pincode) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [user.rows[0].id, name, mobile, address || null, city || null, state || null, pincode || null]
  );
  const customer = await query("SELECT * FROM customers WHERE mobile = ? LIMIT 1", [mobile]);

  res.status(201).json({
    user: publicUser(user.rows[0]),
    customer: customer.rows[0]
  });
}));

app.post("/technicians", asyncRoute(async (req, res) => {
  const { name, mobile, email, password, city, serviceAreas } = req.body;
  if (!name || !mobile) {
    return res.status(400).json({ error: "name and mobile are required" });
  }

  await query(
    "INSERT INTO users (role, name, mobile, email, password_hash, status) VALUES ('Technician', ?, ?, ?, ?, 'Pending')",
    [name, mobile, email ? String(email).trim().toLowerCase() || null : null, password ? hashPassword(password) : null]
  );
  const user = await query("SELECT * FROM users WHERE mobile = ? AND role = 'Technician' LIMIT 1", [mobile]);
  await query(
    "INSERT INTO technicians (user_id, name, mobile, city, service_areas) VALUES (?, ?, ?, ?, ?)",
    [user.rows[0].id, name, mobile, city || null, serviceAreas || null]
  );
  const technician = await query("SELECT * FROM technicians WHERE mobile = ? LIMIT 1", [mobile]);

  res.status(201).json({
    user: publicUser(user.rows[0]),
    technician: technician.rows[0]
  });
}));

app.get("/dealers", asyncRoute(async (_req, res) => {
  const result = await query("SELECT * FROM dealers ORDER BY created_at DESC");
  res.json({ dealers: result.rows });
}));

app.post("/dealers", asyncRoute(async (req, res) => {
  const { dealerNo, name, contactPerson, mobile, address, city, state } = req.body;
  if (!dealerNo || !name || !mobile) {
    return res.status(400).json({ error: "dealerNo, name, and mobile are required" });
  }

  await query(
    "INSERT INTO dealers (dealer_no, name, contact_person, mobile, address, city, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [dealerNo, name, contactPerson || null, mobile, address || null, city || null, state || null]
  );
  const result = await query("SELECT * FROM dealers WHERE dealer_no = ? LIMIT 1", [dealerNo]);
  res.status(201).json({ dealer: result.rows[0] });
}));

app.get("/warranties/customer/:customerId", asyncRoute(async (req, res) => {
  const result = await query(
    "SELECT * FROM warranties WHERE customer_id = ? ORDER BY created_at DESC",
    [req.params.customerId]
  );
  res.json({ warranties: result.rows });
}));

/** List complaints (staff panels). Customers should use `/complaints/customer/:customerId`. */
app.get("/complaints", asyncRoute(async (_req, res) => {
  const result = await query(
    "SELECT * FROM complaints ORDER BY created_at DESC LIMIT 800"
  );
  res.json({ complaints: result.rows });
}));

/** Serial inventory for dispatch/dealer tooling */
app.get("/serial-numbers", asyncRoute(async (_req, res) => {
  const result = await query(
    `SELECT s.*, p.name AS product_name, p.model_no
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     ORDER BY s.created_at DESC
     LIMIT 800`
  );
  res.json({ serials: result.rows });
}));

app.get("/complaints/customer/:customerId", asyncRoute(async (req, res) => {
  const result = await query(
    "SELECT * FROM complaints WHERE customer_id = ? ORDER BY created_at DESC",
    [req.params.customerId]
  );
  res.json({ complaints: result.rows });
}));

app.post("/complaints", asyncRoute(async (req, res) => {
  const { complaintNo, warrantyId, customerId, problemType, description, priority } = req.body;
  if (!complaintNo || !customerId || !problemType) {
    return res.status(400).json({ error: "complaintNo, customerId, and problemType are required" });
  }

  await query(
    "INSERT INTO complaints (complaint_no, warranty_id, customer_id, problem_type, description, priority) VALUES (?, ?, ?, ?, ?, ?)",
    [complaintNo, warrantyId || null, customerId, problemType, description || null, priority || "Normal"]
  );
  const result = await query("SELECT * FROM complaints WHERE complaint_no = ? LIMIT 1", [complaintNo]);
  res.status(201).json({ complaint: result.rows[0] });
}));

app.use((error, _req, res, _next) => {
  console.error(error);
  const code = error?.code;
  if (code === "ETIMEDOUT" || code === "ECONNREFUSED" || code === "ENOTFOUND" || code === "PROTOCOL_CONNECTION_LOST") {
    return res.status(503).json({
      error: "Database unreachable. Confirm VPN/network, .env DB_HOST, and that the database allows connections from this PC.",
      code
    });
  }
  res.status(500).json({ error: error?.message || "Internal server error" });
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Hitaishi CRM API listening on http://0.0.0.0:${port} (reachable from phone via your PC LAN IP)`);
});
