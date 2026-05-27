import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import { createRequire } from "module";
import { query, withTransaction } from "./db.js";

dotenv.config();

const require = createRequire(import.meta.url);
const QRCode = require("qrcode-terminal/vendor/QRCode");
const QRErrorCorrectLevel = require("qrcode-terminal/vendor/QRCode/QRErrorCorrectLevel");

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

function cleanString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function cleanSerialNo(value) {
  return cleanString(value).replace(/\s+/g, "").toUpperCase();
}

function serialFromPayload(value) {
  const raw = cleanString(value);
  if (!raw) return "";
  try {
    const url = new URL(raw);
    const serial = url.searchParams.get("serial") || url.searchParams.get("serialNo") || url.searchParams.get("sn");
    if (serial) return cleanSerialNo(serial);
    const lastPath = url.pathname.split("/").filter(Boolean).pop();
    if (lastPath) return cleanSerialNo(decodeURIComponent(lastPath));
  } catch {
    // Plain serials and simple key-value QR payloads are handled below.
  }
  const match = raw.match(/(?:serial|serialNo|sn)\s*[:=]\s*([A-Za-z0-9._/-]+)/i);
  return cleanSerialNo(match?.[1] || raw);
}

function cleanDate(value) {
  const raw = cleanString(value);
  if (!raw) return null;
  const iso = raw.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (iso) return raw;
  const indian = raw.match(/^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$/);
  if (indian) {
    const [, dd, mm, yyyy] = indian;
    return `${yyyy}-${String(mm).padStart(2, "0")}-${String(dd).padStart(2, "0")}`;
  }
  return null;
}

function serialQrPayload(serialNo) {
  return `hitaishi://serial?serial=${encodeURIComponent(serialNo)}`;
}

function qrSvg(payload, size = 220) {
  const qr = new QRCode(-1, QRErrorCorrectLevel.M);
  qr.addData(payload);
  qr.make();
  const count = qr.getModuleCount();
  const quiet = 4;
  const cell = size / (count + quiet * 2);
  const total = (count + quiet * 2) * cell;
  const rects = [];
  for (let row = 0; row < count; row += 1) {
    for (let col = 0; col < count; col += 1) {
      if (qr.isDark(row, col)) {
        rects.push(`<rect x="${(col + quiet) * cell}" y="${(row + quiet) * cell}" width="${cell}" height="${cell}"/>`);
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" width="${size}" height="${size}" role="img"><rect width="100%" height="100%" fill="#fff"/><g fill="#000">${rects.join("")}</g></svg>`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function parseCsvLine(line) {
  const cells = [];
  let current = "";
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    const next = line[i + 1];
    if (char === "\"" && quoted && next === "\"") {
      current += "\"";
      i += 1;
    } else if (char === "\"") {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      cells.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }
  cells.push(current.trim());
  return cells;
}

function parseSerialCsv(csv) {
  const lines = String(csv || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!lines.length) return [];
  const headers = parseCsvLine(lines[0]).map((header) => header.trim().toLowerCase());
  return lines.slice(1).map((line) => {
    const cells = parseCsvLine(line);
    const row = {};
    headers.forEach((header, index) => {
      row[header] = cells[index] || "";
    });
    return row;
  });
}

function pickRowValue(row, names) {
  for (const name of names) {
    if (row?.[name] !== undefined && row?.[name] !== null && String(row[name]).trim()) {
      return String(row[name]).trim();
    }
  }
  return "";
}

async function ensureSerialNumbersSchema() {
  const columns = [
    ["invoice_no", "ALTER TABLE serial_numbers ADD COLUMN invoice_no VARCHAR(120) NULL AFTER serial_no"],
    ["challan_no", "ALTER TABLE serial_numbers ADD COLUMN challan_no VARCHAR(120) NULL AFTER invoice_no"],
    ["batch_no", "ALTER TABLE serial_numbers ADD COLUMN batch_no VARCHAR(120) NULL AFTER challan_no"],
    ["dispatch_date", "ALTER TABLE serial_numbers ADD COLUMN dispatch_date DATE NULL AFTER batch_no"],
    ["qr_payload", "ALTER TABLE serial_numbers ADD COLUMN qr_payload VARCHAR(255) NULL AFTER qr_status"],
    ["qr_printed_at", "ALTER TABLE serial_numbers ADD COLUMN qr_printed_at TIMESTAMP NULL AFTER qr_payload"],
    ["dispatched_at", "ALTER TABLE serial_numbers ADD COLUMN dispatched_at TIMESTAMP NULL AFTER dispatch_status"]
  ];

  for (const [columnName, ddl] of columns) {
    const found = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'serial_numbers'
         AND COLUMN_NAME = ?
       LIMIT 1`,
      [columnName]
    );
    if (!found.rowCount) {
      await query(ddl);
    }
  }
}

async function getNextDealerNo(runQuery = query) {
  const result = await runQuery(
    `SELECT dealer_no
     FROM dealers
     WHERE dealer_no REGEXP '^DLR[0-9]+$'
     ORDER BY CAST(SUBSTRING(dealer_no, 4) AS UNSIGNED) DESC
     LIMIT 1`
  );
  const lastNo = result.rows?.[0]?.dealer_no || "";
  const lastNumber = Number(String(lastNo).replace(/^DLR/i, "")) || 0;
  return `DLR${String(lastNumber + 1).padStart(6, "0")}`;
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
  let dealer = null;
  if (role === "Customer") {
    const cr = await query("SELECT * FROM customers WHERE user_id = ? LIMIT 1", [userRow.id]);
    if (cr.rowCount) customer = cr.rows[0];
  }
  if (role === "Technician") {
    const tr = await query("SELECT * FROM technicians WHERE user_id = ? LIMIT 1", [userRow.id]);
    if (tr.rowCount) technician = tr.rows[0];
  }
  if (role === "Dealer") {
    const dealerMobile = normalizeMobileValue(userRow.mobile);
    const dr = await query(
      "SELECT * FROM dealers WHERE mobile = ? OR REPLACE(REPLACE(REPLACE(REPLACE(mobile, ' ', ''), '-', ''), '+', ''), '(', '') = ? LIMIT 1",
      [userRow.mobile, dealerMobile]
    );
    if (dr.rowCount) dealer = dr.rows[0];
  }

  res.json({
    user: publicUser(userRow),
    customer,
    technician,
    dealer
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

app.get("/dealers/next-number", asyncRoute(async (_req, res) => {
  res.json({ dealerNo: await getNextDealerNo() });
}));

app.get("/admin/dashboard", asyncRoute(async (_req, res) => {
  const [
    totalDealers,
    totalProducts,
    totalSerials,
    printedQr,
    warrantiesToday,
    activeWarranties,
    pendingInstallations,
    completedInstallations,
    openTasks,
    activeDealers,
    overdueComplaints,
    pendingComplaints,
    closedToday,
    pendingTechnicians,
    pendingSerials,
    pendingQuotationApprovals,
    pendingPayable
  ] = await Promise.all([
    query("SELECT COUNT(*) AS total FROM dealers"),
    query("SELECT COUNT(*) AS total FROM products"),
    query("SELECT COUNT(*) AS total FROM serial_numbers"),
    query("SELECT COUNT(*) AS total FROM serial_numbers WHERE qr_status = 'Printed'"),
    query("SELECT COUNT(*) AS total FROM warranties WHERE DATE(created_at) = CURDATE()"),
    query("SELECT COUNT(*) AS total FROM warranties WHERE status = 'Active'"),
    query("SELECT COUNT(*) AS total FROM tasks WHERE work_type = 'Installation' AND status NOT IN ('Closed', 'Completed', 'Cancelled')"),
    query("SELECT COUNT(*) AS total FROM tasks WHERE work_type = 'Installation' AND status IN ('Closed', 'Completed')"),
    query("SELECT COUNT(*) AS total FROM tasks WHERE status NOT IN ('Closed', 'Completed', 'Cancelled')"),
    query("SELECT COUNT(*) AS total FROM dealers WHERE status = 'Active'"),
    query(
      `SELECT COUNT(DISTINCT c.id) AS total
       FROM complaints c
       LEFT JOIN tasks t ON t.complaint_id = c.id
       WHERE c.status NOT IN ('Closed', 'Completed', 'Cancelled')
         AND t.due_at IS NOT NULL
         AND t.due_at < NOW()`
    ),
    query("SELECT COUNT(*) AS total FROM complaints WHERE status NOT IN ('Closed', 'Completed', 'Cancelled')"),
    query("SELECT COUNT(*) AS total FROM complaints WHERE status IN ('Closed', 'Completed') AND DATE(created_at) = CURDATE()"),
    query("SELECT COUNT(*) AS total FROM technicians WHERE approval_status = 'Pending'"),
    query("SELECT COUNT(*) AS total FROM serial_numbers WHERE qr_status = 'Not Printed' OR dispatch_status = 'Pending'"),
    query("SELECT COUNT(*) AS total FROM quotations WHERE status = 'Pending Admin Approval'"),
    query("SELECT COALESCE(SUM(amount), 0) AS total FROM payments WHERE status = 'Pending'")
  ]);

  const count = (result) => Number(result.rows?.[0]?.total || 0);
  res.json({
    summary: {
      totalDealers: count(totalDealers),
      totalProducts: count(totalProducts),
      totalSerials: count(totalSerials),
      printedQr: count(printedQr),
      warrantiesToday: count(warrantiesToday),
      activeWarranties: count(activeWarranties),
      pendingInstallations: count(pendingInstallations),
      completedInstallations: count(completedInstallations),
      openTasks: count(openTasks),
      activeDealers: count(activeDealers),
      overdueComplaints: count(overdueComplaints),
      pendingComplaints: count(pendingComplaints),
      closedToday: count(closedToday),
      pendingTechnicians: count(pendingTechnicians),
      pendingSerials: count(pendingSerials),
      pendingQuotationApprovals: count(pendingQuotationApprovals),
      pendingPayable: Number(pendingPayable.rows?.[0]?.total || 0)
    }
  });
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

  const deleted = await withTransaction(async (tx) => {
    const counts = {
      attachments: 0,
      payments: 0,
      quotations: 0,
      tasks: 0,
      complaints: 0,
      warranties: 0,
      feedback: 0,
      customers: 0,
      technicians: 0,
      dealers: 0,
      users: 0
    };

    const add = (key, result) => {
      counts[key] += Number(result?.affectedRows || 0);
    };
    const placeholders = (items) => items.map(() => "?").join(",");
    const idsFrom = (result) => result.rows.map((row) => row.id).filter(Boolean);
    const deleteAttachments = async (entityType, ids) => {
      if (!ids.length) return;
      add(
        "attachments",
        await tx(
          `DELETE FROM attachments WHERE entity_type = ? AND entity_id IN (${placeholders(ids)})`,
          [entityType, ...ids]
        )
      );
    };

    if (account.role === "Customer") {
      const customers = await tx("SELECT id FROM customers WHERE user_id = ? OR mobile = ?", [account.id, account.mobile]);
      const customerIds = idsFrom(customers);

      if (customerIds.length) {
        const warranties = await tx(
          `SELECT id FROM warranties WHERE customer_id IN (${placeholders(customerIds)})`,
          customerIds
        );
        const warrantyIds = idsFrom(warranties);
        const complaints = await tx(
          `SELECT id FROM complaints WHERE customer_id IN (${placeholders(customerIds)})`,
          customerIds
        );
        const complaintIds = idsFrom(complaints);
        const tasks = complaintIds.length
          ? await tx(`SELECT id FROM tasks WHERE complaint_id IN (${placeholders(complaintIds)})`, complaintIds)
          : { rows: [] };
        const taskIds = idsFrom(tasks);

        await deleteAttachments("Customer", customerIds);
        await deleteAttachments("customers", customerIds);
        await deleteAttachments("Warranty", warrantyIds);
        await deleteAttachments("warranties", warrantyIds);
        await deleteAttachments("Complaint", complaintIds);
        await deleteAttachments("complaints", complaintIds);
        await deleteAttachments("Task", taskIds);
        await deleteAttachments("tasks", taskIds);

        if (taskIds.length) {
          add("payments", await tx(`DELETE FROM payments WHERE task_id IN (${placeholders(taskIds)})`, taskIds));
          add("tasks", await tx(`DELETE FROM tasks WHERE id IN (${placeholders(taskIds)})`, taskIds));
        }
        if (complaintIds.length) {
          add("quotations", await tx(`DELETE FROM quotations WHERE complaint_id IN (${placeholders(complaintIds)})`, complaintIds));
          add("feedback", await tx(`DELETE FROM feedback WHERE complaint_id IN (${placeholders(complaintIds)})`, complaintIds));
          add("complaints", await tx(`DELETE FROM complaints WHERE id IN (${placeholders(complaintIds)})`, complaintIds));
        }
        if (warrantyIds.length) {
          add("warranties", await tx(`DELETE FROM warranties WHERE id IN (${placeholders(warrantyIds)})`, warrantyIds));
        }
        add("feedback", await tx(`DELETE FROM feedback WHERE customer_id IN (${placeholders(customerIds)})`, customerIds));
        add("customers", await tx(`DELETE FROM customers WHERE id IN (${placeholders(customerIds)})`, customerIds));
      }
    }

    if (account.role === "Technician") {
      const technicians = await tx("SELECT id FROM technicians WHERE user_id = ? OR mobile = ?", [account.id, account.mobile]);
      const technicianIds = idsFrom(technicians);

      if (technicianIds.length) {
        const tasks = await tx(`SELECT id FROM tasks WHERE technician_id IN (${placeholders(technicianIds)})`, technicianIds);
        const taskIds = idsFrom(tasks);

        await deleteAttachments("Technician", technicianIds);
        await deleteAttachments("technicians", technicianIds);
        await deleteAttachments("Task", taskIds);
        await deleteAttachments("tasks", taskIds);

        if (taskIds.length) {
          add("payments", await tx(`DELETE FROM payments WHERE task_id IN (${placeholders(taskIds)})`, taskIds));
          add("tasks", await tx(`DELETE FROM tasks WHERE id IN (${placeholders(taskIds)})`, taskIds));
        }
        add("payments", await tx(`DELETE FROM payments WHERE technician_id IN (${placeholders(technicianIds)})`, technicianIds));
        add("quotations", await tx(`DELETE FROM quotations WHERE technician_id IN (${placeholders(technicianIds)})`, technicianIds));
        add("technicians", await tx(`DELETE FROM technicians WHERE id IN (${placeholders(technicianIds)})`, technicianIds));
      }
    }

    if (account.role === "Dealer") {
      const dealers = await tx("SELECT id FROM dealers WHERE mobile = ?", [account.mobile]);
      const dealerIds = idsFrom(dealers);

      if (dealerIds.length) {
        await deleteAttachments("Dealer", dealerIds);
        await deleteAttachments("dealers", dealerIds);
        add("dealers", await tx(`DELETE FROM dealers WHERE id IN (${placeholders(dealerIds)})`, dealerIds));
      }
    }

    const userDelete = await tx("DELETE FROM users WHERE id = ?", [account.id]);
    counts.users = userDelete.affectedRows;
    return counts;
  });

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

  if (cleanRole === "Dealer") {
    const finalDealerNo = cleanString(dealerNo) || await getNextDealerNo();
    await query(
      "INSERT INTO dealers (dealer_no, name, contact_person, mobile, address, city, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [finalDealerNo, cleanName, contactPerson || null, cleanMobile, address || null, city || null, state || null]
    );
    const result = await query("SELECT * FROM dealers WHERE dealer_no = ? LIMIT 1", [finalDealerNo]);
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

app.get("/technicians", asyncRoute(async (req, res) => {
  const status = cleanString(req.query.status);
  const allowed = ["Pending", "Approved", "Rejected"];
  const where = allowed.includes(status) ? "WHERE t.approval_status = ?" : "";
  const params = allowed.includes(status) ? [status] : [];
  const result = await query(
    `SELECT
       t.*,
       u.email,
       u.status AS user_status
     FROM technicians t
     LEFT JOIN users u ON u.id = t.user_id
     ${where}
     ORDER BY t.created_at DESC
     LIMIT 800`,
    params
  );
  res.json({ technicians: result.rows });
}));

app.patch("/technicians/:id/approval", asyncRoute(async (req, res) => {
  const requesterRole = cleanString(req.body.requesterRole);
  const status = cleanString(req.body.status);
  const technicianId = cleanString(req.params.id);

  if (requesterRole !== "Admin") {
    return res.status(403).json({ error: "Only Admin can approve or reject technicians." });
  }
  if (!["Approved", "Rejected"].includes(status)) {
    return res.status(400).json({ error: "Status must be Approved or Rejected." });
  }

  const existing = await query("SELECT id, user_id FROM technicians WHERE id = ? LIMIT 1", [technicianId]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Technician not found." });
  }

  await withTransaction(async (tx) => {
    await tx("UPDATE technicians SET approval_status = ? WHERE id = ?", [status, technicianId]);
    if (existing.rows[0].user_id) {
      await tx("UPDATE users SET status = ? WHERE id = ?", [status === "Approved" ? "Active" : "Rejected", existing.rows[0].user_id]);
    }
  });

  const result = await query(
    `SELECT t.*, u.email, u.status AS user_status
     FROM technicians t
     LEFT JOIN users u ON u.id = t.user_id
     WHERE t.id = ?
     LIMIT 1`,
    [technicianId]
  );
  res.json({ technician: result.rows[0] });
}));

app.get("/dealers", asyncRoute(async (_req, res) => {
  const result = await query(
    `SELECT
       COALESCE(d.id, u.id) AS id,
       COALESCE(d.dealer_no, 'Pending Dealer No') AS dealer_no,
       COALESCE(d.name, u.name) AS name,
       COALESCE(d.contact_person, u.name) AS contact_person,
       COALESCE(d.mobile, u.mobile) AS mobile,
       d.address,
       d.city,
       d.state,
       COALESCE(d.status, u.status, 'Active') AS status,
       COALESCE(d.created_at, u.created_at) AS created_at
     FROM users u
     LEFT JOIN dealers d ON d.mobile = u.mobile
     WHERE u.role = 'Dealer'
     UNION
     SELECT
       d.id,
       d.dealer_no,
       d.name,
       d.contact_person,
       d.mobile,
       d.address,
       d.city,
       d.state,
       d.status,
       d.created_at
     FROM dealers d
     LEFT JOIN users u ON u.mobile = d.mobile AND u.role = 'Dealer'
     WHERE u.id IS NULL
     ORDER BY created_at DESC`
  );
  res.json({ dealers: result.rows });
}));

app.get("/dealers/:id/dashboard", asyncRoute(async (req, res) => {
  const dealerId = cleanString(req.params.id);
  if (!dealerId) {
    return res.status(400).json({ error: "Dealer id is required." });
  }
  const dealer = await query("SELECT * FROM dealers WHERE id = ? LIMIT 1", [dealerId]);
  if (!dealer.rowCount) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  const [serials, warranties, openComplaints, pendingScan] = await Promise.all([
    query("SELECT COUNT(*) AS total FROM serial_numbers WHERE dealer_id = ?", [dealerId]),
    query("SELECT COUNT(*) AS total FROM warranties WHERE dealer_id = ?", [dealerId]),
    query(
      `SELECT COUNT(*) AS total
       FROM complaints c
       INNER JOIN warranties w ON w.id = c.warranty_id
       LEFT JOIN serial_numbers s ON s.id = w.serial_id
       WHERE COALESCE(w.dealer_id, s.dealer_id) = ?
         AND c.status NOT IN ('Closed', 'Completed', 'Cancelled')`,
      [dealerId]
    ),
    query(
      `SELECT COUNT(*) AS total
       FROM serial_numbers s
       LEFT JOIN warranties w ON w.serial_id = s.id
       WHERE s.dealer_id = ? AND w.id IS NULL`,
      [dealerId]
    )
  ]);
  const complaints = await query(
    `SELECT
       c.*,
       w.warranty_no,
       w.start_date,
       w.expiry_date,
       w.status AS warranty_status,
       w.installation_status,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       s.serial_no,
       p.name AS product_name,
       p.model_no,
       tech.name AS technician_name
     FROM complaints c
     INNER JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN tasks t ON t.complaint_id = c.id
     LEFT JOIN technicians tech ON tech.id = t.technician_id
     WHERE COALESCE(w.dealer_id, s.dealer_id) = ?
     ORDER BY c.created_at DESC
     LIMIT 3`,
    [dealerId]
  );
  const count = (result) => Number(result.rows[0]?.total || 0);
  res.json({
    dealer: dealer.rows[0],
    stats: {
      productsDispatched: count(serials),
      warrantiesRegistered: count(warranties),
      complaintsOpen: count(openComplaints),
      pendingScan: count(pendingScan)
    },
    complaints: complaints.rows
  });
}));

app.post("/dealers", asyncRoute(async (req, res) => {
  const { dealerNo, name, contactPerson, mobile, address, city, state } = req.body;
  if (!name || !mobile) {
    return res.status(400).json({ error: "name and mobile are required" });
  }

  const finalDealerNo = cleanString(dealerNo) || await getNextDealerNo();
  await query(
    "INSERT INTO dealers (dealer_no, name, contact_person, mobile, address, city, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [finalDealerNo, name, contactPerson || null, mobile, address || null, city || null, state || null]
  );
  const result = await query("SELECT * FROM dealers WHERE dealer_no = ? LIMIT 1", [finalDealerNo]);
  res.status(201).json({ dealer: result.rows[0] });
}));

app.patch("/dealers/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const dealerNo = cleanString(req.body.dealerNo || req.body.dealer_no);
  const name = cleanString(req.body.name);
  const contactPerson = cleanString(req.body.contactPerson || req.body.contact_person) || null;
  const mobile = normalizeMobileValue(req.body.mobile);
  const address = cleanString(req.body.address) || null;
  const city = cleanString(req.body.city) || null;
  const state = cleanString(req.body.state) || null;
  const status = cleanString(req.body.status) || "Active";

  if (!id || !dealerNo || !name || !mobile) {
    return res.status(400).json({ error: "Dealer id, dealer number, name, and mobile are required." });
  }

  const duplicate = await query("SELECT id FROM dealers WHERE LOWER(TRIM(dealer_no)) = LOWER(?) AND id <> ? LIMIT 1", [dealerNo, id]);
  if (duplicate.rowCount) {
    return res.status(409).json({ error: "This dealer number already exists." });
  }

  const result = await query(
    `UPDATE dealers
     SET dealer_no = ?, name = ?, contact_person = ?, mobile = ?, address = ?, city = ?, state = ?, status = ?
     WHERE id = ?`,
    [dealerNo, name, contactPerson, mobile, address, city, state, status, id]
  );
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  const row = await query("SELECT * FROM dealers WHERE id = ? LIMIT 1", [id]);
  res.json({ dealer: row.rows[0] });
}));

app.delete("/dealers/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const result = await query("DELETE FROM dealers WHERE id = ?", [id]);
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  res.json({ ok: true });
}));

app.get("/products", asyncRoute(async (_req, res) => {
  const result = await query("SELECT * FROM products ORDER BY created_at DESC LIMIT 800");
  res.json({ products: result.rows });
}));

app.post("/products", asyncRoute(async (req, res) => {
  const name = cleanString(req.body.name);
  const modelNo = cleanString(req.body.modelNo || req.body.model_no);
  const category = cleanString(req.body.category) || null;
  const warrantyMonths = Number(req.body.warrantyMonths || req.body.warranty_months || 12);

  if (!name || !modelNo) {
    return res.status(400).json({ error: "Product name and model number are required." });
  }

  const duplicate = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) LIMIT 1", [modelNo]);
  if (duplicate.rowCount) {
    return res.status(409).json({ error: "This product model already exists." });
  }

  await query(
    "INSERT INTO products (name, model_no, category, warranty_months) VALUES (?, ?, ?, ?)",
    [name, modelNo, category, Number.isFinite(warrantyMonths) && warrantyMonths > 0 ? warrantyMonths : 12]
  );
  const result = await query("SELECT * FROM products WHERE model_no = ? LIMIT 1", [modelNo]);
  res.status(201).json({ product: result.rows[0] });
}));

app.patch("/products/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const name = cleanString(req.body.name);
  const modelNo = cleanString(req.body.modelNo || req.body.model_no);
  const category = cleanString(req.body.category) || null;
  const warrantyMonths = Number(req.body.warrantyMonths || req.body.warranty_months || 12);

  if (!id || !name || !modelNo) {
    return res.status(400).json({ error: "Product id, name, and model number are required." });
  }

  const duplicate = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) AND id <> ? LIMIT 1", [modelNo, id]);
  if (duplicate.rowCount) {
    return res.status(409).json({ error: "This product model already exists." });
  }

  const result = await query(
    "UPDATE products SET name = ?, model_no = ?, category = ?, warranty_months = ? WHERE id = ?",
    [name, modelNo, category, Number.isFinite(warrantyMonths) && warrantyMonths > 0 ? warrantyMonths : 12, id]
  );
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Product not found." });
  }
  const row = await query("SELECT * FROM products WHERE id = ? LIMIT 1", [id]);
  res.json({ product: row.rows[0] });
}));

app.delete("/products/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const linked = await query("SELECT id FROM serial_numbers WHERE product_id = ? LIMIT 1", [id]);
  if (linked.rowCount) {
    return res.status(409).json({ error: "Product is linked with serial numbers. Edit it instead of deleting." });
  }
  const result = await query("DELETE FROM products WHERE id = ?", [id]);
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Product not found." });
  }
  res.json({ ok: true });
}));

app.get("/service-areas", asyncRoute(async (_req, res) => {
  const result = await query("SELECT * FROM service_areas ORDER BY created_at DESC LIMIT 800");
  res.json({ areas: result.rows });
}));

app.post("/service-areas", asyncRoute(async (req, res) => {
  const state = cleanString(req.body.state) || null;
  const city = cleanString(req.body.city);
  const area = cleanString(req.body.area);
  const pincode = cleanString(req.body.pincode) || null;
  const status = cleanString(req.body.status) || "Active";

  if (!city || !area) {
    return res.status(400).json({ error: "City and area are required." });
  }

  await query(
    "INSERT INTO service_areas (state, city, area, pincode, status) VALUES (?, ?, ?, ?, ?)",
    [state, city, area, pincode, status]
  );
  const result = await query(
    "SELECT * FROM service_areas WHERE city = ? AND area = ? ORDER BY created_at DESC LIMIT 1",
    [city, area]
  );
  res.status(201).json({ area: result.rows[0] });
}));

app.patch("/service-areas/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const state = cleanString(req.body.state) || null;
  const city = cleanString(req.body.city);
  const area = cleanString(req.body.area);
  const pincode = cleanString(req.body.pincode) || null;
  const status = cleanString(req.body.status) || "Active";

  if (!id || !city || !area) {
    return res.status(400).json({ error: "Area id, city, and area are required." });
  }

  const result = await query(
    "UPDATE service_areas SET state = ?, city = ?, area = ?, pincode = ?, status = ? WHERE id = ?",
    [state, city, area, pincode, status, id]
  );
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Service area not found." });
  }
  const row = await query("SELECT * FROM service_areas WHERE id = ? LIMIT 1", [id]);
  res.json({ area: row.rows[0] });
}));

app.delete("/service-areas/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const result = await query("DELETE FROM service_areas WHERE id = ?", [id]);
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Service area not found." });
  }
  res.json({ ok: true });
}));

app.get("/work-type-costs", asyncRoute(async (_req, res) => {
  const result = await query(
    `SELECT c.*, t.name AS technician_name
     FROM work_type_costs c
     LEFT JOIN technicians t ON t.id = c.technician_id
     ORDER BY c.created_at DESC
     LIMIT 800`
  );
  res.json({ costs: result.rows });
}));

app.post("/work-type-costs", asyncRoute(async (req, res) => {
  const workType = cleanString(req.body.workType || req.body.work_type);
  const productCategory = cleanString(req.body.productCategory || req.body.product_category) || null;
  const modelNo = cleanString(req.body.modelNo || req.body.model_no) || null;
  const city = cleanString(req.body.city) || null;
  const payableAmount = Number(req.body.payableAmount || req.body.payable_amount || 0);
  const defaultTimeframeHours = Number(req.body.defaultTimeframeHours || req.body.default_timeframe_hours || 24);
  const effectiveDate = cleanString(req.body.effectiveDate || req.body.effective_date) || null;
  const status = cleanString(req.body.status) || "Active";

  if (!workType) {
    return res.status(400).json({ error: "Work type is required." });
  }

  await query(
    `INSERT INTO work_type_costs
     (work_type, product_category, model_no, city, payable_amount, default_timeframe_hours, effective_date, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      workType,
      productCategory,
      modelNo,
      city,
      Number.isFinite(payableAmount) ? payableAmount : 0,
      Number.isFinite(defaultTimeframeHours) && defaultTimeframeHours > 0 ? defaultTimeframeHours : 24,
      effectiveDate,
      status
    ]
  );
  const result = await query("SELECT * FROM work_type_costs ORDER BY created_at DESC LIMIT 1");
  res.status(201).json({ cost: result.rows[0] });
}));

app.patch("/work-type-costs/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const workType = cleanString(req.body.workType || req.body.work_type);
  const productCategory = cleanString(req.body.productCategory || req.body.product_category) || null;
  const modelNo = cleanString(req.body.modelNo || req.body.model_no) || null;
  const city = cleanString(req.body.city) || null;
  const payableAmount = Number(req.body.payableAmount || req.body.payable_amount || 0);
  const defaultTimeframeHours = Number(req.body.defaultTimeframeHours || req.body.default_timeframe_hours || 24);
  const effectiveDate = cleanString(req.body.effectiveDate || req.body.effective_date) || null;
  const status = cleanString(req.body.status) || "Active";

  if (!id || !workType) {
    return res.status(400).json({ error: "Cost rule id and work type are required." });
  }

  const result = await query(
    `UPDATE work_type_costs
     SET work_type = ?, product_category = ?, model_no = ?, city = ?, payable_amount = ?, default_timeframe_hours = ?, effective_date = ?, status = ?
     WHERE id = ?`,
    [
      workType,
      productCategory,
      modelNo,
      city,
      Number.isFinite(payableAmount) ? payableAmount : 0,
      Number.isFinite(defaultTimeframeHours) && defaultTimeframeHours > 0 ? defaultTimeframeHours : 24,
      effectiveDate,
      status,
      id
    ]
  );
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Cost rule not found." });
  }
  const row = await query("SELECT * FROM work_type_costs WHERE id = ? LIMIT 1", [id]);
  res.json({ cost: row.rows[0] });
}));

app.delete("/work-type-costs/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const result = await query("DELETE FROM work_type_costs WHERE id = ?", [id]);
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Cost rule not found." });
  }
  res.json({ ok: true });
}));

app.get("/warranties/customer/:customerId", asyncRoute(async (req, res) => {
  const result = await query(
    `SELECT
       w.*,
       s.serial_no,
       p.name AS product_name,
       p.model_no,
       p.warranty_months,
       d.dealer_no,
       d.name AS dealer_name
     FROM warranties w
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     WHERE w.customer_id = ?
     ORDER BY w.created_at DESC`,
    [req.params.customerId]
  );
  res.json({ warranties: result.rows });
}));

app.post("/warranties/activate-from-qr", asyncRoute(async (req, res) => {
  const customerId = cleanString(req.body.customerId || req.body.customer_id);
  const serialNo = serialFromPayload(req.body.serialNo || req.body.serial_no || req.body.qr || req.body.qrPayload);
  const purchaseDate = cleanDate(req.body.purchaseDate || req.body.purchase_date) || new Date().toISOString().slice(0, 10);
  const invoiceNo = cleanString(req.body.invoiceNo || req.body.invoice_no);

  if (!customerId || !serialNo) {
    return res.status(400).json({ error: "Customer and serial number are required." });
  }

  const customer = await query("SELECT id FROM customers WHERE id = ? LIMIT 1", [customerId]);
  if (!customer.rowCount) {
    return res.status(404).json({ error: "Customer account not found." });
  }

  const serial = await query(
    `SELECT
       s.id,
       s.serial_no,
       s.dealer_id,
       s.qr_status,
       p.id AS product_id,
       p.name AS product_name,
       p.model_no,
       p.warranty_months
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     WHERE LOWER(TRIM(s.serial_no)) = LOWER(TRIM(?))
     LIMIT 1`,
    [serialNo]
  );
  if (!serial.rowCount) {
    return res.status(404).json({ error: "Serial number not found. Please scan admin generated QR." });
  }
  const row = serial.rows[0];
  if (row.qr_status !== "Printed") {
    return res.status(400).json({ error: "QR is not generated/printed for this serial yet." });
  }

  const existing = await query(
    "SELECT * FROM warranties WHERE serial_id = ? ORDER BY created_at DESC LIMIT 1",
    [row.id]
  );
  if (existing.rowCount && existing.rows[0].customer_id) {
    if (existing.rows[0].customer_id === customerId) {
      return res.status(409).json({ error: "QR expired. This product warranty is already active in your account." });
    }
    return res.status(409).json({ error: "QR expired. This product warranty is already activated by another customer." });
  }

  const months = Number(row.warranty_months || 12);
  const warrantyNo = existing.rowCount ? existing.rows[0].warranty_no : `WAR-${Date.now()}`;

  if (existing.rowCount) {
    await query(
      `UPDATE warranties
       SET customer_id = ?,
           dealer_id = COALESCE(dealer_id, ?),
           start_date = COALESCE(start_date, ?),
           expiry_date = COALESCE(expiry_date, DATE_ADD(?, INTERVAL ? MONTH)),
           status = 'Active',
           installation_status = CASE WHEN installation_status IS NULL OR installation_status = '' THEN 'Required' ELSE installation_status END
       WHERE id = ?`,
      [customerId, row.dealer_id || null, purchaseDate, purchaseDate, months, existing.rows[0].id]
    );
  } else {
    await query(
      `INSERT INTO warranties
       (warranty_no, customer_id, dealer_id, serial_id, start_date, expiry_date, status, installation_status)
       VALUES (?, ?, ?, ?, ?, DATE_ADD(?, INTERVAL ? MONTH), 'Active', 'Required')`,
      [warrantyNo, customerId, row.dealer_id || null, row.id, purchaseDate, purchaseDate, months]
    );
  }

  if (invoiceNo) {
    await query("UPDATE serial_numbers SET invoice_no = COALESCE(NULLIF(invoice_no, ''), ?) WHERE id = ?", [invoiceNo, row.id]);
  }

  const warranty = await query(
    `SELECT
       w.*,
       s.serial_no,
       p.name AS product_name,
       p.model_no,
       p.warranty_months,
       d.dealer_no,
       d.name AS dealer_name
     FROM warranties w
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     WHERE w.warranty_no = ?
     LIMIT 1`,
    [warrantyNo]
  );
  res.json({ warranty: warranty.rows[0] });
}));

/** List complaints (staff panels). Customers should use `/complaints/customer/:customerId`. */
app.get("/complaints", asyncRoute(async (_req, res) => {
  const result = await query(
    `SELECT
       c.*,
       w.warranty_no,
       w.start_date,
       w.expiry_date,
       w.status AS warranty_status,
       w.installation_status,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       s.serial_no,
       p.name AS product_name,
       p.model_no,
       d.dealer_no,
       d.name AS dealer_name,
       tech.name AS technician_name
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     LEFT JOIN tasks t ON t.complaint_id = c.id
     LEFT JOIN technicians tech ON tech.id = t.technician_id
     ORDER BY c.created_at DESC
     LIMIT 800`
  );
  res.json({ complaints: result.rows });
}));

/** Serial inventory for dispatch/dealer tooling */
app.get("/serial-numbers", asyncRoute(async (_req, res) => {
  const result = await query(
    `SELECT
       s.*,
       p.name AS product_name,
       p.model_no,
       d.dealer_no,
       d.name AS dealer_name,
       COALESCE((
         SELECT w.status
         FROM warranties w
         WHERE w.serial_id = s.id
         ORDER BY w.created_at DESC
         LIMIT 1
       ), 'Pending') AS warranty_status
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = s.dealer_id
     ORDER BY s.created_at DESC
     LIMIT 800`
  );
  res.json({ serials: result.rows });
}));

app.post("/serial-numbers", asyncRoute(async (req, res) => {
  const productId = cleanString(req.body.productId || req.body.product_id);
  const modelNo = cleanString(req.body.modelNo || req.body.model_no);
  const dealerNo = cleanString(req.body.dealerNo || req.body.dealer_no);
  const serialNo = cleanSerialNo(req.body.serialNo || req.body.serial_no);
  const invoiceNo = cleanString(req.body.invoiceNo || req.body.invoice_no);
  const challanNo = cleanString(req.body.challanNo || req.body.challan_no);
  const batchNo = cleanString(req.body.batchNo || req.body.batch_no);
  const dispatchDate = cleanDate(req.body.dispatchDate || req.body.dispatch_date);

  if (!serialNo) {
    return res.status(400).json({ error: "Serial number is required." });
  }
  if (serialNo.length > 120) {
    return res.status(400).json({ error: "Serial number must be 120 characters or less." });
  }

  let product = null;
  if (productId) {
    const result = await query("SELECT id FROM products WHERE id = ? LIMIT 1", [productId]);
    product = result.rows[0] || null;
  } else if (modelNo) {
    const result = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) LIMIT 1", [modelNo]);
    product = result.rows[0] || null;
    if (!product) {
      await query(
        "INSERT INTO products (name, model_no, category, warranty_months) VALUES (?, ?, ?, ?)",
        [`Product ${modelNo}`, modelNo, "General", 12]
      );
      const created = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) LIMIT 1", [modelNo]);
      product = created.rows[0] || null;
    }
  }

  let dealer = null;
  if (dealerNo) {
    const result = await query("SELECT id FROM dealers WHERE LOWER(TRIM(dealer_no)) = LOWER(?) AND status = 'Active' LIMIT 1", [dealerNo]);
    dealer = result.rows[0] || null;
    if (!dealer) {
      return res.status(400).json({ error: "Active dealer not found for this dealer number." });
    }
  }

  const duplicate = await query("SELECT id FROM serial_numbers WHERE LOWER(TRIM(serial_no)) = LOWER(?) LIMIT 1", [serialNo]);
  if (duplicate.rowCount) {
    return res.status(409).json({ error: "This serial number is already saved." });
  }

  const qrPayload = serialQrPayload(serialNo);
  await query(
    `INSERT INTO serial_numbers
       (product_id, dealer_id, serial_no, invoice_no, challan_no, batch_no, dispatch_date, qr_status, qr_payload, qr_printed_at, dispatch_status, dispatched_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'Printed', ?, NOW(), ?, ?)`,
    [
      product?.id || null,
      dealer?.id || null,
      serialNo,
      invoiceNo || null,
      challanNo || null,
      batchNo || null,
      dispatchDate,
      qrPayload,
      dealer ? "Dispatched" : "Pending",
      dealer ? new Date() : null
    ]
  );
  const result = await query(
    `SELECT
       s.*,
       p.name AS product_name,
       p.model_no,
       d.dealer_no,
       d.name AS dealer_name,
       COALESCE((
         SELECT w.status
         FROM warranties w
         WHERE w.serial_id = s.id
         ORDER BY w.created_at DESC
         LIMIT 1
       ), 'Pending') AS warranty_status
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = s.dealer_id
     WHERE s.serial_no = ?
     LIMIT 1`,
    [serialNo]
  );
  res.status(201).json({ serial: result.rows[0] });
}));

app.post("/serial-numbers/generate-qr", asyncRoute(async (req, res) => {
  const serialNumbers = Array.isArray(req.body?.serialNumbers)
    ? req.body.serialNumbers.map(cleanSerialNo).filter(Boolean)
    : [];

  const result = serialNumbers.length
    ? await query(
        `UPDATE serial_numbers
         SET qr_status = 'Printed',
             qr_payload = COALESCE(qr_payload, CONCAT('hitaishi://serial?serial=', serial_no)),
             qr_printed_at = COALESCE(qr_printed_at, NOW())
         WHERE serial_no IN (${serialNumbers.map(() => "?").join(",")})`,
        serialNumbers
      )
    : await query(
        `UPDATE serial_numbers
         SET qr_status = 'Printed',
             qr_payload = COALESCE(qr_payload, CONCAT('hitaishi://serial?serial=', serial_no)),
             qr_printed_at = COALESCE(qr_printed_at, NOW())
         WHERE qr_status = 'Not Printed'`
      );

  res.json({
    ok: true,
    generated: result.affectedRows,
    message: result.affectedRows
      ? `${result.affectedRows} QR code(s) generated.`
      : "All selected serials already have QR codes."
  });
}));

app.post("/serial-numbers/bulk", asyncRoute(async (req, res) => {
  const rows = Array.isArray(req.body?.rows)
    ? req.body.rows
    : parseSerialCsv(req.body?.csv);

  if (!rows.length) {
    return res.status(400).json({ error: "Upload at least one serial row." });
  }

  const summary = { total: rows.length, saved: 0, failed: 0, duplicates: 0 };
  const errors = [];

  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index] || {};
    const serialNo = cleanSerialNo(pickRowValue(row, ["serial", "serialno", "serial_no", "serial number"]));
    const modelNo = cleanString(pickRowValue(row, ["model", "modelno", "model_no", "model number"]));
    const productName = cleanString(pickRowValue(row, ["product", "productname", "product_name", "product name"])) || (modelNo ? `Product ${modelNo}` : "");
    const dealerNo = cleanString(pickRowValue(row, ["dealer", "dealerno", "dealer_no", "dealer number"]));
    const invoiceNo = cleanString(pickRowValue(row, ["invoice", "invoiceno", "invoice_no", "invoice number"])) || null;
    const challanNo = cleanString(pickRowValue(row, ["challan", "challanno", "challan_no", "challan number"])) || null;
    const batchNo = cleanString(pickRowValue(row, ["batch", "batchno", "batch_no", "batch number"])) || null;
    const dispatchDate = cleanDate(pickRowValue(row, ["dispatchdate", "dispatch_date", "dispatch date"]));

    if (!serialNo) {
      summary.failed += 1;
      errors.push({ row: index + 2, serial: "", error: "Serial number is required." });
      continue;
    }

    try {
      const duplicate = await query("SELECT id FROM serial_numbers WHERE LOWER(TRIM(serial_no)) = LOWER(?) LIMIT 1", [serialNo]);
      if (duplicate.rowCount) {
        summary.duplicates += 1;
        errors.push({ row: index + 2, serial: serialNo, error: "Duplicate serial." });
        continue;
      }

      let product = null;
      if (modelNo) {
        const productResult = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) LIMIT 1", [modelNo]);
        product = productResult.rows[0] || null;
        if (!product) {
          await query(
            "INSERT INTO products (name, model_no, category, warranty_months) VALUES (?, ?, ?, ?)",
            [productName || `Product ${modelNo}`, modelNo, "General", 12]
          );
          const created = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) LIMIT 1", [modelNo]);
          product = created.rows[0] || null;
        }
      }

      let dealer = null;
      if (dealerNo) {
        const dealerResult = await query("SELECT id FROM dealers WHERE LOWER(TRIM(dealer_no)) = LOWER(?) AND status = 'Active' LIMIT 1", [dealerNo]);
        dealer = dealerResult.rows[0] || null;
        if (!dealer) {
          summary.failed += 1;
          errors.push({ row: index + 2, serial: serialNo, error: "Active dealer not found." });
          continue;
        }
      }

      await query(
        `INSERT INTO serial_numbers
         (product_id, dealer_id, serial_no, invoice_no, challan_no, batch_no, dispatch_date, qr_status, qr_payload, qr_printed_at, dispatch_status, dispatched_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'Printed', ?, NOW(), ?, ?)`,
        [
          product?.id || null,
          dealer?.id || null,
          serialNo,
          invoiceNo,
          challanNo,
          batchNo,
          dispatchDate,
          serialQrPayload(serialNo),
          dealer ? "Dispatched" : "Pending",
          dealer ? new Date() : null
        ]
      );
      summary.saved += 1;
    } catch (error) {
      summary.failed += 1;
      errors.push({ row: index + 2, serial: serialNo, error: error?.message || "Save failed." });
    }
  }

  res.json({ ok: true, summary, errors });
}));

app.get("/serial-numbers/print-stickers", asyncRoute(async (req, res) => {
  const requested = cleanString(req.query.serials)
    .split(",")
    .map(cleanSerialNo)
    .filter(Boolean);
  const where = requested.length
    ? `WHERE s.serial_no IN (${requested.map(() => "?").join(",")})`
    : "WHERE s.qr_status = 'Printed'";
  const result = await query(
    `SELECT s.*, p.name AS product_name, p.model_no, d.dealer_no, d.name AS dealer_name
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = s.dealer_id
     ${where}
     ORDER BY s.created_at DESC
     LIMIT 300`,
    requested
  );

  const cards = result.rows.map((serial) => {
    const payload = serial.qr_payload || serialQrPayload(serial.serial_no);
    const qrUrl = `/serial-numbers/${encodeURIComponent(serial.serial_no)}/qr.svg?download=1`;
    return `
      <section class="label">
        ${qrSvg(payload, 150)}
        <div class="brand">Hitaishi CRM</div>
        <div class="serial">${escapeHtml(serial.serial_no)}</div>
        <div>${escapeHtml(serial.product_name || "Product")} ${escapeHtml(serial.model_no || "")}</div>
        <div>${escapeHtml(serial.dealer_no || "")} ${escapeHtml(serial.dealer_name || "")}</div>
        <a class="download" href="${qrUrl}">Download QR</a>
      </section>`;
  }).join("");

  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Hitaishi QR Stickers</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 16px; color: #111827; }
    .toolbar { margin-bottom: 16px; }
    .sheet { display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 12px; }
    .label { border: 1px solid #111827; border-radius: 8px; padding: 10px; text-align: center; break-inside: avoid; }
    .brand { font-weight: 700; margin-top: 4px; }
    .serial { font-size: 18px; font-weight: 800; margin-top: 4px; }
    .download { display: inline-block; margin-top: 6px; color: #0f3f6b; font-size: 12px; }
    @media print { .toolbar, .download { display: none; } body { margin: 0; } .label { border-color: #000; } }
  </style>
</head>
<body>
  <div class="toolbar"><button onclick="window.print()">Print Stickers</button></div>
  <main class="sheet">${cards || "<p>No printed QR serials found.</p>"}</main>
</body>
</html>`);
}));

app.get("/serial-numbers/:serialNo/qr.svg", asyncRoute(async (req, res) => {
  const serialNo = cleanSerialNo(req.params.serialNo);
  const result = await query("SELECT serial_no, qr_payload FROM serial_numbers WHERE serial_no = ? LIMIT 1", [serialNo]);
  if (!result.rowCount) {
    return res.status(404).send("Serial number not found.");
  }
  const payload = result.rows[0].qr_payload || serialQrPayload(result.rows[0].serial_no);
  if (String(req.query.download || "") === "1") {
    res.setHeader("Content-Disposition", `attachment; filename="${result.rows[0].serial_no}-qr.svg"`);
  }
  res.type("image/svg+xml").send(qrSvg(payload));
}));

app.get("/tasks", asyncRoute(async (req, res) => {
  const status = cleanString(req.query.status);
  const where = [];
  const params = [];
  if (status && status !== "All") {
    where.push("LOWER(t.status) = LOWER(?)");
    params.push(status);
  }
  const sqlWhere = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const result = await query(
    `SELECT
       t.id,
       t.task_no,
       t.work_type,
       t.due_at,
       t.status,
       t.payable_amount,
       t.created_at,
       c.complaint_no,
       c.problem_type,
       c.description,
       c.priority,
       c.status AS complaint_status,
       tech.name AS technician_name,
       tech.mobile AS technician_mobile,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       cust.address AS customer_address,
       cust.city AS customer_city,
       p.name AS product_name,
       p.model_no,
       s.serial_no,
       w.warranty_no,
       w.status AS warranty_status,
       pay.status AS payment_status,
       pay.amount AS payment_amount
     FROM tasks t
     LEFT JOIN complaints c ON c.id = t.complaint_id
     LEFT JOIN technicians tech ON tech.id = t.technician_id
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = COALESCE(c.customer_id, w.customer_id)
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN (
       SELECT task_id, MAX(status) AS status, SUM(amount) AS amount
       FROM payments
       GROUP BY task_id
     ) pay ON pay.task_id = t.id
     ${sqlWhere}
     ORDER BY t.created_at DESC
     LIMIT 200`,
    params
  );
  res.json({ tasks: result.rows });
}));

app.patch("/tasks/:id/status", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const status = cleanString(req.body?.status);
  if (!id || !status) {
    return res.status(400).json({ error: "Task id and status are required." });
  }
  const allowed = ["Assigned", "Accepted", "Rejected", "Scheduled", "Rescheduled", "Reached", "Inspection Started", "Completed"];
  if (!allowed.includes(status)) {
    return res.status(400).json({ error: "Invalid task status." });
  }
  const result = await query("UPDATE tasks SET status = ? WHERE id = ?", [status, id]);
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Task not found." });
  }
  const task = await query("SELECT * FROM tasks WHERE id = ? LIMIT 1", [id]);
  res.json({ task: task.rows[0] });
}));

async function dealerWarrantyReportRows(req) {
  const dealerNo = cleanString(req.query.dealerNo);
  const product = cleanString(req.query.product);
  const city = cleanString(req.query.city);
  const technician = cleanString(req.query.technician);
  const status = cleanString(req.query.status);
  const dateFrom = cleanDate(req.query.dateFrom);
  const dateTo = cleanDate(req.query.dateTo);
  const where = [];
  const params = [];

  if (dealerNo && dealerNo !== "All") {
    where.push("d.dealer_no = ?");
    params.push(dealerNo);
  }
  if (product && product !== "All") {
    where.push("(p.name = ? OR p.model_no = ?)");
    params.push(product, product);
  }
  if (city && city !== "All") {
    where.push("(d.city = ? OR cust.city = ?)");
    params.push(city, city);
  }
  if (technician && technician !== "All") {
    where.push("tech.name = ?");
    params.push(technician);
  }
  if (status && status !== "All") {
    where.push("LOWER(w.status) = LOWER(?)");
    params.push(status);
  }
  if (dateFrom) {
    where.push("DATE(w.created_at) >= ?");
    params.push(dateFrom);
  }
  if (dateTo) {
    where.push("DATE(w.created_at) <= ?");
    params.push(dateTo);
  }

  const sqlWhere = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const result = await query(
    `SELECT
       COALESCE(d.dealer_no, 'Unmapped') AS dealer_no,
       COALESCE(d.name, 'Unmapped Dealer') AS dealer_name,
       COALESCE(d.city, cust.city, '') AS city,
       COUNT(w.id) AS total_warranties,
       SUM(CASE WHEN LOWER(w.status) = 'active' THEN 1 ELSE 0 END) AS active_warranties,
       SUM(CASE WHEN LOWER(w.status) LIKE 'pending%' THEN 1 ELSE 0 END) AS pending_warranties,
       SUM(CASE WHEN LOWER(w.status) = 'expired' THEN 1 ELSE 0 END) AS expired_warranties,
       COUNT(DISTINCT c.id) AS complaints,
       COUNT(DISTINCT t.id) AS tasks
     FROM warranties w
     LEFT JOIN dealers d ON d.id = w.dealer_id
     LEFT JOIN customers cust ON cust.id = w.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN complaints c ON c.warranty_id = w.id
     LEFT JOIN tasks t ON t.complaint_id = c.id
     LEFT JOIN technicians tech ON tech.id = t.technician_id
     ${sqlWhere}
     GROUP BY dealer_no, dealer_name, city
     ORDER BY total_warranties DESC, dealer_name ASC
     LIMIT 500`,
    params
  );
  return result.rows;
}

app.get("/reports/dealer-warranty", asyncRoute(async (req, res) => {
  const rows = await dealerWarrantyReportRows(req);
  const summary = rows.reduce((acc, row) => {
    acc.total += Number(row.total_warranties || 0);
    acc.active += Number(row.active_warranties || 0);
    acc.pending += Number(row.pending_warranties || 0);
    acc.expired += Number(row.expired_warranties || 0);
    acc.complaints += Number(row.complaints || 0);
    acc.tasks += Number(row.tasks || 0);
    return acc;
  }, { total: 0, active: 0, pending: 0, expired: 0, complaints: 0, tasks: 0 });
  res.json({ summary, rows });
}));

app.get("/reports/dealer-warranty.csv", asyncRoute(async (req, res) => {
  const rows = await dealerWarrantyReportRows(req);
  const header = ["Dealer Number", "Dealer Name", "City", "Total Warranties", "Active", "Pending", "Expired", "Complaints", "Tasks"];
  const escapeCsv = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
  const body = rows.map((row) => [
    row.dealer_no,
    row.dealer_name,
    row.city,
    row.total_warranties,
    row.active_warranties,
    row.pending_warranties,
    row.expired_warranties,
    row.complaints,
    row.tasks
  ].map(escapeCsv).join(","));
  res.setHeader("Content-Disposition", "attachment; filename=\"dealer-warranty-report.csv\"");
  res.type("text/csv").send([header.map(escapeCsv).join(","), ...body].join("\n"));
}));

app.get("/serial-numbers/:serialNo", asyncRoute(async (req, res) => {
  const serialNo = typeof req.params.serialNo === "string" ? req.params.serialNo.trim() : "";
  if (!serialNo) {
    return res.status(400).json({ error: "Serial number is required." });
  }

  const result = await query(
    `SELECT
       s.*,
       p.name AS product_name,
       p.model_no,
       p.category,
       p.warranty_months,
       d.dealer_no,
       d.name AS dealer_name,
       d.mobile AS dealer_mobile,
       w.warranty_no,
       w.status AS warranty_status,
       w.installation_status,
       w.start_date,
       w.expiry_date
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = s.dealer_id
     LEFT JOIN warranties w ON w.serial_id = s.id
     WHERE LOWER(TRIM(s.serial_no)) = LOWER(TRIM(?))
     ORDER BY w.created_at DESC
     LIMIT 1`,
    [serialNo]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "Serial number not found." });
  }

  res.json({ serial: result.rows[0] });
}));

app.patch("/serial-numbers/:serialNo", asyncRoute(async (req, res) => {
  const currentSerialNo = cleanSerialNo(req.params.serialNo);
  const nextSerialNo = cleanSerialNo(req.body.serialNo || req.body.serial_no || currentSerialNo);
  const modelNo = cleanString(req.body.modelNo || req.body.model_no);
  const dealerNo = cleanString(req.body.dealerNo || req.body.dealer_no);
  const invoiceNo = cleanString(req.body.invoiceNo || req.body.invoice_no) || null;
  const challanNo = cleanString(req.body.challanNo || req.body.challan_no) || null;
  const batchNo = cleanString(req.body.batchNo || req.body.batch_no) || null;
  const dispatchDate = cleanDate(req.body.dispatchDate || req.body.dispatch_date);

  if (!currentSerialNo || !nextSerialNo) {
    return res.status(400).json({ error: "Serial number is required." });
  }

  const existing = await query("SELECT id FROM serial_numbers WHERE serial_no = ? LIMIT 1", [currentSerialNo]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Serial number not found." });
  }

  if (nextSerialNo !== currentSerialNo) {
    const duplicate = await query("SELECT id FROM serial_numbers WHERE LOWER(TRIM(serial_no)) = LOWER(?) AND serial_no <> ? LIMIT 1", [nextSerialNo, currentSerialNo]);
    if (duplicate.rowCount) {
      return res.status(409).json({ error: "This serial number is already saved." });
    }
  }

  let product = null;
  if (modelNo) {
    const productResult = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) LIMIT 1", [modelNo]);
    product = productResult.rows[0] || null;
    if (!product) {
      await query("INSERT INTO products (name, model_no, category, warranty_months) VALUES (?, ?, ?, ?)", [`Product ${modelNo}`, modelNo, "General", 12]);
      const created = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) LIMIT 1", [modelNo]);
      product = created.rows[0] || null;
    }
  }

  let dealer = null;
  if (dealerNo) {
    const dealerResult = await query("SELECT id FROM dealers WHERE LOWER(TRIM(dealer_no)) = LOWER(?) AND status = 'Active' LIMIT 1", [dealerNo]);
    dealer = dealerResult.rows[0] || null;
    if (!dealer) {
      return res.status(400).json({ error: "Active dealer not found for this dealer number." });
    }
  }

  await query(
    `UPDATE serial_numbers
     SET serial_no = ?,
         product_id = COALESCE(?, product_id),
         dealer_id = ?,
         invoice_no = ?,
         challan_no = ?,
         batch_no = ?,
         dispatch_date = ?,
         qr_payload = ?
     WHERE serial_no = ?`,
    [nextSerialNo, product?.id || null, dealer?.id || null, invoiceNo, challanNo, batchNo, dispatchDate, serialQrPayload(nextSerialNo), currentSerialNo]
  );

  const row = await query("SELECT * FROM serial_numbers WHERE serial_no = ? LIMIT 1", [nextSerialNo]);
  res.json({ serial: row.rows[0] });
}));

app.patch("/serial-numbers/:serialNo/qr", asyncRoute(async (req, res) => {
  const serialNo = cleanSerialNo(req.params.serialNo);
  if (!serialNo) {
    return res.status(400).json({ error: "Serial number is required." });
  }
  const result = await query(
    `UPDATE serial_numbers
     SET qr_status = 'Printed',
         qr_payload = COALESCE(qr_payload, ?),
         qr_printed_at = COALESCE(qr_printed_at, NOW())
     WHERE serial_no = ?`,
    [serialQrPayload(serialNo), serialNo]
  );
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Serial number not found." });
  }
  res.json({ ok: true });
}));

app.delete("/serial-numbers/:serialNo", asyncRoute(async (req, res) => {
  const serialNo = cleanSerialNo(req.params.serialNo);
  if (!serialNo) {
    return res.status(400).json({ error: "Serial number is required." });
  }
  const linkedWarranty = await query(
    `SELECT id FROM warranties
     WHERE serial_id = (SELECT id FROM serial_numbers WHERE serial_no = ? LIMIT 1)
     LIMIT 1`,
    [serialNo]
  );
  if (linkedWarranty.rowCount) {
    return res.status(409).json({ error: "Serial is linked with warranty. Edit it instead of deleting." });
  }
  const result = await query("DELETE FROM serial_numbers WHERE serial_no = ?", [serialNo]);
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Serial number not found." });
  }
  res.json({ ok: true });
}));

app.post("/dispatch-mapping", asyncRoute(async (req, res) => {
  const dealerNo = cleanString(req.body.dealerNo || req.body.dealer_no);
  const serialNumbers = Array.isArray(req.body.serialNumbers)
    ? req.body.serialNumbers.map(cleanSerialNo).filter(Boolean)
    : cleanSerialNo(req.body.serialNo || req.body.serial_no)
      ? [cleanSerialNo(req.body.serialNo || req.body.serial_no)]
      : [];
  const invoiceNo = cleanString(req.body.invoiceNo || req.body.invoice_no);
  const challanNo = cleanString(req.body.challanNo || req.body.challan_no);
  const dispatchDate = cleanDate(req.body.dispatchDate || req.body.dispatch_date);

  if (!dealerNo || !serialNumbers.length) {
    return res.status(400).json({ error: "Dealer number and at least one serial number are required." });
  }

  const dealer = await query("SELECT id FROM dealers WHERE LOWER(TRIM(dealer_no)) = LOWER(?) AND status = 'Active' LIMIT 1", [dealerNo]);
  if (!dealer.rowCount) {
    return res.status(404).json({ error: "Active dealer not found." });
  }

  const placeholders = serialNumbers.map(() => "?").join(",");
  const result = await query(
    `UPDATE serial_numbers
     SET dealer_id = ?,
         dispatch_status = 'Dispatched',
         dispatched_at = COALESCE(dispatched_at, NOW()),
         invoice_no = COALESCE(NULLIF(?, ''), invoice_no),
         challan_no = COALESCE(NULLIF(?, ''), challan_no),
         dispatch_date = COALESCE(?, dispatch_date)
     WHERE serial_no IN (${placeholders})`,
    [dealer.rows[0].id, invoiceNo, challanNo, dispatchDate, ...serialNumbers]
  );

  res.json({ ok: true, mapped: result.affectedRows });
}));

app.get("/complaints/customer/:customerId", asyncRoute(async (req, res) => {
  const result = await query(
    `SELECT
       c.*,
       s.serial_no,
       p.name AS product_name,
       p.model_no,
       d.dealer_no,
       d.name AS dealer_name
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     WHERE c.customer_id = ?
     ORDER BY c.created_at DESC`,
    [req.params.customerId]
  );
  res.json({ complaints: result.rows });
}));

app.get("/complaints/dealer/:dealerId", asyncRoute(async (req, res) => {
  const dealerId = cleanString(req.params.dealerId);
  const result = await query(
    `SELECT
       c.*,
       w.warranty_no,
       w.start_date,
       w.expiry_date,
       w.status AS warranty_status,
       w.installation_status,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       s.serial_no,
       p.name AS product_name,
       p.model_no,
       d.dealer_no,
       d.name AS dealer_name,
       tech.name AS technician_name
     FROM complaints c
     INNER JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     LEFT JOIN tasks t ON t.complaint_id = c.id
     LEFT JOIN technicians tech ON tech.id = t.technician_id
     WHERE COALESCE(w.dealer_id, s.dealer_id) = ?
     ORDER BY c.created_at DESC`,
    [dealerId]
  );
  res.json({ complaints: result.rows });
}));

app.post("/complaints/:id/assign-technician", asyncRoute(async (req, res) => {
  const complaintId = cleanString(req.params.id);
  const technicianId = cleanString(req.body.technicianId || req.body.technician_id);
  const workType = cleanString(req.body.workType || req.body.work_type) || "Warranty Repair";
  const dueAt = cleanString(req.body.dueAt || req.body.due_at) || null;
  const payableAmount = Number(req.body.payableAmount || req.body.payable_amount || 0);

  if (!complaintId || !technicianId) {
    return res.status(400).json({ error: "Complaint and technician are required." });
  }
  const complaint = await query("SELECT * FROM complaints WHERE id = ? LIMIT 1", [complaintId]);
  if (!complaint.rowCount) {
    return res.status(404).json({ error: "Complaint not found." });
  }
  const technician = await query("SELECT id FROM technicians WHERE id = ? AND approval_status = 'Approved' LIMIT 1", [technicianId]);
  if (!technician.rowCount) {
    return res.status(404).json({ error: "Approved technician not found." });
  }

  const existingTask = await query("SELECT id FROM tasks WHERE complaint_id = ? ORDER BY created_at DESC LIMIT 1", [complaintId]);
  await withTransaction(async (tx) => {
    await tx("UPDATE complaints SET status = 'In Progress' WHERE id = ?", [complaintId]);
    if (existingTask.rowCount) {
      await tx(
        "UPDATE tasks SET technician_id = ?, work_type = ?, due_at = ?, status = 'Assigned', payable_amount = ? WHERE id = ?",
        [technicianId, workType, dueAt, Number.isFinite(payableAmount) ? payableAmount : 0, existingTask.rows[0].id]
      );
    } else {
      await tx(
        "INSERT INTO tasks (task_no, complaint_id, technician_id, work_type, due_at, status, payable_amount) VALUES (?, ?, ?, ?, ?, 'Assigned', ?)",
        [`TASK-${Date.now()}`, complaintId, technicianId, workType, dueAt, Number.isFinite(payableAmount) ? payableAmount : 0]
      );
    }
  });

  const result = await query(
    `SELECT c.*, t.task_no, t.status AS task_status, tech.name AS technician_name
     FROM complaints c
     LEFT JOIN tasks t ON t.complaint_id = c.id
     LEFT JOIN technicians tech ON tech.id = t.technician_id
     WHERE c.id = ?
     ORDER BY t.created_at DESC
     LIMIT 1`,
    [complaintId]
  );
  res.json({ complaint: result.rows[0] });
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
  if (code === "ER_DUP_ENTRY") {
    return res.status(409).json({ error: "This record already exists." });
  }
  res.status(500).json({ error: error?.message || "Internal server error" });
});

try {
  await ensureSerialNumbersSchema();
} catch (error) {
  console.warn("Serial number schema check skipped:", error?.message || error);
}

app.listen(port, "0.0.0.0", () => {
  console.log(`Hitaishi CRM API listening on http://0.0.0.0:${port} (reachable from phone via your PC LAN IP)`);
});
