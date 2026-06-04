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
const accountCreatorRoles = ["Admin", "Dealer"];
const customerOnlyAccountCreators = ["Front Desk"];
const dealerCreatableRoles = ["Customer", "Technician"];

function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

function normalizeMobileValue(mobile) {
  return typeof mobile === "string" ? mobile.replace(/\D/g, "") : "";
}

/** Match dealers.mobile to users.mobile even when formatting differs (+91, spaces, etc.). */
function sqlNormalizeMobileColumn(column) {
  return `REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(${column}, ' ', ''), '-', ''), '+', ''), '(', ''), ')', ''), '.', '')`;
}

async function findDealerForUser(userRow) {
  const dealerMobile = normalizeMobileValue(userRow?.mobile);
  if (!dealerMobile) {
    return null;
  }
  const result = await query(
    `SELECT * FROM dealers WHERE ${sqlNormalizeMobileColumn("mobile")} = ? LIMIT 1`,
    [dealerMobile]
  );
  return result.rowCount ? result.rows[0] : null;
}

/** Dealer table id from profile id or dealer login user id. */
async function resolveDealerRecord(idOrUserId) {
  const key = cleanString(idOrUserId);
  if (!key) {
    return null;
  }
  const byProfile = await query("SELECT * FROM dealers WHERE id = ? LIMIT 1", [key]);
  if (byProfile.rowCount) {
    return byProfile.rows[0];
  }
  const userResult = await query("SELECT * FROM users WHERE id = ? AND role = 'Dealer' LIMIT 1", [key]);
  if (!userResult.rowCount) {
    return null;
  }
  return findDealerForUser(userResult.rows[0]);
}

const DEALER_COMPLAINT_FROM = `
  FROM complaints c
  LEFT JOIN warranties w ON w.id = c.warranty_id
  LEFT JOIN serial_numbers s ON s.id = w.serial_id`;

/** Same rules as isComplaintSolvedInDb / app isComplaintSolved (case-insensitive task status). */
const COMPLAINT_TASK_COMPLETED_SQL = `
  EXISTS (
    SELECT 1 FROM tasks t
    WHERE t.complaint_id = c.id AND LOWER(TRIM(COALESCE(t.status, ''))) = 'completed'
  )`;

const COMPLAINT_SOLVED_WHERE = `
  (
    ${COMPLAINT_TASK_COMPLETED_SQL}
    OR LOWER(COALESCE(c.status, '')) LIKE '%closed%'
    OR LOWER(COALESCE(c.status, '')) LIKE '%completed%'
    OR LOWER(COALESCE(c.status, '')) LIKE '%solved%'
  )`;

const COMPLAINT_OPEN_WHERE = `
  (
    TRIM(COALESCE(c.status, '')) NOT IN ('Cancelled')
    AND NOT (
      ${COMPLAINT_TASK_COMPLETED_SQL}
      OR LOWER(COALESCE(c.status, '')) LIKE '%closed%'
      OR LOWER(COALESCE(c.status, '')) LIKE '%completed%'
      OR LOWER(COALESCE(c.status, '')) LIKE '%solved%'
    )
  )`;

async function getDealerDashboardStats(dealerId) {
  const [serials, warranties, totalComplaints, openComplaints, solvedComplaints, pendingScan] = await Promise.all([
    query("SELECT COUNT(*) AS total FROM serial_numbers WHERE dealer_id = ?", [dealerId]),
    query("SELECT COUNT(*) AS total FROM warranties WHERE dealer_id = ?", [dealerId]),
    query(
      `SELECT COUNT(*) AS total ${DEALER_COMPLAINT_FROM} WHERE COALESCE(w.dealer_id, s.dealer_id) = ?`,
      [dealerId]
    ),
    query(
      `SELECT COUNT(*) AS total ${DEALER_COMPLAINT_FROM}
       WHERE COALESCE(w.dealer_id, s.dealer_id) = ? AND ${COMPLAINT_OPEN_WHERE}`,
      [dealerId]
    ),
    query(
      `SELECT COUNT(*) AS total ${DEALER_COMPLAINT_FROM}
       WHERE COALESCE(w.dealer_id, s.dealer_id) = ? AND ${COMPLAINT_SOLVED_WHERE}`,
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
  const count = (result) => Number(result.rows[0]?.total || 0);
  const productsSold = count(warranties);
  const openProblems = count(openComplaints);
  const solvedProblems = count(solvedComplaints);
  return {
    productsDispatched: count(serials),
    productsSold,
    warrantiesRegistered: productsSold,
    complaintsOnSoldProducts: count(totalComplaints),
    openProblems,
    complaintsOpen: openProblems,
    solvedProblems,
    complaintsSolved: solvedProblems,
    pendingScan: count(pendingScan)
  };
}

/** Resolve technician profile for login — by user_id, then mobile (auto-links user_id when missing). */
async function findTechnicianForUser(userRow) {
  if (!userRow?.id) {
    return null;
  }
  const byUser = await query("SELECT * FROM technicians WHERE user_id = ? LIMIT 1", [userRow.id]);
  if (byUser.rowCount) {
    return byUser.rows[0];
  }
  const techMobile = normalizeMobileValue(userRow.mobile);
  if (!techMobile) {
    return null;
  }
  const byMobile = await query(
    `SELECT * FROM technicians WHERE ${sqlNormalizeMobileColumn("mobile")} = ? LIMIT 1`,
    [techMobile]
  );
  if (!byMobile.rowCount) {
    return null;
  }
  const technician = byMobile.rows[0];
  if (!technician.user_id) {
    await query("UPDATE technicians SET user_id = ? WHERE id = ?", [userRow.id, technician.id]);
    technician.user_id = userRow.id;
  }
  return technician;
}

function cleanString(value) {
  return typeof value === "string" ? value.trim() : "";
}

/** Customer login accounts must have a customers row for lists and dashboard counts. */
async function syncCustomerProfilesFromUsers(runQuery = query) {
  await runQuery(
    `UPDATE customers c
     INNER JOIN users u ON u.role = 'Customer'
       AND ${sqlNormalizeMobileColumn("c.mobile")} = ${sqlNormalizeMobileColumn("u.mobile")}
     SET c.user_id = u.id,
         c.name = COALESCE(NULLIF(TRIM(c.name), ''), u.name)
     WHERE c.user_id IS NULL`
  );
  await runQuery(
    `INSERT INTO customers (user_id, name, mobile, address, city, state, pincode)
     SELECT u.id, u.name, u.mobile, NULL, NULL, NULL, NULL
     FROM users u
     WHERE u.role = 'Customer'
       AND NOT EXISTS (SELECT 1 FROM customers c WHERE c.user_id = u.id)
       AND NOT EXISTS (
         SELECT 1 FROM customers c
         WHERE ${sqlNormalizeMobileColumn("c.mobile")} = ${sqlNormalizeMobileColumn("u.mobile")}
       )`
  );
}

/** Keep complaints.status aligned with the latest technician task action. */
function complaintStatusForTaskStatus(taskStatus) {
  const s = cleanString(taskStatus);
  if (!s) return null;
  if (s === "Completed") return "Closed";
  if (s === "Rejected") return "Open";
  if (s === "Assigned") return "Awaiting Technician";
  if (
    s === "Accepted" ||
    s === "In Progress" ||
    s === "Scheduled" ||
    s === "Rescheduled" ||
    s === "Reached" ||
    s === "Inspection Started"
  ) {
    return "In Progress";
  }
  return null;
}

const COMPLAINT_LATEST_TASK_JOIN = `
  LEFT JOIN tasks t ON t.id = (
    SELECT t2.id FROM tasks t2 WHERE t2.complaint_id = c.id ORDER BY t2.created_at DESC LIMIT 1
  )
  LEFT JOIN technicians tech ON tech.id = t.technician_id`;

const COMPLAINT_LATEST_TASK_FIELDS = `
       t.technician_id,
       tech.name AS technician_name,
       tech.mobile AS technician_mobile,
       t.task_no,
       t.work_type AS task_work_type,
       t.due_at,
       t.status AS task_status,
       t.completed_at AS task_completed_at,
       t.resolution_notes AS task_resolution_notes,
       t.created_at AS task_created_at,
       fb.complaint_id AS feedback_id,
       fb.rating AS feedback_rating,
       fb.remarks AS feedback_remarks,
       fb.created_at AS feedback_at`;

const COMPLAINT_FEEDBACK_JOIN = `
  LEFT JOIN feedback fb ON fb.complaint_id = c.id`;

const COMPLAINT_LATEST_QUOTATION_JOIN = `
  LEFT JOIN quotations qt ON qt.id = (
    SELECT q2.id FROM quotations q2 WHERE q2.complaint_id = c.id ORDER BY q2.created_at DESC LIMIT 1
  )`;

const COMPLAINT_LATEST_QUOTATION_FIELDS = `
       qt.id AS quotation_id,
       qt.quotation_no,
       qt.status AS quotation_status,
       qt.spare_part_amount AS quotation_spare_part,
       qt.service_charge AS quotation_service_charge,
       qt.visit_charge AS quotation_visit_charge,
       qt.tax_amount AS quotation_tax,
       qt.discount_amount AS quotation_discount,
       qt.total_amount AS quotation_total,
       qt.technician_remarks AS quotation_technician_remarks,
       qt.customer_remarks AS quotation_customer_remarks,
       qt.created_at AS quotation_created_at`;

function isWarrantyExpiredStatus(status, expiryDate) {
  const st = String(status || "").toLowerCase();
  if (st.includes("expired")) {
    return true;
  }
  if (expiryDate) {
    const exp = new Date(expiryDate);
    if (!Number.isNaN(exp.getTime())) {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      exp.setHours(23, 59, 59, 999);
      if (exp.getTime() < today.getTime()) {
        return true;
      }
    }
  }
  return false;
}

function calcQuotationTotal(parts) {
  const spare = Number(parts.sparePartAmount) || 0;
  const service = Number(parts.serviceCharge) || 0;
  const visit = Number(parts.visitCharge) || 0;
  const tax = Number(parts.taxAmount) || 0;
  const discount = Number(parts.discountAmount) || 0;
  const total = spare + service + visit + tax - discount;
  return Math.max(0, Math.round(total * 100) / 100);
}

async function ensureQuotationsSchema() {
  await query(
    `CREATE TABLE IF NOT EXISTS quotations (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      quotation_no VARCHAR(80) NOT NULL UNIQUE,
      complaint_id CHAR(36),
      technician_id CHAR(36),
      spare_part_amount DECIMAL(10, 2) DEFAULT 0,
      service_charge DECIMAL(10, 2) DEFAULT 0,
      visit_charge DECIMAL(10, 2) DEFAULT 0,
      tax_amount DECIMAL(10, 2) DEFAULT 0,
      discount_amount DECIMAL(10, 2) DEFAULT 0,
      total_amount DECIMAL(10, 2) DEFAULT 0,
      technician_remarks TEXT,
      customer_remarks TEXT,
      customer_decided_at TIMESTAMP NULL,
      status VARCHAR(60) NOT NULL DEFAULT 'Pending Customer Approval',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_quotations_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
      CONSTRAINT fk_quotations_technician FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );
  const columns = [
    ["technician_remarks", "ALTER TABLE quotations ADD COLUMN technician_remarks TEXT NULL AFTER total_amount"],
    ["customer_remarks", "ALTER TABLE quotations ADD COLUMN customer_remarks TEXT NULL AFTER technician_remarks"],
    ["customer_decided_at", "ALTER TABLE quotations ADD COLUMN customer_decided_at TIMESTAMP NULL AFTER customer_remarks"]
  ];
  for (const [columnName, ddl] of columns) {
    const found = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'quotations'
         AND COLUMN_NAME = ?
       LIMIT 1`,
      [columnName]
    );
    if (!found.rowCount) {
      await query(ddl);
    }
  }
}

async function getNextQuotationNo(runQuery = query) {
  const year = new Date().getFullYear();
  const prefix = `QT-${year}-`;
  const result = await runQuery(
    `SELECT quotation_no FROM quotations WHERE quotation_no LIKE ? ORDER BY quotation_no DESC LIMIT 1`,
    [`${prefix}%`]
  );
  let seq = 1;
  if (result.rowCount) {
    const last = String(result.rows[0].quotation_no || "");
    const match = last.match(/(\d+)$/);
    if (match) {
      seq = Number(match[1]) + 1;
    }
  }
  return `${prefix}${String(seq).padStart(4, "0")}`;
}

async function loadComplaintForQuotation(complaintId, runQuery = query) {
  const result = await runQuery(
    `SELECT
       c.id,
       c.complaint_no,
       c.customer_id,
       c.status AS complaint_status,
       COALESCE(c.warranty_status, w.status) AS warranty_status,
       COALESCE(c.warranty_end_date, w.expiry_date) AS warranty_expiry,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.model_no, p.model_no) AS model_no,
       s.serial_no,
       cust.name AS customer_name
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     WHERE c.id = ?
     LIMIT 1`,
    [complaintId]
  );
  return result.rowCount ? result.rows[0] : null;
}

async function fetchQuotationById(quotationId, runQuery = query) {
  const result = await runQuery(
    `SELECT
       q.*,
       c.complaint_no,
       c.customer_id,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.model_no, p.model_no) AS model_no,
       s.serial_no,
       cust.name AS customer_name,
       tech.name AS technician_name
     FROM quotations q
     LEFT JOIN complaints c ON c.id = q.complaint_id
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN technicians tech ON tech.id = q.technician_id
     WHERE q.id = ?
     LIMIT 1`,
    [quotationId]
  );
  return result.rowCount ? result.rows[0] : null;
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

function productQrPayload(product) {
  const productId = cleanString(product?.id || product?.product_id);
  const model = cleanString(product?.model_no || product?.modelNo);
  const name = cleanString(product?.name || product?.product_name);
  const params = new URLSearchParams();
  if (productId) params.set("productId", productId);
  if (model) params.set("model", model);
  if (name) params.set("name", name);
  return `hitaishi://product?${params.toString()}`;
}

function productFromPayload(value) {
  const raw = cleanString(value);
  if (!raw) return { productId: "", model: "", name: "" };
  try {
    const url = new URL(raw);
    if (url.protocol === "hitaishi:" && url.hostname === "product") {
      return {
        productId: cleanString(url.searchParams.get("productId") || url.searchParams.get("product_id")),
        model: cleanString(url.searchParams.get("model") || url.searchParams.get("modelNo")),
        name: cleanString(url.searchParams.get("name")),
      };
    }
    const productId = url.searchParams.get("productId") || url.searchParams.get("product_id");
    if (productId) {
      return {
        productId: cleanString(productId),
        model: cleanString(url.searchParams.get("model") || url.searchParams.get("modelNo")),
        name: cleanString(url.searchParams.get("name")),
      };
    }
  } catch {
    // Plain payloads handled below.
  }
  const idMatch = raw.match(/(?:productId|product_id)\s*[:=]\s*([A-Za-z0-9-]+)/i);
  const modelMatch = raw.match(/(?:model|modelNo|model_no)\s*[:=]\s*([^&\s]+)/i);
  const nameMatch = raw.match(/(?:name)\s*[:=]\s*([^&]+)/i);
  return {
    productId: cleanString(idMatch?.[1] || ""),
    model: cleanString(modelMatch?.[1] || ""),
    name: cleanString(nameMatch?.[1] || ""),
  };
}

async function ensureProductsQrSchema() {
  const columns = [
    ["qr_status", "ALTER TABLE products ADD COLUMN qr_status VARCHAR(40) NOT NULL DEFAULT 'Not Printed' AFTER warranty_months"],
    ["qr_payload", "ALTER TABLE products ADD COLUMN qr_payload VARCHAR(255) NULL AFTER qr_status"],
    ["qr_printed_at", "ALTER TABLE products ADD COLUMN qr_printed_at TIMESTAMP NULL AFTER qr_payload"],
    ["qr_locked", "ALTER TABLE products ADD COLUMN qr_locked TINYINT(1) NOT NULL DEFAULT 0 AFTER qr_printed_at"],
  ];
  for (const [columnName, ddl] of columns) {
    const found = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'products'
         AND COLUMN_NAME = ?`,
      [columnName]
    );
    if (!found.rowCount) {
      await query(ddl);
    }
  }
}

async function productHasActiveWarranty(productId) {
  if (!productId) return false;
  const result = await query(
    `SELECT 1
     FROM warranties w
     INNER JOIN serial_numbers s ON s.id = w.serial_id
     WHERE s.product_id = ?
       AND w.customer_id IS NOT NULL
       AND LOWER(TRIM(COALESCE(w.status, ''))) = 'active'
     LIMIT 1`,
    [productId]
  );
  return Boolean(result.rowCount);
}

async function lockProductQrAfterWarrantyActivation(productId) {
  if (!productId) return;
  await query("UPDATE products SET qr_locked = 1 WHERE id = ?", [productId]);
}

/** Link serials only to products already saved in Product Master (admin name). */
async function resolveProductFromMaster({ productId, productName, modelNo }) {
  const id = cleanString(productId);
  if (id) {
    const byId = await query("SELECT id, name, model_no FROM products WHERE id = ? LIMIT 1", [id]);
    if (byId.rowCount) return byId.rows[0];
    const err = new Error("Selected product not found in Product Master.");
    err.statusCode = 404;
    throw err;
  }

  const name = cleanString(productName);
  if (name) {
    const byName = await query("SELECT id, name, model_no FROM products WHERE LOWER(TRIM(name)) = LOWER(?) LIMIT 1", [name]);
    if (byName.rowCount) return byName.rows[0];
  }

  const model = cleanString(modelNo);
  if (model) {
    const byModel = await query("SELECT id, name, model_no FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) LIMIT 1", [model]);
    if (byModel.rowCount) return byModel.rows[0];
  }

  const err = new Error("Product not found in Product Master. Add the product with admin name first, then create serial.");
  err.statusCode = 400;
  throw err;
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

async function ensureDealerCreatedBySchema() {
  for (const [tableName, columnName, ddl] of [
    ["customers", "created_by_dealer_id", "ALTER TABLE customers ADD COLUMN created_by_dealer_id CHAR(36) NULL AFTER pincode"],
    ["technicians", "created_by_dealer_id", "ALTER TABLE technicians ADD COLUMN created_by_dealer_id CHAR(36) NULL AFTER approval_status"]
  ]) {
    const found = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = ?
         AND COLUMN_NAME = ?
       LIMIT 1`,
      [tableName, columnName]
    );
    if (!found.rowCount) {
      await query(ddl);
    }
  }
}

async function ensureTasksSchema() {
  const columns = [
    ["completed_at", "ALTER TABLE tasks ADD COLUMN completed_at TIMESTAMP NULL AFTER status"],
    ["resolution_notes", "ALTER TABLE tasks ADD COLUMN resolution_notes TEXT NULL AFTER completed_at"]
  ];
  for (const [columnName, ddl] of columns) {
    const found = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'tasks'
         AND COLUMN_NAME = ?
       LIMIT 1`,
      [columnName]
    );
    if (!found.rowCount) {
      await query(ddl);
    }
  }
  await query(
    `UPDATE tasks
     SET completed_at = COALESCE(completed_at, created_at)
     WHERE LOWER(TRIM(COALESCE(status, ''))) = 'completed' AND completed_at IS NULL`
  );
}

async function ensureTechniciansSchema() {
  await ensureDealerCreatedBySchema();
  const columns = [
    ["pincode", "ALTER TABLE technicians ADD COLUMN pincode VARCHAR(20) NULL AFTER city"]
  ];

  for (const [columnName, ddl] of columns) {
    const found = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'technicians'
         AND COLUMN_NAME = ?
       LIMIT 1`,
      [columnName]
    );
    if (!found.rowCount) {
      await query(ddl);
    }
  }
}

async function ensureComplaintsSchema() {
  const columns = [
    ["product_name", "ALTER TABLE complaints ADD COLUMN product_name VARCHAR(160) NULL AFTER priority"],
    ["model_no", "ALTER TABLE complaints ADD COLUMN model_no VARCHAR(120) NULL AFTER product_name"],
    ["warranty_start_date", "ALTER TABLE complaints ADD COLUMN warranty_start_date DATE NULL AFTER model_no"],
    ["warranty_end_date", "ALTER TABLE complaints ADD COLUMN warranty_end_date DATE NULL AFTER warranty_start_date"],
    ["warranty_status", "ALTER TABLE complaints ADD COLUMN warranty_status VARCHAR(60) NULL AFTER warranty_end_date"]
  ];

  for (const [columnName, ddl] of columns) {
    const found = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'complaints'
         AND COLUMN_NAME = ?
       LIMIT 1`,
      [columnName]
    );
    if (!found.rowCount) {
      await query(ddl);
    }
  }
}

async function ensureFeedbackSchema() {
  await query(
    `CREATE TABLE IF NOT EXISTS feedback (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      complaint_id CHAR(36),
      customer_id CHAR(36),
      technician_id CHAR(36),
      rating INT NOT NULL,
      remarks TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_feedback_complaint (complaint_id),
      CONSTRAINT chk_feedback_rating CHECK (rating BETWEEN 1 AND 5),
      CONSTRAINT fk_feedback_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
      CONSTRAINT fk_feedback_customer FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
      CONSTRAINT fk_feedback_technician FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );

  const columns = [
    ["technician_id", "ALTER TABLE feedback ADD COLUMN technician_id CHAR(36) NULL AFTER customer_id"]
  ];
  for (const [columnName, ddl] of columns) {
    const found = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'feedback'
         AND COLUMN_NAME = ?
       LIMIT 1`,
      [columnName]
    );
    if (!found.rowCount) {
      await query(ddl);
    }
  }

  await query(
    `UPDATE feedback f
     INNER JOIN tasks t ON t.complaint_id = f.complaint_id
     SET f.technician_id = t.technician_id
     WHERE f.technician_id IS NULL AND t.technician_id IS NOT NULL`
  );
}

async function getTechnicianRankMap(runQuery = query) {
  const result = await runQuery(
    `SELECT
       t.id,
       COUNT(f.complaint_id) AS review_count,
       ROUND(AVG(f.rating), 2) AS avg_rating
     FROM technicians t
     INNER JOIN feedback f ON f.technician_id = t.id
     WHERE t.approval_status = 'Approved'
     GROUP BY t.id
     HAVING review_count > 0
     ORDER BY avg_rating DESC, review_count DESC, t.name ASC`
  );
  const map = new Map();
  let rank = 0;
  let prevAvg = null;
  let prevCount = null;
  for (const row of result.rows) {
    const avg = Number(row.avg_rating);
    const cnt = Number(row.review_count);
    if (prevAvg !== avg || prevCount !== cnt) {
      rank += 1;
      prevAvg = avg;
      prevCount = cnt;
    }
    map.set(String(row.id), {
      rank,
      reviewCount: cnt,
      avgRating: avg,
      totalRanked: result.rows.length
    });
  }
  const totalRanked = result.rows.length;
  for (const [, value] of map) {
    value.totalRanked = totalRanked;
  }
  return map;
}

async function getTechnicianRatingSummary(technicianId, runQuery = query) {
  const id = cleanString(technicianId);
  if (!id) {
    return { reviewCount: 0, avgRating: null, rank: null, totalRanked: 0 };
  }
  const stats = await runQuery(
    `SELECT COUNT(*) AS review_count, ROUND(AVG(rating), 2) AS avg_rating
     FROM feedback
     WHERE technician_id = ?
     LIMIT 1`,
    [id]
  );
  const reviewCount = Number(stats.rows[0]?.review_count || 0);
  const avgRating = stats.rows[0]?.avg_rating != null ? Number(stats.rows[0].avg_rating) : null;
  const rankMap = await getTechnicianRankMap(runQuery);
  const ranked = rankMap.get(id);
  return {
    reviewCount,
    avgRating,
    rank: ranked?.rank ?? null,
    totalRanked: ranked?.totalRanked ?? rankMap.size
  };
}

function withTechnicianRatingFields(technicianRow, rankMap) {
  if (!technicianRow) {
    return technicianRow;
  }
  const id = String(technicianRow.id || "");
  const ranked = rankMap?.get(id);
  const reviewCount = ranked?.reviewCount ?? Number(technicianRow.review_count || 0);
  const avgRating =
    ranked?.avgRating ?? (technicianRow.avg_rating != null ? Number(technicianRow.avg_rating) : null);
  return {
    ...technicianRow,
    review_count: reviewCount,
    avg_rating: avgRating,
    rank: ranked?.rank ?? null,
    total_ranked: ranked?.totalRanked ?? rankMap?.size ?? 0
  };
}

async function resolveComplaintId(identifier, runQuery = query) {
  const key = cleanString(identifier);
  if (!key) {
    return null;
  }
  const result = await runQuery(
    "SELECT id FROM complaints WHERE id = ? OR complaint_no = ? LIMIT 1",
    [key, key]
  );
  return result.rowCount ? result.rows[0].id : null;
}

async function isComplaintSolvedInDb(complaintId, runQuery = query) {
  const result = await runQuery(
    `SELECT c.status AS complaint_status, t.status AS task_status
     FROM complaints c
     LEFT JOIN tasks t ON t.id = (
       SELECT t2.id FROM tasks t2 WHERE t2.complaint_id = c.id ORDER BY t2.created_at DESC LIMIT 1
     )
     WHERE c.id = ?
     LIMIT 1`,
    [complaintId]
  );
  if (!result.rowCount) {
    return false;
  }
  const taskStatus = String(result.rows[0].task_status || "").toLowerCase();
  const complaintStatus = String(result.rows[0].complaint_status || "").toLowerCase();
  return (
    taskStatus === "completed" ||
    complaintStatus.includes("closed") ||
    complaintStatus.includes("completed") ||
    complaintStatus.includes("solved")
  );
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
    technician = await findTechnicianForUser(userRow);
  }
  if (role === "Dealer") {
    dealer = await findDealerForUser(userRow);
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
  await syncCustomerProfilesFromUsers();
  const [
    totalCustomers,
    totalTechnicians,
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
    pendingCallsToday,
    closedToday,
    pendingTechnicians,
    pendingSerials,
    pendingQuotationApprovals,
    pendingPayable
  ] = await Promise.all([
    query("SELECT COUNT(*) AS total FROM customers"),
    query("SELECT COUNT(*) AS total FROM technicians"),
    query("SELECT COUNT(*) AS total FROM dealers"),
    query("SELECT COUNT(*) AS total FROM products"),
    query("SELECT COUNT(*) AS total FROM serial_numbers"),
    query("SELECT COUNT(*) AS total FROM products WHERE qr_status = 'Printed'"),
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
    query("SELECT COUNT(*) AS total FROM tasks WHERE status NOT IN ('Closed', 'Completed', 'Cancelled') AND DATE(COALESCE(due_at, created_at)) <= CURDATE()"),
    query("SELECT COUNT(*) AS total FROM complaints WHERE status IN ('Closed', 'Completed') AND DATE(created_at) = CURDATE()"),
    query("SELECT COUNT(*) AS total FROM technicians WHERE approval_status = 'Pending'"),
    query("SELECT COUNT(*) AS total FROM serial_numbers WHERE qr_status = 'Not Printed' OR dispatch_status = 'Pending'"),
    query("SELECT COUNT(*) AS total FROM quotations WHERE status = 'Pending Admin Approval'"),
    query("SELECT COALESCE(SUM(amount), 0) AS total FROM payments WHERE status = 'Pending'")
  ]);

  const count = (result) => Number(result.rows?.[0]?.total || 0);
  res.json({
    summary: {
      totalCustomers: count(totalCustomers),
      totalTechnicians: count(totalTechnicians),
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
      pendingCallsToday: count(pendingCallsToday),
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
  await ensureTechniciansSchema();
  const {
    role,
    name,
    mobile,
    email,
    password,
    status,
    createdByRole,
    dealerId,
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
    return res.status(403).json({ error: "You are not allowed to create login accounts." });
  }
  if (customerOnlyAccountCreators.includes(cleanCreatedByRole) && cleanRole !== "Customer") {
    return res.status(403).json({ error: "Only customer login accounts can be created for this role." });
  }
  if (cleanCreatedByRole === "Dealer" && !dealerCreatableRoles.includes(cleanRole)) {
    return res.status(403).json({ error: "Dealers can create customer or technician login accounts only." });
  }

  let creatorDealerId = null;
  const linkToDealerRole = cleanRole === "Customer" || cleanRole === "Technician";
  if (cleanCreatedByRole === "Dealer" && linkToDealerRole) {
    const dealerProfile = await resolveDealerRecord(cleanString(dealerId));
    if (!dealerProfile) {
      return res.status(400).json({
        error: "Dealer profile is required. Link your login mobile with Dealer Management in Admin.",
      });
    }
    creatorDealerId = dealerProfile.id;
  } else if (cleanCreatedByRole === "Admin" && linkToDealerRole) {
    const dealerProfile = await resolveDealerRecord(cleanString(dealerId));
    if (!dealerProfile) {
      return res.status(400).json({
        error: "Select a dealer. This account will show in that dealer's customer or technician list.",
      });
    }
    creatorDealerId = dealerProfile.id;
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
      "INSERT INTO customers (user_id, name, mobile, address, city, state, pincode, created_by_dealer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [userId, cleanName, cleanMobile, address || null, city || null, state || null, cleanString(pincode) || null, creatorDealerId]
    );
    const result = await query("SELECT * FROM customers WHERE user_id = ? LIMIT 1", [userId]);
    customer = result.rows[0] || null;
  }

  if (cleanRole === "Technician") {
    const cleanPincode = cleanString(pincode) || null;
    await query(
      "INSERT INTO technicians (user_id, name, mobile, city, pincode, service_areas, approval_status, created_by_dealer_id) VALUES (?, ?, ?, ?, ?, ?, 'Pending', ?)",
      [userId, cleanName, cleanMobile, city || null, cleanPincode, serviceAreas || null, creatorDealerId]
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

app.get("/customers", asyncRoute(async (_req, res) => {
  await syncCustomerProfilesFromUsers();
  const result = await query(
    `SELECT
       c.id,
       c.user_id,
       c.name,
       c.mobile,
       c.address,
       c.city,
       c.state,
       c.pincode,
       c.created_at,
       u.email,
       COALESCE(u.status, 'Active') AS user_status,
       COUNT(DISTINCT w.id) AS warranties,
       COUNT(DISTINCT comp.id) AS complaints
     FROM customers c
     LEFT JOIN users u ON u.id = c.user_id
     LEFT JOIN warranties w ON w.customer_id = c.id
     LEFT JOIN complaints comp ON comp.customer_id = c.id
     GROUP BY
       c.id,
       c.user_id,
       c.name,
       c.mobile,
       c.address,
       c.city,
       c.state,
       c.pincode,
       c.created_at,
       u.email,
       u.status
     ORDER BY c.created_at DESC
     LIMIT 800`
  );
  res.json({ customers: result.rows });
}));

app.get("/customers/by-mobile/:mobile", asyncRoute(async (req, res) => {
  const cleanMobile = normalizeMobileValue(req.params.mobile);
  if (cleanMobile.length < 10) {
    return res.status(400).json({ error: "Enter a valid 10-digit mobile number." });
  }

  await syncCustomerProfilesFromUsers();

  const result = await query(
    `SELECT
       c.id,
       c.user_id,
       c.name,
       c.mobile,
       c.address,
       c.city,
       c.state,
       c.pincode,
       c.created_at,
       u.email,
       COALESCE(u.status, 'Active') AS user_status,
       (u.password_hash IS NOT NULL AND TRIM(u.password_hash) <> '') AS has_login_account
     FROM customers c
     LEFT JOIN users u ON u.id = c.user_id
     WHERE ${sqlNormalizeMobileColumn("c.mobile")} = ?
     LIMIT 1`,
    [cleanMobile]
  );

  if (!result.rowCount) {
    return res.status(404).json({ error: "No customer found for this mobile number." });
  }

  const customer = result.rows[0];

  const dealerResult = await query(
    `SELECT
       d.id AS dealer_id,
       d.dealer_no,
       d.name AS dealer_name,
       d.city AS dealer_city,
       w.created_at AS registered_at
     FROM warranties w
     INNER JOIN dealers d ON d.id = w.dealer_id
     WHERE w.customer_id = ?
     ORDER BY w.created_at ASC
     LIMIT 1`,
    [customer.id]
  );

  const warrantyCount = await query("SELECT COUNT(*) AS total FROM warranties WHERE customer_id = ?", [customer.id]);
  const complaintCount = await query("SELECT COUNT(*) AS total FROM complaints WHERE customer_id = ?", [customer.id]);

  const registrationDealer = dealerResult.rows[0] || null;
  const hasLoginAccount = Boolean(customer.has_login_account);

  let accountSource = null;
  if (registrationDealer && hasLoginAccount) {
    accountSource = "dealer_and_login";
  } else if (registrationDealer) {
    accountSource = "dealer_warranty";
  } else if (hasLoginAccount) {
    accountSource = "login_only";
  }

  res.json({
    customer: {
      id: customer.id,
      user_id: customer.user_id,
      name: customer.name,
      mobile: customer.mobile,
      email: customer.email || null,
      address: customer.address,
      city: customer.city,
      state: customer.state,
      pincode: customer.pincode,
      created_at: customer.created_at,
      user_status: customer.user_status
    },
    hasLoginAccount,
    registrationDealer,
    accountSource,
    warranties: Number(warrantyCount.rows[0]?.total || 0),
    complaints: Number(complaintCount.rows[0]?.total || 0)
  });
}));

app.post("/technicians", asyncRoute(async (req, res) => {
  await ensureTechniciansSchema();
  const { name, mobile, email, password, city, serviceAreas, pincode } = req.body;
  if (!name || !mobile) {
    return res.status(400).json({ error: "name and mobile are required" });
  }

  await query(
    "INSERT INTO users (role, name, mobile, email, password_hash, status) VALUES ('Technician', ?, ?, ?, ?, 'Pending')",
    [name, mobile, email ? String(email).trim().toLowerCase() || null : null, password ? hashPassword(password) : null]
  );
  const user = await query("SELECT * FROM users WHERE mobile = ? AND role = 'Technician' LIMIT 1", [mobile]);
  await query(
    "INSERT INTO technicians (user_id, name, mobile, city, pincode, service_areas) VALUES (?, ?, ?, ?, ?, ?)",
    [user.rows[0].id, name, mobile, city || null, cleanString(pincode) || null, serviceAreas || null]
  );
  const technician = await query("SELECT * FROM technicians WHERE mobile = ? LIMIT 1", [mobile]);

  res.status(201).json({
    user: publicUser(user.rows[0]),
    technician: technician.rows[0]
  });
}));

app.get("/technicians", asyncRoute(async (req, res) => {
  await ensureFeedbackSchema();
  const status = cleanString(req.query.status);
  const allowed = ["Pending", "Approved", "Rejected"];
  const where = allowed.includes(status) ? "WHERE t.approval_status = ?" : "";
  const params = allowed.includes(status) ? [status] : [];
  const result = await query(
    `SELECT
       t.*,
       u.email,
       u.status AS user_status,
       (SELECT COUNT(*) FROM feedback f WHERE f.technician_id = t.id) AS review_count,
       (SELECT ROUND(AVG(f.rating), 2) FROM feedback f WHERE f.technician_id = t.id) AS avg_rating
     FROM technicians t
     LEFT JOIN users u ON u.id = t.user_id
     ${where}
     ORDER BY t.created_at DESC
     LIMIT 800`,
    params
  );
  const rankMap = await getTechnicianRankMap();
  res.json({
    technicians: result.rows.map((row) => withTechnicianRatingFields(row, rankMap))
  });
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
       d.id AS id,
       u.id AS user_id,
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
     LEFT JOIN dealers d ON ${sqlNormalizeMobileColumn("d.mobile")} = ${sqlNormalizeMobileColumn("u.mobile")}
     WHERE u.role = 'Dealer'
     UNION
     SELECT
       d.id,
       NULL AS user_id,
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
     LEFT JOIN users u ON ${sqlNormalizeMobileColumn("u.mobile")} = ${sqlNormalizeMobileColumn("d.mobile")} AND u.role = 'Dealer'
     WHERE u.id IS NULL
     ORDER BY created_at DESC`
  );
  const dealers = [];
  for (const row of result.rows) {
    const entry = { ...row };
    if (row.id) {
      try {
        entry.stats = await getDealerDashboardStats(row.id);
      } catch {
        entry.stats = null;
      }
    }
    dealers.push(entry);
  }
  res.json({ dealers });
}));

app.get("/dealers/by-user/:userId", asyncRoute(async (req, res) => {
  const userId = cleanString(req.params.userId);
  if (!userId) {
    return res.status(400).json({ error: "userId is required." });
  }
  const userResult = await query("SELECT * FROM users WHERE id = ? AND role = 'Dealer' LIMIT 1", [userId]);
  if (!userResult.rowCount) {
    return res.status(404).json({ error: "Dealer login not found." });
  }
  const dealer = await findDealerForUser(userResult.rows[0]);
  if (!dealer) {
    return res.status(404).json({
      error:
        "Dealer profile not linked. In Admin → Dealer Management, use the same mobile number as this login account.",
    });
  }
  res.json({ dealer });
}));

app.get("/technicians/by-user/:userId", asyncRoute(async (req, res) => {
  await ensureFeedbackSchema();
  const userId = cleanString(req.params.userId);
  if (!userId) {
    return res.status(400).json({ error: "userId is required." });
  }
  const userResult = await query("SELECT * FROM users WHERE id = ? AND role = 'Technician' LIMIT 1", [userId]);
  if (!userResult.rowCount) {
    return res.status(404).json({ error: "Technician login not found." });
  }
  const technician = await findTechnicianForUser(userResult.rows[0]);
  if (!technician) {
    return res.status(404).json({
      error:
        "Technician profile not linked. Use the same mobile in Technician Management as this login, or sign up again.",
    });
  }
  const rankMap = await getTechnicianRankMap();
  res.json({ technician: withTechnicianRatingFields(technician, rankMap) });
}));

app.get("/technicians/:id/rating", asyncRoute(async (req, res) => {
  await ensureFeedbackSchema();
  const technicianId = cleanString(req.params.id);
  const existing = await query("SELECT id, name FROM technicians WHERE id = ? LIMIT 1", [technicianId]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Technician not found." });
  }
  const summary = await getTechnicianRatingSummary(technicianId);
  const recent = await query(
    `SELECT
       f.complaint_id AS id,
       f.rating,
       f.remarks,
       f.created_at,
       c.complaint_no,
       cust.name AS customer_name
     FROM feedback f
     LEFT JOIN complaints c ON c.id = f.complaint_id
     LEFT JOIN customers cust ON cust.id = f.customer_id
     WHERE f.technician_id = ?
     ORDER BY f.created_at DESC
     LIMIT 10`,
    [technicianId]
  );
  res.json({
    technicianId,
    technicianName: existing.rows[0].name,
    ...summary,
    recentReviews: recent.rows
  });
}));

app.get("/feedback/customer/:customerId", asyncRoute(async (req, res) => {
  await ensureFeedbackSchema();
  const customerId = cleanString(req.params.customerId);
  const result = await query(
    `SELECT
       f.*,
       c.complaint_no,
       tech.name AS technician_name
     FROM feedback f
     LEFT JOIN complaints c ON c.id = f.complaint_id
     LEFT JOIN technicians tech ON tech.id = f.technician_id
     WHERE f.customer_id = ?
     ORDER BY f.created_at DESC
     LIMIT 200`,
    [customerId]
  );
  res.json({ feedback: result.rows });
}));

app.post("/feedback", asyncRoute(async (req, res) => {
  await ensureFeedbackSchema();
  const complaintId = await resolveComplaintId(req.body.complaintId || req.body.complaint_id);
  const customerId = cleanString(req.body.customerId || req.body.customer_id);
  const rating = Number(req.body.rating);
  const remarks =
    typeof req.body.remarks === "string" && req.body.remarks.trim() ? req.body.remarks.trim() : null;

  if (!complaintId || !customerId) {
    return res.status(400).json({ error: "complaintId and customerId are required." });
  }
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ error: "Rating must be between 1 and 5." });
  }

  const complaint = await query(
    "SELECT id, customer_id FROM complaints WHERE id = ? AND customer_id = ? LIMIT 1",
    [complaintId, customerId]
  );
  if (!complaint.rowCount) {
    return res.status(404).json({ error: "Complaint not found for this customer." });
  }
  if (!(await isComplaintSolvedInDb(complaintId))) {
    return res.status(400).json({ error: "You can review only after the problem is solved." });
  }

  const existing = await query("SELECT id FROM feedback WHERE complaint_id = ? LIMIT 1", [complaintId]);
  if (existing.rowCount) {
    return res.status(409).json({ error: "Feedback already submitted for this complaint." });
  }

  const task = await query(
    `SELECT technician_id FROM tasks
     WHERE complaint_id = ? AND technician_id IS NOT NULL
     ORDER BY created_at DESC
     LIMIT 1`,
    [complaintId]
  );
  const technicianId = cleanString(task.rows[0]?.technician_id);
  if (!technicianId) {
    return res.status(400).json({ error: "No technician is linked to this complaint yet." });
  }

  await query(
    "INSERT INTO feedback (complaint_id, customer_id, technician_id, rating, remarks) VALUES (?, ?, ?, ?, ?)",
    [complaintId, customerId, technicianId, rating, remarks]
  );
  const saved = await query(
    `SELECT f.*, c.complaint_no, tech.name AS technician_name
     FROM feedback f
     LEFT JOIN complaints c ON c.id = f.complaint_id
     LEFT JOIN technicians tech ON tech.id = f.technician_id
     WHERE f.complaint_id = ?
     LIMIT 1`,
    [complaintId]
  );
  const technicianRating = await getTechnicianRatingSummary(technicianId);
  res.status(201).json({
    feedback: saved.rows[0] || null,
    technicianRating
  });
}));

app.get("/quotations", asyncRoute(async (req, res) => {
  await ensureQuotationsSchema();
  const status = cleanString(req.query.status);
  const where = status ? "WHERE q.status = ?" : "";
  const params = status ? [status] : [];
  const result = await query(
    `SELECT
       q.*,
       c.complaint_no,
       c.customer_id,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.model_no, p.model_no) AS model_no,
       s.serial_no,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       tech.name AS technician_name
     FROM quotations q
     LEFT JOIN complaints c ON c.id = q.complaint_id
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN technicians tech ON tech.id = q.technician_id
     ${where}
     ORDER BY q.created_at DESC
     LIMIT 500`,
    params
  );
  res.json({ quotations: result.rows });
}));

app.get("/quotations/complaint/:complaintId", asyncRoute(async (req, res) => {
  await ensureQuotationsSchema();
  const complaintId = await resolveComplaintId(req.params.complaintId);
  if (!complaintId) {
    return res.status(404).json({ error: "Complaint not found." });
  }
  const result = await query(
    `SELECT
       q.*,
       c.complaint_no,
       c.customer_id,
       COALESCE(c.product_name, p.name) AS product_name,
       tech.name AS technician_name
     FROM quotations q
     LEFT JOIN complaints c ON c.id = q.complaint_id
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN technicians tech ON tech.id = q.technician_id
     WHERE q.complaint_id = ?
     ORDER BY q.created_at DESC
     LIMIT 20`,
    [complaintId]
  );
  res.json({ quotations: result.rows });
}));

app.get("/quotations/customer/:customerId", asyncRoute(async (req, res) => {
  await ensureQuotationsSchema();
  const customerId = cleanString(req.params.customerId);
  const result = await query(
    `SELECT
       q.*,
       c.complaint_no,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.model_no, p.model_no) AS model_no,
       s.serial_no,
       tech.name AS technician_name
     FROM quotations q
     INNER JOIN complaints c ON c.id = q.complaint_id
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN technicians tech ON tech.id = q.technician_id
     WHERE c.customer_id = ?
     ORDER BY q.created_at DESC
     LIMIT 100`,
    [customerId]
  );
  res.json({ quotations: result.rows });
}));

app.post("/quotations", asyncRoute(async (req, res) => {
  await ensureQuotationsSchema();
  const complaintId = await resolveComplaintId(req.body.complaintId || req.body.complaint_id);
  const technicianId = cleanString(req.body.technicianId || req.body.technician_id);
  const sparePartAmount = Number(req.body.sparePartAmount ?? req.body.spare_part_amount ?? 0);
  const serviceCharge = Number(req.body.serviceCharge ?? req.body.service_charge ?? 0);
  const visitCharge = Number(req.body.visitCharge ?? req.body.visit_charge ?? 0);
  const taxAmount = Number(req.body.taxAmount ?? req.body.tax_amount ?? 0);
  const discountAmount = Number(req.body.discountAmount ?? req.body.discount_amount ?? 0);
  const technicianRemarks = cleanString(req.body.technicianRemarks || req.body.technician_remarks) || null;

  if (!complaintId || !technicianId) {
    return res.status(400).json({ error: "complaintId and technicianId are required." });
  }

  const complaint = await loadComplaintForQuotation(complaintId);
  if (!complaint) {
    return res.status(404).json({ error: "Complaint not found." });
  }
  if (!isWarrantyExpiredStatus(complaint.warranty_status, complaint.warranty_expiry)) {
    return res.status(400).json({
      error: "Quotation is required only when product warranty is expired. Active warranty repairs do not need a paid quotation.",
    });
  }

  const task = await query(
    `SELECT id FROM tasks
     WHERE complaint_id = ? AND technician_id = ?
     ORDER BY created_at DESC
     LIMIT 1`,
    [complaintId, technicianId]
  );
  if (!task.rowCount) {
    return res.status(403).json({ error: "This complaint is not assigned to you." });
  }

  const pending = await query(
    `SELECT id FROM quotations
     WHERE complaint_id = ? AND status IN ('Pending Customer Approval', 'Pending Admin Approval')
     LIMIT 1`,
    [complaintId]
  );
  if (pending.rowCount) {
    return res.status(409).json({ error: "A quotation is already waiting for approval on this complaint." });
  }

  const totalAmount = calcQuotationTotal({
    sparePartAmount,
    serviceCharge,
    visitCharge,
    taxAmount,
    discountAmount
  });
  if (totalAmount <= 0) {
    return res.status(400).json({ error: "Quotation total must be greater than zero." });
  }

  const quotationNo = await getNextQuotationNo();
  await query(
    `INSERT INTO quotations
     (quotation_no, complaint_id, technician_id, spare_part_amount, service_charge, visit_charge, tax_amount, discount_amount, total_amount, technician_remarks, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending Customer Approval')`,
    [
      quotationNo,
      complaintId,
      technicianId,
      sparePartAmount,
      serviceCharge,
      visitCharge,
      taxAmount,
      discountAmount,
      totalAmount,
      technicianRemarks
    ]
  );

  await query("UPDATE complaints SET status = ? WHERE id = ?", ["Quotation Pending", complaintId]);

  const saved = await fetchQuotationById(
    (await query("SELECT id FROM quotations WHERE quotation_no = ? LIMIT 1", [quotationNo])).rows[0]?.id
  );
  res.status(201).json({ quotation: saved });
}));

app.patch("/quotations/:id/customer-decision", asyncRoute(async (req, res) => {
  await ensureQuotationsSchema();
  const quotationId = cleanString(req.params.id);
  const customerId = cleanString(req.body.customerId || req.body.customer_id);
  const decision = cleanString(req.body.decision);
  const customerRemarks = cleanString(req.body.customerRemarks || req.body.customer_remarks) || null;

  if (!quotationId || !customerId) {
    return res.status(400).json({ error: "Quotation id and customerId are required." });
  }
  if (!["Accepted", "Rejected"].includes(decision)) {
    return res.status(400).json({ error: "decision must be Accepted or Rejected." });
  }

  const row = await fetchQuotationById(quotationId);
  if (!row) {
    return res.status(404).json({ error: "Quotation not found." });
  }
  if (String(row.customer_id) !== customerId) {
    return res.status(403).json({ error: "This quotation does not belong to your account." });
  }
  if (row.status !== "Pending Customer Approval") {
    return res.status(400).json({ error: "This quotation is no longer waiting for your decision." });
  }

  const nextStatus = decision === "Accepted" ? "Accepted by Customer" : "Rejected by Customer";
  const nextComplaintStatus = decision === "Accepted" ? "Paid Repair Approved" : "Quotation Rejected";

  await withTransaction(async (tx) => {
    await tx(
      `UPDATE quotations
       SET status = ?, customer_remarks = ?, customer_decided_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [nextStatus, customerRemarks, quotationId]
    );
    if (row.complaint_id) {
      await tx("UPDATE complaints SET status = ? WHERE id = ?", [nextComplaintStatus, row.complaint_id]);
    }
  });

  const updated = await fetchQuotationById(quotationId);
  res.json({ quotation: updated });
}));

app.patch("/quotations/:id/admin-decision", asyncRoute(async (req, res) => {
  await ensureQuotationsSchema();
  const quotationId = cleanString(req.params.id);
  const decision = cleanString(req.body.decision);
  const remarks = cleanString(req.body.remarks) || null;

  if (!quotationId) {
    return res.status(400).json({ error: "Quotation id is required." });
  }
  if (!["Approved", "Rejected"].includes(decision)) {
    return res.status(400).json({ error: "decision must be Approved or Rejected." });
  }

  const row = await fetchQuotationById(quotationId);
  if (!row) {
    return res.status(404).json({ error: "Quotation not found." });
  }
  if (row.status !== "Pending Admin Approval") {
    return res.status(400).json({ error: "Quotation is not pending admin approval." });
  }

  const nextStatus = decision === "Approved" ? "Pending Customer Approval" : "Rejected by Admin";
  await query("UPDATE quotations SET status = ?, technician_remarks = COALESCE(?, technician_remarks) WHERE id = ?", [
    nextStatus,
    remarks,
    quotationId
  ]);
  if (row.complaint_id && decision === "Approved") {
    await query("UPDATE complaints SET status = ? WHERE id = ?", ["Quotation Pending", row.complaint_id]);
  }
  const updated = await fetchQuotationById(quotationId);
  res.json({ quotation: updated });
}));

app.get("/dealers/:id/dashboard", asyncRoute(async (req, res) => {
  await ensureFeedbackSchema();
  const dealerKey = cleanString(req.params.id);
  if (!dealerKey) {
    return res.status(400).json({ error: "Dealer id is required." });
  }
  const dealer = await resolveDealerRecord(dealerKey);
  if (!dealer) {
    return res.status(404).json({
      error:
        "Dealer profile not found. Link the dealer login mobile to a dealer record in Admin → Dealer Management.",
    });
  }
  const dealerId = dealer.id;
  const stats = await getDealerDashboardStats(dealerId);
  const complaints = await query(
    `SELECT
       c.*,
       w.warranty_no,
       COALESCE(c.warranty_start_date, w.start_date) AS start_date,
       COALESCE(c.warranty_end_date, w.expiry_date) AS expiry_date,
       COALESCE(c.warranty_status, w.status) AS warranty_status,
       w.installation_status,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       s.serial_no,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.model_no, p.model_no) AS model_no,
       ${COMPLAINT_LATEST_TASK_FIELDS}
     FROM complaints c
     INNER JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     ${COMPLAINT_LATEST_TASK_JOIN}
     ${COMPLAINT_FEEDBACK_JOIN}
     WHERE COALESCE(w.dealer_id, s.dealer_id) = ?
     ORDER BY c.created_at DESC
     LIMIT 3`,
    [dealerId]
  );
  res.json({
    dealer,
    stats,
    complaints: complaints.rows
  });
}));

app.get("/dealers/:id/created-customers", asyncRoute(async (req, res) => {
  await ensureDealerCreatedBySchema();
  const dealer = await resolveDealerRecord(req.params.id);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  const result = await query(
    `SELECT
       c.id,
       c.user_id,
       c.name,
       c.mobile,
       c.address,
       c.city,
       c.state,
       c.pincode,
       c.created_at,
       u.email,
       COALESCE(u.status, 'Active') AS user_status,
       COUNT(DISTINCT w.id) AS warranties,
       COUNT(DISTINCT comp.id) AS complaints
     FROM customers c
     LEFT JOIN users u ON u.id = c.user_id
     LEFT JOIN warranties w ON w.customer_id = c.id
     LEFT JOIN complaints comp ON comp.customer_id = c.id
     WHERE c.created_by_dealer_id = ?
     GROUP BY
       c.id,
       c.user_id,
       c.name,
       c.mobile,
       c.address,
       c.city,
       c.state,
       c.pincode,
       c.created_at,
       u.email,
       u.status
     ORDER BY c.created_at DESC
     LIMIT 500`,
    [dealer.id]
  );
  res.json({ dealer: { id: dealer.id, name: dealer.name, dealer_no: dealer.dealer_no }, customers: result.rows });
}));

app.get("/dealers/:id/created-technicians", asyncRoute(async (req, res) => {
  await ensureDealerCreatedBySchema();
  const dealer = await resolveDealerRecord(req.params.id);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  const result = await query(
    `SELECT
       t.*,
       u.email,
       u.status AS user_status
     FROM technicians t
     LEFT JOIN users u ON u.id = t.user_id
     WHERE t.created_by_dealer_id = ?
     ORDER BY t.created_at DESC
     LIMIT 500`,
    [dealer.id]
  );
  res.json({ dealer: { id: dealer.id, name: dealer.name, dealer_no: dealer.dealer_no }, technicians: result.rows });
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

app.get("/products/print-sticker", asyncRoute(async (req, res) => {
  const productId = cleanString(req.query.productId || req.query.product_id);
  if (!productId) {
    return res.status(400).json({ error: "productId is required." });
  }
  const result = await query("SELECT * FROM products WHERE id = ? LIMIT 1", [productId]);
  if (!result.rowCount) {
    return res.status(404).json({ error: "Product not found." });
  }
  const product = result.rows[0];
  if (product.qr_status !== "Printed") {
    return res.status(400).send("Generate product QR before printing.");
  }
  const payload = product.qr_payload || productQrPayload(product);
  const qrUrl = `/products/${encodeURIComponent(productId)}/qr.svg?download=1`;
  const card = `
    <section class="label">
      ${qrSvg(payload, 180)}
      <div class="brand">Hitaishi CRM</div>
      <div class="product">${escapeHtml(product.name)}</div>
      <div class="model">${escapeHtml(product.model_no)}</div>
      <div class="meta">${escapeHtml(product.category || "Product")} · ${Number(product.warranty_months || 12)} months warranty</div>
      <a class="download" href="${qrUrl}">Download QR</a>
    </section>`;
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Hitaishi Product QR</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 16px; color: #111827; }
    .toolbar { margin-bottom: 16px; }
    .sheet { display: flex; justify-content: center; }
    .label { border: 1px solid #111827; border-radius: 8px; padding: 14px; text-align: center; max-width: 260px; }
    .brand { font-weight: 700; margin-top: 6px; }
    .product { font-size: 18px; font-weight: 800; margin-top: 4px; }
    .model { font-size: 15px; margin-top: 2px; }
    .meta { font-size: 12px; color: #4b5563; margin-top: 4px; }
    .download { display: inline-block; margin-top: 8px; color: #0f3f6b; font-size: 12px; }
    @media print { .toolbar, .download { display: none; } body { margin: 0; } }
  </style>
</head>
<body>
  <div class="toolbar"><button onclick="window.print()">Print Product QR</button></div>
  <main class="sheet">${card}</main>
</body>
</html>`);
}));

app.post("/products/:productId/generate-qr", asyncRoute(async (req, res) => {
  const productId = cleanString(req.params.productId);
  const result = await query("SELECT * FROM products WHERE id = ? LIMIT 1", [productId]);
  if (!result.rowCount) {
    return res.status(404).json({ error: "Product not found." });
  }
  const product = result.rows[0];
  if (Number(product.qr_locked) === 1 || await productHasActiveWarranty(productId)) {
    return res.status(409).json({
      error: "Warranty is already active for this product. New QR cannot be created.",
    });
  }
  if (product.qr_status === "Printed") {
    return res.status(409).json({
      error: "This product already has a QR code. Use Print to reprint the same sticker.",
    });
  }
  const payload = productQrPayload(product);
  await query(
    `UPDATE products
     SET qr_status = 'Printed',
         qr_payload = ?,
         qr_printed_at = COALESCE(qr_printed_at, NOW())
     WHERE id = ?`,
    [payload, productId]
  );
  const updated = await query("SELECT * FROM products WHERE id = ? LIMIT 1", [productId]);
  res.json({
    ok: true,
    product: updated.rows[0],
    message: "Product QR generated. You can print the sticker now.",
  });
}));

app.get("/products/:productId/qr.svg", asyncRoute(async (req, res) => {
  const productId = cleanString(req.params.productId);
  const result = await query("SELECT id, name, model_no, qr_status, qr_payload FROM products WHERE id = ? LIMIT 1", [productId]);
  if (!result.rowCount) {
    return res.status(404).send("Product not found.");
  }
  const product = result.rows[0];
  if (product.qr_status !== "Printed") {
    return res.status(400).send("Product QR is not generated yet.");
  }
  const payload = product.qr_payload || productQrPayload(product);
  if (cleanString(req.query.download)) {
    res.setHeader("Content-Disposition", `attachment; filename="${product.model_no || product.id}-product-qr.svg"`);
  }
  res.type("image/svg+xml").send(qrSvg(payload, 220));
}));

app.get("/products/:productId/scan", asyncRoute(async (req, res) => {
  const productId = cleanString(req.params.productId);
  const dealerId = cleanString(req.query.dealerId || req.query.dealer_id);
  const result = await query("SELECT * FROM products WHERE id = ? LIMIT 1", [productId]);
  if (!result.rowCount) {
    return res.status(404).json({ error: "Product not found." });
  }
  const product = result.rows[0];
  if (product.qr_status !== "Printed") {
    return res.status(400).json({ error: "Product QR is not generated yet." });
  }
  const serialWhere = dealerId
    ? "s.product_id = ? AND (s.dealer_id = ? OR s.dealer_id IS NULL)"
    : "s.product_id = ?";
  const serialParams = dealerId ? [product.id, dealerId] : [product.id];
  const serials = await query(
    `SELECT
       s.*,
       p.name AS product_name,
       p.model_no,
       p.qr_status AS product_qr_status,
       p.qr_locked AS product_qr_locked,
       d.dealer_no,
       d.name AS dealer_name,
       COALESCE((
         SELECT w.status
         FROM warranties w
         WHERE w.serial_id = s.id
         ORDER BY w.created_at DESC
         LIMIT 1
       ), 'Pending') AS warranty_status,
       (
         SELECT w.warranty_no
         FROM warranties w
         WHERE w.serial_id = s.id
         ORDER BY w.created_at DESC
         LIMIT 1
       ) AS warranty_no
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = s.dealer_id
     WHERE ${serialWhere}
     ORDER BY s.created_at DESC
     LIMIT 100`,
    serialParams
  );
  res.json({
    product: {
      id: product.id,
      name: product.name,
      model_no: product.model_no,
      category: product.category,
      warranty_months: product.warranty_months,
      qr_status: product.qr_status,
      qr_locked: product.qr_locked,
    },
    serials: serials.rows,
  });
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

async function findOrCreateCustomer({ name, mobile, email, address, city, state, pincode, password, createdByDealerId }) {
  const cleanName = cleanString(name);
  const cleanMobile = normalizeMobileValue(mobile);
  const emailNorm = normalizeEmail(email);
  const cleanPassword = typeof password === "string" ? password : "";
  if (!cleanName || cleanMobile.length < 10) {
    const err = new Error("Customer name and a valid 10-digit mobile number are required.");
    err.statusCode = 400;
    throw err;
  }
  if (cleanPassword && cleanPassword.length < 8) {
    const err = new Error("Customer login password must be at least 8 characters.");
    err.statusCode = 400;
    throw err;
  }

  let existing = await query(
    `SELECT * FROM customers WHERE ${sqlNormalizeMobileColumn("mobile")} = ? LIMIT 1`,
    [cleanMobile]
  );
  if (existing.rowCount) {
    const row = existing.rows[0];
    let userId = row.user_id || null;
    let user = userId
      ? await query("SELECT * FROM users WHERE id = ? LIMIT 1", [userId])
      : await query("SELECT * FROM users WHERE mobile = ? LIMIT 1", [cleanMobile]);
    if (user.rowCount && user.rows[0].role !== "Customer") {
      const err = new Error("This mobile number is already used for another account type.");
      err.statusCode = 409;
      throw err;
    }
    if (user.rowCount) {
      userId = user.rows[0].id;
      await query(
        `UPDATE users
         SET name = ?,
             email = COALESCE(?, email),
             password_hash = CASE
               WHEN (password_hash IS NULL OR TRIM(password_hash) = '') AND ? <> '' THEN ?
               ELSE password_hash
             END
         WHERE id = ?`,
        [cleanName, emailNorm || null, cleanPassword, cleanPassword ? hashPassword(cleanPassword) : null, userId]
      );
    } else {
      await query(
        "INSERT INTO users (role, name, mobile, email, password_hash, status) VALUES ('Customer', ?, ?, ?, ?, 'Active')",
        [cleanName, cleanMobile, emailNorm || null, cleanPassword ? hashPassword(cleanPassword) : null]
      );
      const createdUser = await query("SELECT id FROM users WHERE mobile = ? AND role = 'Customer' LIMIT 1", [cleanMobile]);
      userId = createdUser.rows[0]?.id || null;
    }
    await query(
      `UPDATE customers
       SET user_id = COALESCE(user_id, ?),
           name = ?,
           address = COALESCE(?, address),
           city = COALESCE(?, city),
           state = COALESCE(?, state),
           pincode = COALESCE(?, pincode),
           created_by_dealer_id = COALESCE(created_by_dealer_id, ?)
       WHERE id = ?`,
      [userId, cleanName, address || null, city || null, state || null, pincode || null, createdByDealerId || null, row.id]
    );
    const updated = await query("SELECT * FROM customers WHERE id = ? LIMIT 1", [row.id]);
    return updated.rows[0];
  }

  const userCheck = await query("SELECT id, role FROM users WHERE mobile = ? LIMIT 1", [cleanMobile]);
  if (userCheck.rowCount && userCheck.rows[0].role !== "Customer") {
    const err = new Error("This mobile number is already used for another account type.");
    err.statusCode = 409;
    throw err;
  }

  let userId;
  if (userCheck.rowCount) {
    userId = userCheck.rows[0].id;
    await query(
      `UPDATE users
       SET name = ?,
           email = COALESCE(?, email),
           password_hash = CASE
             WHEN (password_hash IS NULL OR TRIM(password_hash) = '') AND ? <> '' THEN ?
             ELSE password_hash
           END
       WHERE id = ?`,
      [cleanName, emailNorm || null, cleanPassword, cleanPassword ? hashPassword(cleanPassword) : null, userId]
    );
    const orphan = await query("SELECT id FROM customers WHERE user_id = ? LIMIT 1", [userId]);
    if (orphan.rowCount) {
      const updated = await query("SELECT * FROM customers WHERE user_id = ? LIMIT 1", [userId]);
      return updated.rows[0];
    }
  } else {
    await query(
      "INSERT INTO users (role, name, mobile, email, password_hash, status) VALUES ('Customer', ?, ?, ?, ?, 'Active')",
      [cleanName, cleanMobile, emailNorm || null, cleanPassword ? hashPassword(cleanPassword) : null]
    );
    const user = await query("SELECT id FROM users WHERE mobile = ? AND role = 'Customer' LIMIT 1", [cleanMobile]);
    userId = user.rows[0].id;
  }

  await query(
    "INSERT INTO customers (user_id, name, mobile, address, city, state, pincode, created_by_dealer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [userId, cleanName, cleanMobile, address || null, city || null, state || null, pincode || null, createdByDealerId || null]
  );
  const created = await query("SELECT * FROM customers WHERE user_id = ? LIMIT 1", [userId]);
  return created.rows[0];
}

async function activateWarrantyFromSerial({ customerId, serialNo, purchaseDate, invoiceNo, actingDealerId }) {
  const cleanSerial = serialFromPayload(serialNo);
  if (!customerId || !cleanSerial) {
    const err = new Error("Customer and serial number are required.");
    err.statusCode = 400;
    throw err;
  }

  const customer = await query("SELECT id FROM customers WHERE id = ? LIMIT 1", [customerId]);
  if (!customer.rowCount) {
    const err = new Error("Customer account not found.");
    err.statusCode = 404;
    throw err;
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
    [cleanSerial]
  );
  if (!serial.rowCount) {
    const err = new Error("Serial number not found. Please scan admin generated QR.");
    err.statusCode = 404;
    throw err;
  }

  const row = serial.rows[0];
  if (!row.product_id) {
    const err = new Error("Serial is not linked to a product. Contact dispatch.");
    err.statusCode = 400;
    throw err;
  }

  const productRow = await query(
    "SELECT id, name, model_no, qr_status, qr_locked, qr_payload FROM products WHERE id = ? LIMIT 1",
    [row.product_id]
  );
  if (!productRow.rowCount) {
    const err = new Error("Product not found for this serial.");
    err.statusCode = 404;
    throw err;
  }
  const product = productRow.rows[0];
  if (product.qr_status !== "Printed") {
    const err = new Error("Product QR is not generated yet. Ask admin to print product QR sticker.");
    err.statusCode = 400;
    throw err;
  }

  if (actingDealerId && row.dealer_id && String(row.dealer_id) !== String(actingDealerId)) {
    const err = new Error("This product QR is mapped to another dealer.");
    err.statusCode = 403;
    throw err;
  }

  const warrantyDealerId = row.dealer_id || actingDealerId || null;

  const existing = await query(
    "SELECT * FROM warranties WHERE serial_id = ? ORDER BY created_at DESC LIMIT 1",
    [row.id]
  );
  if (existing.rowCount && existing.rows[0].customer_id) {
    if (existing.rows[0].customer_id === customerId) {
      const err = new Error("This product warranty is already active for this customer.");
      err.statusCode = 409;
      throw err;
    }
    const err = new Error("QR expired. This product warranty is already activated for another customer.");
    err.statusCode = 409;
    throw err;
  }

  const months = Number(row.warranty_months || 12);
  const warrantyNo = existing.rowCount ? existing.rows[0].warranty_no : `WAR-${Date.now()}`;
  const startDate = purchaseDate || new Date().toISOString().slice(0, 10);

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
      [customerId, warrantyDealerId, startDate, startDate, months, existing.rows[0].id]
    );
  } else {
    await query(
      `INSERT INTO warranties
       (warranty_no, customer_id, dealer_id, serial_id, start_date, expiry_date, status, installation_status)
       VALUES (?, ?, ?, ?, ?, DATE_ADD(?, INTERVAL ? MONTH), 'Active', 'Required')`,
      [warrantyNo, customerId, warrantyDealerId, row.id, startDate, startDate, months]
    );
  }

  if (invoiceNo) {
    await query("UPDATE serial_numbers SET invoice_no = COALESCE(NULLIF(invoice_no, ''), ?) WHERE id = ?", [invoiceNo, row.id]);
  }

  if (actingDealerId && !row.dealer_id) {
    await query("UPDATE serial_numbers SET dealer_id = ? WHERE id = ?", [actingDealerId, row.id]);
  }

  await lockProductQrAfterWarrantyActivation(row.product_id);

  const warranty = await query(
    `SELECT
       w.*,
       s.serial_no,
       p.name AS product_name,
       p.model_no,
       p.warranty_months,
       d.dealer_no,
       d.name AS dealer_name,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile
     FROM warranties w
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     LEFT JOIN customers cust ON cust.id = w.customer_id
     WHERE w.warranty_no = ?
     LIMIT 1`,
    [warrantyNo]
  );
  return warranty.rows[0];
}

app.post("/warranties/activate-from-qr", asyncRoute(async (req, res) => {
  const customerId = cleanString(req.body.customerId || req.body.customer_id);
  const serialNo = serialFromPayload(req.body.serialNo || req.body.serial_no);
  const scannedProduct = productFromPayload(req.body.qr || req.body.qrPayload || req.body.productQr);
  const productId = cleanString(req.body.productId || req.body.product_id || scannedProduct.productId);
  const purchaseDate = cleanDate(req.body.purchaseDate || req.body.purchase_date) || new Date().toISOString().slice(0, 10);
  const invoiceNo = cleanString(req.body.invoiceNo || req.body.invoice_no);

  if (!serialNo) {
    return res.status(400).json({ error: "Serial number is required after scanning product QR." });
  }
  if (productId) {
    const serialCheck = await query(
      "SELECT product_id FROM serial_numbers WHERE LOWER(TRIM(serial_no)) = LOWER(TRIM(?)) LIMIT 1",
      [serialNo]
    );
    if (!serialCheck.rowCount) {
      return res.status(404).json({ error: "Serial number not found." });
    }
    if (String(serialCheck.rows[0].product_id || "") !== String(productId)) {
      return res.status(400).json({ error: "This serial number does not belong to the scanned product." });
    }
  }

  const warranty = await activateWarrantyFromSerial({
    customerId,
    serialNo,
    purchaseDate,
    invoiceNo,
    actingDealerId: null,
  });
  res.json({ warranty });
}));

/** Dealer scans QR and registers customer details to activate warranty. */
app.post("/warranties/dealer/activate-from-qr", asyncRoute(async (req, res) => {
  const dealerId = cleanString(req.body.dealerId || req.body.dealer_id);
  const serialNo = serialFromPayload(req.body.serialNo || req.body.serial_no);
  const scannedProduct = productFromPayload(req.body.qr || req.body.qrPayload || req.body.productQr);
  const productId = cleanString(req.body.productId || req.body.product_id || scannedProduct.productId);
  const purchaseDate = cleanDate(req.body.purchaseDate || req.body.purchase_date) || new Date().toISOString().slice(0, 10);
  const invoiceNo = cleanString(req.body.invoiceNo || req.body.invoice_no);
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const { name, mobile, email, address, city, state, pincode } = req.body;
  const cleanMobile = normalizeMobileValue(mobile);
  const cleanEmail = normalizeEmail(email);

  if (!dealerId) {
    return res.status(400).json({ error: "Dealer id is required." });
  }
  const dealer = await query("SELECT id FROM dealers WHERE id = ? LIMIT 1", [dealerId]);
  if (!dealer.rowCount) {
    return res.status(404).json({ error: "Dealer not found." });
  }

  if (!serialNo) {
    return res.status(400).json({ error: "Serial number is required after scanning product QR." });
  }
  if (productId) {
    const serialCheck = await query(
      "SELECT product_id FROM serial_numbers WHERE LOWER(TRIM(serial_no)) = LOWER(TRIM(?)) LIMIT 1",
      [serialNo]
    );
    if (!serialCheck.rowCount) {
      return res.status(404).json({ error: "Serial number not found." });
    }
    if (String(serialCheck.rows[0].product_id || "") !== String(productId)) {
      return res.status(400).json({ error: "This serial number does not belong to the scanned product." });
    }
  }

  const existingCustomer = cleanMobile.length >= 10
    ? await query(
        `SELECT
           c.id,
           c.user_id,
           u.password_hash,
           u.email
         FROM customers c
         LEFT JOIN users u ON u.id = c.user_id
         WHERE ${sqlNormalizeMobileColumn("c.mobile")} = ?
         LIMIT 1`,
        [cleanMobile]
      )
    : { rowCount: 0, rows: [] };
  const hasExistingLogin = Boolean(
    existingCustomer.rowCount &&
      existingCustomer.rows[0]?.user_id &&
      existingCustomer.rows[0]?.password_hash &&
      String(existingCustomer.rows[0].password_hash).trim()
  );
  if (!hasExistingLogin) {
    if (!cleanEmail) {
      return res.status(400).json({ error: "Login Email ID is required for a new customer account." });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ error: "Customer login password must be at least 8 characters." });
    }
  }

  const customer = await findOrCreateCustomer({
    name,
    mobile,
    email: cleanEmail || null,
    address,
    city,
    state,
    pincode,
    password,
    createdByDealerId: dealerId,
  });
  const warranty = await activateWarrantyFromSerial({
    customerId: customer.id,
    serialNo,
    purchaseDate,
    invoiceNo,
    actingDealerId: dealerId,
  });
  res.status(201).json({ customer, warranty });
}));

/** List complaints (staff panels). Customers should use `/complaints/customer/:customerId`. */
app.get("/complaints", asyncRoute(async (_req, res) => {
  await ensureFeedbackSchema();
  const result = await query(
    `SELECT
       c.*,
       w.warranty_no,
       COALESCE(c.warranty_start_date, w.start_date) AS start_date,
       COALESCE(c.warranty_end_date, w.expiry_date) AS expiry_date,
       COALESCE(c.warranty_status, w.status) AS warranty_status,
       w.installation_status,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       s.serial_no,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.model_no, p.model_no) AS model_no,
       d.dealer_no,
       d.name AS dealer_name,
       ${COMPLAINT_LATEST_TASK_FIELDS}
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     ${COMPLAINT_LATEST_TASK_JOIN}
     ${COMPLAINT_FEEDBACK_JOIN}
     ORDER BY c.created_at DESC
     LIMIT 800`
  );
  res.json({ complaints: result.rows });
}));

/** Serial inventory for dispatch/dealer tooling */
app.get("/serial-numbers", asyncRoute(async (req, res) => {
  const productId = cleanString(req.query.productId || req.query.product_id);
  const dealerId = cleanString(req.query.dealerId || req.query.dealer_id);
  const modelNo = cleanString(req.query.modelNo || req.query.model_no);
  const qrStatus = cleanString(req.query.qrStatus || req.query.qr_status);
  const where = [];
  const params = [];
  if (productId) {
    where.push("s.product_id = ?");
    params.push(productId);
  }
  if (dealerId) {
    where.push("(s.dealer_id = ? OR s.dealer_id IS NULL)");
    params.push(dealerId);
  }
  if (modelNo) {
    where.push("LOWER(TRIM(p.model_no)) = LOWER(?)");
    params.push(modelNo);
  }
  if (qrStatus && ["Printed", "Not Printed"].includes(qrStatus)) {
    where.push("s.qr_status = ?");
    params.push(qrStatus);
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const result = await query(
    `SELECT
       s.*,
       p.name AS product_name,
       p.model_no,
       p.qr_status AS product_qr_status,
       p.qr_locked AS product_qr_locked,
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
     ${whereSql}
     ORDER BY s.created_at DESC
     LIMIT 800`,
    params
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

  const productName = cleanString(req.body.productName || req.body.product_name || req.body.name);
  let product = null;
  if (productId || productName || modelNo) {
    product = await resolveProductFromMaster({ productId, productName, modelNo });
  } else {
    return res.status(400).json({ error: "Select a product from Product Master before saving serial." });
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
     VALUES (?, ?, ?, ?, ?, ?, ?, 'Not Printed', ?, NULL, ?, ?)`,
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
    const productName = cleanString(pickRowValue(row, ["product", "productname", "product_name", "product name"]));
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

      if (!productName && !modelNo) {
        summary.failed += 1;
        errors.push({ row: index + 2, serial: serialNo, error: "Product name (admin) or model required from Product Master." });
        continue;
      }

      let product;
      try {
        product = await resolveProductFromMaster({ productName, modelNo });
      } catch (error) {
        summary.failed += 1;
        errors.push({ row: index + 2, serial: serialNo, error: error.message || "Product not in Product Master." });
        continue;
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
         VALUES (?, ?, ?, ?, ?, ?, ?, 'Not Printed', ?, NULL, ?, ?)`,
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
  const productId = cleanString(req.query.productId || req.query.product_id);
  const modelNo = cleanString(req.query.modelNo || req.query.model_no);
  const clauses = [];
  const params = [];
  if (requested.length) {
    clauses.push(`s.serial_no IN (${requested.map(() => "?").join(",")})`);
    params.push(...requested);
  } else {
    if (productId) {
      clauses.push("s.product_id = ?");
      params.push(productId);
    }
    if (modelNo) {
      clauses.push("LOWER(TRIM(p.model_no)) = LOWER(?)");
      params.push(modelNo);
    }
    if (!productId && !modelNo) {
      clauses.push("s.qr_status = 'Printed'");
    }
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const result = await query(
    `SELECT s.*, p.name AS product_name, p.model_no, d.dealer_no, d.name AS dealer_name
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = s.dealer_id
     ${where}
     ORDER BY s.created_at DESC
     LIMIT 300`,
    params
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

const TASK_DETAIL_SELECT = `
       t.id,
       t.task_no,
       t.complaint_id,
       t.technician_id,
       t.work_type,
       t.due_at,
       t.status,
       t.completed_at,
       t.resolution_notes,
       t.payable_amount,
       t.created_at,
       c.id AS complaint_db_id,
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
       cust.state AS customer_state,
       cust.pincode AS customer_pincode,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.model_no, p.model_no) AS model_no,
       s.serial_no,
       w.warranty_no,
       COALESCE(c.warranty_start_date, w.start_date) AS warranty_start,
       COALESCE(c.warranty_end_date, w.expiry_date) AS warranty_expiry,
       COALESCE(c.warranty_status, w.status) AS warranty_status,
       w.installation_status,
       d.dealer_no,
       d.name AS dealer_name,
       pay.status AS payment_status,
       pay.amount AS payment_amount`;

const TASK_DETAIL_JOINS = `
     FROM tasks t
     LEFT JOIN complaints c ON c.id = t.complaint_id
     LEFT JOIN technicians tech ON tech.id = t.technician_id
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = COALESCE(c.customer_id, w.customer_id)
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     LEFT JOIN (
       SELECT task_id, MAX(status) AS status, SUM(amount) AS amount
       FROM payments
       GROUP BY task_id
     ) pay ON pay.task_id = t.id`;

app.get("/tasks", asyncRoute(async (req, res) => {
  const status = cleanString(req.query.status);
  const technicianId = cleanString(req.query.technicianId || req.query.technician_id);
  const where = [];
  const params = [];
  if (status && status !== "All") {
    where.push("LOWER(t.status) = LOWER(?)");
    params.push(status);
  }
  if (technicianId) {
    where.push("t.technician_id = ?");
    params.push(technicianId);
  }
  const sqlWhere = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const result = await query(
    `SELECT ${TASK_DETAIL_SELECT}
     ${TASK_DETAIL_JOINS}
     ${sqlWhere}
     ORDER BY t.created_at DESC
     LIMIT 200`,
    params
  );
  res.json({ tasks: result.rows });
}));

app.get("/tasks/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  if (!id) {
    return res.status(400).json({ error: "Task id is required." });
  }
  const result = await query(
    `SELECT ${TASK_DETAIL_SELECT}
     ${TASK_DETAIL_JOINS}
     WHERE t.id = ?
     LIMIT 1`,
    [id]
  );
  if (!result.rowCount) {
    return res.status(404).json({ error: "Task not found." });
  }
  res.json({ task: result.rows[0] });
}));

app.patch("/tasks/:id/status", asyncRoute(async (req, res) => {
  await ensureTasksSchema();
  const id = cleanString(req.params.id);
  const status = cleanString(req.body?.status);
  const dueAt = cleanString(req.body?.dueAt || req.body?.due_at) || null;
  const technicianId = cleanString(req.body?.technicianId || req.body?.technician_id);
  const resolutionNotes = cleanString(req.body?.resolutionNotes || req.body?.resolution_notes) || null;
  if (!id || !status) {
    return res.status(400).json({ error: "Task id and status are required." });
  }
  const allowed = [
    "Assigned",
    "Accepted",
    "Rejected",
    "In Progress",
    "Scheduled",
    "Rescheduled",
    "Reached",
    "Inspection Started",
    "Completed"
  ];
  if (!allowed.includes(status)) {
    return res.status(400).json({ error: "Invalid task status." });
  }
  const existing = await query("SELECT id, complaint_id, technician_id, status FROM tasks WHERE id = ? LIMIT 1", [id]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Task not found." });
  }
  const row = existing.rows[0];
  if (technicianId && String(row.technician_id) !== technicianId) {
    return res.status(403).json({ error: "This task is not assigned to you." });
  }
  const current = String(row.status || "");
  if (status === "Accepted" && current !== "Assigned") {
    return res.status(400).json({ error: "Only new assignments can be accepted." });
  }
  if (status === "Rejected" && current !== "Assigned") {
    return res.status(400).json({ error: "Only new assignments can be rejected." });
  }

  await withTransaction(async (tx) => {
    if (dueAt && (status === "Rescheduled" || status === "Scheduled")) {
      await tx("UPDATE tasks SET status = ?, due_at = ? WHERE id = ?", [status, dueAt, id]);
    } else if (status === "Completed") {
      await tx(
        "UPDATE tasks SET status = ?, completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP), resolution_notes = COALESCE(?, resolution_notes) WHERE id = ?",
        [status, resolutionNotes, id]
      );
    } else if (resolutionNotes) {
      await tx("UPDATE tasks SET status = ?, resolution_notes = ? WHERE id = ?", [status, resolutionNotes, id]);
    } else {
      await tx("UPDATE tasks SET status = ? WHERE id = ?", [status, id]);
    }
    const complaintId = row.complaint_id;
    if (!complaintId) return;
    const nextComplaintStatus = complaintStatusForTaskStatus(status);
    if (nextComplaintStatus) {
      await tx("UPDATE complaints SET status = ? WHERE id = ?", [nextComplaintStatus, complaintId]);
    }
  });

  const taskResult = await query(
    `SELECT ${TASK_DETAIL_SELECT}
     ${TASK_DETAIL_JOINS}
     WHERE t.id = ?
     LIMIT 1`,
    [id]
  );
  res.json({ task: taskResult.rowCount ? taskResult.rows[0] : null });
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
       p.qr_status AS product_qr_status,
       p.qr_locked AS product_qr_locked,
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

  const patchProductId = cleanString(req.body.productId || req.body.product_id);
  const patchProductName = cleanString(req.body.productName || req.body.product_name);
  let product = null;
  if (patchProductId || patchProductName || modelNo) {
    product = await resolveProductFromMaster({
      productId: patchProductId,
      productName: patchProductName,
      modelNo,
    });
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
  await ensureFeedbackSchema();
  await ensureQuotationsSchema();
  const result = await query(
    `SELECT
       c.*,
       w.warranty_no,
       COALESCE(c.warranty_start_date, w.start_date) AS start_date,
       COALESCE(c.warranty_end_date, w.expiry_date) AS expiry_date,
       COALESCE(c.warranty_status, w.status) AS warranty_status,
       w.installation_status,
       s.serial_no,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.model_no, p.model_no) AS model_no,
       d.dealer_no,
       d.name AS dealer_name,
       ${COMPLAINT_LATEST_TASK_FIELDS},
       ${COMPLAINT_LATEST_QUOTATION_FIELDS}
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     ${COMPLAINT_LATEST_TASK_JOIN}
     ${COMPLAINT_FEEDBACK_JOIN}
     ${COMPLAINT_LATEST_QUOTATION_JOIN}
     WHERE c.customer_id = ?
     ORDER BY c.created_at DESC`,
    [req.params.customerId]
  );
  res.json({ complaints: result.rows });
}));

app.get("/complaints/dealer/:dealerId", asyncRoute(async (req, res) => {
  await ensureFeedbackSchema();
  const dealerKey = cleanString(req.params.dealerId);
  const dealer = await resolveDealerRecord(dealerKey);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  const dealerId = dealer.id;
  const result = await query(
    `SELECT
       c.*,
       w.warranty_no,
       COALESCE(c.warranty_start_date, w.start_date) AS start_date,
       COALESCE(c.warranty_end_date, w.expiry_date) AS expiry_date,
       COALESCE(c.warranty_status, w.status) AS warranty_status,
       w.installation_status,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       s.serial_no,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.model_no, p.model_no) AS model_no,
       d.dealer_no,
       d.name AS dealer_name,
       ${COMPLAINT_LATEST_TASK_FIELDS}
     FROM complaints c
     INNER JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     ${COMPLAINT_LATEST_TASK_JOIN}
     ${COMPLAINT_FEEDBACK_JOIN}
     WHERE COALESCE(w.dealer_id, s.dealer_id) = ?
     ORDER BY c.created_at DESC`,
    [dealerId]
  );
  res.json({ complaints: result.rows });
}));

async function handleComplaintUpdate(req, res) {
  await ensureComplaintsSchema();
  const complaintKey = cleanString(req.params.id);
  const requesterRole = cleanString(req.body.requesterRole || req.body.requester_role);
  const productPayload = req.body.product && typeof req.body.product === "object" ? req.body.product : {};
  const cleanProductName = cleanString(
    productPayload.name || productPayload.productName || productPayload.product_name || req.body.productName || req.body.product_name
  );
  const cleanModelNo = cleanString(
    productPayload.modelNo || productPayload.model_no || productPayload.model || req.body.modelNo || req.body.model_no
  );
  const cleanWarrantyStatus = cleanString(
    productPayload.warrantyStatus || productPayload.warranty_status || req.body.warrantyStatus || req.body.warranty_status
  ) || "Active";
  const cleanWarrantyStartDate = cleanWarrantyStatus === "Expired"
    ? null
    : cleanDate(productPayload.warrantyStartDate || productPayload.warranty_start_date || productPayload.startDate || req.body.warrantyStartDate || req.body.warranty_start_date);
  const cleanWarrantyEndDate = cleanWarrantyStatus === "Expired"
    ? null
    : cleanDate(productPayload.warrantyEndDate || productPayload.warranty_end_date || productPayload.endDate || req.body.warrantyEndDate || req.body.warranty_end_date);
  const cleanProblemType = cleanString(req.body.problemType || req.body.problem_type);
  const cleanDescription = cleanString(req.body.description) || null;
  const cleanPriority = cleanString(req.body.priority) || "Normal";

  if (!complaintKey) {
    return res.status(400).json({ error: "Complaint id is required." });
  }
  if (!["Front Desk", "Admin"].includes(requesterRole)) {
    return res.status(403).json({ error: "Only Front Desk or Admin can edit complaints." });
  }
  if (!cleanProductName || !cleanModelNo) {
    return res.status(400).json({ error: "Product name and model number are required." });
  }
  if (cleanWarrantyStatus === "Active" && (!cleanWarrantyStartDate || !cleanWarrantyEndDate)) {
    return res.status(400).json({ error: "Warranty start and end date are required for active warranty." });
  }
  if (!cleanProblemType) {
    return res.status(400).json({ error: "Problem type is required." });
  }

  const complaintId = await resolveComplaintId(complaintKey);
  if (!complaintId) {
    return res.status(404).json({ error: "Complaint not found." });
  }
  if (requesterRole === "Front Desk" && (await isComplaintSolvedInDb(complaintId))) {
    return res.status(403).json({ error: "Solved complaints cannot be edited by Front Desk." });
  }

  const result = await query(
    `UPDATE complaints
     SET problem_type = ?,
         description = ?,
         priority = ?,
         product_name = ?,
         model_no = ?,
         warranty_start_date = ?,
         warranty_end_date = ?,
         warranty_status = ?
     WHERE id = ?`,
    [
      cleanProblemType,
      cleanDescription,
      cleanPriority,
      cleanProductName,
      cleanModelNo,
      cleanWarrantyStartDate,
      cleanWarrantyEndDate,
      cleanWarrantyStatus,
      complaintId
    ]
  );
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Complaint not found." });
  }
  const updated = await query("SELECT * FROM complaints WHERE id = ? LIMIT 1", [complaintId]);
  res.json({ complaint: updated.rows[0] });
}

async function handleComplaintDelete(req, res) {
  const complaintKey = cleanString(req.params.id);
  const requesterRole = cleanString(req.body.requesterRole || req.body.requester_role);

  if (!complaintKey) {
    return res.status(400).json({ error: "Complaint id is required." });
  }
  if (!["Front Desk", "Admin"].includes(requesterRole)) {
    return res.status(403).json({ error: "Only Front Desk or Admin can delete complaints." });
  }

  const complaintId = await resolveComplaintId(complaintKey);
  if (!complaintId) {
    return res.status(404).json({ error: "Complaint not found." });
  }
  if (requesterRole === "Front Desk" && (await isComplaintSolvedInDb(complaintId))) {
    return res.status(403).json({ error: "Solved complaints cannot be deleted by Front Desk." });
  }

  await withTransaction(async (tx) => {
    await tx("DELETE FROM tasks WHERE complaint_id = ?", [complaintId]);
    await tx("DELETE FROM complaints WHERE id = ?", [complaintId]);
  });
  res.json({ ok: true });
}

app.patch("/complaints/:id", asyncRoute(handleComplaintUpdate));
app.post("/complaints/:id/update", asyncRoute(handleComplaintUpdate));
app.delete("/complaints/:id", asyncRoute(handleComplaintDelete));
app.post("/complaints/:id/delete", asyncRoute(handleComplaintDelete));

app.post("/complaints/:id/assign-technician", asyncRoute(async (req, res) => {
  const complaintKey = cleanString(req.params.id);
  const technicianId = cleanString(req.body.technicianId || req.body.technician_id);
  const workType = cleanString(req.body.workType || req.body.work_type) || "Warranty Repair";
  const dueAt = cleanString(req.body.dueAt || req.body.due_at) || null;
  const payableAmount = Number(req.body.payableAmount || req.body.payable_amount || 0);

  const complaintId = await resolveComplaintId(complaintKey);
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
    await tx("UPDATE complaints SET status = 'Awaiting Technician' WHERE id = ?", [complaintId]);
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

  const taskResult = await query(
    `SELECT ${TASK_DETAIL_SELECT}
     ${TASK_DETAIL_JOINS}
     WHERE t.complaint_id = ?
     ORDER BY t.created_at DESC
     LIMIT 1`,
    [complaintId]
  );
  const complaintRow = await query("SELECT * FROM complaints WHERE id = ? LIMIT 1", [complaintId]);
  res.json({
    complaint: complaintRow.rows[0],
    task: taskResult.rowCount ? taskResult.rows[0] : null,
  });
}));

app.post("/complaints", asyncRoute(async (req, res) => {
  const {
    complaintNo,
    warrantyId,
    customerId,
    problemType,
    description,
    priority,
    createdByRole,
    customer,
    product
  } = req.body;
  const creatorRole = typeof createdByRole === "string" ? createdByRole.trim() : "";
  const cleanProblemType = typeof problemType === "string" ? problemType.trim() : "";
  const cleanComplaintNo = typeof complaintNo === "string" ? complaintNo.trim() : "";
  const productPayload = product && typeof product === "object" ? product : {};
  const cleanProductName = cleanString(
    productPayload.name || productPayload.productName || productPayload.product_name || req.body.productName || req.body.product_name
  ) || null;
  const cleanModelNo = cleanString(
    productPayload.modelNo || productPayload.model_no || productPayload.model || req.body.modelNo || req.body.model_no
  ) || null;
  const cleanWarrantyStatus = cleanString(
    productPayload.warrantyStatus || productPayload.warranty_status || req.body.warrantyStatus || req.body.warranty_status
  ) || null;
  const cleanWarrantyStartDate = cleanWarrantyStatus === "Expired"
    ? null
    : cleanDate(productPayload.warrantyStartDate || productPayload.warranty_start_date || productPayload.startDate || req.body.warrantyStartDate || req.body.warranty_start_date);
  const cleanWarrantyEndDate = cleanWarrantyStatus === "Expired"
    ? null
    : cleanDate(productPayload.warrantyEndDate || productPayload.warranty_end_date || productPayload.endDate || req.body.warrantyEndDate || req.body.warranty_end_date);

  const staffComplaintCreators = ["Front Desk", "Dealer"];
  const isStaffCreator = staffComplaintCreators.includes(creatorRole);

  if (!cleanComplaintNo || !cleanProblemType) {
    return res.status(400).json({ error: "complaintNo and problemType are required" });
  }
  if (isStaffCreator && (!cleanProductName || !cleanModelNo)) {
    return res.status(400).json({ error: "Product name and model number are required." });
  }
  if (isStaffCreator && cleanWarrantyStatus === "Active" && (!cleanWarrantyStartDate || !cleanWarrantyEndDate)) {
    return res.status(400).json({ error: "Warranty start and end date are required for active warranty." });
  }

  let actingDealerId = null;
  if (creatorRole === "Dealer") {
    actingDealerId = cleanString(req.body.dealerId || req.body.dealer_id);
    const dealerProfile = actingDealerId ? await resolveDealerRecord(actingDealerId) : null;
    if (!dealerProfile) {
      return res.status(400).json({
        error: "Dealer profile is required. Link your login mobile with Dealer Management in Admin.",
      });
    }
    actingDealerId = dealerProfile.id;
  }

  let resolvedCustomerId = typeof customerId === "string" ? customerId.trim() : "";

  if (isStaffCreator) {
    const customerPayload = customer && typeof customer === "object" ? customer : null;
    if (!resolvedCustomerId && customerPayload) {
      const profile = await findOrCreateCustomer({
        name: customerPayload.name,
        mobile: customerPayload.mobile,
        email: customerPayload.email,
        address: customerPayload.address,
        city: customerPayload.city,
        state: customerPayload.state,
        pincode: customerPayload.pincode
      });
      resolvedCustomerId = profile.id;
    }
    if (!resolvedCustomerId) {
      return res.status(400).json({ error: "Customer name and mobile are required." });
    }
  } else if (!resolvedCustomerId) {
    return res.status(400).json({ error: "complaintNo, customerId, and problemType are required" });
  }

  const customerCheck = await query("SELECT id FROM customers WHERE id = ? LIMIT 1", [resolvedCustomerId]);
  if (!customerCheck.rowCount) {
    return res.status(404).json({ error: "Customer account not found." });
  }

  let resolvedWarrantyId = typeof warrantyId === "string" && warrantyId.trim() ? warrantyId.trim() : null;
  if (resolvedWarrantyId) {
    if (creatorRole === "Dealer") {
      const warrantyCheck = await query(
        `SELECT w.id
         FROM warranties w
         LEFT JOIN serial_numbers s ON s.id = w.serial_id
         WHERE w.id = ? AND w.customer_id = ?
           AND COALESCE(w.dealer_id, s.dealer_id) = ?
         LIMIT 1`,
        [resolvedWarrantyId, resolvedCustomerId, actingDealerId]
      );
      if (!warrantyCheck.rowCount) {
        return res.status(400).json({ error: "Selected warranty does not belong to this customer or your dealership." });
      }
    } else {
      const warrantyCheck = await query(
        "SELECT id FROM warranties WHERE id = ? AND customer_id = ? LIMIT 1",
        [resolvedWarrantyId, resolvedCustomerId]
      );
      if (!warrantyCheck.rowCount) {
        return res.status(400).json({ error: "Selected warranty does not belong to this customer." });
      }
    }
  }

  await query(
    `INSERT INTO complaints
     (complaint_no, warranty_id, customer_id, problem_type, description, priority, product_name, model_no, warranty_start_date, warranty_end_date, warranty_status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      cleanComplaintNo,
      resolvedWarrantyId,
      resolvedCustomerId,
      cleanProblemType,
      typeof description === "string" && description.trim() ? description.trim() : null,
      typeof priority === "string" && priority.trim() ? priority.trim() : "Normal",
      cleanProductName,
      cleanModelNo,
      cleanWarrantyStartDate,
      cleanWarrantyEndDate,
      cleanWarrantyStatus
    ]
  );
  const result = await query("SELECT * FROM complaints WHERE complaint_no = ? LIMIT 1", [cleanComplaintNo]);
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
  const status = Number(error?.statusCode);
  if (status >= 400 && status < 600) {
    return res.status(status).json({ error: error?.message || "Request failed" });
  }
  res.status(500).json({ error: error?.message || "Internal server error" });
});

try {
  await ensureSerialNumbersSchema();
  await ensureProductsQrSchema();
  await ensureComplaintsSchema();
  await ensureFeedbackSchema();
  await ensureTasksSchema();
  await ensureQuotationsSchema();
} catch (error) {
  console.warn("Runtime schema check skipped:", error?.message || error);
}

app.listen(port, "0.0.0.0", () => {
  console.log(`Hitaishi CRM API listening on http://0.0.0.0:${port} (reachable from phone via your PC LAN IP)`);
});
