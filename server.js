import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";
import { query, withTransaction } from "./db.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, "..", ".env") });
dotenv.config({ path: path.join(__dirname, ".env") });

const require = createRequire(import.meta.url);
const adminWebsitePath = path.join(__dirname, "..", "admin-website");
const adminIndexPath = path.join(adminWebsitePath, "index.html");
const QRCode = require("qrcode-terminal/vendor/QRCode");
const QRErrorCorrectLevel = require("qrcode-terminal/vendor/QRCode/QRErrorCorrectLevel");

const app = express();
const port = process.env.PORT || 4000;
const APP_QR_URL = process.env.HITAISHI_APP_QR_URL || "https://play.google.com/store/apps/details?id=com.instagram.android";

app.use(cors());
app.use(express.json());

app.get(["/admin", "/admin/"], (_req, res) => {
  if (!fs.existsSync(adminIndexPath)) {
    return res.status(503).send("Admin website files are missing from this deployment.");
  }
  res.sendFile(adminIndexPath);
});
app.use("/admin", express.static(adminWebsitePath, {
  index: false,
  redirect: false,
  setHeaders(res) {
    res.setHeader("Cache-Control", "no-cache");
  },
}));

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
const accountCreatorRoles = ["Admin", "Dealer", "Front Desk"];
const customerOnlyAccountCreators = [];
const dealerCreatableRoles = ["Customer"];
const frontDeskCreatableRoles = ["Customer", "Technician"];
const loginOtpChallenges = new Map();
const selfSaleOtpChallenges = new Map();
const customerAccountOtpChallenges = new Map();
const accountOtpChallenges = new Map();
const LOGIN_OTP_TTL_MS = 5 * 60 * 1000;
const NOTIFICATION_TTL_HOURS = 48;
const pincodeLookupCache = new Map();

function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

function normalizeMobileValue(mobile) {
  return typeof mobile === "string" ? mobile.replace(/\D/g, "") : "";
}

function normalizeLoginMobile(value) {
  let digits = normalizeMobileValue(value);
  if (!digits) {
    return "";
  }
  const dial = "91";
  if (digits.length > 10 && digits.startsWith(dial)) {
    digits = digits.slice(dial.length);
  }
  if (digits.length > 10) {
    digits = digits.slice(-10);
  }
  return digits.slice(0, 10);
}

function normalizeStoredMobile(mobile, countryDial) {
  const dial = cleanString(countryDial) || "91";
  return normalizeLoginMobile(
    dial === "91" ? mobile : `${normalizeMobileValue(dial)}${normalizeMobileValue(mobile)}`
  );
}

function requireTenDigitMobile(mobile, countryDial) {
  const national = normalizeStoredMobile(mobile, countryDial);
  if (national.length !== 10) {
    return { ok: false, error: "Enter a valid 10 digit mobile number." };
  }
  return { ok: true, national };
}

async function ensureUniqueLoginIdentity({ mobile, email, excludeUserId = null }, runQuery = query) {
  const cleanMobile = normalizeLoginMobile(mobile);
  const cleanEmail = normalizeEmail(email);
  if (cleanMobile) {
    const params = [cleanMobile];
    const exclude = excludeUserId ? " AND id <> ?" : "";
    if (excludeUserId) params.push(excludeUserId);
    const existingMobile = await runQuery(
      `SELECT id FROM users WHERE RIGHT(${sqlNormalizeMobileColumn("mobile")}, 10) = ?${exclude} LIMIT 1`,
      params
    );
    if (existingMobile.rowCount) {
      const err = new Error("This mobile number already has a login account.");
      err.statusCode = 409;
      throw err;
    }
  }
  if (cleanEmail) {
    const params = [cleanEmail];
    const exclude = excludeUserId ? " AND id <> ?" : "";
    if (excludeUserId) params.push(excludeUserId);
    const existingEmail = await runQuery(
      `SELECT id FROM users WHERE LOWER(TRIM(COALESCE(email,''))) = ?${exclude} LIMIT 1`,
      params
    );
    if (existingEmail.rowCount) {
      const err = new Error("This email ID already has a login account.");
      err.statusCode = 409;
      throw err;
    }
  }
}

function renderSmsTemplate(template, values) {
  return String(template || "").replace(/\{\{(\w+)\}\}/g, (_match, key) => encodeURIComponent(values[key] ?? ""));
}

async function sendLoginOtpSms(mobile, otp) {
  const smsUrlTemplate = cleanString(process.env.SMS_OTP_URL);
  if (!smsUrlTemplate) {
    return { sent: false, reason: "not_configured" };
  }

  let targetMobile = normalizeMobileValue(mobile);
  if (targetMobile.length === 10) {
    targetMobile = `91${targetMobile}`;
  }

  const message = `Your Hitaishi CRM login OTP is ${otp}. It is valid for 5 minutes.`;
  const method = cleanString(process.env.SMS_OTP_METHOD || "POST").toUpperCase();
  const headers = { Accept: "application/json" };
  const authHeader = cleanString(process.env.SMS_OTP_AUTH_HEADER);
  const authValue = cleanString(process.env.SMS_OTP_AUTH_VALUE);
  if (authHeader && authValue) {
    headers[authHeader] = authValue;
  }

  const url = renderSmsTemplate(smsUrlTemplate, { mobile: targetMobile, otp, message });
  const options = { method, headers };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    const bodyTemplate = cleanString(process.env.SMS_OTP_BODY_TEMPLATE);
    options.body = bodyTemplate
      ? renderSmsTemplate(bodyTemplate, { mobile: targetMobile, otp, message })
      : JSON.stringify({ mobile: targetMobile, otp, message });
  }

  const response = await fetch(url, options);
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    const err = new Error(body || `SMS provider failed (${response.status})`);
    err.statusCode = 502;
    throw err;
  }
  return { sent: true };
}

/** Match dealers.mobile to users.mobile even when formatting differs (+91, spaces, etc.). */
function sqlNormalizeMobileColumn(column) {
  return `REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(${column}, ' ', ''), '-', ''), '+', ''), '(', ''), ')', ''), '.', '')`;
}

/** Resolve dealer profile for login - by user_id, then last 10 digits of mobile (auto-links user_id when missing). */
async function findDealerForUser(userRow) {
  if (!userRow?.id) {
    return null;
  }
  await ensureDealersUserIdSchema();
  const byUser = await query("SELECT * FROM dealers WHERE user_id = ? LIMIT 1", [userRow.id]);
  if (byUser.rowCount) {
    return byUser.rows[0];
  }
  const dealerMobile = normalizeLoginMobile(userRow.mobile);
  if (dealerMobile.length < 10) {
    return null;
  }
  const byMobile = await query(
    `SELECT * FROM dealers WHERE RIGHT(${sqlNormalizeMobileColumn("mobile")}, 10) = ? LIMIT 1`,
    [dealerMobile]
  );
  if (!byMobile.rowCount) {
    return null;
  }
  const dealer = byMobile.rows[0];
  if (!dealer.user_id) {
    await query("UPDATE dealers SET user_id = ? WHERE id = ?", [userRow.id, dealer.id]);
    dealer.user_id = userRow.id;
  }
  return dealer;
}

function parseDealerNoSequence(dealerNo) {
  const match = String(dealerNo || "").match(/(\d+)/);
  return match ? Number(match[1]) : Number.MAX_SAFE_INTEGER;
}

function normalizeDealerNoInput(value) {
  const raw = cleanString(value);
  if (!raw) {
    return "";
  }
  if (/^DLR\d+$/i.test(raw)) {
    return raw.toUpperCase();
  }
  if (/^\d+$/.test(raw)) {
    return `DLR${String(Number(raw)).padStart(6, "0")}`;
  }
  return raw;
}

async function moveDealerForeignKeys(fromDealerId, toDealerId, runQuery = query) {
  if (!fromDealerId || !toDealerId || fromDealerId === toDealerId) {
    return;
  }
  const updates = [
    ["serial_numbers", "dealer_id"],
    ["warranties", "dealer_id"],
    ["complaints", "dealer_id"],
    ["customers", "created_by_dealer_id"],
    ["technicians", "created_by_dealer_id"],
    ["replace_return_cases", "dealer_id"],
  ];
  for (const [table, column] of updates) {
    await runQuery(`UPDATE ${table} SET ${column} = ? WHERE ${column} = ?`, [toDealerId, fromDealerId]);
  }
}

async function deleteDealerIfOrphan(dealerId, runQuery = query) {
  const checks = await runQuery(
    `SELECT
       (SELECT COUNT(*) FROM serial_numbers WHERE dealer_id = ?) AS serials,
       (SELECT COUNT(*) FROM warranties WHERE dealer_id = ?) AS warranties,
       (SELECT COUNT(*) FROM complaints WHERE dealer_id = ?) AS complaints,
       (SELECT COUNT(*) FROM customers WHERE created_by_dealer_id = ?) AS customers,
       (SELECT COUNT(*) FROM technicians WHERE created_by_dealer_id = ?) AS technicians`,
    [dealerId, dealerId, dealerId, dealerId, dealerId]
  );
  const row = checks.rows[0] || {};
  const total =
    Number(row.serials || 0) +
    Number(row.warranties || 0) +
    Number(row.complaints || 0) +
    Number(row.customers || 0) +
    Number(row.technicians || 0);
  if (total > 0) {
    return false;
  }
  await runQuery("DELETE FROM dealers WHERE id = ?", [dealerId]);
  return true;
}

async function relinkDealerLoginToTarget(userRow, targetDealer, runQuery = query) {
  if (!userRow?.id || !targetDealer?.id) {
    return null;
  }
  const storedMobile = normalizeLoginMobile(userRow.mobile);
  const linked = await findDealerForUser(userRow);
  if (linked && linked.id !== targetDealer.id) {
    await moveDealerForeignKeys(linked.id, targetDealer.id, runQuery);
    await runQuery("UPDATE dealers SET user_id = NULL WHERE id = ?", [linked.id]);
    await deleteDealerIfOrphan(linked.id, runQuery);
  }
  await runQuery(
    `UPDATE dealers
     SET user_id = ?,
         mobile = ?,
         name = COALESCE(NULLIF(name, ''), ?),
         contact_person = COALESCE(NULLIF(contact_person, ''), ?),
         status = COALESCE(NULLIF(status, ''), 'Active')
     WHERE id = ?`,
    [userRow.id, storedMobile, cleanString(userRow.name), cleanString(userRow.name), targetDealer.id]
  );
  const refreshed = await runQuery("SELECT * FROM dealers WHERE id = ? LIMIT 1", [targetDealer.id]);
  return refreshed.rowCount ? refreshed.rows[0] : null;
}

/** Prefer the earliest dealer_no when duplicate profiles exist for the same dealer name. */
async function repairPreferredDealerLinkForUser(userRow, runQuery = query) {
  const cleanName = cleanString(userRow?.name);
  if (!cleanName) {
    return null;
  }
  const preferredResult = await runQuery(
    `SELECT * FROM dealers WHERE LOWER(TRIM(name)) = LOWER(?) ORDER BY dealer_no ASC, created_at ASC`,
    [cleanName]
  );
  if (!preferredResult.rowCount) {
    return null;
  }
  const preferred = preferredResult.rows[0];
  const linked = await findDealerForUser(userRow);
  if (!linked) {
    if (!preferred.user_id || String(preferred.user_id) === String(userRow.id)) {
      return relinkDealerLoginToTarget(userRow, preferred, runQuery);
    }
    return null;
  }
  if (linked.id === preferred.id) {
    return linked;
  }
  if (parseDealerNoSequence(preferred.dealer_no) < parseDealerNoSequence(linked.dealer_no)) {
    return relinkDealerLoginToTarget(userRow, preferred, runQuery);
  }
  return linked;
}

/** Create dealer profile when login exists but dealers row is missing (legacy/orphan logins). */
async function ensureDealerProfileForUser(userRow, runQuery = query) {
  let existing = await repairPreferredDealerLinkForUser(userRow, runQuery);
  if (!existing) {
    existing = await findDealerForUser(userRow);
  }
  if (!existing) {
    const cleanName = cleanString(userRow?.name);
    const unlinked = cleanName
      ? await runQuery(
          `SELECT * FROM dealers
           WHERE LOWER(TRIM(name)) = LOWER(?)
             AND (user_id IS NULL OR user_id = '')
           ORDER BY dealer_no ASC, created_at ASC
           LIMIT 1`,
          [cleanName]
        )
      : { rowCount: 0, rows: [] };
    if (unlinked.rowCount) {
      existing = await relinkDealerLoginToTarget(userRow, unlinked.rows[0], runQuery);
    }
  }
  if (existing) {
    const currentNo = cleanString(existing.dealer_no);
    if (!currentNo || currentNo === "Pending Dealer No") {
      const finalDealerNo = await getNextDealerNo(runQuery);
      await runQuery("UPDATE dealers SET dealer_no = ? WHERE id = ?", [finalDealerNo, existing.id]);
      existing.dealer_no = finalDealerNo;
    }
    return existing;
  }
  const storedMobile = normalizeLoginMobile(userRow?.mobile);
  const cleanName = cleanString(userRow?.name);
  if (!userRow?.id || storedMobile.length !== 10 || !cleanName) {
    return null;
  }
  await ensureDealersUserIdSchema();
  const finalDealerNo = await getNextDealerNo(runQuery);
  await runQuery(
    `INSERT INTO dealers (user_id, dealer_no, name, contact_person, mobile, status)
     VALUES (?, ?, ?, ?, ?, 'Active')`,
    [userRow.id, finalDealerNo, cleanName, cleanName, storedMobile]
  );
  const created = await runQuery("SELECT * FROM dealers WHERE user_id = ? LIMIT 1", [userRow.id]);
  return created.rowCount ? created.rows[0] : null;
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
  const byDealerNo = await query(
    "SELECT * FROM dealers WHERE LOWER(TRIM(dealer_no)) = LOWER(?) LIMIT 1",
    [key]
  );
  if (byDealerNo.rowCount) {
    return byDealerNo.rows[0];
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
  const [serials, warranties, totalComplaints, openComplaints, solvedComplaints, pendingScan, pendingInstallation, rewards] =
    await Promise.all([
    query("SELECT COUNT(*) AS total FROM serial_numbers WHERE dealer_id = ?", [dealerId]),
    query("SELECT COUNT(*) AS total FROM warranties WHERE dealer_id = ? AND customer_id IS NOT NULL", [dealerId]),
    query(
      `SELECT COUNT(*) AS total ${DEALER_COMPLAINT_FROM} WHERE COALESCE(c.dealer_id, w.dealer_id, s.dealer_id) = ?`,
      [dealerId]
    ),
    query(
      `SELECT COUNT(*) AS total ${DEALER_COMPLAINT_FROM}
       WHERE COALESCE(c.dealer_id, w.dealer_id, s.dealer_id) = ? AND ${COMPLAINT_OPEN_WHERE}`,
      [dealerId]
    ),
    query(
      `SELECT COUNT(*) AS total ${DEALER_COMPLAINT_FROM}
       WHERE COALESCE(c.dealer_id, w.dealer_id, s.dealer_id) = ? AND ${COMPLAINT_SOLVED_WHERE}`,
      [dealerId]
    ),
    query(
      `SELECT COUNT(*) AS total
       FROM serial_numbers s
       WHERE s.dealer_id = ?
         AND NOT EXISTS (
           SELECT 1
           FROM warranties w
           WHERE w.serial_id = s.id
             AND w.customer_id IS NOT NULL
         )`,
      [dealerId]
    ),
    query(
      `SELECT COUNT(*) AS total
       FROM warranties w
       WHERE w.dealer_id = ?
         AND w.customer_id IS NOT NULL
         AND LOWER(TRIM(COALESCE(w.installation_status, ''))) = 'required'`,
      [dealerId]
    ),
    query(
      "SELECT COALESCE(SUM(points), 0) AS total FROM dealer_reward_transactions WHERE dealer_id = ?",
      [dealerId]
    ),
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
    pendingScan: count(pendingScan),
    assignedProducts: count(pendingScan),
    pendingInstallation: count(pendingInstallation),
    rewardPoints: count(rewards),
    productsSold,
  };
}

/** Resolve technician profile for login - by user_id, then mobile (auto-links user_id when missing). */
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

function normalizePincode(value) {
  return String(value ?? "").replace(/\D/g, "").slice(0, 6);
}

function bestCityFromPostalOffice(postOffice) {
  return cleanString(
    postOffice?.Block ||
      postOffice?.Taluk ||
      postOffice?.District ||
      postOffice?.Name ||
      postOffice?.Division
  );
}

async function fetchJsonWithTimeout(url, options = {}, timeoutMs = 6000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(options.headers || {}),
      },
    });
    if (!response.ok) {
      return null;
    }
    return response.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function lookupPincodeLocation(pincode) {
  const pin = normalizePincode(pincode);
  if (pin.length !== 6) {
    const err = new Error("Enter a valid 6 digit pin code.");
    err.statusCode = 400;
    throw err;
  }

  const cached = pincodeLookupCache.get(pin);
  if (cached && Date.now() - cached.at < 24 * 60 * 60 * 1000) {
    return cached.data;
  }

  let local = null;
  try {
    const areaResult = await query(
      `SELECT state, city, area, pincode
       FROM service_areas
       WHERE pincode = ?
       ORDER BY created_at DESC
       LIMIT 1`,
      [pin]
    );
    local = areaResult.rows?.[0] || null;
  } catch {
    local = null;
  }
  if (local?.city || local?.state) {
    const data = {
      pincode: pin,
      city: cleanString(local.city),
      state: cleanString(local.state),
      area: cleanString(local.area),
      source: "service_areas",
    };
    pincodeLookupCache.set(pin, { data, at: Date.now() });
    return data;
  }

  const postalData = await fetchJsonWithTimeout(`https://api.postalpincode.in/pincode/${encodeURIComponent(pin)}`);
  const postalOffice = Array.isArray(postalData?.[0]?.PostOffice) ? postalData[0].PostOffice[0] : null;
  if (postalOffice) {
    const data = {
      pincode: pin,
      city: bestCityFromPostalOffice(postalOffice),
      state: cleanString(postalOffice.State),
      area: cleanString(postalOffice.Name),
      district: cleanString(postalOffice.District),
      source: "postalpincode",
    };
    pincodeLookupCache.set(pin, { data, at: Date.now() });
    return data;
  }

  const osmUrl =
    `https://nominatim.openstreetmap.org/search?format=json&addressdetails=1&limit=1&country=India&postalcode=${encodeURIComponent(pin)}`;
  const osmData = await fetchJsonWithTimeout(osmUrl, {
    headers: { "User-Agent": "HitaishiCRM/1.0 pincode lookup" },
  });
  const first = Array.isArray(osmData) ? osmData[0] : null;
  if (first?.address) {
    const address = first.address;
    const data = {
      pincode: pin,
      city: cleanString(address.city || address.town || address.village || address.county || address.state_district),
      state: cleanString(address.state),
      area: cleanString(address.suburb || address.neighbourhood || address.state_district),
      source: "openstreetmap",
    };
    pincodeLookupCache.set(pin, { data, at: Date.now() });
    return data;
  }

  const err = new Error("Pin code location not found.");
  err.statusCode = 404;
  throw err;
}

function purgeExpiredOtpChallenges(store) {
  for (const [key, value] of store.entries()) {
    if (Date.now() > value.expiresAt) {
      store.delete(key);
    }
  }
}

/** 0 = no warranty period (product treated as expired). Years input is converted to months. */
function resolveProductWarrantyMonths(body = {}) {
  if (body.warrantyYears !== undefined || body.warranty_years !== undefined) {
    const yearsRaw = cleanString(body.warrantyYears ?? body.warranty_years);
    if (!yearsRaw) {
      return 0;
    }
    const years = Number(yearsRaw);
    return Number.isFinite(years) && years > 0 ? Math.round(years * 12) : 0;
  }
  const monthsRaw = body.warrantyMonths ?? body.warranty_months;
  if (monthsRaw === "" || monthsRaw === null || monthsRaw === undefined) {
    return 0;
  }
  const months = Number(monthsRaw);
  return Number.isFinite(months) && months > 0 ? Math.round(months) : 0;
}

function productHasWarrantyCoverage(warrantyMonths) {
  const months = Number(warrantyMonths);
  return Number.isFinite(months) && months > 0;
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
  if (s === "Closed") return "Closed";
  if (s === "Pending Happy Code") return "Pending Customer Confirmation";
  if (s === "On Hold") return "On Hold";
  if (s === "Rejected") return "Technician Rejected";
  if (s === "Unrepairable") return "Awaiting Dealer Action";
  if (s === "Assigned") return "Assigned to Technician";
  if (s === "Accepted") return "Technician Accepted";
  if (
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

async function ensureWorkflowAuditSchema() {
  await query(
    `CREATE TABLE IF NOT EXISTS status_history (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      complaint_id CHAR(36),
      old_status VARCHAR(80),
      new_status VARCHAR(80) NOT NULL,
      changed_by_role VARCHAR(80),
      changed_by_id CHAR(36),
      remarks TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_status_history_complaint (complaint_id),
      INDEX idx_status_history_created (created_at),
      CONSTRAINT fk_status_history_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );
  await query(
    `CREATE TABLE IF NOT EXISTS complaint_assignments (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      complaint_id CHAR(36) NOT NULL,
      technician_id CHAR(36) NOT NULL,
      assigned_by_role VARCHAR(80),
      assigned_by_id CHAR(36),
      assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      status VARCHAR(40) NOT NULL DEFAULT 'Assigned',
      remarks TEXT,
      INDEX idx_complaint_assignments_complaint (complaint_id),
      INDEX idx_complaint_assignments_technician (technician_id),
      CONSTRAINT fk_complaint_assignments_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
      CONSTRAINT fk_complaint_assignments_technician FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );
  await query(
    `CREATE TABLE IF NOT EXISTS messages_or_comments (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      complaint_id CHAR(36),
      quotation_id CHAR(36),
      sender_role VARCHAR(80),
      sender_id CHAR(36),
      receiver_role VARCHAR(80),
      receiver_id CHAR(36),
      message TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_messages_complaint (complaint_id),
      INDEX idx_messages_quotation (quotation_id),
      INDEX idx_messages_created (created_at),
      CONSTRAINT fk_messages_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
      CONSTRAINT fk_messages_quotation FOREIGN KEY (quotation_id) REFERENCES quotations(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );
}

async function recordStatusHistory({
  complaintId,
  oldStatus = null,
  newStatus,
  changedByRole = null,
  changedById = null,
  remarks = null,
}, runQuery = query) {
  if (!complaintId || !newStatus) return;
  await runQuery(
    `INSERT INTO status_history
     (complaint_id, old_status, new_status, changed_by_role, changed_by_id, remarks)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [complaintId, oldStatus, newStatus, changedByRole, changedById, remarks]
  );
}

async function createWorkflowMessage({
  complaintId = null,
  quotationId = null,
  senderRole = null,
  senderId = null,
  receiverRole = null,
  receiverId = null,
  message,
}, runQuery = query) {
  if (!message) return;
  await runQuery(
    `INSERT INTO messages_or_comments
     (complaint_id, quotation_id, sender_role, sender_id, receiver_role, receiver_id, message)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [complaintId, quotationId, senderRole, senderId, receiverRole, receiverId, message]
  );
}

const COMPLAINT_LATEST_TASK_JOIN = `
  LEFT JOIN tasks t ON t.id = (
    SELECT t2.id FROM tasks t2 WHERE t2.complaint_id = c.id ORDER BY t2.created_at DESC LIMIT 1
  )
  LEFT JOIN technicians tech ON tech.id = t.technician_id
  LEFT JOIN users assigned_user ON assigned_user.id = t.assigned_by_id`;

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
       t.completion_code_sent_at AS task_completion_code_sent_at,
       t.completion_verified_at AS task_completion_verified_at,
       t.created_at AS task_created_at,
       t.assigned_by_role AS task_assigned_by_role,
       t.assigned_by_id AS task_assigned_by_id,
       assigned_user.name AS task_assigned_by_name,
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
       qt.customer_payment_status AS quotation_payment_status,
       qt.customer_paid_at AS quotation_paid_at,
       qt.created_at AS quotation_created_at`;

const COMPLAINT_REPLACEMENT_JOIN = `
  LEFT JOIN replace_return_cases rr ON rr.complaint_id = c.id
  LEFT JOIN serial_numbers old_sn ON old_sn.id = rr.serial_id
  LEFT JOIN products old_p ON old_p.id = old_sn.product_id
  LEFT JOIN serial_numbers repl_sn ON repl_sn.id = rr.replacement_serial_id
  LEFT JOIN products repl_p ON repl_p.id = repl_sn.product_id`;

const COMPLAINT_REPLACEMENT_FIELDS = `
       rr.id AS replacement_case_id,
       rr.case_no AS replacement_case_no,
       rr.action_type AS replacement_action_type,
       rr.status AS replacement_case_status,
       rr.problem_details AS replacement_problem_details,
       rr.delivered_to_customer_at AS replacement_delivered_at,
       rr.replacement_dispatched_at AS replacement_dispatched_at,
       old_sn.serial_no AS replaced_serial_no,
       COALESCE(old_p.name, c.product_name) AS replaced_product_name,
       COALESCE(old_p.model_no, c.model_no) AS replaced_model_no,
       repl_sn.serial_no AS replacement_serial_no,
       repl_p.name AS replacement_product_name,
       repl_p.model_no AS replacement_model_no`;

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

const WARRANTY_ACTIVE_SQL = `
  LOWER(TRIM(COALESCE(c.warranty_status, w.status, ''))) NOT LIKE '%expired%'
  AND (
    COALESCE(c.warranty_end_date, w.expiry_date) IS NULL
    OR DATE(COALESCE(c.warranty_end_date, w.expiry_date)) >= CURDATE()
  )`;

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
    ["customer_decided_at", "ALTER TABLE quotations ADD COLUMN customer_decided_at TIMESTAMP NULL AFTER customer_remarks"],
    ["frontdesk_instruction", "ALTER TABLE quotations ADD COLUMN frontdesk_instruction VARCHAR(40) NULL AFTER customer_decided_at"],
    ["frontdesk_instructed_at", "ALTER TABLE quotations ADD COLUMN frontdesk_instructed_at TIMESTAMP NULL AFTER frontdesk_instruction"],
    ["sent_to_frontdesk_at", "ALTER TABLE quotations ADD COLUMN sent_to_frontdesk_at TIMESTAMP NULL AFTER status"],
    ["customer_payment_status", "ALTER TABLE quotations ADD COLUMN customer_payment_status VARCHAR(40) NOT NULL DEFAULT 'Pending' AFTER frontdesk_instructed_at"],
    ["customer_paid_at", "ALTER TABLE quotations ADD COLUMN customer_paid_at TIMESTAMP NULL AFTER customer_payment_status"]
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

async function ensureNotificationsSchema() {
  await query(
    `CREATE TABLE IF NOT EXISTS notifications (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      recipient_role VARCHAR(80),
      customer_id CHAR(36),
      user_id CHAR(36),
      type VARCHAR(80) NOT NULL,
      title VARCHAR(180) NOT NULL,
      message TEXT,
      entity_type VARCHAR(80),
      entity_id CHAR(36),
      read_at TIMESTAMP NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_notifications_customer (customer_id),
      INDEX idx_notifications_role (recipient_role),
      INDEX idx_notifications_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );
}

async function purgeExpiredNotifications(runQuery = query) {
  await runQuery(
    `DELETE FROM notifications
     WHERE created_at < DATE_SUB(NOW(), INTERVAL ${NOTIFICATION_TTL_HOURS} HOUR)`
  );
}

async function ensurePushTokensSchema() {
  await query(
    `CREATE TABLE IF NOT EXISTS push_tokens (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      token VARCHAR(255) NOT NULL UNIQUE,
      user_id CHAR(36),
      customer_id CHAR(36),
      role VARCHAR(80),
      platform VARCHAR(40),
      last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_push_tokens_user (user_id),
      INDEX idx_push_tokens_customer (customer_id),
      INDEX idx_push_tokens_role (role)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );
}

async function sendExpoPushMessages(messages) {
  const payload = messages
    .filter((msg) => msg?.to && String(msg.to).startsWith("ExponentPushToken["))
    .slice(0, 100);
  if (!payload.length) {
    return;
  }
  try {
    const response = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      console.warn("Expo push failed:", response.status, await response.text().catch(() => ""));
    }
  } catch (err) {
    console.warn("Expo push skipped:", err?.message || err);
  }
}

async function sendPushForNotification({ recipientRole = null, customerId = null, userId = null, title, message, entityType = null, entityId = null, type = null }) {
  try {
    await ensurePushTokensSchema();
    const where = [];
    const params = [];
    if (customerId) {
      where.push("customer_id = ?");
      params.push(customerId);
    }
    if (userId) {
      where.push("user_id = ?");
      params.push(userId);
    }
    if (!where.length) {
      return;
    }
    const result = await query(
      `SELECT DISTINCT token FROM push_tokens WHERE (${where.join(" OR ")}) ORDER BY last_seen_at DESC LIMIT 100`,
      params
    );
    await sendExpoPushMessages(
      result.rows.map((row) => ({
        to: row.token,
        sound: "default",
        title: title || "Hitaishi CRM",
        body: message || "",
        data: { type, entityType, entityId },
      }))
    );
  } catch (err) {
    console.warn("Push notification skipped:", err?.message || err);
  }
}

async function createNotification({
  recipientRole = null,
  customerId = null,
  userId = null,
  type,
  title,
  message = null,
  entityType = null,
  entityId = null,
}, runQuery = query) {
  await runQuery(
    `INSERT INTO notifications
     (recipient_role, customer_id, user_id, type, title, message, entity_type, entity_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [recipientRole, customerId, userId, type, title, message, entityType, entityId]
  );
  sendPushForNotification({ recipientRole, customerId, userId, type, title, message, entityType, entityId });
}

async function getComplaintNotifyContext(complaintId, runQuery = query) {
  const result = await runQuery(
    `SELECT
       c.id,
       c.complaint_no,
       c.customer_id,
       c.created_by_role,
       c.status AS complaint_status,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.dealer_id, w.dealer_id, s.dealer_id) AS dealer_id,
       du.id AS dealer_user_id,
       t.id AS task_id,
       t.technician_id,
       tech.user_id AS technician_user_id,
       tech.name AS technician_name
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(c.dealer_id, w.dealer_id, s.dealer_id)
     LEFT JOIN users du ON du.role = 'Dealer' AND ${sqlNormalizeMobileColumn("du.mobile")} = ${sqlNormalizeMobileColumn("d.mobile")}
     LEFT JOIN tasks t ON t.complaint_id = c.id
     LEFT JOIN technicians tech ON tech.id = t.technician_id
     WHERE c.id = ?
     ORDER BY t.created_at DESC
     LIMIT 1`,
    [complaintId]
  );
  return result.rowCount ? result.rows[0] : null;
}

async function notifyTechnicianForComplaint(ctx, { type, title, message, entityType = "complaint", entityId = null }, runQuery = query) {
  if (!ctx?.technician_user_id) {
    return;
  }
  await createNotification({
    userId: ctx.technician_user_id,
    recipientRole: "Technician",
    type,
    title,
    message,
    entityType,
    entityId: entityId || ctx.task_id || ctx.id,
  }, runQuery);
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
       c.status AS complaint_status,
       COALESCE(c.warranty_status, w.status) AS warranty_status,
       COALESCE(c.warranty_end_date, w.expiry_date) AS warranty_expiry,
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

function dispatchUnitQrPayload({
  productId,
  productName,
  modelNo,
  serialNo,
  dealerId,
  dealerNo,
  dealerName,
  customerId,
  customerName,
  customerMobile,
  dispatchType,
}) {
  const params = new URLSearchParams();
  if (productId) params.set("productId", productId);
  if (productName) params.set("name", productName);
  if (modelNo) params.set("model", modelNo);
  if (serialNo) params.set("serial", serialNo);
  if (dealerId) params.set("dealerId", dealerId);
  if (dealerNo) params.set("dealerNo", dealerNo);
  if (dealerName) params.set("dealerName", dealerName);
  if (customerId) params.set("customerId", customerId);
  if (customerName) params.set("customerName", customerName);
  if (customerMobile) params.set("customerMobile", customerMobile);
  if (dispatchType) params.set("dispatchType", dispatchType);
  return `hitaishi://unit?${params.toString()}`;
}

function replaceReturnQrPayload({ caseId, caseNo, serialNo, actionType }) {
  const params = new URLSearchParams();
  if (caseId) params.set("caseId", caseId);
  if (caseNo) params.set("caseNo", caseNo);
  if (serialNo) params.set("serial", serialNo);
  if (actionType) params.set("action", actionType);
  return `hitaishi://replace-return?${params.toString()}`;
}

function replacementDeliveryQrPayload({ caseId, caseNo, serialNo, customerId, complaintNo }) {
  const params = new URLSearchParams();
  if (caseId) params.set("caseId", caseId);
  if (caseNo) params.set("caseNo", caseNo);
  if (serialNo) params.set("serial", serialNo);
  if (customerId) params.set("customerId", customerId);
  if (complaintNo) params.set("complaint", complaintNo);
  return `hitaishi://replacement-delivery?${params.toString()}`;
}

async function allocateDispatchSerialNumbers(product, quantity, tx) {
  const modelBase = cleanString(product?.model_no).replace(/[^A-Za-z0-9]/g, "").toUpperCase() || "UNIT";
  const prefix = `${modelBase}-`;
  const escapedPrefix = prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const latest = await tx(
    `SELECT serial_no FROM serial_numbers WHERE serial_no LIKE ? ORDER BY serial_no DESC LIMIT 1`,
    [`${prefix}%`]
  );
  let nextNum = 1;
  if (latest.rowCount) {
    const match = String(latest.rows[0].serial_no || "").match(new RegExp(`^${escapedPrefix}(\\d+)$`));
    if (match) nextNum = Number(match[1]) + 1;
  }
  const serials = [];
  for (let index = 0; index < quantity; index += 1) {
    let candidateNum = nextNum + index;
    let candidate = `${prefix}${String(candidateNum).padStart(5, "0")}`;
    let guard = 0;
    while (guard < 10000) {
      const exists = await tx("SELECT id FROM serial_numbers WHERE serial_no = ? LIMIT 1", [candidate]);
      if (!exists.rowCount) {
        serials.push(candidate);
        break;
      }
      candidateNum += 1;
      candidate = `${prefix}${String(candidateNum).padStart(5, "0")}`;
      guard += 1;
    }
    if (guard >= 10000) {
      const err = new Error("Could not allocate unique serial numbers.");
      err.statusCode = 500;
      throw err;
    }
  }
  return serials;
}

function parseQrLabelCopies(value) {
  const copies = Number.parseInt(value, 10);
  if (!Number.isFinite(copies) || copies < 1) {
    return 1;
  }
  return Math.min(copies, 100);
}

function parseQrProductCopies(value) {
  if (!value) return new Map();
  try {
    const parsed = JSON.parse(String(value));
    if (!parsed || typeof parsed !== "object") return new Map();
    return new Map(
      Object.entries(parsed)
        .map(([key, copies]) => [String(key), parseQrLabelCopies(copies)])
        .filter(([key]) => key)
    );
  } catch {
    return new Map();
  }
}

function productCopyKeys(row) {
  return [
    cleanString(row?.product_id),
    cleanString(row?.product_name),
    cleanString(row?.name),
  ].filter(Boolean);
}

function expandQrPrintRows(rows, copies = 1, copiesByProduct = new Map()) {
  const labelCopies = parseQrLabelCopies(copies);
  const printRows = [];
  rows.forEach((row) => {
    const rowCopies = productCopyKeys(row).reduce(
      (matchedCopies, key) => matchedCopies || copiesByProduct.get(key),
      0
    ) || labelCopies;
    for (let index = 0; index < rowCopies; index += 1) {
      printRows.push(row);
    }
  });
  return printRows;
}

function buildWarrantyQrLabel({ payload, title = "PLEASE REGISTER", qrUrl = "", serial = "", model = "", product = "" }) {
  const serviceCategory = [model, serial].filter(Boolean).join(" | ");
  return `
    <div class="label-print-slot">
    <section class="warranty-label">
      <div class="label-main">
        <header class="label-header">
          <div class="headline">${escapeHtml(title)}</div>
          <div class="subhead">to activate warranty</div>
        </header>
        <div class="label-scans">
          <div class="rule"></div>
          <div class="scan-row">
            <div class="scan-icon person-icon" aria-hidden="true">
              <span></span>
            </div>
            <div class="scan-copy">
              <div class="scan-title">DEALER SCAN</div>
              <div class="scan-text">Dealer scans to activate warranty</div>
            </div>
          </div>
          <div class="rule"></div>
          <div class="scan-row">
            <div class="scan-icon group-icon" aria-hidden="true">
              <span></span><span></span>
            </div>
            <div class="scan-copy">
              <div class="scan-title">CUSTOMER SCAN</div>
              <div class="scan-text">If dealer not scan</div>
            </div>
          </div>
        </div>
        <div class="app-install-block">
          <div class="app-install-qr">${qrSvg(APP_QR_URL, 84, 1)}</div>
          <div class="app-install-text">Scan to install app</div>
        </div>
        <div class="qr-panel">
          <div class="qr-wrap">
            ${qrSvg(payload, 300, 2)}
          </div>
          <div class="service-category">${escapeHtml(serviceCategory)}</div>
          <div class="service-product">${escapeHtml(product)}</div>
          <a class="download" href="${escapeHtml(qrUrl)}">Download QR</a>
        </div>
      </div>
      <footer class="label-footer">
        <div class="footer-mark" aria-hidden="true"></div>
        <div class="footer-warning">DON'T BUY IF DON'T SCAN</div>
        <div class="footer-divider"></div>
        <div class="footer-brand">HITAISHI TECHNOLOGIES PVT. LTD.</div>
      </footer>
      <div class="print-meta">
        ${escapeHtml(serviceCategory || product)}
      </div>
    </section>
    </div>`;
}

function buildDispatchQrPrintHtml(rows, title = "Dispatch QR Sheet", copies = 1, copiesByProduct = new Map()) {
  const printRows = expandQrPrintRows(rows, copies, copiesByProduct);
  const pageHtml = printRows
    .map((serial) => {
      const payload =
        serial.qr_payload ||
        dispatchUnitQrPayload({
          productId: serial.product_id,
          productName: serial.product_name,
          modelNo: serial.model_no,
          serialNo: serial.serial_no,
          dealerId: serial.dealer_id,
          dealerNo: serial.dealer_no,
          dealerName: serial.dealer_name,
          customerId: serial.dispatched_customer_id,
          customerName: serial.customer_name,
          customerMobile: serial.customer_mobile,
          dispatchType: serial.dispatched_customer_id ? "selfSale" : "",
        });
      const qrUrl = `/serial-numbers/${encodeURIComponent(serial.serial_no)}/qr.svg?download=1`;
      return buildWarrantyQrLabel({
        payload,
        qrUrl,
        serial: serial.serial_no,
        model: serial.model_no,
        product: serial.product_name || "Product",
      });
    })
    .join("");

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(title)}</title>
  <style id="pageSizeStyle">@page { size: 60mm 40mm; margin: 0; }</style>
  <style>
    * { box-sizing: border-box; }
    :root { --label-print-scale: 0.78; }
    html, body, .warranty-label, .label-footer, .scan-icon, .footer-mark, .footer-divider {
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    html, body { margin: 0; padding: 0; background: #f3f4f6; color: #050505; }
    body { font-family: Arial, Helvetica, sans-serif; }
    .toolbar { padding: 12px 16px; border-bottom: 1px solid #d1d5db; }
    .toolbar-row { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
    .toolbar label { font-size: 14px; font-weight: 700; }
    .toolbar select { min-height: 36px; padding: 6px 10px; font-size: 14px; border: 1px solid #9ca3af; border-radius: 6px; background: #fff; }
    .toolbar button { padding: 8px 14px; font-size: 14px; cursor: pointer; border: 1px solid #111; border-radius: 6px; background: #111; color: #fff; font-weight: 700; }
    .hint { font-size: 12px; color: #4b5563; margin-top: 8px; max-width: 760px; line-height: 1.45; }
    main { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 10px 0; }
    .label-print-slot {
      position: relative;
      overflow: hidden;
      margin: 0 auto;
      page-break-after: always;
      break-after: page;
      page-break-inside: avoid;
      break-inside: avoid;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .label-print-slot:last-child { page-break-after: auto; }
    body[data-rotate="0"] .label-print-slot,
    body[data-rotate="180"] .label-print-slot {
      width: 60mm;
      height: 40mm;
    }
    body[data-rotate="90"] .label-print-slot,
    body[data-rotate="270"] .label-print-slot {
      width: 40mm;
      height: 60mm;
    }
    .warranty-label {
      position: relative;
      width: 60mm;
      height: 40mm;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      background: #fff;
      border: 0.18mm solid #181818;
      border-radius: 2mm;
      box-shadow: 0 1mm 3.2mm rgba(0, 0, 0, 0.18);
      flex-shrink: 0;
      transform-origin: center center;
    }
    body[data-rotate="0"] .warranty-label { transform: scale(var(--label-print-scale)) rotate(0deg); }
    body[data-rotate="90"] .warranty-label { transform: scale(var(--label-print-scale)) rotate(90deg); }
    body[data-rotate="180"] .warranty-label { transform: scale(var(--label-print-scale)) rotate(180deg); }
    body[data-rotate="270"] .warranty-label { transform: scale(var(--label-print-scale)) rotate(270deg); }
    .label-main {
      flex: 1 1 auto;
      min-height: 0;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 24.2mm;
      grid-template-rows: auto 1fr;
      grid-template-areas:
        "header ."
        "scans qr";
      column-gap: 1.15mm;
      padding: 2.35mm 2.1mm 1.5mm 2.8mm;
      align-items: start;
      position: relative;
    }
    .label-header {
      grid-area: header;
      line-height: 1;
      min-width: 0;
      max-width: 100%;
    }
    .label-scans {
      grid-area: scans;
      min-width: 0;
      max-width: 100%;
      padding-bottom: 0.85mm;
    }
    .headline {
      font-size: 3.72mm;
      line-height: 1;
      font-weight: 900;
      letter-spacing: -0.06mm;
      white-space: nowrap;
    }
    .subhead {
      margin-top: 0.55mm;
      font-size: 2.4mm;
      line-height: 1;
      font-weight: 800;
    }
    .rule { height: 0.22mm; background: #111; margin: 1.35mm 0 1.15mm; opacity: 0.95; }
    .scan-row {
      display: flex;
      align-items: center;
      gap: 1.45mm;
      min-height: 7.5mm;
    }
    .scan-copy {
      min-width: 0;
      flex: 1;
    }
    .scan-icon {
      position: relative;
      flex: 0 0 5.4mm;
      width: 5.4mm;
      height: 5.4mm;
      border-radius: 50%;
      background: #050505;
    }
    .person-icon:before {
      content: "";
      left: 1.66mm;
      top: 1mm;
      width: 2.08mm;
      height: 2.08mm;
    }
    .person-icon:after {
      content: "";
      left: 1.14mm;
      top: 3.24mm;
      width: 3.14mm;
      height: 1.3mm;
    }
    .scan-icon:before {
      content: "";
      position: absolute;
      border-radius: 50%;
      background: #fff;
    }
    .scan-icon:after {
      content: "";
      position: absolute;
      border-radius: 2mm 2mm 0.45mm 0.45mm;
      background: #fff;
    }
    .group-icon span:first-child:before,
    .group-icon span:first-child:after,
    .group-icon span:nth-child(2):before,
    .group-icon span:nth-child(2):after {
      content: "";
      position: absolute;
      background: #fff;
    }
    .group-icon:before,
    .group-icon:after { display: none; }
    .scan-icon.group-icon {
      flex: 0 0 5.4mm;
      width: 5.4mm;
      height: 5.4mm;
    }
    .group-icon span:first-child:before {
      left: 1.05mm;
      top: 1.28mm;
      width: 1.8mm;
      height: 1.8mm;
      border-radius: 50%;
    }
    .group-icon span:first-child:after {
      left: 0.62mm;
      top: 3.38mm;
      width: 3mm;
      height: 1.22mm;
      border-radius: 2mm 2mm 0.45mm 0.45mm;
    }
    .group-icon span:nth-child(2):before {
      left: 2.78mm;
      top: 1.2mm;
      width: 1.75mm;
      height: 1.75mm;
      border-radius: 50%;
    }
    .group-icon span:nth-child(2):after {
      left: 2.42mm;
      top: 3.22mm;
      width: 2.88mm;
      height: 1.22mm;
      border-radius: 2mm 2mm 0.45mm 0.45mm;
    }
    .scan-title {
      font-size: 2.25mm;
      line-height: 1;
      font-weight: 900;
      letter-spacing: 0;
      white-space: nowrap;
    }
    .scan-text {
      margin-top: 0.45mm;
      font-size: 1.62mm;
      line-height: 1.13;
      font-weight: 700;
    }
    .app-install-block {
      position: absolute;
      left: 2.8mm;
      bottom: 1.15mm;
      display: flex;
      align-items: center;
      gap: 1.1mm;
      max-width: 30mm;
      min-width: 0;
    }
    .app-install-qr {
      width: 5.9mm;
      height: 5.9mm;
      flex: 0 0 5.9mm;
      overflow: hidden;
      background: #fff;
    }
    .app-install-qr svg {
      width: 100%;
      height: 100%;
      display: block;
    }
    .app-install-text {
      font-size: 1.55mm;
      line-height: 1;
      font-weight: 800;
      white-space: nowrap;
    }
    .qr-panel {
      grid-area: qr;
      width: 24.2mm;
      min-height: 27mm;
      align-self: center;
      justify-self: end;
      position: relative;
      margin-top: -0.4mm;
    }
    .qr-wrap {
      width: 24.2mm;
      height: 24.2mm;
      border: 0.38mm solid #111;
      border-radius: 1.55mm;
      padding: 0.4mm;
      background: #fff;
      overflow: hidden;
    }
    .qr-wrap svg { width: 100%; height: 100%; display: block; }
    .service-category {
      margin-top: 0.75mm;
      width: 24.2mm;
      font-size: 1.5mm;
      line-height: 1;
      font-weight: 800;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: clip;
    }
    .service-product {
      margin-top: 0.55mm;
      width: 24.2mm;
      font-size: 1.35mm;
      line-height: 1;
      font-weight: 800;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: clip;
    }
    .label-footer {
      flex: 0 0 7.85mm;
      display: flex;
      align-items: center;
      gap: 0.8mm;
      padding: 0 2.8mm;
      background: #050505;
      color: #fff;
      font-weight: 900;
      white-space: nowrap;
    }
    .footer-mark {
      position: relative;
      flex: 0 0 4.6mm;
      width: 4.6mm;
      height: 5.1mm;
      background: #fff;
      border: none;
      border-radius: 1mm 1mm 1.7mm 1.7mm;
      clip-path: polygon(50% 0, 100% 18%, 88% 74%, 50% 100%, 12% 74%, 0 18%);
    }
    .footer-warning {
      font-size: 1.42mm;
      flex: 0 0 auto;
      letter-spacing: -0.03mm;
    }
    .footer-divider {
      height: 4.6mm;
      width: 0.22mm;
      flex: 0 0 0.22mm;
      background: rgba(255, 255, 255, 0.9);
    }
    .footer-brand {
      font-size: 1.22mm;
      flex: 1 1 auto;
      min-width: 0;
      letter-spacing: -0.04mm;
      font-weight: 800;
    }
    .print-meta {
      position: absolute;
      left: 3mm;
      right: 3mm;
      bottom: 7.1mm;
      color: transparent;
      font-size: 1.4mm;
      line-height: 1;
      white-space: nowrap;
      overflow: hidden;
    }
    .download { position: absolute; left: -9999px; }
    .empty-state { padding: 16px; color: #374151; }
    @media print {
      .toolbar { display: none; }
      main { display: block; padding: 0; margin: 0; }
      body[data-rotate="0"] html, body[data-rotate="0"] body,
      body[data-rotate="180"] html, body[data-rotate="180"] body {
        width: 60mm; min-height: 40mm; margin: 0; padding: 0; background: #fff;
      }
      body[data-rotate="90"] html, body[data-rotate="90"] body,
      body[data-rotate="270"] html, body[data-rotate="270"] body {
        width: 40mm; min-height: 60mm; margin: 0; padding: 0; background: #fff;
      }
      .label-print-slot {
        margin: 0;
        page-break-after: always;
        break-after: page;
        page-break-inside: avoid;
        break-inside: avoid;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .label-print-slot:last-child { page-break-after: auto; break-after: auto; }
      body[data-rotate="0"] .label-print-slot,
      body[data-rotate="180"] .label-print-slot { width: 60mm; height: 40mm; }
      body[data-rotate="90"] .label-print-slot,
      body[data-rotate="270"] .label-print-slot { width: 40mm; height: 60mm; }
      .warranty-label {
        margin: 0;
        position: relative;
        width: 60mm;
        height: 40mm;
        box-shadow: none;
        border-radius: 2mm;
        transform-origin: center center;
      }
      body[data-rotate="0"] .warranty-label { transform: scale(var(--label-print-scale)) rotate(0deg); }
      body[data-rotate="90"] .warranty-label { transform: scale(var(--label-print-scale)) rotate(90deg); }
      body[data-rotate="180"] .warranty-label { transform: scale(var(--label-print-scale)) rotate(180deg); }
      body[data-rotate="270"] .warranty-label { transform: scale(var(--label-print-scale)) rotate(270deg); }
    }
  </style>
</head>
<body data-rotate="0">
  <div class="toolbar">
    <div class="toolbar-row">
      <label for="labelRotation">Label rotation</label>
      <select id="labelRotation" aria-label="Label rotation">
        <option value="0" selected>0 deg - Normal (60x40 horizontal)</option>
        <option value="90">90 deg - Clockwise (40x60 vertical)</option>
        <option value="180">180 deg - Upside down</option>
        <option value="270">270 deg - Counter-clockwise</option>
      </select>
      <button id="printBtn" type="button">Print / Save as PDF</button>
    </div>
    <div class="hint" id="rotationHint">0 deg Normal - page 60x40mm. Label as designed (wide). Print Scale 100%, margins none.</div>
  </div>
  <main>${pageHtml || '<p class="empty-state">No QR codes found for this dispatch.</p>'}</main>
  <script>
    (function () {
      var select = document.getElementById("labelRotation");
      var hint = document.getElementById("rotationHint");
      var pageStyle = document.getElementById("pageSizeStyle");
      var hints = {
        "0": "0 deg Normal - page 60x40mm. Label as designed (wide). Print Scale 100%, margins none.",
        "90": "90 deg Clockwise - page 40x60mm. Label rotated right.",
        "180": "180 deg Upside down - page 60x40mm. Label flipped.",
        "270": "270 deg Counter-clockwise - page 40x60mm. Label rotated left."
      };
      function normalizeRotation(value) {
        var num = Number.parseInt(String(value || "0"), 10);
        if (num === 90 || num === 180 || num === 270) return String(num);
        return "0";
      }
      function applyRotation(value) {
        var rotate = normalizeRotation(value);
        document.body.dataset.rotate = rotate;
        if (pageStyle) {
          pageStyle.textContent = (rotate === "90" || rotate === "270")
            ? "@page { size: 40mm 60mm; margin: 0; }"
            : "@page { size: 60mm 40mm; margin: 0; }";
        }
        if (hint) hint.textContent = hints[rotate] || hints["0"];
        try { localStorage.setItem("hitaishi.labelRotate", rotate); } catch (e) {}
      }
      var saved = "";
      try {
        saved = localStorage.getItem("hitaishi.labelRotate")
          || (localStorage.getItem("hitaishi.labelOrient") === "vertical" ? "90" : "0")
          || "";
      } catch (e) {}
      var params = new URLSearchParams(window.location.search);
      var initial = params.get("rotate") || params.get("orient") || saved || "0";
      if (initial === "vertical") initial = "90";
      if (initial === "horizontal") initial = "0";
      if (select) {
        select.value = normalizeRotation(initial);
        applyRotation(select.value);
        select.addEventListener("change", function () { applyRotation(select.value); });
      }
      var printBtn = document.getElementById("printBtn");
      if (printBtn) {
        printBtn.addEventListener("click", function () {
          applyRotation(select ? select.value : "0");
          window.print();
        });
      }
    })();
  </script>
</body>
</html>`;
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

function parseInstallationRequired(value, fallback = false) {
  if (value === undefined || value === null || value === "") {
    return Boolean(fallback);
  }
  if (value === true || value === 1 || value === "1") {
    return true;
  }
  if (value === false || value === 0 || value === "0") {
    return false;
  }
  const normalized = String(value).trim().toLowerCase();
  if (["yes", "true", "required", "y"].includes(normalized)) {
    return true;
  }
  if (["no", "false", "not required", "n"].includes(normalized)) {
    return false;
  }
  return Boolean(fallback);
}

function installationStatusFromRequired(required) {
  return parseInstallationRequired(required) ? "Required" : "Not Required";
}

async function ensureProductsQrSchema() {
  const columns = [
    ["reward_points", "ALTER TABLE products ADD COLUMN reward_points INT UNSIGNED NOT NULL DEFAULT 0 AFTER warranty_months"],
    ["qr_status", "ALTER TABLE products ADD COLUMN qr_status VARCHAR(40) NOT NULL DEFAULT 'Not Printed' AFTER warranty_months"],
    ["qr_payload", "ALTER TABLE products ADD COLUMN qr_payload VARCHAR(255) NULL AFTER qr_status"],
    ["qr_printed_at", "ALTER TABLE products ADD COLUMN qr_printed_at TIMESTAMP NULL AFTER qr_payload"],
    ["qr_locked", "ALTER TABLE products ADD COLUMN qr_locked TINYINT(1) NOT NULL DEFAULT 0 AFTER qr_printed_at"],
    ["installation_required", "ALTER TABLE products ADD COLUMN installation_required TINYINT(1) NOT NULL DEFAULT 0 AFTER warranty_months"],
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

async function ensureDealerRewardsSchema() {
  await query(
    `CREATE TABLE IF NOT EXISTS dealer_reward_transactions (
       id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
       dealer_id CHAR(36) NOT NULL,
       serial_id CHAR(36) NOT NULL,
       warranty_id CHAR(36) NOT NULL,
       points INT UNSIGNED NOT NULL,
       description VARCHAR(255),
       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       UNIQUE KEY uq_dealer_reward_serial (serial_id),
       INDEX idx_dealer_rewards_dealer (dealer_id),
       CONSTRAINT fk_dealer_rewards_dealer FOREIGN KEY (dealer_id) REFERENCES dealers(id) ON DELETE CASCADE,
       CONSTRAINT fk_dealer_rewards_serial FOREIGN KEY (serial_id) REFERENCES serial_numbers(id) ON DELETE CASCADE,
       CONSTRAINT fk_dealer_rewards_warranty FOREIGN KEY (warranty_id) REFERENCES warranties(id) ON DELETE CASCADE
     ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );
  await query(
    `INSERT IGNORE INTO dealer_reward_transactions
     (dealer_id, serial_id, warranty_id, points, description)
     SELECT
       COALESCE(w.dealer_id, s.dealer_id),
       s.id,
       w.id,
       p.reward_points,
       CONCAT('Warranty activated for ', s.serial_no)
     FROM warranties w
     INNER JOIN serial_numbers s ON s.id = w.serial_id
     INNER JOIN products p ON p.id = s.product_id
     WHERE w.customer_id IS NOT NULL
       AND COALESCE(w.dealer_id, s.dealer_id) IS NOT NULL
       AND p.reward_points > 0`
  );
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

function parseSequenceSeed(raw, label, options = {}) {
  const value = cleanString(raw);
  if (!value) {
    if (options.defaultValue !== undefined) {
      const fallback = cleanString(options.defaultValue);
      const fallbackSeed = parseSequenceSeed(fallback || "1", label);
      return {
        ...fallbackSeed,
        useCategoryPrefix: true,
      };
    }
    const err = new Error(`${label} is required.`);
    err.statusCode = 400;
    throw err;
  }
  const match = value.match(/^(.*?)(\d+)$/);
  if (!match) {
    if (options.defaultValue !== undefined) {
      const fallback = cleanString(options.defaultValue);
      const fallbackSeed = parseSequenceSeed(fallback || "1", label);
      return {
        ...fallbackSeed,
        prefix: value,
        useCategoryPrefix: false,
      };
    }
    const err = new Error(`${label} must end with a number (e.g. RO-001).`);
    err.statusCode = 400;
    throw err;
  }
  return {
    prefix: match[1],
    width: match[2].length,
    nextNumber: Number.parseInt(match[2], 10),
    useCategoryPrefix: false,
  };
}

function formatSequenceNumber(prefix, width, number) {
  return `${prefix}${String(number).padStart(width, "0")}`;
}

function categoryPrefixFromName(name) {
  const cleaned = cleanString(name).replace(/[^A-Za-z0-9\s]/g, " ").trim();
  if (!cleaned) {
    return "C-";
  }
  const words = cleaned.split(/\s+/).filter(Boolean);
  const code =
    words.length >= 2
      ? words.map((word) => word[0]).join("").toUpperCase()
      : words[0].toUpperCase().slice(0, 3);
  return `${code.slice(0, 4)}-`;
}

function applyCategorySequencePrefixes(name, model, serial) {
  const categoryPrefix = categoryPrefixFromName(name);
  return {
    model: {
      ...model,
      prefix: model.prefix || (model.useCategoryPrefix ? categoryPrefix : ""),
    },
    serial: {
      ...serial,
      prefix: serial.prefix || (serial.useCategoryPrefix ? categoryPrefix : ""),
    },
  };
}

function parseSequenceSuffix(fullValue, prefix, width) {
  const value = cleanString(fullValue);
  if (!value || !value.startsWith(prefix)) {
    return null;
  }
  const suffix = value.slice(prefix.length);
  if (!/^\d+$/.test(suffix) || suffix.length !== width) {
    return null;
  }
  return Number.parseInt(suffix, 10);
}

async function resolveCategorySequenceNext(category, tx) {
  const run = tx || query;
  const startModel = Number(category.model_start_number ?? category.next_model_number ?? 1);
  const startSerial = Number(category.serial_start_number ?? category.next_serial_number ?? 1);
  const rows = await run(
    `SELECT p.model_no, s.serial_no
     FROM products p
     LEFT JOIN serial_numbers s ON s.product_id = p.id
     WHERE p.category_id = ?`,
    [category.id]
  );
  if (!rows.rowCount) {
    return {
      modelNext: startModel,
      serialNext: startSerial,
      productCount: 0,
    };
  }
  let maxModel = startModel - 1;
  let maxSerial = startSerial - 1;
  rows.rows.forEach((row) => {
    const modelNum = parseSequenceSuffix(row.model_no, category.model_prefix, category.model_number_width);
    const serialNum = parseSequenceSuffix(row.serial_no, category.serial_prefix, category.serial_number_width);
    if (modelNum !== null) {
      maxModel = Math.max(maxModel, modelNum);
    }
    if (serialNum !== null) {
      maxSerial = Math.max(maxSerial, serialNum);
    }
  });
  return {
    modelNext: Math.max(startModel, maxModel + 1),
    serialNext: Math.max(startSerial, maxSerial + 1),
    productCount: rows.rowCount,
  };
}

async function ensureProductCategoriesSchema() {
  await query(
    `CREATE TABLE IF NOT EXISTS product_categories (
       id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
       name VARCHAR(120) NOT NULL UNIQUE,
       model_prefix VARCHAR(100) NOT NULL DEFAULT '',
       model_number_width INT NOT NULL DEFAULT 1,
       model_start_number BIGINT NOT NULL DEFAULT 1,
       next_model_number BIGINT NOT NULL,
       serial_prefix VARCHAR(100) NOT NULL DEFAULT '',
       serial_number_width INT NOT NULL DEFAULT 1,
       serial_start_number BIGINT NOT NULL DEFAULT 1,
       next_serial_number BIGINT NOT NULL,
       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
     ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );
  const categoryColumns = [
    ["model_start_number", "ALTER TABLE product_categories ADD COLUMN model_start_number BIGINT NOT NULL DEFAULT 1 AFTER model_number_width"],
    ["serial_start_number", "ALTER TABLE product_categories ADD COLUMN serial_start_number BIGINT NOT NULL DEFAULT 1 AFTER serial_number_width"],
  ];
  for (const [columnName, alterSql] of categoryColumns) {
    const exists = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'product_categories'
         AND COLUMN_NAME = ?
       LIMIT 1`,
      [columnName]
    );
    if (!exists.rowCount) {
      await query(alterSql);
    }
  }
  const startModelExists = await query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'product_categories'
       AND COLUMN_NAME = 'model_start_number'
     LIMIT 1`
  );
  if (startModelExists.rowCount) {
    await query(
      `UPDATE product_categories
       SET model_start_number = COALESCE(NULLIF(model_start_number, 0), next_model_number),
           serial_start_number = COALESCE(NULLIF(serial_start_number, 0), next_serial_number)
       WHERE model_start_number = 1
         AND serial_start_number = 1
         AND (next_model_number <> 1 OR next_serial_number <> 1)`
    );
  }
  const emptySerialPrefix = await query(
    `SELECT id, name FROM product_categories WHERE TRIM(serial_prefix) = '' OR serial_prefix IS NULL`
  );
  for (const row of emptySerialPrefix.rows) {
    const prefix = categoryPrefixFromName(row.name);
    await query(
      `UPDATE product_categories
       SET serial_prefix = CASE WHEN TRIM(serial_prefix) = '' OR serial_prefix IS NULL THEN ? ELSE serial_prefix END,
           model_prefix = CASE WHEN TRIM(model_prefix) = '' OR model_prefix IS NULL THEN ? ELSE model_prefix END
       WHERE id = ?`,
      [prefix, prefix, row.id]
    );
  }
  const categoryColumn = await query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'products'
       AND COLUMN_NAME = 'category_id'
     LIMIT 1`
  );
  if (!categoryColumn.rowCount) {
    await query("ALTER TABLE products ADD COLUMN category_id CHAR(36) NULL AFTER category");
    await query("ALTER TABLE products ADD INDEX idx_products_category_id (category_id)");
    await query(
      "ALTER TABLE products ADD CONSTRAINT fk_products_category FOREIGN KEY (category_id) REFERENCES product_categories(id) ON DELETE SET NULL"
    );
  }
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

function qrSvg(payload, size = 220, quiet = 4) {
  const qr = new QRCode(-1, QRErrorCorrectLevel.M);
  qr.addData(payload);
  qr.make();
  const count = qr.getModuleCount();
  const quietModules = Math.max(1, Number(quiet) || 4);
  const cell = size / (count + quietModules * 2);
  const total = (count + quietModules * 2) * cell;
  const rects = [];
  for (let row = 0; row < count; row += 1) {
    for (let col = 0; col < count; col += 1) {
      if (qr.isDark(row, col)) {
        rects.push(`<rect x="${(col + quietModules) * cell}" y="${(row + quietModules) * cell}" width="${cell}" height="${cell}"/>`);
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

async function ensureTableColumn(tableName, columnName, ddl) {
  try {
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
  } catch (e) {
    const msg = String(e?.message || e?.sqlMessage || "");
    if (e?.code === "ER_DUP_FIELDNAME" || msg.includes("Duplicate column")) {
      return;
    }
    throw e;
  }
}

async function ensureSerialNumbersSchema() {
  const columns = [
    ["invoice_no", "ALTER TABLE serial_numbers ADD COLUMN invoice_no VARCHAR(120) NULL AFTER serial_no"],
    ["challan_no", "ALTER TABLE serial_numbers ADD COLUMN challan_no VARCHAR(120) NULL AFTER invoice_no"],
    ["batch_no", "ALTER TABLE serial_numbers ADD COLUMN batch_no VARCHAR(120) NULL AFTER challan_no"],
    ["dispatch_date", "ALTER TABLE serial_numbers ADD COLUMN dispatch_date DATE NULL AFTER batch_no"],
    ["qr_payload", "ALTER TABLE serial_numbers ADD COLUMN qr_payload VARCHAR(255) NULL AFTER qr_status"],
    ["qr_printed_at", "ALTER TABLE serial_numbers ADD COLUMN qr_printed_at TIMESTAMP NULL AFTER qr_payload"],
    ["dispatched_at", "ALTER TABLE serial_numbers ADD COLUMN dispatched_at TIMESTAMP NULL AFTER dispatch_status"],
    ["installation_required", "ALTER TABLE serial_numbers ADD COLUMN installation_required TINYINT(1) NOT NULL DEFAULT 0 AFTER dispatched_at"],
    ["replacement_case_id", "ALTER TABLE serial_numbers ADD COLUMN replacement_case_id CHAR(36) NULL AFTER installation_required"],
    ["replacement_for_customer_id", "ALTER TABLE serial_numbers ADD COLUMN replacement_for_customer_id CHAR(36) NULL AFTER replacement_case_id"],
    ["replacement_label", "ALTER TABLE serial_numbers ADD COLUMN replacement_label VARCHAR(255) NULL AFTER replacement_for_customer_id"],
    ["dispatched_customer_id", "ALTER TABLE serial_numbers ADD COLUMN dispatched_customer_id CHAR(36) NULL AFTER dealer_id"],
  ];

  for (const [columnName, ddl] of columns) {
    await ensureTableColumn("serial_numbers", columnName, ddl);
  }
}

async function ensureDealersUserIdSchema() {
  await ensureTableColumn("dealers", "user_id", "ALTER TABLE dealers ADD COLUMN user_id CHAR(36) NULL AFTER id");
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

async function ensureCustomersVillageSchema() {
  await ensureTableColumn("customers", "village", "ALTER TABLE customers ADD COLUMN village VARCHAR(120) NULL AFTER city");
}

async function ensureTasksSchema() {
  const columns = [
    ["completed_at", "ALTER TABLE tasks ADD COLUMN completed_at TIMESTAMP NULL AFTER status"],
    ["resolution_notes", "ALTER TABLE tasks ADD COLUMN resolution_notes TEXT NULL AFTER completed_at"],
    ["assigned_by_role", "ALTER TABLE tasks ADD COLUMN assigned_by_role VARCHAR(80) NULL AFTER payable_amount"],
    ["assigned_by_id", "ALTER TABLE tasks ADD COLUMN assigned_by_id CHAR(36) NULL AFTER assigned_by_role"],
    ["completion_happy_code", "ALTER TABLE tasks ADD COLUMN completion_happy_code VARCHAR(12) NULL AFTER resolution_notes"],
    ["completion_code_sent_at", "ALTER TABLE tasks ADD COLUMN completion_code_sent_at TIMESTAMP NULL AFTER completion_happy_code"],
    ["completion_verified_at", "ALTER TABLE tasks ADD COLUMN completion_verified_at TIMESTAMP NULL AFTER completion_code_sent_at"]
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

function isTaskStatusReassignable(status) {
  const normalized = String(status || "").trim().toLowerCase();
  return ["rejected", "cancelled", "canceled"].includes(normalized);
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

async function ensureWorkTypeCostsSchema() {
  const columns = [
    ["service_charge", "ALTER TABLE work_type_costs ADD COLUMN service_charge DECIMAL(10, 2) NOT NULL DEFAULT 0 AFTER payable_amount"],
    ["visit_charge", "ALTER TABLE work_type_costs ADD COLUMN visit_charge DECIMAL(10, 2) NOT NULL DEFAULT 0 AFTER service_charge"],
    ["tax_amount", "ALTER TABLE work_type_costs ADD COLUMN tax_amount DECIMAL(10, 2) NOT NULL DEFAULT 0 AFTER visit_charge"],
    ["discount_amount", "ALTER TABLE work_type_costs ADD COLUMN discount_amount DECIMAL(10, 2) NOT NULL DEFAULT 0 AFTER tax_amount"],
  ];
  for (const [columnName, ddl] of columns) {
    const found = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'work_type_costs'
         AND COLUMN_NAME = ?
       LIMIT 1`,
      [columnName]
    );
    if (!found.rowCount) {
      await query(ddl);
    }
  }
  await query(
    `UPDATE work_type_costs
     SET service_charge = payable_amount
     WHERE service_charge = 0 AND payable_amount > 0`
  );
}

function resolveWorkTypeCostRule(rows, { productCategory, modelNo, city }) {
  const scoreRule = (row) => {
    const ruleCategory = cleanString(row.product_category);
    const ruleModel = cleanString(row.model_no);
    const ruleCity = cleanString(row.city);
    if (ruleCategory && (!productCategory || ruleCategory.toLowerCase() !== productCategory.toLowerCase())) {
      return -1;
    }
    if (ruleModel && (!modelNo || ruleModel.toLowerCase() !== modelNo.toLowerCase())) {
      return -1;
    }
    if (ruleCity && (!city || ruleCity.toLowerCase() !== city.toLowerCase())) {
      return -1;
    }
    let score = 0;
    if (ruleCategory) score += 4;
    if (ruleModel) score += 2;
    if (ruleCity) score += 1;
    return score;
  };

  let best = null;
  let bestScore = -1;
  for (const row of rows) {
    const score = scoreRule(row);
    if (score > bestScore) {
      bestScore = score;
      best = row;
    }
  }
  if (!best && rows.length) {
    best =
      rows.find((row) => !cleanString(row.product_category) && !cleanString(row.model_no) && !cleanString(row.city)) ||
      rows[0];
  }
  return best;
}

function mapWorkTypeCostCharges(row) {
  const serviceCharge = Number(row?.service_charge ?? 0);
  const visitCharge = Number(row?.visit_charge ?? 0);
  const taxAmount = Number(row?.tax_amount ?? 0);
  const discountAmount = Number(row?.discount_amount ?? 0);
  const payableAmount = Number(row?.payable_amount ?? 0);
  return {
    serviceCharge: serviceCharge > 0 ? serviceCharge : payableAmount,
    visitCharge,
    taxAmount,
    discountAmount,
    payableAmount,
    ruleId: row?.id || null,
  };
}

async function ensureComplaintsSchema() {
  const columns = [
    ["dealer_id", "ALTER TABLE complaints ADD COLUMN dealer_id CHAR(36) NULL AFTER customer_id"],
    ["product_name", "ALTER TABLE complaints ADD COLUMN product_name VARCHAR(160) NULL AFTER priority"],
    ["model_no", "ALTER TABLE complaints ADD COLUMN model_no VARCHAR(120) NULL AFTER product_name"],
    ["warranty_start_date", "ALTER TABLE complaints ADD COLUMN warranty_start_date DATE NULL AFTER model_no"],
    ["warranty_end_date", "ALTER TABLE complaints ADD COLUMN warranty_end_date DATE NULL AFTER warranty_start_date"],
    ["warranty_status", "ALTER TABLE complaints ADD COLUMN warranty_status VARCHAR(60) NULL AFTER warranty_end_date"],
    ["created_by_role", "ALTER TABLE complaints ADD COLUMN created_by_role VARCHAR(40) NOT NULL DEFAULT 'Customer' AFTER status"]
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

async function ensureReplaceReturnSchema() {
  await query(
    `CREATE TABLE IF NOT EXISTS replace_return_cases (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      case_no VARCHAR(80) NOT NULL UNIQUE,
      complaint_id CHAR(36) NOT NULL,
      task_id CHAR(36),
      warranty_id CHAR(36),
      customer_id CHAR(36),
      dealer_id CHAR(36) NOT NULL,
      serial_id CHAR(36),
      action_type VARCHAR(40) NOT NULL,
      problem_details TEXT NOT NULL,
      technician_remarks TEXT,
      status VARCHAR(60) NOT NULL DEFAULT 'Pending Admin Scan',
      qr_status VARCHAR(40) NOT NULL DEFAULT 'Not Printed',
      qr_payload VARCHAR(255),
      qr_printed_at TIMESTAMP NULL,
      admin_scanned_at TIMESTAMP NULL,
      admin_scanned_by CHAR(36),
      replacement_serial_id CHAR(36),
      replacement_dispatched_at TIMESTAMP NULL,
      replacement_dispatched_by CHAR(36),
      requested_exchange_serial_id CHAR(36),
      delivered_to_customer_at TIMESTAMP NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_rr_dealer (dealer_id),
      INDEX idx_rr_status (status),
      INDEX idx_rr_complaint (complaint_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );
  const columns = [
    ["replacement_serial_id", "ALTER TABLE replace_return_cases ADD COLUMN replacement_serial_id CHAR(36) NULL AFTER admin_scanned_by"],
    ["replacement_dispatched_at", "ALTER TABLE replace_return_cases ADD COLUMN replacement_dispatched_at TIMESTAMP NULL AFTER replacement_serial_id"],
    ["replacement_dispatched_by", "ALTER TABLE replace_return_cases ADD COLUMN replacement_dispatched_by CHAR(36) NULL AFTER replacement_dispatched_at"],
    ["requested_exchange_serial_id", "ALTER TABLE replace_return_cases ADD COLUMN requested_exchange_serial_id CHAR(36) NULL AFTER replacement_dispatched_by"],
    ["delivered_to_customer_at", "ALTER TABLE replace_return_cases ADD COLUMN delivered_to_customer_at TIMESTAMP NULL AFTER replacement_dispatched_by"],
  ];
  for (const [columnName, ddl] of columns) {
    await ensureTableColumn("replace_return_cases", columnName, ddl);
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

async function resolveWarrantyId(identifier, runQuery = query) {
  const key = cleanString(identifier);
  if (!key) {
    return null;
  }
  const result = await runQuery(
    "SELECT id FROM warranties WHERE id = ? OR warranty_no = ? LIMIT 1",
    [key, key]
  );
  return result.rowCount ? result.rows[0].id : null;
}

async function resolveTaskId(identifier, runQuery = query) {
  const key = cleanString(identifier);
  if (!key) {
    return null;
  }
  const byId = await runQuery("SELECT id FROM tasks WHERE id = ? LIMIT 1", [key]);
  if (byId.rowCount) {
    return byId.rows[0].id;
  }
  const byTaskNo = await runQuery("SELECT id FROM tasks WHERE task_no = ? LIMIT 1", [key]);
  if (byTaskNo.rowCount) {
    return byTaskNo.rows[0].id;
  }
  const byComplaint = await runQuery(
    `SELECT t.id
     FROM tasks t
     INNER JOIN complaints c ON c.id = t.complaint_id
     WHERE c.complaint_no = ?
     ORDER BY t.created_at DESC
     LIMIT 1`,
    [key]
  );
  return byComplaint.rowCount ? byComplaint.rows[0].id : null;
}

async function resolveInstallationPayable({ productCategory, modelNo, city }) {
  await ensureWorkTypeCostsSchema();
  const result = await query(
    `SELECT *
     FROM work_type_costs
     WHERE LOWER(TRIM(work_type)) = 'installation'
       AND LOWER(TRIM(COALESCE(status, 'Active'))) = 'active'`
  );
  const best = resolveWorkTypeCostRule(result.rows, { productCategory, modelNo, city });
  return Number(best?.payable_amount || 0);
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

async function buildAuthLoginResponse(userRow, role) {
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
    dealer = await ensureDealerProfileForUser(userRow);
  }

  return {
    user: publicUser(userRow),
    customer,
    technician,
    dealer,
  };
}

async function findUserForAuth({ loginId, mobile, email, role }) {
  const lid = cleanString(loginId);
  let rawEmail = cleanString(email).toLowerCase();
  let rawMobile = normalizeLoginMobile(mobile);

  if (lid) {
    if (lid.includes("@")) {
      rawEmail = lid.toLowerCase();
      rawMobile = "";
    } else {
      const digitsOnly = normalizeLoginMobile(lid);
      if (digitsOnly.length >= 10) {
        rawMobile = digitsOnly;
        rawEmail = "";
      } else {
        rawEmail = lid.toLowerCase();
        rawMobile = "";
      }
    }
  }

  if (!role || (!rawEmail && !rawMobile)) {
    const err = new Error("role is required plus login ID: use loginId (email or mobile) or legacy email/mobile fields.");
    err.statusCode = 400;
    throw err;
  }

  const result = rawEmail
    ? await query(
        "SELECT * FROM users WHERE LOWER(TRIM(COALESCE(email,''))) = LOWER(?) AND role = ? LIMIT 1",
        [rawEmail, role]
      )
    : await query(
        `SELECT * FROM users WHERE RIGHT(${sqlNormalizeMobileColumn("mobile")}, 10) = ? AND role = ? LIMIT 1`,
        [rawMobile, role]
      );
  if (!result.rowCount) {
    const err = new Error("User not found");
    err.statusCode = 404;
    throw err;
  }
  return { userRow: result.rows[0], rawEmail, rawMobile };
}

app.post("/auth/login", asyncRoute(async (req, res) => {
  return res.status(410).json({ error: "Password login is disabled. Use mobile OTP login." });
}));

app.post("/auth/request-otp", asyncRoute(async (req, res) => {
  const { role } = req.body;
  const { userRow, rawMobile } = await findUserForAuth(req.body);
  if (!rawMobile) {
    return res.status(400).json({ error: "Enter a mobile number to request OTP." });
  }
  if (String(userRow.status || "Active").toLowerCase() !== "active") {
    return res.status(403).json({ error: "This login account is not active." });
  }

  const otp = String(crypto.randomInt(100000, 1000000));
  const token = crypto.randomUUID();
  for (const [key, value] of loginOtpChallenges.entries()) {
    if (Date.now() > value.expiresAt) {
      loginOtpChallenges.delete(key);
    }
  }
  loginOtpChallenges.set(token, {
    userId: userRow.id,
    role,
    mobile: rawMobile,
    otp,
    attempts: 0,
    expiresAt: Date.now() + LOGIN_OTP_TTL_MS,
  });

  let smsResult;
  try {
    smsResult = await sendLoginOtpSms(rawMobile, otp);
  } catch (err) {
    loginOtpChallenges.delete(token);
    throw err;
  }

  res.json({
    token,
    expiresInSeconds: Math.floor(LOGIN_OTP_TTL_MS / 1000),
    message: smsResult.sent
      ? "OTP sent to registered mobile number."
      : "SMS gateway is not configured. Use development OTP for testing.",
    smsSent: Boolean(smsResult.sent),
    devOtp: smsResult.sent ? undefined : otp,
  });
}));

app.post("/auth/verify-otp", asyncRoute(async (req, res) => {
  const token = cleanString(req.body.token);
  const otp = normalizeMobileValue(req.body.otp);
  const challenge = loginOtpChallenges.get(token);
  if (!token || !challenge) {
    return res.status(400).json({ error: "OTP session expired. Send OTP again." });
  }
  if (Date.now() > challenge.expiresAt) {
    loginOtpChallenges.delete(token);
    return res.status(400).json({ error: "OTP expired. Send OTP again." });
  }
  if (challenge.attempts >= 5) {
    loginOtpChallenges.delete(token);
    return res.status(429).json({ error: "Too many wrong OTP attempts. Send OTP again." });
  }
  if (otp !== challenge.otp) {
    challenge.attempts += 1;
    return res.status(401).json({ error: "Invalid OTP." });
  }

  const result = await query("SELECT * FROM users WHERE id = ? AND role = ? LIMIT 1", [challenge.userId, challenge.role]);
  loginOtpChallenges.delete(token);
  if (!result.rowCount) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json(await buildAuthLoginResponse(result.rows[0], challenge.role));
}));

app.post("/admin/self-sale/request-otp", asyncRoute(async (req, res) => {
  await ensureCustomersVillageSchema();
  const name = cleanString(req.body.name);
  const mobile = normalizeStoredMobile(req.body.mobile, req.body.countryDial);
  const city = cleanString(req.body.city);
  const village = cleanString(req.body.village);
  const pincode = cleanString(req.body.pincode);

  if (!name || !mobile || !city || !village || !pincode) {
    return res.status(400).json({ error: "Customer name, phone number, city, village and pin code are required." });
  }
  const mobileCheck = requireTenDigitMobile(mobile);
  if (!mobileCheck.ok) {
    return res.status(400).json({ error: mobileCheck.error });
  }
  const storedMobile = mobileCheck.national;

  try {
    await ensureUniqueLoginIdentity({ mobile: storedMobile });
  } catch (err) {
    return res.status(err.statusCode || 409).json({ error: err.message || "This mobile number already has a login account." });
  }
  const existingCustomer = await query("SELECT id FROM customers WHERE mobile = ? LIMIT 1", [storedMobile]);
  if (existingCustomer.rowCount) {
    return res.status(409).json({ error: "This mobile number already has a customer profile." });
  }

  const otp = String(crypto.randomInt(100000, 1000000));
  const token = crypto.randomUUID();
  purgeExpiredOtpChallenges(selfSaleOtpChallenges);
  selfSaleOtpChallenges.set(token, {
    payload: { name, mobile: storedMobile, city, village, pincode },
    otp,
    attempts: 0,
    expiresAt: Date.now() + LOGIN_OTP_TTL_MS,
  });

  let smsResult;
  try {
    smsResult = await sendLoginOtpSms(storedMobile, otp);
  } catch (err) {
    selfSaleOtpChallenges.delete(token);
    throw err;
  }

  res.json({
    token,
    expiresInSeconds: Math.floor(LOGIN_OTP_TTL_MS / 1000),
    message: smsResult.sent
      ? "OTP sent to customer mobile number."
      : "SMS gateway is not configured. Use development OTP for testing.",
    smsSent: Boolean(smsResult.sent),
    devOtp: smsResult.sent ? undefined : otp,
  });
}));

app.post("/admin/self-sale/verify-otp", asyncRoute(async (req, res) => {
  await ensureCustomersVillageSchema();
  const token = cleanString(req.body.token);
  const otp = normalizeMobileValue(req.body.otp);
  const challenge = selfSaleOtpChallenges.get(token);
  if (!token || !challenge) {
    return res.status(400).json({ error: "OTP session expired. Send OTP again." });
  }
  if (Date.now() > challenge.expiresAt) {
    selfSaleOtpChallenges.delete(token);
    return res.status(400).json({ error: "OTP expired. Send OTP again." });
  }
  if (challenge.attempts >= 5) {
    selfSaleOtpChallenges.delete(token);
    return res.status(429).json({ error: "Too many wrong OTP attempts. Send OTP again." });
  }
  if (otp !== challenge.otp) {
    challenge.attempts += 1;
    return res.status(401).json({ error: "Invalid OTP." });
  }

  const { name, mobile, city, village, pincode } = challenge.payload;
  const created = await withTransaction(async (run) => {
    await ensureUniqueLoginIdentity({ mobile }, run);
    const existingCustomer = await run("SELECT id FROM customers WHERE mobile = ? LIMIT 1", [mobile]);
    if (existingCustomer.rowCount) {
      const err = new Error("This mobile number already has a customer profile.");
      err.statusCode = 409;
      throw err;
    }

    const userId = crypto.randomUUID();
    const customerId = crypto.randomUUID();
    await run(
      "INSERT INTO users (id, role, name, mobile, email, password_hash, status) VALUES (?, 'Customer', ?, ?, NULL, NULL, 'Active')",
      [userId, name, mobile]
    );
    await run(
      "INSERT INTO customers (id, user_id, name, mobile, address, city, village, state, pincode, created_by_dealer_id) VALUES (?, ?, ?, ?, NULL, ?, ?, NULL, ?, NULL)",
      [customerId, userId, name, mobile, city, village, pincode]
    );

    const userResult = await run("SELECT * FROM users WHERE id = ? LIMIT 1", [userId]);
    const customerResult = await run("SELECT * FROM customers WHERE id = ? LIMIT 1", [customerId]);
    return { user: publicUser(userResult.rows[0]), customer: customerResult.rows[0] };
  });

  selfSaleOtpChallenges.delete(token);
  res.status(201).json({
    ...created,
    message: "Customer mobile verified and self-sale account created.",
  });
}));

app.post("/accounts/customer/request-otp", asyncRoute(async (req, res) => {
  await ensureCustomersVillageSchema();
  const createdByRole = cleanString(req.body.createdByRole);
  const name = cleanString(req.body.name);
  const mobile = normalizeStoredMobile(req.body.mobile, req.body.countryDial);
  const city = cleanString(req.body.city);
  const state = cleanString(req.body.state);
  const pincode = cleanString(req.body.pincode);
  const address = cleanString(req.body.address);
  const village = cleanString(req.body.village);
  const dealerId = cleanString(req.body.dealerId || req.body.dealer_id);

  if (!["Admin", "Dealer", "Front Desk"].includes(createdByRole)) {
    return res.status(403).json({ error: "You are not allowed to create customer login accounts." });
  }
  if (!name || !mobile || !city) {
    return res.status(400).json({ error: "Customer name, mobile number and city are required." });
  }
  const mobileCheck = requireTenDigitMobile(mobile);
  if (!mobileCheck.ok) {
    return res.status(400).json({ error: mobileCheck.error });
  }
  const storedMobile = mobileCheck.national;

  let creatorDealerId = null;
  if (createdByRole === "Dealer") {
    const dealerProfile = await resolveDealerRecord(dealerId);
    if (!dealerProfile) {
      return res.status(400).json({
        error: "Dealer profile is required. Link your login mobile with Dealer Management in Admin.",
      });
    }
    creatorDealerId = dealerProfile.id;
  } else if (createdByRole === "Admin") {
    if (!dealerId) {
      return res.status(400).json({ error: "Select a dealer for this customer account." });
    }
    const dealerProfile = await resolveDealerRecord(dealerId);
    if (!dealerProfile) {
      return res.status(400).json({ error: "Dealer not found." });
    }
    creatorDealerId = dealerProfile.id;
  }

  try {
    await ensureUniqueLoginIdentity({ mobile: storedMobile });
  } catch (err) {
    return res.status(err.statusCode || 409).json({ error: err.message || "This mobile number already has a login account." });
  }
  const existingCustomer = await query("SELECT id FROM customers WHERE mobile = ? LIMIT 1", [storedMobile]);
  if (existingCustomer.rowCount) {
    return res.status(409).json({ error: "This mobile number already has a customer profile." });
  }

  const otp = String(crypto.randomInt(100000, 1000000));
  const token = crypto.randomUUID();
  purgeExpiredOtpChallenges(customerAccountOtpChallenges);
  customerAccountOtpChallenges.set(token, {
    payload: {
      createdByRole,
      dealerId: creatorDealerId,
      name,
      mobile: storedMobile,
      city,
      state: state || null,
      pincode: pincode || null,
      address: address || null,
      village: village || null,
    },
    otp,
    attempts: 0,
    expiresAt: Date.now() + LOGIN_OTP_TTL_MS,
  });

  let smsResult;
  try {
    smsResult = await sendLoginOtpSms(storedMobile, otp);
  } catch (err) {
    customerAccountOtpChallenges.delete(token);
    throw err;
  }

  res.json({
    token,
    expiresInSeconds: Math.floor(LOGIN_OTP_TTL_MS / 1000),
    message: smsResult.sent
      ? "OTP sent to customer mobile number."
      : "SMS gateway is not configured. Use development OTP for testing.",
    smsSent: Boolean(smsResult.sent),
    devOtp: smsResult.sent ? undefined : otp,
  });
}));

app.post("/accounts/customer/verify-otp", asyncRoute(async (req, res) => {
  await ensureCustomersVillageSchema();
  const token = cleanString(req.body.token);
  const otp = normalizeMobileValue(req.body.otp);
  const challenge = customerAccountOtpChallenges.get(token);
  if (!token || !challenge) {
    return res.status(400).json({ error: "OTP session expired. Send OTP again." });
  }
  if (Date.now() > challenge.expiresAt) {
    customerAccountOtpChallenges.delete(token);
    return res.status(400).json({ error: "OTP expired. Send OTP again." });
  }
  if (challenge.attempts >= 5) {
    customerAccountOtpChallenges.delete(token);
    return res.status(429).json({ error: "Too many wrong OTP attempts. Send OTP again." });
  }
  if (otp !== challenge.otp) {
    challenge.attempts += 1;
    return res.status(401).json({ error: "Invalid OTP." });
  }

  const { dealerId, name, mobile, city, state, pincode, address, village } = challenge.payload;
  const created = await withTransaction(async (run) => {
    await ensureUniqueLoginIdentity({ mobile }, run);
    const existingCustomer = await run("SELECT id FROM customers WHERE mobile = ? LIMIT 1", [mobile]);
    if (existingCustomer.rowCount) {
      const err = new Error("This mobile number already has a customer profile.");
      err.statusCode = 409;
      throw err;
    }

    const userId = crypto.randomUUID();
    const customerId = crypto.randomUUID();
    await run(
      "INSERT INTO users (id, role, name, mobile, email, password_hash, status) VALUES (?, 'Customer', ?, ?, NULL, NULL, 'Active')",
      [userId, name, mobile]
    );
    await run(
      "INSERT INTO customers (id, user_id, name, mobile, address, city, village, state, pincode, created_by_dealer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [customerId, userId, name, mobile, address || null, city, village || null, state || null, pincode || null, dealerId || null]
    );

    const userResult = await run("SELECT * FROM users WHERE id = ? LIMIT 1", [userId]);
    const customerResult = await run("SELECT * FROM customers WHERE id = ? LIMIT 1", [customerId]);
    return { user: publicUser(userResult.rows[0]), customer: customerResult.rows[0] };
  });

  customerAccountOtpChallenges.delete(token);
  res.status(201).json({
    ...created,
    message: "Customer mobile verified and login account created.",
  });
}));

async function prepareOtpAccountPayload(body) {
  await ensureTechniciansSchema();
  const cleanRole = cleanString(body.role);
  const cleanCreatedByRole = cleanString(body.createdByRole);
  const cleanName = cleanString(body.name);
  const mobileCheck = requireTenDigitMobile(body.mobile, body.countryDial);
  const cleanEmail = normalizeEmail(body.email) || null;

  if (!accountCreatorRoles.includes(cleanCreatedByRole)) {
    const err = new Error("You are not allowed to create login accounts.");
    err.statusCode = 403;
    throw err;
  }
  if (!accountRoles.includes(cleanRole)) {
    const err = new Error("Select a valid role.");
    err.statusCode = 400;
    throw err;
  }
  if (customerOnlyAccountCreators.includes(cleanCreatedByRole) && cleanRole !== "Customer") {
    const err = new Error("Only customer login accounts can be created for this role.");
    err.statusCode = 403;
    throw err;
  }
  if (cleanCreatedByRole === "Dealer" && !dealerCreatableRoles.includes(cleanRole)) {
    const err = new Error("Dealers can create customer login accounts only.");
    err.statusCode = 403;
    throw err;
  }
  if (cleanCreatedByRole === "Front Desk" && !frontDeskCreatableRoles.includes(cleanRole)) {
    const err = new Error("Front Desk can create customer or technician login accounts only.");
    err.statusCode = 403;
    throw err;
  }
  if (!cleanName || !mobileCheck.ok) {
    const err = new Error(!cleanName ? "Name is required." : mobileCheck.error);
    err.statusCode = 400;
    throw err;
  }

  let creatorDealerId = null;
  const linkToDealerRole = cleanRole === "Customer";
  if (cleanCreatedByRole === "Dealer" && linkToDealerRole) {
    const dealerProfile = await resolveDealerRecord(cleanString(body.dealerId));
    if (!dealerProfile) {
      const err = new Error("Dealer profile is required. Link your login mobile with Dealer Management in Admin.");
      err.statusCode = 400;
      throw err;
    }
    creatorDealerId = dealerProfile.id;
  } else if (cleanCreatedByRole === "Admin" && linkToDealerRole) {
    const dealerProfile = await resolveDealerRecord(cleanString(body.dealerId));
    if (!dealerProfile) {
      const err = new Error("Select a dealer. This customer account will show in that dealer's customer list.");
      err.statusCode = 400;
      throw err;
    }
    creatorDealerId = dealerProfile.id;
  }

  if (cleanRole === "Technician" && !cleanString(body.pincode)) {
    const err = new Error("Technician account ke liye pin code required hai.");
    err.statusCode = 400;
    throw err;
  }

  await ensureUniqueLoginIdentity({ mobile: mobileCheck.national, email: cleanEmail });

  if (cleanRole === "Customer") {
    const existingCustomer = await query("SELECT id FROM customers WHERE mobile = ? LIMIT 1", [mobileCheck.national]);
    if (existingCustomer.rowCount) {
      const err = new Error("This mobile number already has a customer profile.");
      err.statusCode = 409;
      throw err;
    }
  }

  if (cleanRole === "Dealer" && cleanString(body.dealerNo)) {
    const existingDealer = await query("SELECT id FROM dealers WHERE dealer_no = ? LIMIT 1", [cleanString(body.dealerNo)]);
    if (existingDealer.rowCount) {
      const err = new Error("This dealer number already exists.");
      err.statusCode = 409;
      throw err;
    }
  }

  return {
    role: cleanRole,
    createdByRole: cleanCreatedByRole,
    dealerId: creatorDealerId,
    name: cleanName,
    mobile: mobileCheck.national,
    email: cleanEmail,
    status: cleanString(body.status) || "Active",
    city: cleanString(body.city) || null,
    state: cleanString(body.state) || null,
    address: cleanString(body.address) || null,
    pincode: cleanString(body.pincode) || null,
    serviceAreas: cleanString(body.serviceAreas) || null,
    dealerNo: cleanString(body.dealerNo) || null,
    contactPerson: cleanString(body.contactPerson) || null,
  };
}

async function createOtpAccount(payload) {
  return withTransaction(async (run) => {
    await ensureUniqueLoginIdentity({ mobile: payload.mobile, email: payload.email }, run);

    const userId = crypto.randomUUID();
    await run(
      "INSERT INTO users (id, role, name, mobile, email, password_hash, status) VALUES (?, ?, ?, ?, ?, NULL, ?)",
      [userId, payload.role, payload.name, payload.mobile, payload.email, payload.status || "Active"]
    );

    let customer = null;
    let technician = null;
    let dealer = null;

    if (payload.role === "Customer") {
      const customerId = crypto.randomUUID();
      await run(
        "INSERT INTO customers (id, user_id, name, mobile, address, city, state, pincode, created_by_dealer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [customerId, userId, payload.name, payload.mobile, payload.address, payload.city, payload.state, payload.pincode, payload.dealerId]
      );
      const result = await run("SELECT * FROM customers WHERE id = ? LIMIT 1", [customerId]);
      customer = result.rows[0] || null;
    }

    if (payload.role === "Technician") {
      const technicianId = crypto.randomUUID();
      await run(
        "INSERT INTO technicians (id, user_id, name, mobile, city, pincode, service_areas, approval_status, created_by_dealer_id) VALUES (?, ?, ?, ?, ?, ?, ?, 'Approved', ?)",
        [technicianId, userId, payload.name, payload.mobile, payload.city, payload.pincode, payload.serviceAreas, null]
      );
      const result = await run("SELECT * FROM technicians WHERE id = ? LIMIT 1", [technicianId]);
      technician = result.rows[0] || null;
    }

    if (payload.role === "Dealer") {
      await ensureDealersUserIdSchema();
      const finalDealerNo = payload.dealerNo || await getNextDealerNo();
      await run(
        "INSERT INTO dealers (user_id, dealer_no, name, contact_person, mobile, address, city, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [userId, finalDealerNo, payload.name, payload.contactPerson, payload.mobile, payload.address, payload.city, payload.state]
      );
      const result = await run("SELECT * FROM dealers WHERE dealer_no = ? LIMIT 1", [finalDealerNo]);
      dealer = result.rows[0] || null;
    }

    const userResult = await run("SELECT * FROM users WHERE id = ? LIMIT 1", [userId]);
    return { user: publicUser(userResult.rows[0]), customer, technician, dealer };
  });
}

app.post("/accounts/request-otp", asyncRoute(async (req, res) => {
  const payload = await prepareOtpAccountPayload(req.body);
  const otp = String(crypto.randomInt(100000, 1000000));
  const token = crypto.randomUUID();
  purgeExpiredOtpChallenges(accountOtpChallenges);
  accountOtpChallenges.set(token, {
    payload,
    otp,
    attempts: 0,
    expiresAt: Date.now() + LOGIN_OTP_TTL_MS,
  });

  let smsResult;
  try {
    smsResult = await sendLoginOtpSms(payload.mobile, otp);
  } catch (err) {
    accountOtpChallenges.delete(token);
    throw err;
  }

  res.json({
    token,
    expiresInSeconds: Math.floor(LOGIN_OTP_TTL_MS / 1000),
    message: smsResult.sent
      ? `OTP sent to ${payload.role} mobile number.`
      : "SMS gateway is not configured. Use development OTP for testing.",
    smsSent: Boolean(smsResult.sent),
    devOtp: smsResult.sent ? undefined : otp,
  });
}));

app.post("/accounts/verify-otp", asyncRoute(async (req, res) => {
  const token = cleanString(req.body.token);
  const otp = normalizeMobileValue(req.body.otp);
  const challenge = accountOtpChallenges.get(token);
  if (!token || !challenge) {
    return res.status(400).json({ error: "OTP session expired. Send OTP again." });
  }
  if (Date.now() > challenge.expiresAt) {
    accountOtpChallenges.delete(token);
    return res.status(400).json({ error: "OTP expired. Send OTP again." });
  }
  if (challenge.attempts >= 5) {
    accountOtpChallenges.delete(token);
    return res.status(429).json({ error: "Too many wrong OTP attempts. Send OTP again." });
  }
  if (otp !== challenge.otp) {
    challenge.attempts += 1;
    return res.status(401).json({ error: "Invalid OTP." });
  }

  const created = await createOtpAccount(challenge.payload);
  accountOtpChallenges.delete(token);
  res.status(201).json({
    ...created,
    message: `${created.user?.role || "Login"} mobile verified and login account created.`,
  });
}));

/** Customer / Technician: logged-in profile - change login password after verifying old one. */
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

/** Logged-in user profile - read fresh details from database. */
app.get("/auth/profile", asyncRoute(async (req, res) => {
  const userId = cleanString(req.query.userId);
  const role = cleanString(req.query.role);
  if (!userId || !role) {
    return res.status(400).json({ error: "userId and role are required." });
  }
  const result = await query(
    "SELECT id, role, name, mobile, email, status, created_at FROM users WHERE id = ? AND role = ? LIMIT 1",
    [userId, role]
  );
  if (!result.rowCount) {
    return res.status(404).json({ error: "Profile not found." });
  }
  res.json({ user: publicUser(result.rows[0]) });
}));

/** Logged-in user profile - update name, mobile and email in users table. */
app.patch("/auth/profile", asyncRoute(async (req, res) => {
  const userId = cleanString(req.body.userId);
  const role = cleanString(req.body.role);
  const name = cleanString(req.body.name);
  const mobile = normalizeStoredMobile(req.body.mobile, req.body.countryDial);
  const email = normalizeEmail(req.body.email);

  if (!userId || !role) {
    return res.status(400).json({ error: "userId and role are required." });
  }
  if (!name) {
    return res.status(400).json({ error: "Name is required." });
  }
  const mobileCheck = requireTenDigitMobile(mobile);
  if (!mobileCheck.ok) {
    return res.status(400).json({ error: mobileCheck.error });
  }
  if (!email) {
    return res.status(400).json({ error: "Email is required." });
  }

  const existing = await query("SELECT id FROM users WHERE id = ? AND role = ? LIMIT 1", [userId, role]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Profile not found." });
  }

  try {
    await ensureUniqueLoginIdentity({ mobile: mobileCheck.national, email, excludeUserId: userId });
  } catch (err) {
    return res.status(err.statusCode || 409).json({ error: err.message || "This login identity is already used." });
  }

  await query(
    "UPDATE users SET name = ?, mobile = ?, email = ? WHERE id = ? AND role = ?",
    [name, mobileCheck.national, email, userId, role]
  );

  const updated = await query(
    "SELECT id, role, name, mobile, email, status, created_at FROM users WHERE id = ? LIMIT 1",
    [userId]
  );
  res.json({ user: publicUser(updated.rows[0]), message: "Profile updated." });
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
  await ensureReplaceReturnSchema();
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
    pendingPayable,
    pendingReplaceReturn
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
    query(
      "SELECT COUNT(*) AS total FROM quotations WHERE status IN ('Pending Front Desk Review', 'Pending Admin Approval')"
    ),
    query("SELECT COALESCE(SUM(amount), 0) AS total FROM payments WHERE status = 'Pending'"),
    query(
      `SELECT COUNT(*) AS total FROM replace_return_cases WHERE status = 'Pending Admin Scan'`
    ).catch(() => ({ rows: [{ total: 0 }] }))
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
      pendingPayable: Number(pendingPayable.rows?.[0]?.total || 0),
      pendingReplaceReturn: count(pendingReplaceReturn)
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
  const cleanMobile = normalizeStoredMobile(mobile, req.body.countryDial);
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
    return res.status(403).json({ error: "Dealers can create customer login accounts only." });
  }
  if (cleanCreatedByRole === "Front Desk" && !frontDeskCreatableRoles.includes(cleanRole)) {
    return res.status(403).json({ error: "Front Desk can create customer or technician login accounts only." });
  }

  let creatorDealerId = null;
  const linkToDealerRole = cleanRole === "Customer";
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
        error: "Select a dealer. This customer account will show in that dealer's customer list.",
      });
    }
    creatorDealerId = dealerProfile.id;
  }

  if (!accountRoles.includes(cleanRole)) {
    return res.status(400).json({ error: "Select a valid role." });
  }
  if (cleanRole === "Customer") {
    return res.status(400).json({
      error: "Customer login must be created with mobile OTP verification. Use Send OTP flow.",
    });
  }
  if (!cleanName || !cleanMobile || !cleanEmail || !cleanPassword) {
    return res.status(400).json({ error: "name, mobile, email, and password are required." });
  }
  if (cleanMobile.length !== 10) {
    return res.status(400).json({ error: "Enter a valid 10 digit mobile number." });
  }
  if (cleanPassword.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters." });
  }
  if (cleanRole === "Technician" && !cleanString(pincode)) {
    return res.status(400).json({ error: "Technician account ke liye pin code required hai." });
  }

  try {
    await ensureUniqueLoginIdentity({ mobile: cleanMobile, email: cleanEmail });
  } catch (err) {
    return res.status(err.statusCode || 409).json({ error: err.message || "This login identity is already used." });
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
    const technicianApproval =
      cleanCreatedByRole === "Dealer" || cleanCreatedByRole === "Admin" ? "Approved" : "Pending";
    await query(
      "INSERT INTO technicians (user_id, name, mobile, city, pincode, service_areas, approval_status, created_by_dealer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [userId, cleanName, cleanMobile, city || null, cleanPincode, serviceAreas || null, technicianApproval, null]
    );
    const result = await query("SELECT * FROM technicians WHERE user_id = ? LIMIT 1", [userId]);
    technician = result.rows[0] || null;
  }

  if (cleanRole === "Dealer") {
    await ensureDealersUserIdSchema();
    const finalDealerNo = cleanString(dealerNo) || await getNextDealerNo();
    const storedMobile = normalizeLoginMobile(cleanMobile) || cleanMobile;
    await query(
      "INSERT INTO dealers (user_id, dealer_no, name, contact_person, mobile, address, city, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [userId, finalDealerNo, cleanName, contactPerson || null, storedMobile, address || null, city || null, state || null]
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

app.post("/customers", asyncRoute(async (_req, res) => {
  return res.status(403).json({
    error: "Self-registration is disabled. Ask your dealer or admin to create your customer account.",
  });
}));

app.get("/customers", asyncRoute(async (req, res) => {
  let hasVillageColumn = true;
  try {
    await ensureCustomersVillageSchema();
  } catch (err) {
    console.warn("customers.village migration skipped:", err?.message || err);
    hasVillageColumn = false;
  }
  await ensureDealerCreatedBySchema();
  await syncCustomerProfilesFromUsers();
  const villageSelect = hasVillageColumn ? "c.village" : "NULL AS village";
  const villageGroup = hasVillageColumn ? "c.village," : "";
  const selfSaleOnly =
    String(req.query.selfSale || req.query.self_sale || "").toLowerCase() === "true" ||
    String(req.query.type || "").toLowerCase() === "self-sale";
  const selfSaleClause = selfSaleOnly ? "WHERE c.created_by_dealer_id IS NULL" : "";
  const result = await query(
    `SELECT
       c.id,
       c.user_id,
       c.name,
       c.mobile,
       c.address,
       c.city,
       ${villageSelect},
       c.state,
       c.pincode,
       c.created_by_dealer_id,
       c.created_at,
       u.email,
       COALESCE(u.status, 'Active') AS user_status,
       COUNT(DISTINCT w.id) AS warranties,
       COUNT(DISTINCT comp.id) AS complaints
     FROM customers c
     LEFT JOIN users u ON u.id = c.user_id
     LEFT JOIN warranties w ON w.customer_id = c.id
     LEFT JOIN complaints comp ON comp.customer_id = c.id
     ${selfSaleClause}
     GROUP BY
       c.id,
       c.user_id,
       c.name,
       c.mobile,
       c.address,
       c.city,
       ${villageGroup}
       c.state,
       c.pincode,
       c.created_by_dealer_id,
       c.created_at,
       u.email,
       u.status
     ORDER BY c.created_at DESC
     LIMIT 800`
  );
  res.json({ customers: result.rows });
}));

app.get("/customers/by-mobile/:mobile", asyncRoute(async (req, res) => {
  let hasVillageColumn = true;
  try {
    await ensureCustomersVillageSchema();
  } catch (err) {
    console.warn("customers.village migration skipped:", err?.message || err);
    hasVillageColumn = false;
  }
  const villageSelect = hasVillageColumn ? "c.village" : "NULL AS village";
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
       ${villageSelect},
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

app.delete("/customers/:id", asyncRoute(async (req, res) => {
  const customerId = cleanString(req.params.id);
  if (!customerId) {
    return res.status(400).json({ error: "Customer id is required." });
  }

  const existing = await query("SELECT * FROM customers WHERE id = ? LIMIT 1", [customerId]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Customer not found." });
  }
  const customer = existing.rows[0];

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
      users: 0,
    };
    const add = (key, result) => {
      counts[key] += Number(result?.affectedRows || 0);
    };
    const placeholders = (items) => items.map(() => "?").join(",");
    const idsFrom = (result) => result.rows.map((row) => row.id).filter(Boolean);
    const deleteAttachments = async (entityType, ids) => {
      if (!ids.length) return;
      try {
        add(
          "attachments",
          await tx(
            `DELETE FROM attachments WHERE entity_type = ? AND entity_id IN (${placeholders(ids)})`,
            [entityType, ...ids]
          )
        );
      } catch (err) {
        if (err?.code !== "ER_NO_SUCH_TABLE") {
          throw err;
        }
      }
    };

    const customerIds = [customerId];
    const warranties = await tx(`SELECT id FROM warranties WHERE customer_id IN (${placeholders(customerIds)})`, customerIds);
    const warrantyIds = idsFrom(warranties);
    const complaints = await tx(`SELECT id FROM complaints WHERE customer_id IN (${placeholders(customerIds)})`, customerIds);
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

    if (customer.user_id) {
      const userDelete = await tx("DELETE FROM users WHERE id = ? AND role = 'Customer'", [customer.user_id]);
      counts.users = userDelete.affectedRows;
    }
    return counts;
  });

  res.json({
    ok: true,
    deletedCustomer: customer,
    deleted,
    message: "Customer and linked records deleted.",
  });
}));

app.post("/technicians", asyncRoute(async (_req, res) => {
  return res.status(403).json({
    error: "Self-registration is disabled. Ask your dealer or admin to create your technician account.",
  });
}));

app.get("/technicians", asyncRoute(async (req, res) => {
  await ensureFeedbackSchema();
  const status = cleanString(req.query.status);
  const dealerId = cleanString(req.query.dealerId || req.query.dealer_id);
  const allowed = ["Pending", "Approved", "Rejected"];
  const clauses = [];
  const params = [];
  if (allowed.includes(status)) {
    clauses.push("t.approval_status = ?");
    params.push(status);
  }
  if (dealerId) {
    clauses.push("t.created_by_dealer_id = ?");
    params.push(dealerId);
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const result = await query(
    `SELECT
       t.*,
       u.email,
       u.status AS user_status,
       d.name AS dealer_name,
       d.dealer_no AS dealer_no,
       (SELECT COUNT(*) FROM feedback f WHERE f.technician_id = t.id) AS review_count,
       (SELECT ROUND(AVG(f.rating), 2) FROM feedback f WHERE f.technician_id = t.id) AS avg_rating
     FROM technicians t
     LEFT JOIN users u ON u.id = t.user_id
     LEFT JOIN dealers d ON d.id = t.created_by_dealer_id
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

  const existing = await query(
    "SELECT id, user_id, created_by_dealer_id FROM technicians WHERE id = ? LIMIT 1",
    [technicianId]
  );
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
    `SELECT t.*, u.email, u.status AS user_status, d.name AS dealer_name, d.dealer_no AS dealer_no
     FROM technicians t
     LEFT JOIN users u ON u.id = t.user_id
     LEFT JOIN dealers d ON d.id = t.created_by_dealer_id
     WHERE t.id = ?
     LIMIT 1`,
    [technicianId]
  );
  res.json({ technician: result.rows[0] });
}));

app.patch("/technicians/:id/dealer", asyncRoute(async (req, res) => {
  res.status(410).json({
    error: "Technicians are not assigned to dealers anymore. Create/approve them by pin code and service area.",
  });
}));

async function ensurePaymentsSchema() {
  await query(
    `CREATE TABLE IF NOT EXISTS payments (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      technician_id CHAR(36),
      task_id CHAR(36),
      amount DECIMAL(10, 2) NOT NULL,
      status VARCHAR(40) NOT NULL DEFAULT 'Pending',
      paid_at TIMESTAMP NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_payments_technician FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE CASCADE,
      CONSTRAINT fk_payments_task FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
  );
  const columns = [
    ["payment_mode", "ALTER TABLE payments ADD COLUMN payment_mode VARCHAR(40) NULL AFTER paid_at"],
    ["transaction_ref", "ALTER TABLE payments ADD COLUMN transaction_ref VARCHAR(120) NULL AFTER payment_mode"],
    ["admin_remarks", "ALTER TABLE payments ADD COLUMN admin_remarks TEXT NULL AFTER transaction_ref"],
  ];
  for (const [columnName, ddl] of columns) {
    const found = await query(
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'payments'
         AND COLUMN_NAME = ?
       LIMIT 1`,
      [columnName]
    );
    if (!found.rowCount) {
      await query(ddl);
    }
  }
}

const PAYMENT_LEDGER_TASK_JOIN = `
     FROM tasks t
     LEFT JOIN complaints c ON c.id = t.complaint_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN payments pay ON pay.task_id = t.id`;

async function syncCompletedTaskPayments(technicianId = null) {
  const params = [];
  let techFilter = "";
  if (technicianId) {
    techFilter = "AND t.technician_id = ?";
    params.push(technicianId);
  }
  await query(
    `INSERT INTO payments (technician_id, task_id, amount, status)
     SELECT t.technician_id, t.id, COALESCE(t.payable_amount, 0), 'Pending'
     FROM tasks t
     WHERE t.technician_id IS NOT NULL
       AND LOWER(TRIM(COALESCE(t.status, ''))) IN ('completed', 'closed')
       AND NOT EXISTS (SELECT 1 FROM payments p WHERE p.task_id = t.id)
       ${techFilter}`,
    params
  );
}

async function ensurePaymentForCompletedTask(taskId, tx) {
  const taskResult = await tx(
    "SELECT technician_id, payable_amount FROM tasks WHERE id = ? LIMIT 1",
    [taskId]
  );
  if (!taskResult.rowCount || !taskResult.rows[0].technician_id) {
    return;
  }
  const existing = await tx("SELECT id FROM payments WHERE task_id = ? LIMIT 1", [taskId]);
  if (existing.rowCount) {
    return;
  }
  const amount = Number(taskResult.rows[0].payable_amount || 0);
  await tx(
    "INSERT INTO payments (technician_id, task_id, amount, status) VALUES (?, ?, ?, 'Pending')",
    [taskResult.rows[0].technician_id, taskId, Number.isFinite(amount) ? amount : 0]
  );
}

app.get("/payments/dashboard", asyncRoute(async (req, res) => {
  await ensurePaymentsSchema();
  const month =
    cleanString(req.query.month || req.query.paymentMonth) ||
    new Date().toISOString().slice(0, 7);

  await syncCompletedTaskPayments();

  const statsRows = await query(
    `SELECT
       COALESCE(SUM(COALESCE(pay.amount, t.payable_amount, 0)), 0) AS total_payable,
       COALESCE(SUM(
         CASE WHEN LOWER(COALESCE(pay.status, 'Pending')) = 'paid'
         THEN COALESCE(pay.amount, t.payable_amount, 0) ELSE 0 END
       ), 0) AS paid_amount,
       COUNT(DISTINCT CASE
         WHEN LOWER(COALESCE(pay.status, 'Pending')) <> 'paid' THEN t.technician_id
       END) AS technicians_pending,
       COALESCE(SUM(
         CASE WHEN LOWER(COALESCE(pay.status, 'Pending')) <> 'paid' THEN 1 ELSE 0 END
       ), 0) AS tasks_on_hold
     ${PAYMENT_LEDGER_TASK_JOIN}
     WHERE LOWER(TRIM(COALESCE(t.status, ''))) IN ('completed', 'closed')
       AND DATE_FORMAT(COALESCE(t.completed_at, t.created_at), '%Y-%m') = ?`,
    [month]
  );
  const row = statsRows.rows[0] || {};
  const totalPayable = Number(row.total_payable || 0);
  const paidAmount = Number(row.paid_amount || 0);

  res.json({
    month,
    summary: {
      totalPayable,
      paidAmount,
      pendingAmount: Math.max(0, totalPayable - paidAmount),
      techniciansPendingPayment: Number(row.technicians_pending || 0),
      tasksOnHold: Number(row.tasks_on_hold || 0),
    },
  });
}));

app.get("/technicians/:id/payment-ledger", asyncRoute(async (req, res) => {
  await ensurePaymentsSchema();
  const technicianId = cleanString(req.params.id);
  const month = cleanString(req.query.month || req.query.paymentMonth);
  const existing = await query("SELECT id, name FROM technicians WHERE id = ? LIMIT 1", [technicianId]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Technician not found." });
  }

  await syncCompletedTaskPayments(technicianId);

  const where = ["t.technician_id = ?", "LOWER(TRIM(COALESCE(t.status, ''))) IN ('completed', 'closed')"];
  const params = [technicianId];
  if (month && month !== "All") {
    where.push("DATE_FORMAT(COALESCE(t.completed_at, t.created_at), '%Y-%m') = ?");
    params.push(month);
  }

  const entries = await query(
    `SELECT
       t.id AS task_id,
       t.task_no,
       t.work_type,
       t.status AS task_status,
       t.payable_amount,
       t.completed_at,
       t.created_at,
       c.complaint_no,
       cust.name AS customer_name,
       pay.id AS payment_id,
       COALESCE(pay.status, 'Pending') AS payment_status,
       COALESCE(pay.amount, t.payable_amount, 0) AS payment_amount,
       pay.paid_at
     ${PAYMENT_LEDGER_TASK_JOIN}
     WHERE ${where.join(" AND ")}
     ORDER BY COALESCE(t.completed_at, t.created_at) DESC
     LIMIT 500`,
    params
  );

  const summaryRows = await query(
    `SELECT
       COUNT(*) AS tasks_completed,
       COALESCE(SUM(COALESCE(pay.amount, t.payable_amount, 0)), 0) AS total_payable,
       COALESCE(SUM(
         CASE WHEN LOWER(COALESCE(pay.status, 'Pending')) = 'paid'
         THEN COALESCE(pay.amount, t.payable_amount, 0) ELSE 0 END
       ), 0) AS paid_amount
     ${PAYMENT_LEDGER_TASK_JOIN}
     WHERE ${where.join(" AND ")}`,
    params
  );
  const summaryRow = summaryRows.rows[0] || {};
  const totalPayable = Number(summaryRow.total_payable || 0);
  const paidAmount = Number(summaryRow.paid_amount || 0);

  res.json({
    technician: existing.rows[0],
    month: month || "All",
    summary: {
      tasksCompleted: Number(summaryRow.tasks_completed || 0),
      totalPayable,
      paidAmount,
      pendingBalance: Math.max(0, totalPayable - paidAmount),
    },
    entries: entries.rows,
  });
}));

app.post("/payments/settle", asyncRoute(async (req, res) => {
  await ensurePaymentsSchema();
  const requesterRole = cleanString(req.body.requesterRole);
  if (requesterRole !== "Admin") {
    return res.status(403).json({ error: "Only Admin can settle technician payments." });
  }

  const technicianId = cleanString(req.body.technicianId);
  const month = cleanString(req.body.month || req.body.paymentMonth);
  const paymentDate = cleanString(req.body.paymentDate || req.body.paidAt);
  const paymentMode = cleanString(req.body.paymentMode || req.body.payment_mode) || "UPI";
  const transactionRef = cleanString(req.body.transactionRef || req.body.transactionId || req.body.utr);
  const adminRemarks = cleanString(req.body.adminRemarks || req.body.remarks);
  const receiptNote = cleanString(req.body.receiptNote || req.body.receiptReference);

  if (!technicianId) {
    return res.status(400).json({ error: "Technician is required." });
  }
  if (!month || month === "All") {
    return res.status(400).json({ error: "Payment month is required." });
  }

  const tech = await query("SELECT id, name FROM technicians WHERE id = ? LIMIT 1", [technicianId]);
  if (!tech.rowCount) {
    return res.status(404).json({ error: "Technician not found." });
  }

  await syncCompletedTaskPayments(technicianId);

  const pendingRows = await query(
    `SELECT pay.id
     ${PAYMENT_LEDGER_TASK_JOIN}
     WHERE t.technician_id = ?
       AND LOWER(TRIM(COALESCE(t.status, ''))) IN ('completed', 'closed')
       AND DATE_FORMAT(COALESCE(t.completed_at, t.created_at), '%Y-%m') = ?
       AND LOWER(COALESCE(pay.status, 'Pending')) <> 'paid'`,
    [technicianId, month]
  );

  if (!pendingRows.rowCount) {
    return res.status(400).json({ error: "No pending payments found for this technician and month." });
  }

  const paidAtSql = paymentDate ? "?" : "CURRENT_TIMESTAMP";
  const paidAtParams = paymentDate ? [paymentDate] : [];
  const remarksParts = [adminRemarks, receiptNote ? `Receipt: ${receiptNote}` : ""].filter(Boolean);
  const combinedRemarks = remarksParts.join(" | ") || null;

  for (const row of pendingRows.rows) {
    await query(
      `UPDATE payments
       SET status = 'Paid',
           paid_at = ${paidAtSql},
           payment_mode = ?,
           transaction_ref = ?,
           admin_remarks = ?
       WHERE id = ?`,
      [...paidAtParams, paymentMode, transactionRef || null, combinedRemarks, row.id]
    );
  }

  res.json({
    message: `${pendingRows.rowCount} payment record(s) marked as paid and settled.`,
    technician: tech.rows[0],
    month,
    settledCount: pendingRows.rowCount,
  });
}));

app.patch("/payments/:id", asyncRoute(async (req, res) => {
  await ensurePaymentsSchema();
  const paymentId = cleanString(req.params.id);
  const requesterRole = cleanString(req.body.requesterRole);
  const status = cleanString(req.body.status);
  const paymentMode = cleanString(req.body.paymentMode || req.body.payment_mode);
  const transactionRef = cleanString(req.body.transactionRef || req.body.transactionId);
  const adminRemarks = cleanString(req.body.adminRemarks || req.body.remarks);
  const paymentDate = cleanString(req.body.paymentDate || req.body.paidAt);
  if (requesterRole !== "Admin") {
    return res.status(403).json({ error: "Only Admin can update payment records." });
  }
  if (!["Pending", "Paid"].includes(status)) {
    return res.status(400).json({ error: "Status must be Pending or Paid." });
  }

  const existing = await query("SELECT id FROM payments WHERE id = ? LIMIT 1", [paymentId]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Payment record not found." });
  }

  if (status === "Paid") {
    const paidAtSql = paymentDate ? "?" : "COALESCE(paid_at, CURRENT_TIMESTAMP)";
    const params = paymentDate
      ? [paymentMode || null, transactionRef || null, adminRemarks || null, paymentDate, paymentId]
      : [paymentMode || null, transactionRef || null, adminRemarks || null, paymentId];
    await query(
      `UPDATE payments
       SET status = 'Paid',
           payment_mode = COALESCE(?, payment_mode),
           transaction_ref = COALESCE(?, transaction_ref),
           admin_remarks = COALESCE(?, admin_remarks),
           paid_at = ${paidAtSql}
       WHERE id = ?`,
      params
    );
  } else {
    await query(
      "UPDATE payments SET status = 'Pending', paid_at = NULL, payment_mode = NULL, transaction_ref = NULL WHERE id = ?",
      [paymentId]
    );
  }

  const result = await query("SELECT * FROM payments WHERE id = ? LIMIT 1", [paymentId]);
  res.json({ payment: result.rows[0] });
}));

app.get("/dealers", asyncRoute(async (req, res) => {
  await ensureDealersUserIdSchema();
  const includeStats = ["1", "true", "yes"].includes(String(req.query.includeStats || "").toLowerCase());
  const usersResult = await query(
    "SELECT * FROM users WHERE role = 'Dealer' ORDER BY created_at DESC LIMIT 800"
  );
  const dealers = [];
  const seenDealerIds = new Set();

  for (const userRow of usersResult.rows) {
    const dealer = await ensureDealerProfileForUser(userRow);
    if (!dealer?.id) {
      continue;
    }
    seenDealerIds.add(String(dealer.id));
    const entry = {
      id: dealer.id,
      user_id: userRow.id,
      dealer_no: dealer.dealer_no,
      name: dealer.name || userRow.name,
      contact_person: dealer.contact_person || userRow.name,
      mobile: dealer.mobile || userRow.mobile,
      address: dealer.address,
      city: dealer.city,
      state: dealer.state,
      status: dealer.status || userRow.status || "Active",
      created_at: dealer.created_at || userRow.created_at,
    };
    if (includeStats) {
      try {
        entry.stats = await getDealerDashboardStats(dealer.id);
      } catch {
        entry.stats = null;
      }
    }
    dealers.push(entry);
  }

  const orphanResult = await query(
    `SELECT d.*
     FROM dealers d
     LEFT JOIN users u ON u.id = d.user_id AND u.role = 'Dealer'
     WHERE u.id IS NULL
       AND NOT EXISTS (
         SELECT 1
         FROM users u2
         WHERE u2.role = 'Dealer'
           AND (
             u2.id = d.user_id
             OR RIGHT(${sqlNormalizeMobileColumn("u2.mobile")}, 10) = RIGHT(${sqlNormalizeMobileColumn("d.mobile")}, 10)
           )
       )
     ORDER BY d.created_at DESC
     LIMIT 200`
  );
  for (const dealer of orphanResult.rows) {
    if (!dealer?.id || seenDealerIds.has(String(dealer.id))) {
      continue;
    }
    const entry = {
      id: dealer.id,
      user_id: dealer.user_id || null,
      dealer_no: dealer.dealer_no,
      name: dealer.name,
      contact_person: dealer.contact_person,
      mobile: dealer.mobile,
      address: dealer.address,
      city: dealer.city,
      state: dealer.state,
      status: dealer.status || "Active",
      created_at: dealer.created_at,
    };
    if (includeStats) {
      try {
        entry.stats = await getDealerDashboardStats(dealer.id);
      } catch {
        entry.stats = null;
      }
    }
    dealers.push(entry);
  }

  dealers.sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
  res.json({ dealers });
}));

app.post("/dealers/relink-login", asyncRoute(async (req, res) => {
  await ensureDealersUserIdSchema();
  const loginMobile = normalizeLoginMobile(req.body.loginMobile || req.body.mobile);
  const userName = cleanString(req.body.name || req.body.userName);
  const dealerNo = normalizeDealerNoInput(req.body.dealerNo || req.body.dealer_no || req.body.dealerNumber);

  let userRow = null;
  if (loginMobile.length === 10) {
    const userResult = await query(
      `SELECT * FROM users WHERE role = 'Dealer' AND RIGHT(${sqlNormalizeMobileColumn("mobile")}, 10) = ? LIMIT 1`,
      [loginMobile]
    );
    userRow = userResult.rowCount ? userResult.rows[0] : null;
  }
  if (!userRow && userName) {
    const userResult = await query(
      "SELECT * FROM users WHERE role = 'Dealer' AND LOWER(TRIM(name)) = LOWER(?) LIMIT 1",
      [userName]
    );
    userRow = userResult.rowCount ? userResult.rows[0] : null;
  }
  if (!userRow) {
    return res.status(404).json({ error: "Dealer login not found." });
  }
  if (!dealerNo) {
    return res.status(400).json({ error: "dealerNo is required (e.g. 1 or DLR000001)." });
  }

  const targetResult = await query(
    "SELECT * FROM dealers WHERE LOWER(TRIM(dealer_no)) = LOWER(?) LIMIT 1",
    [dealerNo]
  );
  if (!targetResult.rowCount) {
    return res.status(404).json({ error: `Dealer profile ${dealerNo} not found.` });
  }

  const dealer = await relinkDealerLoginToTarget(userRow, targetResult.rows[0]);
  if (!dealer) {
    return res.status(500).json({ error: "Could not link dealer login." });
  }
  res.json({
    dealer,
    message: `Dealer login linked to ${dealer.dealer_no}.`,
  });
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
        "Dealer profile not linked. In Admin -> Dealer Management, use the same mobile number as this login account.",
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
  const queue = cleanString(req.query.queue);
  const clauses = [];
  const params = [];
  if (queue === "customer_decision") {
    clauses.push("q.status IN ('Accepted by Customer', 'Rejected by Customer')");
    clauses.push("(q.frontdesk_instruction IS NULL OR q.frontdesk_instruction = '')");
  } else if (queue === "frontdesk_review" || status === "Pending Front Desk Review") {
    clauses.push("q.status IN ('Pending Front Desk Review', 'Pending Admin Approval')");
  } else if (status) {
    clauses.push("q.status = ?");
    params.push(status);
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const result = await query(
    `SELECT
       q.*,
       c.complaint_no,
       c.customer_id,
       COALESCE(c.warranty_status, w.status) AS warranty_status,
       COALESCE(c.warranty_end_date, w.expiry_date) AS warranty_expiry,
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

app.get("/notifications", asyncRoute(async (req, res) => {
  await ensureNotificationsSchema();
  await purgeExpiredNotifications();
  const customerId = cleanString(req.query.customerId || req.query.customer_id);
  const userId = cleanString(req.query.userId || req.query.user_id);
  const identityWhere = [];
  const params = [];
  if (customerId) {
    identityWhere.push("customer_id = ?");
    params.push(customerId);
  }
  if (userId) {
    identityWhere.push("user_id = ?");
    params.push(userId);
  }
  if (!identityWhere.length) {
    return res.json({ notifications: [] });
  }
  const where = [
    `(${identityWhere.join(" OR ")})`,
    `created_at >= DATE_SUB(NOW(), INTERVAL ${NOTIFICATION_TTL_HOURS} HOUR)`,
  ];
  const result = await query(
    `SELECT *
     FROM notifications
     WHERE ${where.join(" AND ")}
     ORDER BY created_at DESC
     LIMIT 100`,
    params
  );
  res.json({ notifications: result.rows });
}));

app.post("/push-tokens", asyncRoute(async (req, res) => {
  await ensurePushTokensSchema();
  const token = cleanString(req.body.token);
  const userId = cleanString(req.body.userId || req.body.user_id) || null;
  const customerId = cleanString(req.body.customerId || req.body.customer_id) || null;
  const role = cleanString(req.body.role) || null;
  const platform = cleanString(req.body.platform) || null;
  if (!token || !token.startsWith("ExponentPushToken[")) {
    return res.status(400).json({ error: "Valid Expo push token is required." });
  }
  if (!userId && !customerId && !role) {
    return res.status(400).json({ error: "userId, customerId or role is required." });
  }
  await query(
    `INSERT INTO push_tokens (token, user_id, customer_id, role, platform)
     VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       user_id = VALUES(user_id),
       customer_id = VALUES(customer_id),
       role = VALUES(role),
       platform = VALUES(platform),
       last_seen_at = CURRENT_TIMESTAMP`,
    [token, userId, customerId, role, platform]
  );
  res.json({ ok: true });
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
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
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
  await ensureWorkflowAuditSchema();
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
     WHERE complaint_id = ? AND status IN ('Pending Customer Approval', 'Pending Admin Approval', 'Pending Front Desk Review')
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
  const hasSentToFdCol = await query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'quotations'
       AND COLUMN_NAME = 'sent_to_frontdesk_at'
     LIMIT 1`
  );
  if (hasSentToFdCol.rowCount) {
    await query(
      `INSERT INTO quotations
       (quotation_no, complaint_id, technician_id, spare_part_amount, service_charge, visit_charge, tax_amount, discount_amount, total_amount, technician_remarks, status, sent_to_frontdesk_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending Front Desk Review', NOW())`,
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
  } else {
    await query(
      `INSERT INTO quotations
       (quotation_no, complaint_id, technician_id, spare_part_amount, service_charge, visit_charge, tax_amount, discount_amount, total_amount, technician_remarks, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending Front Desk Review')`,
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
  }

  await withTransaction(async (tx) => {
    await tx("UPDATE complaints SET status = ? WHERE id = ?", ["Quotation Review", complaintId]);
    await recordStatusHistory({
      complaintId,
      oldStatus: complaint.complaint_status || null,
      newStatus: "Quotation Review",
      changedByRole: "Technician",
      changedById: technicianId,
      remarks: `Quotation ${quotationNo} submitted to Front Desk`,
    }, tx);
  });

  const saved = await fetchQuotationById(
    (await query("SELECT id FROM quotations WHERE quotation_no = ? LIMIT 1", [quotationNo])).rows[0]?.id
  );
  await ensureNotificationsSchema();
  await createWorkflowMessage({
    complaintId,
    quotationId: saved?.id || null,
    senderRole: "Technician",
    senderId: technicianId,
    receiverRole: "Front Desk",
    message: `Quotation ${quotationNo} submitted for warranty review.`,
  });
  await createNotification({
    recipientRole: "Front Desk",
    type: "quotation_review",
    title: "Quotation waiting for review",
    message: `Technician submitted ${quotationNo}. Check warranty status before sending to customer.`,
    entityType: "quotation",
    entityId: saved?.id || null,
  });
  res.status(201).json({ quotation: saved });
}));

app.patch("/quotations/:id/customer-decision", asyncRoute(async (req, res) => {
  await ensureQuotationsSchema();
  await ensureNotificationsSchema();
  await ensureWorkflowAuditSchema();
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
  if (decision === "Rejected" && (!customerRemarks || customerRemarks.length < 3)) {
    return res.status(400).json({ error: "Rejection reason is required (at least 3 characters)." });
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
  const nextComplaintStatus = decision === "Accepted" ? "Customer Accepted" : "Quotation Rejected";

  await withTransaction(async (tx) => {
    await tx(
      `UPDATE quotations
       SET status = ?, customer_remarks = ?, customer_decided_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [nextStatus, customerRemarks, quotationId]
    );
    if (row.complaint_id) {
      await tx("UPDATE complaints SET status = ? WHERE id = ?", [nextComplaintStatus, row.complaint_id]);
      if (decision === "Rejected") {
        await tx(
          `UPDATE tasks
           SET status = 'Closed',
               completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP),
               resolution_notes = COALESCE(?, resolution_notes)
           WHERE complaint_id = ? AND technician_id IS NOT NULL`,
          [`Customer rejected quotation: ${customerRemarks}`, row.complaint_id]
        );
      }
      await recordStatusHistory({
        complaintId: row.complaint_id,
        oldStatus: row.complaint_status || null,
        newStatus: nextComplaintStatus,
        changedByRole: "Customer",
        changedById: customerId,
        remarks: customerRemarks || `Quotation ${decision}`,
      }, tx);
      await createWorkflowMessage({
        complaintId: row.complaint_id,
        quotationId,
        senderRole: "Customer",
        senderId: customerId,
        receiverRole: "Front Desk",
        message:
          decision === "Rejected"
            ? `Customer rejected quotation ${row.quotation_no || ""}. Reason: ${customerRemarks}`
            : customerRemarks || `Customer accepted quotation ${row.quotation_no || ""}.`,
      }, tx);
    }
  });

  const ctx = row.complaint_id ? await getComplaintNotifyContext(row.complaint_id) : null;
  if (ctx) {
    await createNotification({
      recipientRole: "Front Desk",
      type: "quotation_customer_decision",
      title: decision === "Accepted" ? "Customer accepted quotation" : "Customer rejected quotation",
      message:
        decision === "Accepted"
          ? `${row.quotation_no || "Quotation"} accepted by customer. Review and send final instruction to technician.`
          : `${row.quotation_no || "Quotation"} rejected by customer. Reason: ${customerRemarks}`,
      entityType: "quotation",
      entityId: quotationId,
    });
    if (ctx.customer_id) {
      await createNotification({
        customerId: ctx.customer_id,
        type: "quotation_decision_saved",
        title: decision === "Accepted" ? "Quotation accepted" : "Quotation rejected",
        message: `Your decision on ${row.quotation_no || "quotation"} was saved.`,
        entityType: "quotation",
        entityId: quotationId,
      });
    }
  }

  const updated = await fetchQuotationById(quotationId);
  res.json({ quotation: updated });
}));

/** Customer pays accepted quotation after technician completes the repair. */
app.post("/quotations/:id/customer-payment", asyncRoute(async (req, res) => {
  await ensureQuotationsSchema();
  await ensureNotificationsSchema();
  await ensureWorkflowAuditSchema();
  const quotationId = cleanString(req.params.id);
  const customerId = cleanString(req.body.customerId || req.body.customer_id);
  const paymentMode = cleanString(req.body.paymentMode || req.body.payment_mode) || "UPI";
  const transactionRef = cleanString(req.body.transactionRef || req.body.transaction_ref) || null;

  if (!quotationId || !customerId) {
    return res.status(400).json({ error: "Quotation id and customerId are required." });
  }

  const row = await fetchQuotationById(quotationId);
  if (!row) {
    return res.status(404).json({ error: "Quotation not found." });
  }
  if (String(row.customer_id) !== customerId) {
    return res.status(403).json({ error: "This quotation does not belong to your account." });
  }
  if (row.status !== "Accepted by Customer") {
    return res.status(400).json({ error: "Payment is allowed only after you accept the quotation." });
  }
  if (String(row.customer_payment_status || "").toLowerCase() === "paid") {
    return res.status(409).json({ error: "This quotation is already paid." });
  }
  if (!row.complaint_id) {
    return res.status(400).json({ error: "Complaint not linked to this quotation." });
  }

  const complaintRow = await query(
    `SELECT c.status AS complaint_status, t.status AS task_status, t.completed_at
     FROM complaints c
     LEFT JOIN tasks t ON t.id = (
       SELECT t2.id FROM tasks t2 WHERE t2.complaint_id = c.id ORDER BY t2.created_at DESC LIMIT 1
     )
     WHERE c.id = ?
     LIMIT 1`,
    [row.complaint_id]
  );
  if (!complaintRow.rowCount) {
    return res.status(404).json({ error: "Complaint not found." });
  }
  const taskStatus = String(complaintRow.rows[0].task_status || "").toLowerCase();
  const complaintStatus = String(complaintRow.rows[0].complaint_status || "").toLowerCase();
  const jobCompleted =
    taskStatus === "completed" ||
    taskStatus === "closed" ||
    complaintStatus.includes("completed") ||
    complaintStatus.includes("closed") ||
    complaintStatus.includes("solved");
  if (!jobCompleted) {
    return res.status(400).json({
      error: "Payment opens only after the technician marks the repair as completed.",
    });
  }

  const amount = Number(row.total_amount || 0);
  if (amount <= 0) {
    return res.status(400).json({ error: "Quotation amount is invalid." });
  }

  await withTransaction(async (tx) => {
    await tx(
      `UPDATE quotations
       SET customer_payment_status = 'Paid', customer_paid_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [quotationId]
    );
    await recordStatusHistory({
      complaintId: row.complaint_id,
      oldStatus: complaintRow.rows[0].complaint_status || null,
      newStatus: complaintRow.rows[0].complaint_status || "Customer Accepted",
      changedByRole: "Customer",
      changedById: customerId,
      remarks: `Quotation paid via ${paymentMode}${transactionRef ? ` (${transactionRef})` : ""}`,
    }, tx);
    await createWorkflowMessage({
      complaintId: row.complaint_id,
      quotationId,
      senderRole: "Customer",
      senderId: customerId,
      receiverRole: "Front Desk",
      message: `Customer paid ${row.quotation_no || "quotation"} - Rs ${amount.toFixed(2)} via ${paymentMode}.`,
    }, tx);
  });

  await createNotification({
    recipientRole: "Front Desk",
    type: "quotation_paid",
    title: "Customer paid repair quotation",
    message: `${row.quotation_no || "Quotation"} - Rs ${amount.toFixed(2)} received from customer.`,
    entityType: "quotation",
    entityId: quotationId,
  });
  await createNotification({
    customerId,
    type: "quotation_paid",
    title: "Payment successful",
    message: `Thank you. Rs ${amount.toFixed(2)} paid for ${row.quotation_no || "repair quotation"}.`,
    entityType: "quotation",
    entityId: quotationId,
  });

  const updated = await fetchQuotationById(quotationId);
  res.json({ quotation: updated, paid: true, amount });
}));

/** Front Desk sends final Proceed / Hold instruction to technician after customer quotation decision. */
app.patch("/quotations/:id/frontdesk-instruction", asyncRoute(async (req, res) => {
  await ensureQuotationsSchema();
  await ensureNotificationsSchema();
  await ensureWorkflowAuditSchema();
  const quotationId = cleanString(req.params.id);
  const instruction = cleanString(req.body.instruction);
  const remarks = cleanString(req.body.remarks) || null;
  const frontDeskUserId = cleanString(req.body.userId || req.body.user_id) || null;

  if (!quotationId) {
    return res.status(400).json({ error: "Quotation id is required." });
  }
  if (!["Proceed", "Hold"].includes(instruction)) {
    return res.status(400).json({ error: "instruction must be Proceed or Hold." });
  }

  const row = await fetchQuotationById(quotationId);
  if (!row) {
    return res.status(404).json({ error: "Quotation not found." });
  }
  if (!["Accepted by Customer", "Rejected by Customer"].includes(row.status)) {
    return res.status(400).json({ error: "Customer must accept or reject quotation before Front Desk instruction." });
  }
  if (row.frontdesk_instruction) {
    return res.status(409).json({ error: "Final instruction already sent to technician." });
  }

  const nextComplaintStatus = instruction === "Proceed" ? "Proceed with Work" : "On Hold";

  await withTransaction(async (tx) => {
    await tx(
      `UPDATE quotations
       SET frontdesk_instruction = ?, frontdesk_instructed_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [instruction, quotationId]
    );
    if (row.complaint_id) {
      await tx("UPDATE complaints SET status = ? WHERE id = ?", [nextComplaintStatus, row.complaint_id]);
      await recordStatusHistory({
        complaintId: row.complaint_id,
        oldStatus: row.complaint_status || null,
        newStatus: nextComplaintStatus,
        changedByRole: "Front Desk",
        changedById: frontDeskUserId,
        remarks: remarks || `Front Desk instruction: ${instruction}`,
      }, tx);
      await createWorkflowMessage({
        complaintId: row.complaint_id,
        quotationId,
        senderRole: "Front Desk",
        senderId: frontDeskUserId,
        receiverRole: "Technician",
        receiverId: row.technician_id || null,
        message:
          instruction === "Proceed"
            ? remarks || "Proceed with work. Customer approved the quotation."
            : remarks || "Hold / do not proceed. Customer rejected the quotation.",
      }, tx);
    }
  });

  const ctx = row.complaint_id ? await getComplaintNotifyContext(row.complaint_id) : null;
  if (ctx) {
    await notifyTechnicianForComplaint(ctx, {
      type: instruction === "Proceed" ? "frontdesk_proceed" : "frontdesk_hold",
      title: instruction === "Proceed" ? "Proceed with work" : "On hold - do not proceed",
      message:
        instruction === "Proceed"
          ? remarks || "Front Desk approved. Continue and complete the repair."
          : remarks || "Front Desk placed this job on hold. Do not proceed until further notice.",
      entityType: "quotation",
      entityId: quotationId,
    });
    if (ctx.customer_id) {
      await createNotification({
        customerId: ctx.customer_id,
        type: "frontdesk_instruction",
        title: instruction === "Proceed" ? "Repair will continue" : "Repair on hold",
        message:
          instruction === "Proceed"
            ? "Front Desk instructed the technician to proceed with your approved quotation."
            : "Front Desk placed the repair on hold after your quotation response.",
        entityType: "complaint",
        entityId: row.complaint_id,
      });
    }
  }

  const updated = await fetchQuotationById(quotationId);
  res.json({ quotation: updated });
}));

app.patch("/quotations/:id/admin-decision", asyncRoute(async (req, res) => {
  await ensureQuotationsSchema();
  await ensureNotificationsSchema();
  await ensureWorkflowAuditSchema();
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
  if (!["Pending Admin Approval", "Pending Front Desk Review"].includes(row.status)) {
    return res.status(400).json({ error: "Quotation is not pending review." });
  }

  const expired = isWarrantyExpiredStatus(row.warranty_status, row.warranty_expiry);
  if (decision === "Approved" && expired) {
    await withTransaction(async (tx) => {
      await tx("UPDATE quotations SET status = ?, technician_remarks = COALESCE(?, technician_remarks) WHERE id = ?", [
        "Pending Customer Approval",
        remarks,
        quotationId
      ]);
      if (row.complaint_id) {
        await tx(
          "UPDATE complaints SET status = ?, warranty_status = ? WHERE id = ?",
          ["Warranty Expired", "Expired", row.complaint_id]
        );
        await recordStatusHistory({
          complaintId: row.complaint_id,
          oldStatus: row.complaint_status || null,
          newStatus: "Warranty Expired",
          changedByRole: "Front Desk",
          remarks: remarks || "Warranty expired; quotation sent to customer",
        }, tx);
        await createWorkflowMessage({
          complaintId: row.complaint_id,
          quotationId,
          senderRole: "Front Desk",
          receiverRole: "Customer",
          receiverId: row.customer_id || null,
          message: remarks || `Warranty expired. Quotation ${row.quotation_no || ""} sent to customer.`,
        }, tx);
      }
      if (row.customer_id) {
        await createNotification({
          customerId: row.customer_id,
          type: "quotation_customer_approval",
          title: "Repair quotation needs approval",
          message: `Warranty is expired. Please accept or reject quotation ${row.quotation_no}.`,
          entityType: "quotation",
          entityId: quotationId,
        }, tx);
      }
    });
  } else if (decision === "Approved" && !expired) {
    await withTransaction(async (tx) => {
      await tx("UPDATE quotations SET status = ?, technician_remarks = COALESCE(?, technician_remarks) WHERE id = ?", [
        "Covered Under Warranty",
        remarks,
        quotationId
      ]);
      if (row.complaint_id) {
        await tx("UPDATE complaints SET status = ? WHERE id = ?", ["Under Warranty Approved", row.complaint_id]);
        await recordStatusHistory({
          complaintId: row.complaint_id,
          oldStatus: row.complaint_status || null,
          newStatus: "Under Warranty Approved",
          changedByRole: "Front Desk",
          remarks: remarks || "Warranty active; proceed with work",
        }, tx);
        await createWorkflowMessage({
          complaintId: row.complaint_id,
          quotationId,
          senderRole: "Front Desk",
          receiverRole: "Technician",
          receiverId: row.technician_id || null,
          message: remarks || "Warranty active. Proceed with work.",
        }, tx);
      }
      if (row.customer_id) {
        await createNotification({
          customerId: row.customer_id,
          type: "problem_accepted",
          title: "Problem accepted under warranty",
          message: "Your product is under warranty. The technician accepted the problem and no paid quotation is required.",
          entityType: "complaint",
          entityId: row.complaint_id || null,
        }, tx);
      }
    });
  } else {
    await withTransaction(async (tx) => {
      await tx("UPDATE quotations SET status = ?, technician_remarks = COALESCE(?, technician_remarks) WHERE id = ?", [
        "Rejected by Front Desk",
        remarks,
        quotationId
      ]);
      if (row.complaint_id) {
        await recordStatusHistory({
          complaintId: row.complaint_id,
          oldStatus: row.complaint_status || null,
          newStatus: row.complaint_status || "Quotation Review",
          changedByRole: "Front Desk",
          remarks: remarks || "Quotation rejected by Front Desk",
        }, tx);
        await createWorkflowMessage({
          complaintId: row.complaint_id,
          quotationId,
          senderRole: "Front Desk",
          receiverRole: "Technician",
          receiverId: row.technician_id || null,
          message: remarks || "Quotation rejected. Please revise or contact Front Desk.",
        }, tx);
      }
    });
  }
  const ctx = row.complaint_id ? await getComplaintNotifyContext(row.complaint_id) : null;
  if (decision === "Approved" && expired && ctx) {
    await notifyTechnicianForComplaint(ctx, {
      type: "quotation_sent_customer",
      title: "Quotation sent to customer",
      message: "Warranty is expired. Wait for customer approval before completing paid repair.",
      entityType: "quotation",
      entityId: quotationId,
    });
  } else if (decision === "Approved" && !expired && ctx) {
    await notifyTechnicianForComplaint(ctx, {
      type: "frontdesk_proceed",
      title: "Proceed with work",
      message: "Front Desk approved this complaint under warranty. Continue and complete the service.",
      entityType: "complaint",
      entityId: row.complaint_id,
    });
  } else if (ctx) {
    await notifyTechnicianForComplaint(ctx, {
      type: "frontdesk_hold",
      title: "Hold or revise quotation",
      message: remarks || "Front Desk rejected the quotation. Review and update the estimate.",
      entityType: "quotation",
      entityId: quotationId,
    });
  }
  const updated = await fetchQuotationById(quotationId);
  res.json({ quotation: updated });
}));

app.get("/dealers/:id/dashboard", asyncRoute(async (req, res) => {
  await ensureFeedbackSchema();
  await ensureTasksSchema();
  const dealerKey = cleanString(req.params.id);
  if (!dealerKey) {
    return res.status(400).json({ error: "Dealer id is required." });
  }
  const dealer = await resolveDealerRecord(dealerKey);
  if (!dealer) {
    return res.status(404).json({
      error:
        "Dealer profile not found. Link the dealer login mobile to a dealer record in Admin -> Dealer Management.",
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
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     ${COMPLAINT_LATEST_TASK_JOIN}
     ${COMPLAINT_FEEDBACK_JOIN}
     WHERE COALESCE(c.dealer_id, w.dealer_id, s.dealer_id) = ?
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

app.get("/dealers/:id/assigned-products", asyncRoute(async (req, res) => {
  const dealer = await resolveDealerRecord(req.params.id);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  const dealerId = dealer.id;
  const result = await query(
    `SELECT
       s.id,
       s.serial_no,
       s.qr_status,
       s.qr_payload,
       s.dispatch_status,
       s.batch_no,
       s.invoice_no,
       s.challan_no,
       s.dispatch_date,
       s.dispatched_at,
       s.installation_required,
       s.created_at,
       p.id AS product_id,
       p.name AS product_name,
       p.model_no,
       p.category AS product_category,
       s.replacement_case_id,
       s.replacement_for_customer_id,
       s.replacement_label,
       rc.name AS replacement_customer_name,
       rc.mobile AS replacement_customer_mobile,
       rr.case_no AS replacement_case_no,
       rr.complaint_id AS replacement_complaint_id,
       c.complaint_no AS replacement_complaint_no
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN replace_return_cases rr ON rr.id = s.replacement_case_id
     LEFT JOIN customers rc ON rc.id = s.replacement_for_customer_id
     LEFT JOIN complaints c ON c.id = rr.complaint_id
     WHERE s.dealer_id = ?
       AND NOT EXISTS (
         SELECT 1
         FROM warranties w
         WHERE w.serial_id = s.id
           AND w.customer_id IS NOT NULL
       )
     ORDER BY COALESCE(s.dispatched_at, s.created_at) DESC, s.serial_no ASC
     LIMIT 800`,
    [dealerId]
  );
  res.json({
    dealer: { id: dealer.id, name: dealer.name, dealer_no: dealer.dealer_no },
    summary: { totalAssigned: result.rows.length },
    products: result.rows,
  });
}));

app.get("/dealers/:id/sold-products", asyncRoute(async (req, res) => {
  const dealer = await resolveDealerRecord(req.params.id);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  const dealerId = dealer.id;
  const result = await query(
    `SELECT
       w.id AS warranty_id,
       w.warranty_no,
       w.status AS warranty_status,
       w.installation_status,
       w.start_date,
       w.expiry_date,
       w.created_at,
       cust.id AS customer_id,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       cust.city AS customer_city,
       s.serial_no,
       s.installation_required AS serial_installation_required,
       p.name AS product_name,
       p.model_no,
       p.category AS product_category,
       (
         SELECT t.status
         FROM tasks t
         INNER JOIN complaints c ON c.id = t.complaint_id
         WHERE c.warranty_id = w.id
           AND LOWER(TRIM(t.work_type)) = 'installation'
         ORDER BY t.created_at DESC
         LIMIT 1
       ) AS installation_task_status,
       (
         SELECT tech.name
         FROM tasks t
         INNER JOIN complaints c ON c.id = t.complaint_id
         LEFT JOIN technicians tech ON tech.id = t.technician_id
         WHERE c.warranty_id = w.id
           AND LOWER(TRIM(t.work_type)) = 'installation'
         ORDER BY t.created_at DESC
         LIMIT 1
       ) AS installation_technician_name
     FROM warranties w
     INNER JOIN customers cust ON cust.id = w.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     WHERE w.dealer_id = ?
     ORDER BY w.created_at DESC
     LIMIT 500`,
    [dealerId]
  );
  const products = result.rows.map((row) => {
    const installStatus = String(row.installation_status || "").trim();
    const needsTechnician = installStatus.toLowerCase() === "required";
    return {
      ...row,
      needsTechnicianAssignment: needsTechnician,
    };
  });
  res.json({
    dealer: { id: dealer.id, name: dealer.name, dealer_no: dealer.dealer_no },
    summary: {
      totalSold: products.length,
      pendingInstallation: products.filter((row) => row.needsTechnicianAssignment).length,
    },
    products,
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
       u.status AS user_status,
       d.name AS dealer_name,
       d.dealer_no AS dealer_no
     FROM technicians t
     LEFT JOIN users u ON u.id = t.user_id
     LEFT JOIN dealers d ON d.id = t.created_by_dealer_id
     WHERE t.created_by_dealer_id = ?
     ORDER BY t.created_at DESC
     LIMIT 500`,
    [dealer.id]
  );
  res.json({ dealer: { id: dealer.id, name: dealer.name, dealer_no: dealer.dealer_no }, technicians: result.rows });
}));

app.post("/dealers", asyncRoute(async (req, res) => {
  const { dealerNo, name, contactPerson, mobile, address, city, state } = req.body;
  const storedMobile = normalizeStoredMobile(mobile, req.body.countryDial);
  if (!name || !storedMobile) {
    return res.status(400).json({ error: "name and mobile are required" });
  }
  const mobileCheck = requireTenDigitMobile(storedMobile);
  if (!mobileCheck.ok) {
    return res.status(400).json({ error: mobileCheck.error });
  }

  const finalDealerNo = cleanString(dealerNo) || await getNextDealerNo();
  await query(
    "INSERT INTO dealers (dealer_no, name, contact_person, mobile, address, city, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [finalDealerNo, name, contactPerson || null, mobileCheck.national, address || null, city || null, state || null]
  );
  const result = await query("SELECT * FROM dealers WHERE dealer_no = ? LIMIT 1", [finalDealerNo]);
  res.status(201).json({ dealer: result.rows[0] });
}));

app.patch("/dealers/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const name = cleanString(req.body.name);
  const contactPerson = cleanString(req.body.contactPerson || req.body.contact_person) || null;
  const mobile = normalizeStoredMobile(req.body.mobile, req.body.countryDial);
  const address = cleanString(req.body.address) || null;
  const city = cleanString(req.body.city) || null;
  const state = cleanString(req.body.state) || null;
  const status = cleanString(req.body.status) || "Active";

  if (!id || !name || !mobile) {
    return res.status(400).json({ error: "Dealer id, name, and mobile are required." });
  }
  const mobileCheck = requireTenDigitMobile(mobile);
  if (!mobileCheck.ok) {
    return res.status(400).json({ error: mobileCheck.error });
  }

  const existing = await query("SELECT dealer_no, user_id, mobile FROM dealers WHERE id = ? LIMIT 1", [id]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  const dealerNo = cleanString(existing.rows[0].dealer_no);
  if (!dealerNo) {
    return res.status(400).json({ error: "Dealer number is missing on this profile." });
  }

  let linkedUserId = cleanString(existing.rows[0].user_id);
  if (!linkedUserId) {
    const oldMobile = normalizeLoginMobile(existing.rows[0].mobile);
    if (oldMobile) {
      const userByOldMobile = await query(
        `SELECT id FROM users WHERE role = 'Dealer' AND RIGHT(${sqlNormalizeMobileColumn("mobile")}, 10) = ? LIMIT 1`,
        [oldMobile]
      );
      linkedUserId = cleanString(userByOldMobile.rows?.[0]?.id);
    }
  }
  try {
    await ensureUniqueLoginIdentity({ mobile: mobileCheck.national, excludeUserId: linkedUserId || null });
  } catch (err) {
    return res.status(err.statusCode || 409).json({ error: err.message || "This mobile number already has a login account." });
  }

  const result = await query(
    `UPDATE dealers
     SET name = ?, contact_person = ?, mobile = ?, address = ?, city = ?, state = ?, status = ?
     WHERE id = ?`,
    [name, contactPerson, mobileCheck.national, address, city, state, status, id]
  );
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  if (linkedUserId) {
    await query("UPDATE dealers SET user_id = ? WHERE id = ?", [linkedUserId, id]);
  }
  if (linkedUserId) {
    await query(
      "UPDATE users SET name = ?, mobile = ?, status = ? WHERE id = ? AND role = 'Dealer'",
      [name, mobileCheck.national, status, linkedUserId]
    );
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

app.get("/product-categories", asyncRoute(async (_req, res) => {
  const result = await query(
    `SELECT
       c.*,
       CONCAT(c.model_prefix, LPAD(COALESCE(c.model_start_number, c.next_model_number), c.model_number_width, '0')) AS starting_model_no,
       CONCAT(c.serial_prefix, LPAD(COALESCE(c.serial_start_number, c.next_serial_number), c.serial_number_width, '0')) AS starting_serial_no,
       CONCAT(c.model_prefix, LPAD(c.next_model_number, c.model_number_width, '0')) AS next_model_no,
       CONCAT(c.serial_prefix, LPAD(c.next_serial_number, c.serial_number_width, '0')) AS next_serial_no,
       COUNT(p.id) AS product_count
     FROM product_categories c
     LEFT JOIN products p ON p.category_id = c.id
     GROUP BY c.id
     ORDER BY c.name`
  );
  res.json({ categories: result.rows });
}));

app.post("/product-categories", asyncRoute(async (req, res) => {
  const name = cleanString(req.body.name);
  if (!name) {
    return res.status(400).json({ error: "Category name is required." });
  }
  const modelSeed = req.body.modelStart ?? req.body.model_start ?? req.body.modelNoStart ?? req.body.model_no_start;
  const serialSeed = req.body.serialStart ?? req.body.serial_start ?? req.body.serialNoStart ?? req.body.serial_no_start ?? req.body.serialNumber ?? req.body.serial_number;
  const model = parseSequenceSeed(modelSeed, "Model starting number", { defaultValue: "1" });
  const serial = parseSequenceSeed(serialSeed, "Serial starting number", { defaultValue: "1" });
  const sequences = applyCategorySequencePrefixes(name, model, serial);
  const id = crypto.randomUUID();
  await query(
    `INSERT INTO product_categories
       (id, name, model_prefix, model_number_width, model_start_number, next_model_number, serial_prefix, serial_number_width, serial_start_number, next_serial_number)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      name,
      sequences.model.prefix,
      sequences.model.width,
      sequences.model.nextNumber,
      sequences.model.nextNumber,
      sequences.serial.prefix,
      sequences.serial.width,
      sequences.serial.nextNumber,
      sequences.serial.nextNumber,
    ]
  );
  const result = await query("SELECT * FROM product_categories WHERE id = ? LIMIT 1", [id]);
  res.status(201).json({ category: result.rows[0] });
}));

app.patch("/product-categories/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const name = cleanString(req.body.name);
  if (!id) {
    return res.status(400).json({ error: "Category id is required." });
  }
  if (!name) {
    return res.status(400).json({ error: "Category name is required." });
  }

  const existing = await query("SELECT * FROM product_categories WHERE id = ? LIMIT 1", [id]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Category not found." });
  }
  const category = existing.rows[0];

  const nameConflict = await query(
    "SELECT id FROM product_categories WHERE LOWER(TRIM(name)) = LOWER(?) AND id <> ? LIMIT 1",
    [name, id]
  );
  if (nameConflict.rowCount) {
    return res.status(409).json({ error: "Category name already exists." });
  }

  const productCountResult = await query("SELECT COUNT(*) AS total FROM products WHERE category_id = ?", [id]);
  const hasProducts = Number(productCountResult.rows?.[0]?.total || 0) > 0;

  if (hasProducts) {
    await query("UPDATE product_categories SET name = ? WHERE id = ?", [name, id]);
    await query("UPDATE products SET category = ? WHERE category_id = ?", [name, id]);
  } else {
    const modelSeed = req.body.modelStart ?? req.body.model_start ?? req.body.modelNoStart ?? req.body.model_no_start;
    const serialSeed = req.body.serialStart ?? req.body.serial_start ?? req.body.serialNoStart ?? req.body.serial_no_start ?? req.body.serialNumber ?? req.body.serial_number;
    const model = parseSequenceSeed(modelSeed, "Model starting code", { defaultValue: "1" });
    const serial = parseSequenceSeed(serialSeed, "Serial starting code", { defaultValue: "1" });
    const sequences = applyCategorySequencePrefixes(name, model, serial);
    await query(
      `UPDATE product_categories
       SET name = ?, model_prefix = ?, model_number_width = ?, model_start_number = ?, next_model_number = ?,
           serial_prefix = ?, serial_number_width = ?, serial_start_number = ?, next_serial_number = ?
       WHERE id = ?`,
      [
        name,
        sequences.model.prefix,
        sequences.model.width,
        sequences.model.nextNumber,
        sequences.model.nextNumber,
        sequences.serial.prefix,
        sequences.serial.width,
        sequences.serial.nextNumber,
        sequences.serial.nextNumber,
        id,
      ]
    );
  }

  const result = await query(
    `SELECT
       c.*,
       CONCAT(c.model_prefix, LPAD(COALESCE(c.model_start_number, c.next_model_number), c.model_number_width, '0')) AS starting_model_no,
       CONCAT(c.serial_prefix, LPAD(COALESCE(c.serial_start_number, c.next_serial_number), c.serial_number_width, '0')) AS starting_serial_no,
       CONCAT(c.model_prefix, LPAD(c.next_model_number, c.model_number_width, '0')) AS next_model_no,
       CONCAT(c.serial_prefix, LPAD(c.next_serial_number, c.serial_number_width, '0')) AS next_serial_no,
       COUNT(p.id) AS product_count
     FROM product_categories c
     LEFT JOIN products p ON p.category_id = c.id
     WHERE c.id = ?
     GROUP BY c.id
     LIMIT 1`,
    [id]
  );
  res.json({
    category: result.rows[0],
    message: hasProducts
      ? "Category name updated. Model/serial codes are locked because products already exist."
      : "Category updated.",
  });
}));

app.delete("/product-categories/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const linked = await query("SELECT id FROM products WHERE category_id = ? LIMIT 1", [id]);
  if (linked.rowCount) {
    return res.status(409).json({ error: "Category is already used by products and cannot be deleted." });
  }
  const result = await query("DELETE FROM product_categories WHERE id = ?", [id]);
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Category not found." });
  }
  res.json({ ok: true });
}));

app.get("/products", asyncRoute(async (_req, res) => {
  const result = await query(
    `SELECT
       p.*,
       (SELECT s.serial_no FROM serial_numbers s WHERE s.product_id = p.id ORDER BY s.created_at LIMIT 1) AS serial_no
     FROM products p
     ORDER BY p.created_at DESC, p.category ASC, p.name ASC, p.model_no ASC
     LIMIT 800`
  );
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
      <div class="qr">${qrSvg(payload, 96)}</div>
      <div class="brand">Hitaishi CRM</div>
      <div class="product">${escapeHtml(product.name)}</div>
      <div class="model">${escapeHtml(product.model_no)}</div>
      <div class="meta">${escapeHtml(product.category || "Product")}</div>
      <a class="download" href="${qrUrl}">Download QR</a>
    </section>`;
  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Hitaishi Product QR</title>
  <style>
    @page { size: 2in 2in; margin: 0; }
    * { box-sizing: border-box; }
    body { font-family: Arial, sans-serif; margin: 0; color: #111827; background: #fff; }
    .toolbar { padding: 12px 16px; border-bottom: 1px solid #d1d5db; }
    .toolbar button { padding: 8px 14px; font-size: 14px; cursor: pointer; }
    .hint { font-size: 12px; color: #4b5563; margin-top: 6px; }
    .sheet {
      width: 2in;
      height: 2in;
      margin: 10px auto;
      display: grid;
      grid-template-columns: repeat(2, 1in);
      grid-template-rows: 2in;
      gap: 0;
    }
    .label {
      width: 1in;
      height: 2in;
      padding: 0.06in 0.04in;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      overflow: hidden;
      border: 1px dashed #cbd5e1;
    }
    .label.empty { visibility: hidden; }
    .qr svg { width: 0.74in; height: 0.74in; display: block; }
    .brand { font-weight: 700; font-size: 7px; line-height: 1.05; margin-top: 0.025in; max-width: 0.9in; }
    .product { font-size: 7.5px; font-weight: 800; line-height: 1.05; margin-top: 0.025in; max-width: 0.9in; overflow: hidden; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow-wrap: anywhere; }
    .model, .meta { font-size: 6.5px; color: #374151; line-height: 1.05; margin-top: 0.018in; max-width: 0.9in; overflow: hidden; display: -webkit-box; -webkit-line-clamp: 1; -webkit-box-orient: vertical; overflow-wrap: anywhere; }
    .download { display: inline-block; margin-top: 4px; color: #0f3f6b; font-size: 9px; }
    @media print {
      .toolbar, .download { display: none; }
      html, body { width: 2in; min-height: 2in; margin: 0; padding: 0; }
      .sheet { margin: 0; width: 2in; height: 2in; }
      .label { border: 0; }
    }
  </style>
</head>
<body>
  <div class="toolbar">
    <button onclick="window.print()">Print Product QR</button>
    <div class="hint">Thermal 2-UP label layout: each sticker is 2 inch height x 1 inch width. Disable browser headers/footers and use zero/minimum margins.</div>
  </div>
  <main class="sheet">${card}<section class="label empty"></section></main>
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
    const unitQrWhere = dealerId
      ? "product_id = ? AND (dealer_id = ? OR dealer_id IS NULL) AND qr_status = 'Printed'"
      : "product_id = ? AND qr_status = 'Printed'";
    const unitQrParams = dealerId ? [product.id, dealerId] : [product.id];
    const unitQr = await query(
      `SELECT id FROM serial_numbers WHERE ${unitQrWhere} LIMIT 1`,
      unitQrParams
    );
    if (!unitQr.rowCount) {
      return res.status(400).json({ error: "QR is not generated yet. Ask admin to generate dispatch QR stickers." });
    }
  }
  if (Number(product.qr_locked) === 1 || await productHasActiveWarranty(product.id)) {
    return res.status(409).json({ error: "Already scanned this QR code. Warranty is already active." });
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
       ) AS warranty_no,
       (
         SELECT w.customer_id
         FROM warranties w
         WHERE w.serial_id = s.id
         ORDER BY w.created_at DESC
         LIMIT 1
       ) AS warranty_customer_id
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
  const warrantyMonths = resolveProductWarrantyMonths(req.body);

  if (!name || !modelNo) {
    return res.status(400).json({ error: "Product name and model number are required." });
  }

  const duplicate = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) LIMIT 1", [modelNo]);
  if (duplicate.rowCount) {
    return res.status(409).json({ error: "This product model already exists." });
  }

  await query(
    "INSERT INTO products (name, model_no, category, warranty_months) VALUES (?, ?, ?, ?)",
    [name, modelNo, category, warrantyMonths]
  );
  const result = await query("SELECT * FROM products WHERE model_no = ? LIMIT 1", [modelNo]);
  res.status(201).json({ product: result.rows[0] });
}));

app.post("/products/bulk", asyncRoute(async (req, res) => {
  const name = cleanString(req.body.name);
  const categoryId = cleanString(req.body.categoryId || req.body.category_id);
  const quantity = Number(req.body.quantity || 1);
  const warrantyMonths = resolveProductWarrantyMonths(req.body);
  const installationRequired = parseInstallationRequired(req.body.installationRequired ?? req.body.installation_required);
  const rewardPoints = Number(req.body.rewardPoints ?? req.body.reward_points ?? 0);

  if (!name || !categoryId) {
    return res.status(400).json({ error: "Product name and category are required." });
  }
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 500) {
    return res.status(400).json({ error: "Quantity must be a whole number between 1 and 500." });
  }
  if (!Number.isInteger(rewardPoints) || rewardPoints < 0 || rewardPoints > 1000000) {
    return res.status(400).json({ error: "Reward points must be a whole number between 0 and 1,000,000." });
  }

  const created = await withTransaction(async (run) => {
    const categoryResult = await run("SELECT * FROM product_categories WHERE id = ? LIMIT 1 FOR UPDATE", [categoryId]);
    if (!categoryResult.rowCount) {
      const err = new Error("Category not found.");
      err.statusCode = 404;
      throw err;
    }
    const category = categoryResult.rows[0];
    const sequence = await resolveCategorySequenceNext(category, run);
    const modelBase = sequence.modelNext;
    const serialBase = sequence.serialNext;
    const products = [];

    for (let index = 0; index < quantity; index += 1) {
      const modelNo = formatSequenceNumber(
        category.model_prefix,
        category.model_number_width,
        modelBase + index
      );
      const serialNo = formatSequenceNumber(
        category.serial_prefix,
        category.serial_number_width,
        serialBase + index
      );
      const productId = crypto.randomUUID();
      const serialId = crypto.randomUUID();

      await run(
        `INSERT INTO products (id, name, model_no, category, category_id, warranty_months, reward_points, installation_required)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [productId, name, modelNo, category.name, categoryId, warrantyMonths, rewardPoints, installationRequired ? 1 : 0]
      );
      await run(
        `INSERT INTO serial_numbers (id, product_id, serial_no, qr_status, dispatch_status)
         VALUES (?, ?, ?, 'Not Printed', 'Pending')`,
        [serialId, productId, serialNo]
      );

      const row = await run(
        `SELECT p.*, ? AS serial_no FROM products p WHERE p.id = ? LIMIT 1`,
        [serialNo, productId]
      );
      products.push(row.rows[0]);
    }

    await run(
      `UPDATE product_categories
       SET next_model_number = ?, next_serial_number = ?
       WHERE id = ?`,
      [modelBase + quantity, serialBase + quantity, categoryId]
    );

    return products;
  });

  res.status(201).json({ products: created, count: created.length });
}));

app.patch("/products/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const name = cleanString(req.body.name);
  const modelNo = cleanString(req.body.modelNo || req.body.model_no);
  const category = cleanString(req.body.category) || null;
  const warrantyMonths = resolveProductWarrantyMonths(req.body);

  if (!id || !name || !modelNo) {
    return res.status(400).json({ error: "Product id, name, and model number are required." });
  }

  const duplicate = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) AND id <> ? LIMIT 1", [modelNo, id]);
  if (duplicate.rowCount) {
    return res.status(409).json({ error: "This product model already exists." });
  }

  const result = await query(
    "UPDATE products SET name = ?, model_no = ?, category = ?, warranty_months = ? WHERE id = ?",
    [name, modelNo, category, warrantyMonths, id]
  );
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Product not found." });
  }
  const row = await query("SELECT * FROM products WHERE id = ? LIMIT 1", [id]);
  res.json({ product: row.rows[0] });
}));

app.delete("/products/:id", asyncRoute(async (req, res) => {
  const id = cleanString(req.params.id);
  const activeWarranty = await query(
    `SELECT s.id
     FROM serial_numbers s
     INNER JOIN warranties w ON w.serial_id = s.id
     WHERE s.product_id = ?
       AND w.customer_id IS NOT NULL
     LIMIT 1`,
    [id]
  );
  if (activeWarranty.rowCount) {
    return res.status(409).json({ error: "Product is linked with warranties and cannot be deleted." });
  }
  await query("DELETE FROM serial_numbers WHERE product_id = ?", [id]);
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

app.get("/locations/pincode/:pincode", asyncRoute(async (req, res) => {
  const location = await lookupPincodeLocation(req.params.pincode);
  res.json({ location });
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
  await ensureWorkTypeCostsSchema();
  const result = await query(
    `SELECT c.*, t.name AS technician_name
     FROM work_type_costs c
     LEFT JOIN technicians t ON t.id = c.technician_id
     ORDER BY c.created_at DESC
     LIMIT 800`
  );
  res.json({ costs: result.rows });
}));

app.get("/work-type-costs/resolve", asyncRoute(async (req, res) => {
  await ensureWorkTypeCostsSchema();
  const workType = cleanString(req.query.workType || req.query.work_type) || "Paid Repair";
  const productCategory = cleanString(req.query.productCategory || req.query.product_category) || null;
  const modelNo = cleanString(req.query.modelNo || req.query.model_no) || null;
  const city = cleanString(req.query.city) || null;
  const result = await query(
    `SELECT *
     FROM work_type_costs
     WHERE status = 'Active' AND LOWER(TRIM(work_type)) = LOWER(TRIM(?))
     ORDER BY created_at DESC
     LIMIT 200`,
    [workType]
  );
  const best = resolveWorkTypeCostRule(result.rows, { productCategory, modelNo, city });
  const charges = mapWorkTypeCostCharges(best);
  res.json({
    workType,
    productCategory,
    modelNo,
    city,
    ...charges,
    matched: Boolean(best),
  });
}));

app.post("/work-type-costs", asyncRoute(async (req, res) => {
  await ensureWorkTypeCostsSchema();
  const workType = cleanString(req.body.workType || req.body.work_type);
  const productCategory = cleanString(req.body.productCategory || req.body.product_category) || null;
  const modelNo = cleanString(req.body.modelNo || req.body.model_no) || null;
  const city = cleanString(req.body.city) || null;
  const payableAmount = Number(req.body.payableAmount || req.body.payable_amount || 0);
  const serviceCharge = Number(req.body.serviceCharge ?? req.body.service_charge ?? payableAmount ?? 0);
  const visitCharge = Number(req.body.visitCharge ?? req.body.visit_charge ?? 0);
  const taxAmount = Number(req.body.taxAmount ?? req.body.tax_amount ?? 0);
  const discountAmount = Number(req.body.discountAmount ?? req.body.discount_amount ?? 0);
  const defaultTimeframeHours = Number(req.body.defaultTimeframeHours || req.body.default_timeframe_hours || 24);
  const effectiveDate = cleanString(req.body.effectiveDate || req.body.effective_date) || null;
  const status = cleanString(req.body.status) || "Active";

  if (!workType) {
    return res.status(400).json({ error: "Work type is required." });
  }

  await query(
    `INSERT INTO work_type_costs
     (work_type, product_category, model_no, city, payable_amount, service_charge, visit_charge, tax_amount, discount_amount, default_timeframe_hours, effective_date, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      workType,
      productCategory,
      modelNo,
      city,
      Number.isFinite(payableAmount) ? payableAmount : 0,
      Number.isFinite(serviceCharge) ? serviceCharge : 0,
      Number.isFinite(visitCharge) ? visitCharge : 0,
      Number.isFinite(taxAmount) ? taxAmount : 0,
      Number.isFinite(discountAmount) ? discountAmount : 0,
      Number.isFinite(defaultTimeframeHours) && defaultTimeframeHours > 0 ? defaultTimeframeHours : 24,
      effectiveDate,
      status
    ]
  );
  const result = await query("SELECT * FROM work_type_costs ORDER BY created_at DESC LIMIT 1");
  res.status(201).json({ cost: result.rows[0] });
}));

app.patch("/work-type-costs/:id", asyncRoute(async (req, res) => {
  await ensureWorkTypeCostsSchema();
  const id = cleanString(req.params.id);
  const workType = cleanString(req.body.workType || req.body.work_type);
  const productCategory = cleanString(req.body.productCategory || req.body.product_category) || null;
  const modelNo = cleanString(req.body.modelNo || req.body.model_no) || null;
  const city = cleanString(req.body.city) || null;
  const payableAmount = Number(req.body.payableAmount || req.body.payable_amount || 0);
  const serviceCharge = Number(req.body.serviceCharge ?? req.body.service_charge ?? payableAmount ?? 0);
  const visitCharge = Number(req.body.visitCharge ?? req.body.visit_charge ?? 0);
  const taxAmount = Number(req.body.taxAmount ?? req.body.tax_amount ?? 0);
  const discountAmount = Number(req.body.discountAmount ?? req.body.discount_amount ?? 0);
  const defaultTimeframeHours = Number(req.body.defaultTimeframeHours || req.body.default_timeframe_hours || 24);
  const effectiveDate = cleanString(req.body.effectiveDate || req.body.effective_date) || null;
  const status = cleanString(req.body.status) || "Active";

  if (!id || !workType) {
    return res.status(400).json({ error: "Cost rule id and work type are required." });
  }

  const result = await query(
    `UPDATE work_type_costs
     SET work_type = ?, product_category = ?, model_no = ?, city = ?, payable_amount = ?, service_charge = ?, visit_charge = ?, tax_amount = ?, discount_amount = ?, default_timeframe_hours = ?, effective_date = ?, status = ?
     WHERE id = ?`,
    [
      workType,
      productCategory,
      modelNo,
      city,
      Number.isFinite(payableAmount) ? payableAmount : 0,
      Number.isFinite(serviceCharge) ? serviceCharge : 0,
      Number.isFinite(visitCharge) ? visitCharge : 0,
      Number.isFinite(taxAmount) ? taxAmount : 0,
      Number.isFinite(discountAmount) ? discountAmount : 0,
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

async function findOrCreateCustomer({ name, mobile, email, address, city, village, state, pincode, password, createdByDealerId }) {
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
      await ensureUniqueLoginIdentity({ email: emailNorm, excludeUserId: userId });
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
      await ensureUniqueLoginIdentity({ mobile: cleanMobile, email: emailNorm });
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
           village = COALESCE(?, village),
           state = COALESCE(?, state),
           pincode = COALESCE(?, pincode),
           created_by_dealer_id = COALESCE(created_by_dealer_id, ?)
       WHERE id = ?`,
      [userId, cleanName, address || null, city || null, village || null, state || null, pincode || null, createdByDealerId || null, row.id]
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
    await ensureUniqueLoginIdentity({ email: emailNorm, excludeUserId: userId });
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
    await ensureUniqueLoginIdentity({ mobile: cleanMobile, email: emailNorm });
    await query(
      "INSERT INTO users (role, name, mobile, email, password_hash, status) VALUES ('Customer', ?, ?, ?, ?, 'Active')",
      [cleanName, cleanMobile, emailNorm || null, cleanPassword ? hashPassword(cleanPassword) : null]
    );
    const user = await query("SELECT id FROM users WHERE mobile = ? AND role = 'Customer' LIMIT 1", [cleanMobile]);
    userId = user.rows[0].id;
  }

  await query(
    "INSERT INTO customers (user_id, name, mobile, address, city, village, state, pincode, created_by_dealer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [userId, cleanName, cleanMobile, address || null, city || null, village || null, state || null, pincode || null, createdByDealerId || null]
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
       s.dispatched_customer_id,
       s.qr_status,
       s.qr_payload,
       s.installation_required AS serial_installation_required,
       p.id AS product_id,
       p.name AS product_name,
       p.model_no,
       p.warranty_months,
       p.reward_points,
       p.installation_required AS product_installation_required
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
  const unitQrReady = String(row.qr_status || "") === "Printed";
  if (product.qr_status !== "Printed" && !unitQrReady) {
    const err = new Error("Unit QR is not generated yet. Ask admin to generate and print dispatch QR stickers.");
    err.statusCode = 400;
    throw err;
  }

  if (row.dispatched_customer_id) {
    if (actingDealerId) {
      const err = new Error("This unit is dispatched for self-sale. The customer must scan the QR to activate warranty.");
      err.statusCode = 403;
      throw err;
    }
    if (String(row.dispatched_customer_id) !== String(customerId)) {
      const err = new Error("This product QR is assigned to another self-sale customer.");
      err.statusCode = 403;
      throw err;
    }
  }

  if (actingDealerId && row.dealer_id && String(row.dealer_id) !== String(actingDealerId)) {
    const err = new Error("This product QR is mapped to another dealer.");
    err.statusCode = 403;
    throw err;
  }

  const warrantyDealerId = row.dispatched_customer_id ? null : (row.dealer_id || actingDealerId || null);

  const existing = await query(
    "SELECT * FROM warranties WHERE serial_id = ? ORDER BY created_at DESC LIMIT 1",
    [row.id]
  );
  if (existing.rowCount && existing.rows[0].customer_id) {
    if (existing.rows[0].customer_id === customerId) {
      const err = new Error("Already scanned this QR code. Warranty is already active.");
      err.statusCode = 409;
      throw err;
    }
    const err = new Error("Already scanned this QR code. Warranty is already active.");
    err.statusCode = 409;
    throw err;
  }

  const months = Number(row.warranty_months);
  const hasWarranty = productHasWarrantyCoverage(months);
  const warrantyNo = existing.rowCount ? existing.rows[0].warranty_no : `WAR-${Date.now()}`;
  const startDate = purchaseDate || new Date().toISOString().slice(0, 10);
  const warrantyStatus = hasWarranty ? "Active" : "Expired";
  const installationStatus = installationStatusFromRequired(
    row.serial_installation_required ?? row.product_installation_required
  );

  if (existing.rowCount) {
    if (hasWarranty) {
      await query(
        `UPDATE warranties
         SET customer_id = ?,
             dealer_id = COALESCE(dealer_id, ?),
             start_date = COALESCE(start_date, ?),
             expiry_date = COALESCE(expiry_date, DATE_ADD(?, INTERVAL ? MONTH)),
             status = ?,
             installation_status = CASE WHEN installation_status IS NULL OR installation_status = '' THEN ? ELSE installation_status END
         WHERE id = ?`,
        [customerId, warrantyDealerId, startDate, startDate, months, warrantyStatus, installationStatus, existing.rows[0].id]
      );
    } else {
      await query(
        `UPDATE warranties
         SET customer_id = ?,
             dealer_id = COALESCE(dealer_id, ?),
             start_date = COALESCE(start_date, ?),
             expiry_date = COALESCE(expiry_date, DATE_SUB(?, INTERVAL 1 DAY)),
             status = ?,
             installation_status = CASE WHEN installation_status IS NULL OR installation_status = '' THEN ? ELSE installation_status END
         WHERE id = ?`,
        [customerId, warrantyDealerId, startDate, startDate, warrantyStatus, installationStatus, existing.rows[0].id]
      );
    }
  } else if (hasWarranty) {
    await query(
      `INSERT INTO warranties
       (warranty_no, customer_id, dealer_id, serial_id, start_date, expiry_date, status, installation_status)
       VALUES (?, ?, ?, ?, ?, DATE_ADD(?, INTERVAL ? MONTH), ?, ?)`,
      [warrantyNo, customerId, warrantyDealerId, row.id, startDate, startDate, months, warrantyStatus, installationStatus]
    );
  } else {
    await query(
      `INSERT INTO warranties
       (warranty_no, customer_id, dealer_id, serial_id, start_date, expiry_date, status, installation_status)
       VALUES (?, ?, ?, ?, ?, DATE_SUB(?, INTERVAL 1 DAY), ?, ?)`,
      [warrantyNo, customerId, warrantyDealerId, row.id, startDate, startDate, warrantyStatus, installationStatus]
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
  const savedWarranty = warranty.rows[0];
  const rewardPoints = Number(row.reward_points || 0);
  if (actingDealerId && savedWarranty?.id && rewardPoints > 0) {
    await query(
      `INSERT IGNORE INTO dealer_reward_transactions
       (dealer_id, serial_id, warranty_id, points, description)
       VALUES (?, ?, ?, ?, ?)`,
      [actingDealerId, row.id, savedWarranty.id, rewardPoints, `Warranty activated for ${row.serial_no}`]
    );
  }
  return { ...savedWarranty, reward_points_awarded: actingDealerId ? rewardPoints : 0 };
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
  const { name, mobile, email, address, city, village, state, pincode } = req.body;
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
           u.email
         FROM customers c
         LEFT JOIN users u ON u.id = c.user_id
         WHERE ${sqlNormalizeMobileColumn("c.mobile")} = ?
         LIMIT 1`,
        [cleanMobile]
      )
    : { rowCount: 0, rows: [] };
  const customer = await findOrCreateCustomer({
    name,
    mobile,
    email: cleanEmail || null,
    address,
    city,
    village,
    state,
    pincode,
    password: "",
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

app.post("/warranties/:id/assign-installation", asyncRoute(async (req, res) => {
  await ensureWorkflowAuditSchema();
  await ensureComplaintsSchema();
  await ensureTasksSchema();
  const warrantyId = await resolveWarrantyId(req.params.id);
  const dealerId = cleanString(req.body.dealerId || req.body.dealer_id);
  const technicianId = cleanString(req.body.technicianId || req.body.technician_id);
  const dueAt = cleanString(req.body.dueAt || req.body.due_at) || null;
  const assignedById = cleanString(req.body.assignedById || req.body.assigned_by_id || req.body.userId || req.body.user_id) || null;

  if (!warrantyId) {
    return res.status(404).json({ error: "Warranty not found." });
  }
  if (!dealerId || !technicianId) {
    return res.status(400).json({ error: "Dealer and technician are required." });
  }
  if (!dueAt) {
    return res.status(400).json({ error: "Installation visit date and time are required." });
  }

  const warrantyRow = await query(
    `SELECT
       w.*,
       s.serial_no,
       p.name AS product_name,
       p.model_no,
       p.category AS product_category,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       cust.city AS customer_city
     FROM warranties w
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN customers cust ON cust.id = w.customer_id
     WHERE w.id = ?
     LIMIT 1`,
    [warrantyId]
  );
  if (!warrantyRow.rowCount) {
    return res.status(404).json({ error: "Warranty not found." });
  }
  const warranty = warrantyRow.rows[0];
  const warrantyDealerId = String(warranty.dealer_id || "");
  if (!warrantyDealerId || warrantyDealerId !== String(dealerId)) {
    return res.status(403).json({ error: "This warranty does not belong to your dealership." });
  }
  if (!warranty.customer_id) {
    return res.status(400).json({ error: "Customer must be registered on this warranty before installation assignment." });
  }
  const installStatus = String(warranty.installation_status || "").trim();
  if (installStatus === "Not Required") {
    return res.status(400).json({ error: "Installation is not required for this product." });
  }
  if (installStatus === "Completed") {
    return res.status(400).json({ error: "Installation is already completed for this warranty." });
  }

  const activeInstallTask = await query(
    `SELECT t.id, t.status
     FROM tasks t
     INNER JOIN complaints c ON c.id = t.complaint_id
     WHERE c.warranty_id = ?
       AND LOWER(TRIM(t.work_type)) = 'installation'
       AND LOWER(TRIM(COALESCE(t.status, ''))) NOT IN ('completed', 'closed', 'rejected', 'cancelled')
     ORDER BY t.created_at DESC
     LIMIT 1`,
    [warrantyId]
  );
  if (activeInstallTask.rowCount) {
    return res.status(409).json({ error: "An installation job is already assigned for this warranty." });
  }

  const technician = await query(
    "SELECT id, user_id, name, created_by_dealer_id FROM technicians WHERE id = ? AND approval_status = 'Approved' LIMIT 1",
    [technicianId]
  );
  if (!technician.rowCount) {
    return res.status(404).json({ error: "Approved technician not found." });
  }
  if (String(technician.rows[0].created_by_dealer_id || "") !== String(dealerId)) {
    return res.status(403).json({ error: "Dealer can assign only technicians linked to this dealership." });
  }

  const payableAmount = await resolveInstallationPayable({
    productCategory: warranty.product_category,
    modelNo: warranty.model_no,
    city: warranty.customer_city,
  });

  let complaintId = null;
  const existingComplaint = await query(
    `SELECT id, complaint_no, status
     FROM complaints
     WHERE warranty_id = ?
       AND LOWER(TRIM(problem_type)) = 'product installation'
     ORDER BY created_at DESC
     LIMIT 1`,
    [warrantyId]
  );
  if (existingComplaint.rowCount) {
    complaintId = existingComplaint.rows[0].id;
  }

  const complaintNo = existingComplaint.rowCount
    ? existingComplaint.rows[0].complaint_no
    : `CMP-${Date.now()}`;
  const taskNo = `TASK-${Date.now()}`;

  await withTransaction(async (tx) => {
    if (!complaintId) {
      await tx(
        `INSERT INTO complaints
           (complaint_no, warranty_id, customer_id, dealer_id, problem_type, description, priority, product_name, model_no, warranty_start_date, warranty_end_date, warranty_status, status)
         VALUES (?, ?, ?, ?, 'Product Installation', ?, 'Normal', ?, ?, ?, ?, ?, 'Assigned to Technician')`,
        [
          complaintNo,
          warrantyId,
          warranty.customer_id,
          dealerId,
          "Install product at customer location. No quotation required - technician payout is fixed by Admin.",
          warranty.product_name,
          warranty.model_no,
          warranty.start_date,
          warranty.expiry_date,
          warranty.status,
        ]
      );
      const created = await tx("SELECT id FROM complaints WHERE complaint_no = ? LIMIT 1", [complaintNo]);
      complaintId = created.rows[0]?.id;
      await recordStatusHistory({
        complaintId,
        oldStatus: null,
        newStatus: "Assigned to Technician",
        changedByRole: "Dealer",
        changedById: assignedById,
        remarks: "Installation job created",
      }, tx);
    } else {
      await tx("UPDATE complaints SET status = 'Assigned to Technician' WHERE id = ?", [complaintId]);
      await recordStatusHistory({
        complaintId,
        oldStatus: existingComplaint.rows[0].status,
        newStatus: "Assigned to Technician",
        changedByRole: "Dealer",
        changedById: assignedById,
        remarks: "Installation technician reassigned",
      }, tx);
    }

    await tx(
      `INSERT INTO complaint_assignments
         (complaint_id, technician_id, assigned_by_role, assigned_by_id, status, remarks)
       VALUES (?, ?, 'Dealer', ?, 'Assigned', 'Installation assignment')`,
      [complaintId, technicianId, assignedById]
    );
    await tx(
      `INSERT INTO tasks
       (task_no, complaint_id, technician_id, work_type, due_at, status, payable_amount, assigned_by_role, assigned_by_id)
       VALUES (?, ?, ?, 'Installation', ?, 'Assigned', ?, 'Dealer', ?)`,
      [taskNo, complaintId, technicianId, dueAt, payableAmount, assignedById]
    );
    await tx("UPDATE warranties SET installation_status = 'Assigned' WHERE id = ?", [warrantyId]);
    await createWorkflowMessage({
      complaintId,
      senderRole: "Dealer",
      senderId: assignedById,
      receiverRole: "Technician",
      receiverId: technicianId,
      message: "Installation job assigned. Visit customer and complete installation - no quotation needed.",
    }, tx);
  });

  const taskResult = await query(
    `SELECT ${TASK_DETAIL_SELECT}
     ${TASK_DETAIL_JOINS}
     WHERE t.complaint_id = ?
     ORDER BY t.created_at DESC
     LIMIT 1`,
    [complaintId]
  );
  await ensureNotificationsSchema();
  if (technician.rows[0]?.user_id) {
    await createNotification({
      userId: technician.rows[0].user_id,
      recipientRole: "Technician",
      type: "installation_assigned",
      title: "New installation job",
      message: `Install ${warranty.product_name || "product"} at ${warranty.customer_name || "customer"}. Accept in Alerts.`,
      entityType: "task",
      entityId: taskResult.rows[0]?.id || null,
    });
  }
  if (warranty.customer_id) {
    await createNotification({
      customerId: warranty.customer_id,
      type: "installation_scheduled",
      title: "Installation scheduled",
      message: `A technician will visit for ${warranty.product_name || "your product"} installation.`,
      entityType: "warranty",
      entityId: warrantyId,
    });
  }

  res.status(201).json({
    task: taskResult.rows[0] || null,
    complaintNo,
    payableAmount,
    message: `${technician.rows[0].name} assigned for installation. Technician payout: Rs ${payableAmount.toFixed(0)} (Admin fixed).`,
  });
}));

const REPLACE_RETURN_DETAIL_SELECT = `
  rr.*,
  c.complaint_no,
  c.status AS complaint_status,
  w.warranty_no,
  w.start_date AS warranty_start,
  w.expiry_date AS warranty_expiry,
  w.status AS warranty_status,
  cust.name AS customer_name,
  cust.mobile AS customer_mobile,
  cust.city AS customer_city,
  cust.address AS customer_address,
  d.dealer_no,
  d.name AS dealer_name,
  d.mobile AS dealer_mobile,
  d.city AS dealer_city,
  s.serial_no,
  p.name AS product_name,
  p.model_no,
  p.category AS product_category,
  t.resolution_notes AS technician_remarks,
  tech.name AS technician_name,
  reqs.serial_no AS requested_exchange_serial_no,
  reqp.name AS requested_exchange_product_name,
  reqp.model_no AS requested_exchange_model_no,
  rs.serial_no AS replacement_serial_no,
  rp.name AS replacement_product_name,
  rp.model_no AS replacement_model_no`;

const REPLACE_RETURN_DETAIL_JOINS = `
  FROM replace_return_cases rr
  INNER JOIN complaints c ON c.id = rr.complaint_id
  LEFT JOIN warranties w ON w.id = rr.warranty_id
  LEFT JOIN customers cust ON cust.id = rr.customer_id
  LEFT JOIN dealers d ON d.id = rr.dealer_id
  LEFT JOIN serial_numbers s ON s.id = rr.serial_id
  LEFT JOIN products p ON p.id = s.product_id
  LEFT JOIN tasks t ON t.id = rr.task_id
  LEFT JOIN technicians tech ON tech.id = t.technician_id
  LEFT JOIN serial_numbers reqs ON reqs.id = rr.requested_exchange_serial_id
  LEFT JOIN products reqp ON reqp.id = reqs.product_id
  LEFT JOIN serial_numbers rs ON rs.id = rr.replacement_serial_id
  LEFT JOIN products rp ON rp.id = rs.product_id`;

const QR_WARRANTY_ACTIONS = new Set(["Replace", "Return", "Product Exchange"]);

async function resolveReplaceReturnCase(identifier) {
  const key = cleanString(identifier);
  if (!key) return null;
  await ensureReplaceReturnSchema();
  const byId = await query("SELECT id FROM replace_return_cases WHERE id = ? OR case_no = ? LIMIT 1", [key, key]);
  return byId.rowCount ? byId.rows[0].id : null;
}

app.get("/replace-return", asyncRoute(async (req, res) => {
  await ensureReplaceReturnSchema();
  const status = cleanString(req.query.status);
  const dealerId = cleanString(req.query.dealerId || req.query.dealer_id);
  const where = [];
  const params = [];
  if (status && status !== "All") {
    where.push("rr.status = ?");
    params.push(status);
  }
  if (dealerId) {
    const dealer = await resolveDealerRecord(dealerId);
    if (dealer) {
      where.push("rr.dealer_id = ?");
      params.push(dealer.id);
    }
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const result = await query(
    `SELECT ${REPLACE_RETURN_DETAIL_SELECT}
     ${REPLACE_RETURN_DETAIL_JOINS}
     ${whereSql}
     ORDER BY rr.created_at DESC
     LIMIT 500`,
    params
  );
  res.json({ cases: result.rows });
}));

app.get("/replace-return/eligible", asyncRoute(async (req, res) => {
  await ensureReplaceReturnSchema();
  await ensureComplaintsSchema();
  const dealerKey = cleanString(req.query.dealerId || req.query.dealer_id);
  const dealer = await resolveDealerRecord(dealerKey);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  const result = await query(
    `SELECT
       c.*,
       w.warranty_no,
       w.id AS warranty_id,
       COALESCE(c.warranty_start_date, w.start_date) AS start_date,
       COALESCE(c.warranty_end_date, w.expiry_date) AS expiry_date,
       COALESCE(c.warranty_status, w.status) AS warranty_status,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       s.serial_no,
       s.id AS serial_id,
       COALESCE(c.product_name, p.name) AS product_name,
       COALESCE(c.model_no, p.model_no) AS model_no,
       t.id AS task_id,
       t.resolution_notes AS technician_remarks,
       t.status AS task_status
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN tasks t ON t.complaint_id = c.id AND LOWER(TRIM(t.status)) = 'unrepairable'
     WHERE COALESCE(c.dealer_id, w.dealer_id, s.dealer_id) = ?
       AND c.status = 'Awaiting Dealer Action'
       AND ${WARRANTY_ACTIVE_SQL}
       AND NOT EXISTS (SELECT 1 FROM replace_return_cases rr WHERE rr.complaint_id = c.id)
     ORDER BY c.created_at DESC
     LIMIT 200`,
    [dealer.id]
  );
  res.json({ complaints: result.rows });
}));

app.post("/replace-return", asyncRoute(async (req, res) => {
  await ensureReplaceReturnSchema();
  await ensureComplaintsSchema();
  const complaintId = cleanString(req.body.complaintId || req.body.complaint_id);
  const dealerId = cleanString(req.body.dealerId || req.body.dealer_id);
  const actionType = cleanString(req.body.actionType || req.body.action_type);
  const problemDetails = cleanString(req.body.problemDetails || req.body.problem_details);
  const createdById = cleanString(req.body.createdById || req.body.userId || req.body.user_id) || null;

  if (!complaintId || !dealerId || !actionType || !problemDetails) {
    return res.status(400).json({ error: "Complaint, dealer, action type, and problem details are required." });
  }
  if (!["Replace", "Return"].includes(actionType)) {
    return res.status(400).json({ error: "Action type must be Replace or Return." });
  }

  const dealer = await resolveDealerRecord(dealerId);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found." });
  }

  const complaintRow = await query(
    `SELECT c.*, w.id AS warranty_id, w.dealer_id AS warranty_dealer_id, w.serial_id, w.customer_id, w.warranty_no, s.serial_no,
            COALESCE(c.warranty_end_date, w.expiry_date) AS expiry_date,
            COALESCE(c.warranty_status, w.status) AS warranty_status,
            t.id AS task_id, t.resolution_notes
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN tasks t ON t.complaint_id = c.id AND LOWER(TRIM(t.status)) = 'unrepairable'
     WHERE c.id = ?
     LIMIT 1`,
    [complaintId]
  );
  if (!complaintRow.rowCount) {
    return res.status(404).json({ error: "Complaint not found." });
  }
  const complaint = complaintRow.rows[0];
  if (String(complaint.status || "") !== "Awaiting Dealer Action") {
    return res.status(400).json({ error: "This complaint is not awaiting dealer replace/return action." });
  }
  if (isWarrantyExpiredStatus(complaint.warranty_status, complaint.expiry_date)) {
    return res.status(400).json({
      error: "Product replacement is only available while warranty is active. This warranty has expired.",
    });
  }
  const owningDealerId = String(complaint.dealer_id || complaint.warranty_dealer_id || "");
  if (owningDealerId && owningDealerId !== String(dealer.id)) {
    return res.status(403).json({ error: "This complaint does not belong to your dealership." });
  }

  const existing = await query("SELECT id FROM replace_return_cases WHERE complaint_id = ? LIMIT 1", [complaintId]);
  if (existing.rowCount) {
    return res.status(409).json({ error: "Replace/Return case already exists for this complaint." });
  }

  const caseNo = `RR-${Date.now()}`;
  const caseId = crypto.randomUUID();
  const qrPayload = replaceReturnQrPayload({
    caseId,
    caseNo,
    serialNo: complaint.serial_no,
    actionType,
  });

  await query(
    `INSERT INTO replace_return_cases
       (id, case_no, complaint_id, task_id, warranty_id, customer_id, dealer_id, serial_id,
        action_type, problem_details, technician_remarks, status, qr_status, qr_payload, qr_printed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending Admin Scan', 'Printed', ?, CURRENT_TIMESTAMP)`,
    [
      caseId,
      caseNo,
      complaintId,
      complaint.task_id || null,
      complaint.warranty_id || null,
      complaint.customer_id || null,
      dealer.id,
      complaint.serial_id || null,
      actionType,
      problemDetails,
      complaint.resolution_notes || null,
      qrPayload,
    ]
  );

  await recordStatusHistory({
    complaintId,
    oldStatus: complaint.status,
    newStatus: "Replace/Return Submitted",
    changedByRole: "Dealer",
    changedById: createdById,
    remarks: `${actionType} case ${caseNo} created`,
  });

  await ensureNotificationsSchema();
  const adminUsers = await query("SELECT id FROM users WHERE role = 'Admin' LIMIT 5");
  for (const admin of adminUsers.rows) {
    await createNotification({
      userId: admin.id,
      recipientRole: "Admin",
      type: "replace_return",
      title: `New ${actionType} case`,
      message: `${caseNo}: ${complaint.product_name || "Product"} - scan QR in Replace/Return panel.`,
      entityType: "replace_return",
      entityId: caseId,
    });
  }

  const detail = await query(
    `SELECT ${REPLACE_RETURN_DETAIL_SELECT}
     ${REPLACE_RETURN_DETAIL_JOINS}
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );

  res.status(201).json({
    case: detail.rows[0],
    qrPayload,
    message: `${actionType} case created. QR is ready - Admin will scan to receive product.`,
  });
}));

app.post("/replace-return/from-warranty-scan", asyncRoute(async (req, res) => {
  await ensureReplaceReturnSchema();
  await ensureComplaintsSchema();
  await ensureNotificationsSchema();
  const dealerId = cleanString(req.body.dealerId || req.body.dealer_id);
  const serialNo = cleanSerialNo(req.body.serialNo || req.body.serial_no);
  const warrantyKey = cleanString(req.body.warrantyId || req.body.warranty_id || req.body.warrantyNo || req.body.warranty_no);
  const actionType = cleanString(req.body.actionType || req.body.action_type);
  const problemDetails = cleanString(req.body.problemDetails || req.body.problem_details);
  const exchangeSerialId = cleanString(req.body.exchangeSerialId || req.body.exchange_serial_id);
  const exchangeSerialNo = cleanSerialNo(req.body.exchangeSerialNo || req.body.exchange_serial_no);
  const createdById = cleanString(req.body.createdById || req.body.userId || req.body.user_id) || null;

  if (!dealerId || (!serialNo && !warrantyKey) || !actionType || !problemDetails) {
    return res.status(400).json({ error: "Dealer, active warranty/product, action type, and details are required." });
  }
  if (!QR_WARRANTY_ACTIONS.has(actionType)) {
    return res.status(400).json({ error: "Action type must be Replace, Return, or Product Exchange." });
  }

  const dealer = await resolveDealerRecord(dealerId);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found." });
  }

  const lookupWhere = warrantyKey
    ? "(w.id = ? OR w.warranty_no = ?)"
    : "LOWER(TRIM(s.serial_no)) = LOWER(TRIM(?))";
  const lookupParams = warrantyKey ? [warrantyKey, warrantyKey] : [serialNo];
  const warrantyResult = await query(
    `SELECT
       w.*,
       s.id AS serial_id,
       s.serial_no,
       s.dealer_id AS serial_dealer_id,
       p.name AS product_name,
       p.model_no,
       p.category AS product_category,
       cust.name AS customer_name,
       cust.mobile AS customer_mobile,
       d.id AS owning_dealer_id,
       d.name AS dealer_name,
       d.dealer_no
     FROM warranties w
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN customers cust ON cust.id = w.customer_id
     LEFT JOIN dealers d ON d.id = COALESCE(w.dealer_id, s.dealer_id)
     WHERE ${lookupWhere}
     ORDER BY w.created_at DESC
     LIMIT 1`,
    lookupParams
  );
  if (!warrantyResult.rowCount) {
    return res.status(404).json({ error: "Active warranty not found for this QR." });
  }
  const warranty = warrantyResult.rows[0];
  if (!warranty.customer_id) {
    return res.status(400).json({ error: "Warranty is not active for a customer yet." });
  }
  if (isWarrantyExpiredStatus(warranty.status, warranty.expiry_date)) {
    return res.status(400).json({ error: "Warranty has expired. Replace/Return/Exchange is not available." });
  }
  const owningDealerId = String(warranty.dealer_id || warranty.serial_dealer_id || warranty.owning_dealer_id || "");
  if (owningDealerId && owningDealerId !== String(dealer.id)) {
    return res.status(403).json({ error: "This warranty belongs to another dealer." });
  }

  let requestedExchangeSerial = null;
  if (actionType === "Product Exchange") {
    if (!exchangeSerialId && !exchangeSerialNo) {
      return res.status(400).json({ error: "Select new product from dealer stock for Product Exchange." });
    }
    const exchangeResult = exchangeSerialId
      ? await query(
          `SELECT s.*, p.name AS product_name, p.model_no
           FROM serial_numbers s
           LEFT JOIN products p ON p.id = s.product_id
           WHERE s.id = ?
           LIMIT 1`,
          [exchangeSerialId]
        )
      : await query(
          `SELECT s.*, p.name AS product_name, p.model_no
           FROM serial_numbers s
           LEFT JOIN products p ON p.id = s.product_id
           WHERE LOWER(TRIM(s.serial_no)) = LOWER(TRIM(?))
           LIMIT 1`,
          [exchangeSerialNo]
        );
    if (!exchangeResult.rowCount) {
      return res.status(404).json({ error: "Selected exchange product serial not found." });
    }
    requestedExchangeSerial = exchangeResult.rows[0];
    if (String(requestedExchangeSerial.dealer_id || "") !== String(dealer.id)) {
      return res.status(403).json({ error: "Selected exchange product is not in this dealer stock." });
    }
    const exchangeWarranty = await query(
      "SELECT id FROM warranties WHERE serial_id = ? AND customer_id IS NOT NULL LIMIT 1",
      [requestedExchangeSerial.id]
    );
    if (exchangeWarranty.rowCount) {
      return res.status(409).json({ error: "Selected exchange product is already sold/activated." });
    }
  }

  const openExisting = await query(
    `SELECT rr.id, rr.case_no, rr.status
     FROM replace_return_cases rr
     WHERE rr.warranty_id = ?
       AND rr.status NOT IN ('Delivered to Customer', 'Closed', 'Cancelled', 'Return Completed')
     ORDER BY rr.created_at DESC
     LIMIT 1`,
    [warranty.id]
  );
  if (openExisting.rowCount) {
    return res.status(409).json({
      error: `Case ${openExisting.rows[0].case_no} is already open for this warranty.`,
      caseId: openExisting.rows[0].id,
      caseNo: openExisting.rows[0].case_no,
      status: openExisting.rows[0].status,
    });
  }

  const complaintId = crypto.randomUUID();
  const complaintNo = `CMP-${Date.now()}`;
  const caseId = crypto.randomUUID();
  const caseNo = `RR-${Date.now()}`;
  const problemType = actionType === "Return" ? "Product Return" : actionType === "Product Exchange" ? "Product Exchange" : "Product Replacement";
  const exchangeDetail = requestedExchangeSerial
    ? ` Exchange with: ${requestedExchangeSerial.product_name || "Product"} - ${requestedExchangeSerial.model_no || "-"} - ${requestedExchangeSerial.serial_no}.`
    : "";
  const description = `${actionType} requested by dealer from active warranty QR scan. ${problemDetails}${exchangeDetail}`.trim();
  const savedProblemDetails = `${problemDetails}${exchangeDetail}`.trim();
  const completesImmediately = actionType === "Product Exchange" && requestedExchangeSerial;
  const complaintStatus = completesImmediately ? "Product Exchange Completed" : "Awaiting Dealer Action";
  const caseStatus = completesImmediately ? "Delivered to Customer" : "Pending Admin Scan";
  const qrPayload = replaceReturnQrPayload({
    caseId,
    caseNo,
    serialNo: warranty.serial_no,
    actionType,
  });

  await withTransaction(async (tx) => {
    await tx(
      `INSERT INTO complaints
         (id, complaint_no, warranty_id, customer_id, dealer_id, problem_type, description, priority,
          product_name, model_no, warranty_start_date, warranty_end_date, warranty_status, status, created_by_role)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'Normal', ?, ?, ?, ?, ?, ?, 'Dealer')`,
      [
        complaintId,
        complaintNo,
        warranty.id,
        warranty.customer_id,
        dealer.id,
        problemType,
        description,
        warranty.product_name,
        warranty.model_no,
        warranty.start_date,
        warranty.expiry_date,
        warranty.status,
        complaintStatus,
      ]
    );
    await tx(
      `INSERT INTO replace_return_cases
         (id, case_no, complaint_id, task_id, warranty_id, customer_id, dealer_id, serial_id,
          action_type, problem_details, technician_remarks, requested_exchange_serial_id,
          replacement_serial_id, replacement_dispatched_at, delivered_to_customer_at,
          status, qr_status, qr_payload, qr_printed_at)
       VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, 'Printed', ?, CURRENT_TIMESTAMP)`,
      [
        caseId,
        caseNo,
        complaintId,
        warranty.id,
        warranty.customer_id,
        dealer.id,
        warranty.serial_id || null,
        actionType,
        savedProblemDetails,
        requestedExchangeSerial?.id || null,
        completesImmediately ? requestedExchangeSerial.id : null,
        completesImmediately ? new Date() : null,
        completesImmediately ? new Date() : null,
        caseStatus,
        qrPayload,
      ]
    );
    if (completesImmediately) {
      await tx("UPDATE warranties SET serial_id = ? WHERE id = ?", [requestedExchangeSerial.id, warranty.id]);
      await tx(
        `UPDATE serial_numbers
         SET replacement_case_id = ?,
             replacement_for_customer_id = ?,
             replacement_label = ?
         WHERE id = ?`,
        [
          caseId,
          warranty.customer_id,
          `Exchange for ${warranty.customer_name || "Customer"} - ${complaintNo}`,
          requestedExchangeSerial.id,
        ]
      );
    }
    await recordStatusHistory({
      complaintId,
      oldStatus: null,
      newStatus: complaintStatus,
      changedByRole: "Dealer",
      changedById: createdById,
      remarks: completesImmediately
        ? `Product exchanged directly by dealer. New serial ${requestedExchangeSerial.serial_no}`
        : `${actionType} case ${caseNo} created from warranty QR scan`,
    }, tx);
  });

  if (!completesImmediately) {
    const adminUsers = await query("SELECT id FROM users WHERE role = 'Admin' LIMIT 5");
    for (const admin of adminUsers.rows) {
      await createNotification({
        userId: admin.id,
        recipientRole: "Admin",
        type: "replace_return",
        title: `New ${actionType} case from QR`,
        message: `${caseNo}: ${warranty.product_name || "Product"} - ${warranty.serial_no || ""}.`,
        entityType: "replace_return",
        entityId: caseId,
      });
    }
  }

  const detail = await query(
    `SELECT ${REPLACE_RETURN_DETAIL_SELECT}
     ${REPLACE_RETURN_DETAIL_JOINS}
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );

  res.status(201).json({
    case: detail.rows[0],
    complaintNo,
    qrPayload,
    message: completesImmediately
      ? `Product exchanged successfully with ${requestedExchangeSerial.serial_no}. Warranty remaining period will continue.`
      : `${actionType} case created. Admin will scan/receive this product. Warranty remaining period will continue.`,
  });
}));

app.get("/replace-return/:id/scan", asyncRoute(async (req, res) => {
  const caseId = await resolveReplaceReturnCase(req.params.id);
  if (!caseId) {
    return res.status(404).json({ error: "Replace/Return case not found." });
  }
  const result = await query(
    `SELECT ${REPLACE_RETURN_DETAIL_SELECT}
     ${REPLACE_RETURN_DETAIL_JOINS}
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );
  if (!result.rowCount) {
    return res.status(404).json({ error: "Replace/Return case not found." });
  }
  res.json({ case: result.rows[0] });
}));

app.get("/replace-return/:id/qr.svg", asyncRoute(async (req, res) => {
  const caseId = await resolveReplaceReturnCase(req.params.id);
  if (!caseId) {
    return res.status(404).json({ error: "Replace/Return case not found." });
  }
  const row = await query("SELECT qr_payload FROM replace_return_cases WHERE id = ? LIMIT 1", [caseId]);
  if (!row.rowCount || !row.rows[0].qr_payload) {
    return res.status(404).json({ error: "QR not generated for this case." });
  }
  res.setHeader("Content-Type", "image/svg+xml");
  res.send(qrSvg(row.rows[0].qr_payload, 280));
}));

app.post("/replace-return/:id/admin-scan", asyncRoute(async (req, res) => {
  await ensureReplaceReturnSchema();
  const caseId = await resolveReplaceReturnCase(req.params.id);
  if (!caseId) {
    return res.status(404).json({ error: "Replace/Return case not found." });
  }
  const adminUserId = cleanString(req.body.adminUserId || req.body.userId || req.body.user_id) || null;
  const scannedByRole = cleanString(req.body.scannedByRole || req.body.scanned_by_role) || "Admin";
  const existing = await query("SELECT * FROM replace_return_cases WHERE id = ? LIMIT 1", [caseId]);
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Replace/Return case not found." });
  }
  const row = existing.rows[0];
  if (
    row.replacement_serial_id ||
    row.replacement_dispatched_at ||
    ["Replacement Dispatched", "Delivered to Customer"].includes(String(row.status || ""))
  ) {
    return res.status(409).json({ error: "This case has already moved to replacement delivery." });
  }
  if (String(row.status || "") === "Admin Received") {
    return res.status(409).json({ error: "This case was already scanned." });
  }
  if (String(row.status || "") !== "Pending Admin Scan") {
    return res.status(409).json({ error: `This case cannot be received while status is ${row.status || "unknown"}.` });
  }

  await query(
    `UPDATE replace_return_cases
     SET status = 'Admin Received', admin_scanned_at = CURRENT_TIMESTAMP, admin_scanned_by = ?
     WHERE id = ?`,
    [adminUserId, caseId]
  );

  await recordStatusHistory({
    complaintId: row.complaint_id,
    oldStatus: row.status,
    newStatus: "Admin Received",
    changedByRole: scannedByRole,
    changedById: adminUserId,
    remarks: `${scannedByRole} scanned ${row.case_no}`,
  });

  const detail = await query(
    `SELECT ${REPLACE_RETURN_DETAIL_SELECT}
     ${REPLACE_RETURN_DETAIL_JOINS}
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );

  res.json({
    case: detail.rows[0],
    message: `Case received in ${scannedByRole} Replace/Return panel.`,
  });
}));

app.get("/replace-return/:id/available-replacement-serials", asyncRoute(async (req, res) => {
  await ensureReplaceReturnSchema();
  await ensureSerialNumbersSchema();
  const caseId = await resolveReplaceReturnCase(req.params.id);
  if (!caseId) {
    return res.status(404).json({ error: "Replace/Return case not found." });
  }
  const caseRow = await query(
    `SELECT rr.*, c.complaint_no, cust.name AS customer_name, p.name AS product_name, p.model_no, p.category_id
     FROM replace_return_cases rr
     INNER JOIN complaints c ON c.id = rr.complaint_id
     LEFT JOIN customers cust ON cust.id = rr.customer_id
     LEFT JOIN serial_numbers s ON s.id = rr.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );
  if (!caseRow.rowCount) {
    return res.status(404).json({ error: "Replace/Return case not found." });
  }
  const row = caseRow.rows[0];
  if (String(row.status || "") !== "Admin Received") {
    return res.status(400).json({ error: "Admin must receive the product before dispatching replacement." });
  }
  if (String(row.action_type || "") === "Return") {
    return res.status(400).json({ error: "Return cases do not need replacement dispatch. Process refund/payment offline after admin receive." });
  }
  if (row.replacement_serial_id) {
    return res.status(409).json({ error: "Replacement already dispatched for this case." });
  }
  const productName = cleanString(row.product_name);
  const modelNo = cleanString(row.model_no);
  const categoryId = cleanString(row.category_id);
  const clauses = ["s.dealer_id IS NULL", "s.dispatch_status = 'Pending'", "s.replacement_case_id IS NULL"];
  const params = [];
  if (String(row.action_type || "") !== "Product Exchange" && productName) {
    clauses.push("p.name = ?");
    params.push(productName);
  } else if (String(row.action_type || "") !== "Product Exchange" && categoryId) {
    clauses.push("p.category_id = ?");
    params.push(categoryId);
  }
  params.push(modelNo || "", 100);
  const result = await query(
    `SELECT s.id, s.serial_no, p.name AS product_name, p.model_no, p.category AS product_category
     FROM serial_numbers s
     INNER JOIN products p ON p.id = s.product_id
     WHERE ${clauses.join(" AND ")}
     ORDER BY CASE WHEN LOWER(TRIM(COALESCE(p.model_no, ''))) = LOWER(?) THEN 0 ELSE 1 END, s.serial_no ASC
     LIMIT ?`,
    params
  );
  res.json({
    caseId,
    caseNo: row.case_no,
    customerName: row.customer_name,
    complaintNo: row.complaint_no,
    productName,
    modelNo,
    serials: result.rows,
  });
}));

app.post("/replace-return/:id/dispatch-replacement", asyncRoute(async (req, res) => {
  await ensureReplaceReturnSchema();
  await ensureSerialNumbersSchema();
  await ensureProductsQrSchema();
  await ensureNotificationsSchema();
  const caseId = await resolveReplaceReturnCase(req.params.id);
  if (!caseId) {
    return res.status(404).json({ error: "Replace/Return case not found." });
  }
  const serialId = cleanString(req.body.serialId || req.body.serial_id);
  const serialNo = cleanSerialNo(req.body.serialNo || req.body.serial_no);
  const adminUserId = cleanString(req.body.adminUserId || req.body.userId || req.body.user_id) || null;
  if (!serialId && !serialNo) {
    return res.status(400).json({ error: "Select a replacement serial number to dispatch." });
  }

  const caseRow = await query(
    `SELECT rr.*, c.complaint_no, c.status AS complaint_status, cust.name AS customer_name, cust.mobile AS customer_mobile,
            d.dealer_no, d.name AS dealer_name, d.mobile AS dealer_mobile,
            du.id AS dealer_user_id,
            p.name AS product_name, p.model_no
     FROM replace_return_cases rr
     INNER JOIN complaints c ON c.id = rr.complaint_id
     LEFT JOIN customers cust ON cust.id = rr.customer_id
     LEFT JOIN dealers d ON d.id = rr.dealer_id
     LEFT JOIN users du ON du.role = 'Dealer' AND ${sqlNormalizeMobileColumn("du.mobile")} = ${sqlNormalizeMobileColumn("d.mobile")}
     LEFT JOIN serial_numbers s ON s.id = rr.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );
  if (!caseRow.rowCount) {
    return res.status(404).json({ error: "Replace/Return case not found." });
  }
  const row = caseRow.rows[0];
  if (String(row.status || "") !== "Admin Received") {
    return res.status(400).json({ error: "Admin must receive the product before dispatching replacement." });
  }
  if (String(row.action_type || "") === "Return") {
    return res.status(400).json({ error: "Return cases do not need replacement dispatch. Process refund/payment offline after admin receive." });
  }
  if (row.replacement_serial_id) {
    return res.status(409).json({ error: "Replacement already dispatched for this case." });
  }

  const serialResult = serialId
    ? await query(
        `SELECT s.*, p.name AS product_name, p.model_no
         FROM serial_numbers s
         LEFT JOIN products p ON p.id = s.product_id
         WHERE s.id = ?
         LIMIT 1`,
        [serialId]
      )
    : await query(
        `SELECT s.*, p.name AS product_name, p.model_no
         FROM serial_numbers s
         LEFT JOIN products p ON p.id = s.product_id
         WHERE s.serial_no = ?
         LIMIT 1`,
        [serialNo]
      );
  if (!serialResult.rowCount) {
    return res.status(404).json({ error: "Replacement serial not found." });
  }
  const serial = serialResult.rows[0];
  if (serial.dealer_id) {
    return res.status(409).json({ error: "This serial is already assigned to a dealer." });
  }
  if (String(serial.dispatch_status || "") !== "Pending") {
    return res.status(409).json({ error: "This serial is not available for dispatch." });
  }
  if (serial.replacement_case_id) {
    return res.status(409).json({ error: "This serial is already marked as a customer replacement." });
  }

  const dealer = await resolveDealerRecord(row.dealer_id);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found for this case." });
  }

  const replacementLabel = `Replacement for ${row.customer_name || "Customer"} - ${row.complaint_no || row.case_no}`;
  const batchNo = `RPL-${Date.now()}`;
  const qrPayload = replacementDeliveryQrPayload({
    caseId,
    caseNo: row.case_no,
    serialNo: serial.serial_no,
    customerId: row.customer_id || null,
    complaintNo: row.complaint_no || null,
  });

  await withTransaction(async (tx) => {
    await tx(
      `UPDATE serial_numbers
       SET dealer_id = ?,
           batch_no = ?,
           dispatch_date = CURDATE(),
           qr_status = 'Printed',
           qr_payload = ?,
           qr_printed_at = NOW(),
           dispatch_status = 'Dispatched',
           dispatched_at = NOW(),
           replacement_case_id = ?,
           replacement_for_customer_id = ?,
           replacement_label = ?
       WHERE id = ?`,
      [dealer.id, batchNo, qrPayload, caseId, row.customer_id || null, replacementLabel, serial.id]
    );
    await tx(
      `UPDATE replace_return_cases
       SET status = 'Replacement Dispatched',
           replacement_serial_id = ?,
           replacement_dispatched_at = CURRENT_TIMESTAMP,
           replacement_dispatched_by = ?
       WHERE id = ?`,
      [serial.id, adminUserId, caseId]
    );
    await tx("UPDATE complaints SET status = 'Replacement Dispatched to Dealer' WHERE id = ?", [row.complaint_id]);
    await recordStatusHistory({
      complaintId: row.complaint_id,
      oldStatus: row.complaint_status,
      newStatus: "Replacement Dispatched to Dealer",
      changedByRole: "Admin",
      changedById: adminUserId,
      remarks: `${replacementLabel} - new serial ${serial.serial_no} sent to ${dealer.dealer_no}`,
    }, tx);
  });

  if (row.dealer_user_id) {
    await createNotification({
      userId: row.dealer_user_id,
      recipientRole: "Dealer",
      type: "replacement_dispatched",
      title: "Customer replacement product dispatched",
      message: `${serial.serial_no} - ${replacementLabel}. Give this unit to the customer.`,
      entityType: "replace_return",
      entityId: caseId,
    });
  }

  const detail = await query(
    `SELECT ${REPLACE_RETURN_DETAIL_SELECT}
     ${REPLACE_RETURN_DETAIL_JOINS}
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );

  res.status(201).json({
    case: detail.rows[0],
    serial: {
      id: serial.id,
      serial_no: serial.serial_no,
      product_name: serial.product_name,
      model_no: serial.model_no,
      replacement_label: replacementLabel,
      qr_payload: qrPayload,
    },
    qrPayload,
    qrUrl: `/replace-return/${caseId}/replacement-qr.svg`,
    message: `Replacement ${serial.serial_no} dispatched to ${dealer.name}. Print QR sticker - dealer will scan to deliver to customer.`,
  });
}));

app.get("/replace-return/:id/replacement-qr.svg", asyncRoute(async (req, res) => {
  const caseId = await resolveReplaceReturnCase(req.params.id);
  if (!caseId) {
    return res.status(404).json({ error: "Replace/Return case not found." });
  }
  const row = await query(
    `SELECT rs.qr_payload
     FROM replace_return_cases rr
     LEFT JOIN serial_numbers rs ON rs.id = rr.replacement_serial_id
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );
  if (!row.rowCount || !row.rows[0].qr_payload) {
    return res.status(404).json({ error: "Replacement QR not generated yet. Dispatch replacement first." });
  }
  res.setHeader("Content-Type", "image/svg+xml");
  res.send(qrSvg(row.rows[0].qr_payload, 280));
}));

app.get("/replacement-delivery/scan", asyncRoute(async (req, res) => {
  await ensureReplaceReturnSchema();
  await ensureSerialNumbersSchema();
  const caseKey = cleanString(req.query.caseId || req.query.case_id || req.query.caseNo || req.query.case_no);
  const serialNo = cleanSerialNo(req.query.serial || req.query.serialNo || req.query.serial_no);
  let caseId = caseKey ? await resolveReplaceReturnCase(caseKey) : null;
  if (!caseId && serialNo) {
    const bySerial = await query(
      `SELECT rr.id
       FROM replace_return_cases rr
       INNER JOIN serial_numbers s ON s.id = rr.replacement_serial_id
       WHERE LOWER(TRIM(s.serial_no)) = LOWER(TRIM(?))
       LIMIT 1`,
      [serialNo]
    );
    caseId = bySerial.rowCount ? bySerial.rows[0].id : null;
  }
  if (!caseId) {
    return res.status(404).json({ error: "Replacement delivery record not found." });
  }
  const result = await query(
    `SELECT ${REPLACE_RETURN_DETAIL_SELECT},
            rs.id AS replacement_serial_id,
            rs.qr_payload AS replacement_qr_payload,
            rs.replacement_label,
            cust.address AS customer_address,
            cust.pincode AS customer_pincode
     ${REPLACE_RETURN_DETAIL_JOINS}
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );
  if (!result.rowCount) {
    return res.status(404).json({ error: "Replacement delivery record not found." });
  }
  const row = result.rows[0];
  if (!row.replacement_serial_id) {
    return res.status(400).json({ error: "Replacement unit not dispatched yet." });
  }
  if (String(row.status || "") === "Delivered to Customer") {
    return res.status(409).json({ error: "This replacement was already delivered to the customer." });
  }
  res.json({
    delivery: {
      caseId: row.id,
      caseNo: row.case_no,
      status: row.status,
      complaintNo: row.complaint_no,
      productName: row.replacement_product_name || row.product_name,
      modelNo: row.replacement_model_no || row.model_no,
      serialNo: row.replacement_serial_no,
      replacementLabel: row.replacement_label,
      qrPayload: row.replacement_qr_payload,
      customerId: row.customer_id,
      customerName: row.customer_name,
      customerMobile: row.customer_mobile,
      customerAddress: row.customer_address,
      customerCity: row.customer_city,
      customerPincode: row.customer_pincode,
      dealerId: row.dealer_id,
      dealerNo: row.dealer_no,
      dealerName: row.dealer_name,
      warrantyNo: row.warranty_no,
      warrantyStatus: row.warranty_status,
      warrantyStart: row.warranty_start,
      warrantyExpiry: row.warranty_expiry,
      problemDetails: row.problem_details,
      technicianRemarks: row.technician_remarks,
    },
  });
}));

app.post("/replacement-delivery/confirm", asyncRoute(async (req, res) => {
  await ensureReplaceReturnSchema();
  await ensureComplaintsSchema();
  await ensureNotificationsSchema();
  const caseId = await resolveReplaceReturnCase(req.body.caseId || req.body.case_id || req.body.caseNo || req.body.case_no);
  const dealerId = cleanString(req.body.dealerId || req.body.dealer_id);
  const confirmedById = cleanString(req.body.userId || req.body.user_id || req.body.dealerUserId) || null;
  if (!caseId) {
    return res.status(400).json({ error: "Replacement case is required." });
  }
  if (!dealerId) {
    return res.status(400).json({ error: "Dealer id is required." });
  }
  const dealer = await resolveDealerRecord(dealerId);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found." });
  }

  const caseRow = await query(
    `SELECT rr.*, c.complaint_no, c.status AS complaint_status, w.id AS warranty_id, w.warranty_no,
            rs.serial_no AS replacement_serial_no, rs.id AS replacement_serial_id,
            rs.dealer_id AS replacement_serial_dealer_id,
            rs.dispatch_status AS replacement_serial_dispatch_status,
            rs.dispatched_at AS replacement_serial_dispatched_at
     FROM replace_return_cases rr
     INNER JOIN complaints c ON c.id = rr.complaint_id
     LEFT JOIN warranties w ON w.id = rr.warranty_id
     LEFT JOIN serial_numbers rs ON rs.id = rr.replacement_serial_id
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );
  if (!caseRow.rowCount) {
    return res.status(404).json({ error: "Replacement case not found." });
  }
  const row = caseRow.rows[0];
  if (String(row.dealer_id) !== String(dealer.id)) {
    return res.status(403).json({ error: "This replacement is not assigned to your dealership." });
  }
  if (!row.replacement_serial_id) {
    return res.status(400).json({ error: "Replacement unit not dispatched yet." });
  }
  if (
    row.replacement_serial_dealer_id &&
    String(row.replacement_serial_dealer_id) !== String(dealer.id)
  ) {
    return res.status(403).json({ error: "This replacement unit is assigned to another dealer." });
  }
  if (String(row.status || "") === "Delivered to Customer") {
    return res.status(409).json({ error: "Already delivered to customer." });
  }
  const hasDispatchEvidence =
    String(row.status || "") === "Replacement Dispatched" ||
    Boolean(row.replacement_dispatched_at) ||
    (
      String(row.replacement_serial_dispatch_status || "") === "Dispatched" &&
      Boolean(row.replacement_serial_dispatched_at) &&
      String(row.replacement_serial_dealer_id || "") === String(dealer.id)
    );
  if (!hasDispatchEvidence) {
    return res.status(400).json({ error: "Replacement must be dispatched by Admin before dealer delivery." });
  }

  await withTransaction(async (tx) => {
    if (row.warranty_id) {
      await tx("UPDATE warranties SET serial_id = ? WHERE id = ?", [row.replacement_serial_id, row.warranty_id]);
    }
    await tx(
      `UPDATE replace_return_cases
       SET status = 'Delivered to Customer', delivered_to_customer_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [caseId]
    );
    await tx("UPDATE complaints SET status = 'Replacement Completed' WHERE id = ?", [row.complaint_id]);
    await recordStatusHistory({
      complaintId: row.complaint_id,
      oldStatus: row.complaint_status,
      newStatus: "Replacement Completed",
      changedByRole: "Dealer",
      changedById: confirmedById,
      remarks: `Replacement unit ${row.replacement_serial_no} delivered to customer`,
    }, tx);
  });

  if (row.customer_id) {
    await createNotification({
      customerId: row.customer_id,
      recipientRole: "Customer",
      type: "replacement_delivered",
      title: "Replacement product received",
      message: `Your replacement ${row.replacement_serial_no} was delivered by ${dealer.name}.`,
      entityType: "complaint",
      entityId: row.complaint_id,
    });
  }

  const detail = await query(
    `SELECT ${REPLACE_RETURN_DETAIL_SELECT}
     ${REPLACE_RETURN_DETAIL_JOINS}
     WHERE rr.id = ?
     LIMIT 1`,
    [caseId]
  );

  res.json({
    case: detail.rows[0],
    message: `Replacement delivered to customer. Warranty now linked to serial ${row.replacement_serial_no}.`,
  });
}));

/** List complaints (staff panels). Customers should use `/complaints/customer/:customerId`. */
app.get("/complaints", asyncRoute(async (_req, res) => {
  await ensureComplaintsSchema();
  await ensureTasksSchema();
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
       ${COMPLAINT_LATEST_TASK_FIELDS},
       ${COMPLAINT_LATEST_QUOTATION_FIELDS}
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
    LEFT JOIN dealers d ON d.id = COALESCE(c.dealer_id, w.dealer_id, s.dealer_id)
     ${COMPLAINT_LATEST_TASK_JOIN}
     ${COMPLAINT_FEEDBACK_JOIN}
     ${COMPLAINT_LATEST_QUOTATION_JOIN}
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
       ), 'Pending') AS warranty_status,
       (
         SELECT w.warranty_no
         FROM warranties w
         WHERE w.serial_id = s.id
         ORDER BY w.created_at DESC
         LIMIT 1
       ) AS warranty_no,
       (
         SELECT w.id
         FROM warranties w
         WHERE w.serial_id = s.id
         ORDER BY w.created_at DESC
         LIMIT 1
       ) AS warranty_id,
       (
         SELECT w.installation_status
         FROM warranties w
         WHERE w.serial_id = s.id
         ORDER BY w.created_at DESC
         LIMIT 1
       ) AS installation_status,
       (
         SELECT w.customer_id
         FROM warranties w
         WHERE w.serial_id = s.id
         ORDER BY w.created_at DESC
         LIMIT 1
       ) AS warranty_customer_id
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

  res.type("html").send(buildDispatchQrPrintHtml(result.rows, "Serial QR Print Sheet"));
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
       t.completion_code_sent_at,
       t.completion_verified_at,
       t.payable_amount,
       t.assigned_by_role,
       t.assigned_by_id,
       assigned_user.name AS assigned_by_name,
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
       p.category AS product_category,
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
     LEFT JOIN users assigned_user ON assigned_user.id = t.assigned_by_id
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
  await ensureTasksSchema();
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
    where.push("(c.status IS NULL OR c.status NOT IN ('Quotation Rejected', 'Customer Rejected'))");
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
  await ensureTasksSchema();
  const taskId = await resolveTaskId(req.params.id);
  if (!taskId) {
    return res.status(404).json({ error: "Task not found." });
  }
  const result = await query(
    `SELECT ${TASK_DETAIL_SELECT}
     ${TASK_DETAIL_JOINS}
     WHERE t.id = ?
     LIMIT 1`,
    [taskId]
  );
  if (!result.rowCount) {
    return res.status(404).json({ error: "Task not found." });
  }
  res.json({ task: result.rows[0] });
}));

app.patch("/tasks/:id/status", asyncRoute(async (req, res) => {
  await ensureTasksSchema();
  const taskId = await resolveTaskId(req.params.id);
  const rawStatus = cleanString(req.body?.status);
  const dueAt = cleanString(req.body?.dueAt || req.body?.due_at) || null;
  const technicianId = cleanString(req.body?.technicianId || req.body?.technician_id);
  const resolutionNotes = cleanString(req.body?.resolutionNotes || req.body?.resolution_notes) || null;
  if (!taskId || !rawStatus) {
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
    "On Hold",
    "Unrepairable",
    "Pending Happy Code",
    "Completed",
    "Closed"
  ];
  const normalizedStatus = allowed.find((item) => item.toLowerCase() === rawStatus.toLowerCase());
  if (!normalizedStatus) {
    return res.status(400).json({ error: "Invalid task status." });
  }
  const status = normalizedStatus;
  const id = taskId;
  const existing = await query(
    `SELECT t.id, t.complaint_id, t.technician_id, t.status, t.work_type, c.warranty_id
     FROM tasks t
     LEFT JOIN complaints c ON c.id = t.complaint_id
     WHERE t.id = ?
     LIMIT 1`,
    [id]
  );
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Task not found." });
  }
  const row = existing.rows[0];
  const isInstallationTask = String(row.work_type || "").trim().toLowerCase() === "installation";
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
  if ((status === "Completed" || status === "Closed") && technicianId && !resolutionNotes) {
    return res.status(400).json({ error: "Completion remark required hai." });
  }

  const complaintId = row.complaint_id;
  const complaintBefore = complaintId
    ? await query("SELECT status FROM complaints WHERE id = ? LIMIT 1", [complaintId])
    : { rowCount: 0, rows: [] };
  const oldComplaintStatus = complaintBefore.rows[0]?.status || null;
  let pendingHappyCode = null;

  await ensureWorkflowAuditSchema();
  await withTransaction(async (tx) => {
    if (dueAt && (status === "Rescheduled" || status === "Scheduled")) {
      await tx("UPDATE tasks SET status = ?, due_at = ? WHERE id = ?", [status, dueAt, id]);
    } else if (status === "Unrepairable") {
      await tx(
        "UPDATE tasks SET status = ?, resolution_notes = COALESCE(?, resolution_notes) WHERE id = ?",
        [status, resolutionNotes, id]
      );
    } else if ((status === "Completed" || status === "Closed") && technicianId) {
      const happyCode = String(crypto.randomInt(100000, 1000000));
      pendingHappyCode = happyCode;
      await tx(
        `UPDATE tasks
         SET status = 'Pending Happy Code',
             resolution_notes = COALESCE(?, resolution_notes),
             completion_happy_code = ?,
             completion_code_sent_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [resolutionNotes, happyCode, id]
      );
    } else if (status === "Completed" || status === "Closed") {
      await tx(
        `UPDATE tasks
         SET status = ?,
             completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP),
             completion_verified_at = COALESCE(completion_verified_at, CURRENT_TIMESTAMP),
             resolution_notes = COALESCE(?, resolution_notes)
         WHERE id = ?`,
        [status, resolutionNotes, id]
      );
      await ensurePaymentForCompletedTask(id, tx);
      if (isInstallationTask && row.warranty_id) {
        await tx("UPDATE warranties SET installation_status = 'Completed' WHERE id = ?", [row.warranty_id]);
      }
    } else if (resolutionNotes) {
      await tx("UPDATE tasks SET status = ?, resolution_notes = ? WHERE id = ?", [status, resolutionNotes, id]);
    } else {
      await tx("UPDATE tasks SET status = ? WHERE id = ?", [status, id]);
    }
    if (status === "Rejected" && isInstallationTask && row.warranty_id) {
      await tx("UPDATE warranties SET installation_status = 'Required' WHERE id = ?", [row.warranty_id]);
    }
    if (status === "Accepted" && isInstallationTask && row.warranty_id) {
      await tx("UPDATE warranties SET installation_status = 'In Progress' WHERE id = ?", [row.warranty_id]);
    }
    if (!complaintId) return;
    const nextComplaintStatus = complaintStatusForTaskStatus((status === "Completed" || status === "Closed") && technicianId ? "Pending Happy Code" : status);
    if (nextComplaintStatus) {
      await tx("UPDATE complaints SET status = ? WHERE id = ?", [nextComplaintStatus, complaintId]);
      await recordStatusHistory({
        complaintId,
        oldStatus: oldComplaintStatus,
        newStatus: nextComplaintStatus,
        changedByRole: "Technician",
        changedById: technicianId || row.technician_id || null,
        remarks: resolutionNotes || `Task marked ${nextComplaintStatus === "Pending Customer Confirmation" ? "Pending Happy Code" : status}`,
      }, tx);
    }
    await createWorkflowMessage({
      complaintId,
      senderRole: "Technician",
      senderId: technicianId || row.technician_id || null,
      receiverRole: "Front Desk",
      message: resolutionNotes || `Task status changed to ${nextComplaintStatus === "Pending Customer Confirmation" ? "Pending Happy Code" : status}.`,
    }, tx);
  });

  const taskResult = await query(
    `SELECT ${TASK_DETAIL_SELECT}
     ${TASK_DETAIL_JOINS}
     WHERE t.id = ?
     LIMIT 1`,
    [id]
  );

  if (["Accepted", "Rejected", "On Hold", "Completed", "Closed"].includes(status) && row.complaint_id) {
    await ensureNotificationsSchema();
    const ctx = await getComplaintNotifyContext(row.complaint_id);
    if (ctx?.customer_id) {
      await createNotification({
        customerId: ctx.customer_id,
        type: `technician_${status.toLowerCase().replace(/\s+/g, "_")}`,
        title:
          status === "Accepted"
            ? "Technician accepted your complaint"
            : status === "Rejected"
              ? "Technician declined assignment"
              : status === "Completed" || status === "Closed"
                ? (pendingHappyCode ? "Happy Code for service confirmation" : "Service completed")
                : "Service put on hold",
        message:
          status === "Accepted"
            ? `${ctx.technician_name || "Technician"} accepted and will schedule a visit.`
            : status === "Rejected"
              ? "Front Desk will assign another technician."
              : status === "Completed" || status === "Closed"
                ? (pendingHappyCode
                  ? `Technician marked the job done. Happy Code: ${pendingHappyCode}. Share this code with technician only after checking the problem is solved.`
                  : `Complaint ${ctx.complaint_no || ""} is marked ${status}.`)
                : `Complaint ${ctx.complaint_no || ""} is on hold. ${resolutionNotes || ""}`.trim(),
        entityType: "complaint",
        entityId: row.complaint_id,
      });
    }
    if (ctx?.created_by_role === "Dealer" && ctx?.dealer_id) {
      await createNotification({
        userId: ctx.dealer_user_id || null,
        recipientRole: "Dealer",
        type: `task_${status.toLowerCase()}`,
        title:
          status === "Accepted"
            ? "Technician accepted job"
            : status === "Rejected"
              ? "Technician rejected job"
              : `Technician marked ${status}`,
        message: `${ctx.complaint_no || "Complaint"} - ${ctx.technician_name || "Technician"} ${status.toLowerCase()}.`,
        entityType: "complaint",
        entityId: row.complaint_id,
      });
    }
    await createNotification({
      recipientRole: "Front Desk",
      type: `task_${status.toLowerCase()}`,
      title:
        status === "Accepted"
          ? "Technician accepted"
          : status === "Rejected"
            ? "Technician rejected"
            : `Technician marked ${status}`,
      message: `${ctx?.complaint_no || "Complaint"}: ${ctx?.technician_name || "Technician"} ${status}.`,
      entityType: "complaint",
      entityId: row.complaint_id,
    });
  }

  res.json({ task: taskResult.rowCount ? taskResult.rows[0] : null });
}));

app.post("/tasks/:id/verify-happy-code", asyncRoute(async (req, res) => {
  await ensureTasksSchema();
  await ensureWorkflowAuditSchema();
  await ensureNotificationsSchema();
  const taskId = await resolveTaskId(req.params.id);
  const technicianId = cleanString(req.body?.technicianId || req.body?.technician_id);
  const happyCode = normalizeMobileValue(req.body?.happyCode || req.body?.happy_code || req.body?.code);
  if (!taskId || !happyCode) {
    return res.status(400).json({ error: "Task and Happy Code are required." });
  }

  const existing = await query(
    `SELECT t.id, t.complaint_id, t.technician_id, t.status, t.work_type, t.completion_happy_code, c.status AS complaint_status, c.warranty_id
     FROM tasks t
     LEFT JOIN complaints c ON c.id = t.complaint_id
     WHERE t.id = ?
     LIMIT 1`,
    [taskId]
  );
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Task not found." });
  }
  const row = existing.rows[0];
  if (technicianId && String(row.technician_id) !== technicianId) {
    return res.status(403).json({ error: "This task is not assigned to you." });
  }
  if (String(row.status || "") !== "Pending Happy Code") {
    return res.status(400).json({ error: "This task is not waiting for Happy Code verification." });
  }
  if (String(row.completion_happy_code || "") !== happyCode) {
    return res.status(401).json({ error: "Happy Code galat hai. Customer notification se sahi code daalein." });
  }

  const isInstallationTask = String(row.work_type || "").trim().toLowerCase() === "installation";
  await withTransaction(async (tx) => {
    await tx(
      `UPDATE tasks
       SET status = 'Completed',
           completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP),
           completion_verified_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [taskId]
    );
    await ensurePaymentForCompletedTask(taskId, tx);
    if (isInstallationTask && row.warranty_id) {
      await tx("UPDATE warranties SET installation_status = 'Completed' WHERE id = ?", [row.warranty_id]);
    }
    if (row.complaint_id) {
      await tx("UPDATE complaints SET status = 'Closed' WHERE id = ?", [row.complaint_id]);
      await recordStatusHistory({
        complaintId: row.complaint_id,
        oldStatus: row.complaint_status || null,
        newStatus: "Closed",
        changedByRole: "Technician",
        changedById: technicianId || row.technician_id || null,
        remarks: "Happy Code verified; problem successfully completed.",
      }, tx);
      await createWorkflowMessage({
        complaintId: row.complaint_id,
        senderRole: "Technician",
        senderId: technicianId || row.technician_id || null,
        receiverRole: "Front Desk",
        message: "Happy Code verified. Problem successfully completed.",
      }, tx);
    }
  });

  const taskResult = await query(
    `SELECT ${TASK_DETAIL_SELECT}
     ${TASK_DETAIL_JOINS}
     WHERE t.id = ?
     LIMIT 1`,
    [taskId]
  );
  const ctx = row.complaint_id ? await getComplaintNotifyContext(row.complaint_id) : null;
  if (ctx?.customer_id) {
    await createNotification({
      customerId: ctx.customer_id,
      type: "happy_code_verified",
      title: "Problem successfully completed",
      message: `Complaint ${ctx.complaint_no || ""} completed after Happy Code verification.`,
      entityType: "complaint",
      entityId: row.complaint_id,
    });
  }
  await createNotification({
    recipientRole: "Front Desk",
    type: "complaint_completed",
    title: "Complaint completed",
    message: `${ctx?.complaint_no || "Complaint"} completed after Happy Code verification.`,
    entityType: "complaint",
    entityId: row.complaint_id,
  });
  await createNotification({
    recipientRole: "Admin",
    type: "complaint_completed",
    title: "Complaint completed",
    message: `${ctx?.complaint_no || "Complaint"} completed after Happy Code verification.`,
    entityType: "complaint",
    entityId: row.complaint_id,
  });

  res.json({
    ok: true,
    message: "Happy Code verified. Problem successfully completed.",
    task: taskResult.rowCount ? taskResult.rows[0] : null,
  });
}));

app.post("/tasks/:id/mark-unrepairable", asyncRoute(async (req, res) => {
  await ensureTasksSchema();
  await ensureWorkflowAuditSchema();
  const taskId = await resolveTaskId(req.params.id);
  const technicianId = cleanString(req.body.technicianId || req.body.technician_id);
  const resolutionNotes = cleanString(req.body.resolutionNotes || req.body.resolution_notes);
  if (!taskId) {
    return res.status(404).json({ error: "Task not found." });
  }
  if (!resolutionNotes) {
    return res.status(400).json({ error: "Explain why the product cannot be repaired." });
  }
  const id = taskId;
  const existing = await query(
    `SELECT t.id, t.complaint_id, t.technician_id, t.status, t.work_type
     FROM tasks t
     WHERE t.id = ?
     LIMIT 1`,
    [id]
  );
  if (!existing.rowCount) {
    return res.status(404).json({ error: "Task not found." });
  }
  const row = existing.rows[0];
  if (technicianId && String(row.technician_id) !== technicianId) {
    return res.status(403).json({ error: "This task is not assigned to you." });
  }
  const current = String(row.status || "");
  if (["Completed", "Closed", "Unrepairable", "Rejected"].includes(current)) {
    return res.status(400).json({ error: `Task cannot be marked unrepairable from status ${current}.` });
  }
  if (String(row.work_type || "").trim().toLowerCase() === "installation") {
    return res.status(400).json({ error: "Installation jobs cannot use cannot-repair. Complete or reject the job." });
  }
  const complaintId = row.complaint_id;
  const complaintBefore = complaintId
    ? await query("SELECT status FROM complaints WHERE id = ? LIMIT 1", [complaintId])
    : { rowCount: 0, rows: [] };
  const oldComplaintStatus = complaintBefore.rows[0]?.status || null;

  await withTransaction(async (tx) => {
    await tx(
      "UPDATE tasks SET status = 'Unrepairable', resolution_notes = ? WHERE id = ?",
      [resolutionNotes, id]
    );
    if (!complaintId) return;
    await tx("UPDATE complaints SET status = 'Awaiting Dealer Action' WHERE id = ?", [complaintId]);
    await recordStatusHistory({
      complaintId,
      oldStatus: oldComplaintStatus,
      newStatus: "Awaiting Dealer Action",
      changedByRole: "Technician",
      changedById: technicianId || row.technician_id || null,
      remarks: resolutionNotes,
    }, tx);
    await createWorkflowMessage({
      complaintId,
      senderRole: "Technician",
      senderId: technicianId || row.technician_id || null,
      receiverRole: "Dealer",
      message: `Product cannot be repaired. Send to dealer for Replace/Return. ${resolutionNotes}`,
    }, tx);
  });

  const taskResult = await query(
    `SELECT ${TASK_DETAIL_SELECT}
     ${TASK_DETAIL_JOINS}
     WHERE t.id = ?
     LIMIT 1`,
    [id]
  );

  if (complaintId) {
    await ensureNotificationsSchema();
    const ctx = await getComplaintNotifyContext(complaintId);
    if (ctx?.created_by_role === "Dealer" && ctx?.dealer_id) {
      await createNotification({
        userId: ctx.dealer_user_id || null,
        recipientRole: "Dealer",
        type: "task_unrepairable",
        title: "Product cannot be repaired",
        message: `${ctx.complaint_no || "Complaint"} - technician could not repair. Open Replace/Return.`,
        entityType: "complaint",
        entityId: complaintId,
      });
    }
  }

  res.json({
    task: taskResult.rowCount ? taskResult.rows[0] : null,
    message: "Marked as cannot repair. Dealer will process Replace/Return.",
  });
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
       cust.name AS dispatched_customer_name,
       cust.mobile AS dispatched_customer_mobile,
       wcust.name AS warranty_customer_name,
       wcust.mobile AS warranty_customer_mobile,
       wcust.name AS customer_name,
       wcust.mobile AS customer_mobile,
       w.warranty_no,
       w.id AS warranty_id,
       w.status AS warranty_status,
       w.customer_id AS warranty_customer_id,
       w.installation_status,
       w.start_date,
       w.expiry_date
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = s.dealer_id
     LEFT JOIN customers cust ON cust.id = s.dispatched_customer_id
     LEFT JOIN warranties w ON w.serial_id = s.id
     LEFT JOIN customers wcust ON wcust.id = w.customer_id
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

async function fetchAvailableSerialUnits({ categoryId, productName, productId, limit, tx }) {
  const run = tx || query;
  const clauses = ["s.dealer_id IS NULL", "s.dispatch_status = 'Pending'"];
  const params = [];
  if (categoryId) {
    clauses.push("p.category_id = ?");
    params.push(categoryId);
  }
  if (productName) {
    clauses.push("p.name = ?");
    params.push(productName);
  }
  if (productId) {
    clauses.push("p.id = ?");
    params.push(productId);
  }
  params.push(limit);
  const result = await run(
    `SELECT s.*, p.name AS product_name, p.model_no, p.id AS product_id, p.category_id
     FROM serial_numbers s
     INNER JOIN products p ON p.id = s.product_id
     WHERE ${clauses.join(" AND ")}
     ORDER BY p.model_no ASC, s.serial_no ASC
     LIMIT ?`,
    params
  );
  return result.rows;
}

app.get("/dispatch/availability", asyncRoute(async (req, res) => {
  await ensureProductsQrSchema();
  const categoryId = cleanString(req.query.categoryId || req.query.category_id);
  const categoriesResult = await query(
    `SELECT
       c.id,
       c.name,
       COUNT(s.id) AS available_count
     FROM product_categories c
     LEFT JOIN products p ON p.category_id = c.id
     LEFT JOIN serial_numbers s
       ON s.product_id = p.id
      AND s.dealer_id IS NULL
      AND s.dispatch_status = 'Pending'
     GROUP BY c.id, c.name
     ORDER BY c.name ASC`
  );

  if (!categoryId) {
    return res.json({
      categories: categoriesResult.rows.map((row) => ({
        id: row.id,
        name: row.name,
        availableCount: Number(row.available_count || 0),
      })),
    });
  }

  const category = categoriesResult.rows.find((row) => row.id === categoryId);
  if (!category) {
    return res.status(404).json({ error: "Category not found." });
  }

  const linesResult = await query(
    `SELECT
       p.name AS product_name,
       COUNT(s.id) AS available_count,
       MIN(p.model_no) AS first_model,
       MAX(p.model_no) AS last_model,
       MAX(COALESCE(p.installation_required, 0)) AS installation_required
     FROM products p
     INNER JOIN serial_numbers s
       ON s.product_id = p.id
      AND s.dealer_id IS NULL
      AND s.dispatch_status = 'Pending'
     WHERE p.category_id = ?
     GROUP BY p.name
     ORDER BY p.name ASC`,
    [categoryId]
  );

  res.json({
    category: {
      id: category.id,
      name: category.name,
      availableCount: Number(category.available_count || 0),
    },
    productLines: linesResult.rows.map((row) => ({
      productName: row.product_name,
      availableCount: Number(row.available_count || 0),
      firstModel: row.first_model,
      lastModel: row.last_model,
      installationRequired: Boolean(Number(row.installation_required || 0)),
    })),
  });
}));

app.post("/dispatch/to-dealer", asyncRoute(async (req, res) => {
  await ensureSerialNumbersSchema();
  await ensureProductsQrSchema();
  const dealerId = cleanString(req.body.dealerId || req.body.dealer_id);
  const dealerNo = cleanString(req.body.dealerNo || req.body.dealer_no);
  const categoryId = cleanString(req.body.categoryId || req.body.category_id);
  const invoiceNo = cleanString(req.body.invoiceNo || req.body.invoice_no) || null;
  const challanNo = cleanString(req.body.challanNo || req.body.challan_no) || null;
  const dispatchDate = cleanDate(req.body.dispatchDate || req.body.dispatch_date);
  const batchNo = cleanString(req.body.batchNo || req.body.batch_no) || `DSP-${Date.now()}`;

  let dealer = null;
  if (dealerId || dealerNo) {
    dealer = dealerId
      ? await resolveDealerRecord(dealerId)
      : (await query("SELECT * FROM dealers WHERE LOWER(TRIM(dealer_no)) = LOWER(?) AND status = 'Active' LIMIT 1", [dealerNo])).rows[0] || null;
    if (!dealer) {
      return res.status(400).json({ error: "Active dealer not found." });
    }
  }

  let dispatchItems = Array.isArray(req.body.items)
    ? req.body.items
        .map((item) => ({
          productName: cleanString(item.productName || item.product_name || item.name),
          quantity: Number(item.quantity),
          installationRequired: parseInstallationRequired(
            item.installationRequired ?? item.installation_required,
            false
          ),
        }))
        .filter((item) => item.productName && Number.isInteger(item.quantity) && item.quantity > 0)
    : [];

  let resolvedCategoryId = categoryId;

  if (!dispatchItems.length) {
    const productId = cleanString(req.body.productId || req.body.product_id);
    const productName = cleanString(req.body.productName || req.body.product_name);
    const modelNo = cleanString(req.body.modelNo || req.body.model_no);
    const quantity = Number(req.body.quantity);
    if (!productId && !productName && !modelNo) {
      return res.status(400).json({ error: "Select a category and product quantities to dispatch." });
    }
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 500) {
      return res.status(400).json({ error: "Quantity must be a whole number between 1 and 500." });
    }
    const product = await resolveProductFromMaster({ productId, productName, modelNo });
    dispatchItems = [{ productName: product.name, quantity }];
    if (!resolvedCategoryId && product.category_id) {
      resolvedCategoryId = cleanString(product.category_id);
    }
  }

  if (!resolvedCategoryId) {
    return res.status(400).json({ error: "Select a product category." });
  }

  const categoryResult = await query("SELECT id, name FROM product_categories WHERE id = ? LIMIT 1", [resolvedCategoryId]);
  if (!categoryResult.rowCount) {
    return res.status(404).json({ error: "Category not found." });
  }

  const totalRequested = dispatchItems.reduce((sum, item) => sum + item.quantity, 0);
  if (totalRequested < 1 || totalRequested > 500) {
    return res.status(400).json({ error: "Total dispatch quantity must be between 1 and 500." });
  }

  const dispatchedSerialNos = await withTransaction(async (tx) => {
    const serialNos = [];
    for (const item of dispatchItems) {
      const units = await fetchAvailableSerialUnits({
        categoryId: resolvedCategoryId,
        productName: item.productName,
        limit: item.quantity,
        tx,
      });
      if (units.length < item.quantity) {
        const err = new Error(
          `Only ${units.length} unit(s) available for ${item.productName}. ${item.quantity} requested.`
        );
        err.statusCode = 409;
        throw err;
      }
      for (const unit of units) {
        const qrPayload = dispatchUnitQrPayload({
          productId: unit.product_id,
          productName: unit.product_name,
          modelNo: unit.model_no,
          serialNo: unit.serial_no,
          dealerId: dealer?.id || "",
          dealerNo: dealer?.dealer_no || "",
          dealerName: dealer?.name || "",
        });
        await tx(
          `UPDATE serial_numbers
           SET dealer_id = ?,
               invoice_no = ?,
               challan_no = ?,
               batch_no = ?,
               dispatch_date = ?,
               qr_status = 'Printed',
               qr_payload = ?,
               qr_printed_at = NOW(),
               dispatch_status = 'Dispatched',
               dispatched_at = NOW(),
               installation_required = ?
          WHERE id = ?`,
          [
            dealer?.id || null,
            invoiceNo,
            challanNo,
            batchNo,
            dispatchDate,
            qrPayload,
            item.installationRequired ? 1 : 0,
            unit.id,
          ]
        );
        serialNos.push(unit.serial_no);
      }
    }
    return serialNos;
  });

  const detail = await query(
    `SELECT s.*, p.name AS product_name, p.model_no, d.dealer_no, d.name AS dealer_name
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = s.dealer_id
     WHERE s.batch_no = ?
     ORDER BY s.serial_no ASC`,
    [batchNo]
  );

  const productSummary = [...new Set(detail.rows.map((row) => row.product_name))].join(", ");
  res.status(201).json({
    batchNo,
    dispatchType: dealer ? "dealer" : "openDealer",
    category: categoryResult.rows[0],
    dealer: dealer ? { id: dealer.id, dealer_no: dealer.dealer_no, name: dealer.name } : null,
    count: dispatchedSerialNos.length,
    items: dispatchItems,
    serials: detail.rows,
    serialNumbers: detail.rows.map((row) => row.serial_no),
    printSheetUrl: `/dispatch/qr-print-sheet?batchNo=${encodeURIComponent(batchNo)}`,
    message: dealer
      ? `${dispatchedSerialNos.length} QR code(s) generated for ${dealer.name}. Open Dispatch QR Print to print stickers.`
      : `${dispatchedSerialNos.length} open dealer QR code(s) generated. Any dealer can scan and activate warranty from their login.`,
    productSummary,
  });
}));

app.post("/dispatch/to-self-sale-customer", asyncRoute(async (req, res) => {
  await ensureSerialNumbersSchema();
  await ensureProductsQrSchema();
  await ensureDealerCreatedBySchema();
  const customerId = cleanString(req.body.customerId || req.body.customer_id);
  const categoryId = cleanString(req.body.categoryId || req.body.category_id);
  const invoiceNo = cleanString(req.body.invoiceNo || req.body.invoice_no) || null;
  const challanNo = cleanString(req.body.challanNo || req.body.challan_no) || null;
  const dispatchDate = cleanDate(req.body.dispatchDate || req.body.dispatch_date);
  const batchNo = cleanString(req.body.batchNo || req.body.batch_no) || `SSD-${Date.now()}`;

  if (!customerId) {
    return res.status(400).json({ error: "Select a self-sale customer to dispatch products." });
  }

  const customerResult = await query(
    `SELECT c.id, c.name, c.mobile, c.created_by_dealer_id, COALESCE(u.status, 'Active') AS user_status
     FROM customers c
     LEFT JOIN users u ON u.id = c.user_id
     WHERE c.id = ?
     LIMIT 1`,
    [customerId]
  );
  if (!customerResult.rowCount) {
    return res.status(404).json({ error: "Customer not found." });
  }
  const customer = customerResult.rows[0];
  if (customer.created_by_dealer_id) {
    return res.status(400).json({ error: "Selected customer is not a self-sale customer. Choose a customer created via Self Sale." });
  }
  if (String(customer.user_status || "Active") !== "Active") {
    return res.status(400).json({ error: "Selected self-sale customer account is not active." });
  }

  let dispatchItems = Array.isArray(req.body.items)
    ? req.body.items
        .map((item) => ({
          productName: cleanString(item.productName || item.product_name || item.name),
          quantity: Number(item.quantity),
          installationRequired: parseInstallationRequired(
            item.installationRequired ?? item.installation_required,
            false
          ),
        }))
        .filter((item) => item.productName && Number.isInteger(item.quantity) && item.quantity > 0)
    : [];

  let resolvedCategoryId = categoryId;

  if (!dispatchItems.length) {
    const productId = cleanString(req.body.productId || req.body.product_id);
    const productName = cleanString(req.body.productName || req.body.product_name);
    const modelNo = cleanString(req.body.modelNo || req.body.model_no);
    const quantity = Number(req.body.quantity);
    if (!productId && !productName && !modelNo) {
      return res.status(400).json({ error: "Select a category and product quantities to dispatch." });
    }
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 500) {
      return res.status(400).json({ error: "Quantity must be a whole number between 1 and 500." });
    }
    const product = await resolveProductFromMaster({ productId, productName, modelNo });
    dispatchItems = [{
      productName: product.name,
      quantity,
      installationRequired: parseInstallationRequired(
        req.body.installationRequired ?? req.body.installation_required,
        false
      ),
    }];
    if (!resolvedCategoryId && product.category_id) {
      resolvedCategoryId = cleanString(product.category_id);
    }
  }

  if (!resolvedCategoryId) {
    return res.status(400).json({ error: "Select a product category." });
  }

  const categoryResult = await query("SELECT id, name FROM product_categories WHERE id = ? LIMIT 1", [resolvedCategoryId]);
  if (!categoryResult.rowCount) {
    return res.status(404).json({ error: "Category not found." });
  }

  const totalRequested = dispatchItems.reduce((sum, item) => sum + item.quantity, 0);
  if (totalRequested < 1 || totalRequested > 500) {
    return res.status(400).json({ error: "Total dispatch quantity must be between 1 and 500." });
  }

  const dispatchedSerialNos = await withTransaction(async (tx) => {
    const serialNos = [];
    for (const item of dispatchItems) {
      const units = await fetchAvailableSerialUnits({
        categoryId: resolvedCategoryId,
        productName: item.productName,
        limit: item.quantity,
        tx,
      });
      if (units.length < item.quantity) {
        const err = new Error(
          `Only ${units.length} unit(s) available for ${item.productName}. ${item.quantity} requested.`
        );
        err.statusCode = 409;
        throw err;
      }
      for (const unit of units) {
        const qrPayload = dispatchUnitQrPayload({
          productId: unit.product_id,
          productName: unit.product_name,
          modelNo: unit.model_no,
          serialNo: unit.serial_no,
          customerId: customer.id,
          customerName: customer.name,
          customerMobile: customer.mobile,
          dispatchType: "selfSale",
        });
        await tx(
          `UPDATE serial_numbers
           SET dispatched_customer_id = ?,
               dealer_id = NULL,
               invoice_no = ?,
               challan_no = ?,
               batch_no = ?,
               dispatch_date = ?,
               qr_status = 'Printed',
               qr_payload = ?,
               qr_printed_at = NOW(),
               dispatch_status = 'Dispatched',
               dispatched_at = NOW(),
               installation_required = ?
           WHERE id = ?`,
          [
            customer.id,
            invoiceNo,
            challanNo,
            batchNo,
            dispatchDate,
            qrPayload,
            item.installationRequired ? 1 : 0,
            unit.id,
          ]
        );
        serialNos.push(unit.serial_no);
      }
    }
    return serialNos;
  });

  const detail = await query(
    `SELECT s.*, p.name AS product_name, p.model_no, c.name AS customer_name, c.mobile AS customer_mobile
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN customers c ON c.id = s.dispatched_customer_id
     WHERE s.batch_no = ?
     ORDER BY s.serial_no ASC`,
    [batchNo]
  );

  const productSummary = [...new Set(detail.rows.map((row) => row.product_name))].join(", ");
  res.status(201).json({
    batchNo,
    dispatchType: "selfSale",
    category: categoryResult.rows[0],
    customer: { id: customer.id, name: customer.name, mobile: customer.mobile },
    count: dispatchedSerialNos.length,
    items: dispatchItems,
    serials: detail.rows,
    serialNumbers: detail.rows.map((row) => row.serial_no),
    printSheetUrl: `/dispatch/qr-print-sheet?batchNo=${encodeURIComponent(batchNo)}`,
    message: `${dispatchedSerialNos.length} QR code(s) generated for self-sale customer ${customer.name}. Customer can scan to activate warranty.`,
    productSummary,
  });
}));

app.get("/dispatch/dashboard", asyncRoute(async (_req, res) => {
  await ensureReplaceReturnSchema();
  const [
    totalDealers,
    stockAvailable,
    qrCreated,
    productsDispatched,
    dispatchBatches,
    replaceReturnTotal,
    replaceReturnOpen,
  ] = await Promise.all([
    query("SELECT COUNT(*) AS total FROM dealers WHERE status = 'Active'"),
    query(
      "SELECT COUNT(*) AS total FROM serial_numbers WHERE dealer_id IS NULL AND dispatch_status = 'Pending'"
    ),
    query("SELECT COUNT(*) AS total FROM serial_numbers WHERE qr_status = 'Printed'"),
    query("SELECT COUNT(*) AS total FROM serial_numbers WHERE dispatch_status = 'Dispatched'"),
    query(
      `SELECT COUNT(DISTINCT batch_no) AS total
       FROM serial_numbers
       WHERE dispatch_status = 'Dispatched' AND batch_no IS NOT NULL AND TRIM(batch_no) <> ''`
    ),
    query("SELECT COUNT(*) AS total FROM replace_return_cases").catch(() => ({ rows: [{ total: 0 }] })),
    query(
      "SELECT COUNT(*) AS total FROM replace_return_cases WHERE status NOT IN ('Delivered to Customer')"
    ).catch(() => ({ rows: [{ total: 0 }] })),
  ]);
  const count = (result) => Number(result.rows?.[0]?.total || 0);
  res.json({
    summary: {
      totalDealers: count(totalDealers),
      stockAvailable: count(stockAvailable),
      qrCreated: count(qrCreated),
      productsDispatched: count(productsDispatched),
      dispatchBatches: count(dispatchBatches),
      replaceReturnTotal: count(replaceReturnTotal),
      replaceReturnOpen: count(replaceReturnOpen),
    },
  });
}));

app.get("/dispatch/stock", asyncRoute(async (_req, res) => {
  await ensureProductsQrSchema();
  const categoriesResult = await query(
    `SELECT
       c.id,
       c.name,
       COUNT(CASE WHEN s.dealer_id IS NULL AND s.dispatch_status = 'Pending' THEN 1 END) AS in_stock,
       COUNT(CASE WHEN s.dispatch_status = 'Dispatched' THEN 1 END) AS dispatched,
       COUNT(CASE WHEN s.qr_status = 'Printed' THEN 1 END) AS qr_printed
     FROM product_categories c
     LEFT JOIN products p ON p.category_id = c.id
     LEFT JOIN serial_numbers s ON s.product_id = p.id
     GROUP BY c.id, c.name
     ORDER BY c.name ASC`
  );
  const productsResult = await query(
    `SELECT
       p.id,
       p.name AS product_name,
       p.model_no,
       c.name AS category_name,
       COUNT(CASE WHEN s.dealer_id IS NULL AND s.dispatch_status = 'Pending' THEN 1 END) AS in_stock,
       COUNT(CASE WHEN s.dispatch_status = 'Dispatched' THEN 1 END) AS dispatched,
       COUNT(CASE WHEN s.qr_status = 'Printed' THEN 1 END) AS qr_printed
     FROM products p
     LEFT JOIN product_categories c ON c.id = p.category_id
     LEFT JOIN serial_numbers s ON s.product_id = p.id
     GROUP BY p.id, p.name, p.model_no, c.name
     HAVING in_stock > 0 OR dispatched > 0 OR qr_printed > 0
     ORDER BY c.name ASC, p.name ASC`
  );
  res.json({
    categories: categoriesResult.rows.map((row) => ({
      id: row.id,
      name: row.name,
      inStock: Number(row.in_stock || 0),
      dispatched: Number(row.dispatched || 0),
      qrPrinted: Number(row.qr_printed || 0),
    })),
    products: productsResult.rows.map((row) => ({
      id: row.id,
      productName: row.product_name,
      modelNo: row.model_no,
      categoryName: row.category_name || "-",
      inStock: Number(row.in_stock || 0),
      dispatched: Number(row.dispatched || 0),
      qrPrinted: Number(row.qr_printed || 0),
    })),
  });
}));

app.get("/dispatch/batches", asyncRoute(async (_req, res) => {
  await ensureSerialNumbersSchema();
  const result = await query(
    `SELECT
       s.batch_no,
       s.dealer_id,
       d.dealer_no,
       d.name AS dealer_name,
       s.dispatched_customer_id,
       c.name AS customer_name,
       c.mobile AS customer_mobile,
       MIN(s.dispatch_date) AS dispatch_date,
       MAX(s.dispatched_at) AS dispatched_at,
       MAX(s.invoice_no) AS invoice_no,
       MAX(s.challan_no) AS challan_no,
       COUNT(s.id) AS unit_count,
       SUM(CASE WHEN s.qr_status = 'Printed' THEN 1 ELSE 0 END) AS qr_ready_count,
       GROUP_CONCAT(DISTINCT p.name ORDER BY p.name SEPARATOR ', ') AS product_summary
     FROM serial_numbers s
     LEFT JOIN dealers d ON d.id = s.dealer_id
     LEFT JOIN customers c ON c.id = s.dispatched_customer_id
     LEFT JOIN products p ON p.id = s.product_id
     WHERE s.dispatch_status = 'Dispatched'
       AND s.batch_no IS NOT NULL
       AND TRIM(s.batch_no) <> ''
     GROUP BY s.batch_no, s.dealer_id, d.dealer_no, d.name, s.dispatched_customer_id, c.name, c.mobile
     ORDER BY MAX(s.dispatched_at) DESC, s.batch_no DESC
     LIMIT 200`
  );
  const batchNos = result.rows.map((row) => row.batch_no).filter(Boolean);
  const productLinesByBatch = new Map();
  if (batchNos.length) {
    const lineResult = await query(
      `SELECT
         s.batch_no,
         COALESCE(p.id, '') AS product_id,
         COALESCE(p.name, 'Product') AS product_name,
         COUNT(s.id) AS unit_count,
         SUM(CASE WHEN s.qr_status = 'Printed' THEN 1 ELSE 0 END) AS qr_ready_count
       FROM serial_numbers s
       LEFT JOIN products p ON p.id = s.product_id
       WHERE s.batch_no IN (${batchNos.map(() => "?").join(",")})
       GROUP BY s.batch_no, p.id, p.name
       ORDER BY p.name ASC`,
      batchNos
    );
    lineResult.rows.forEach((line) => {
      const batchLines = productLinesByBatch.get(line.batch_no) || [];
      batchLines.push({
        productId: line.product_id || line.product_name || "Product",
        productName: line.product_name || "Product",
        unitCount: Number(line.unit_count || 0),
        qrReadyCount: Number(line.qr_ready_count || 0),
      });
      productLinesByBatch.set(line.batch_no, batchLines);
    });
  }
  res.json({
    batches: result.rows.map((row) => ({
      batchNo: row.batch_no,
      dispatchType: row.dispatched_customer_id ? "selfSale" : (row.dealer_id ? "dealer" : "openDealer"),
      dealerId: row.dealer_id,
      dealerNo: row.dealer_no,
      dealerName: row.dealer_name,
      customerId: row.dispatched_customer_id,
      customerName: row.customer_name,
      customerMobile: row.customer_mobile,
      dispatchDate: row.dispatch_date,
      dispatchedAt: row.dispatched_at,
      invoiceNo: row.invoice_no,
      challanNo: row.challan_no,
      unitCount: Number(row.unit_count || 0),
      qrReadyCount: Number(row.qr_ready_count || 0),
      productSummary: row.product_summary || "",
      productLines: productLinesByBatch.get(row.batch_no) || [],
      printSheetUrl: `/dispatch/qr-print-sheet?batchNo=${encodeURIComponent(row.batch_no)}`,
    })),
  });
}));

app.get("/dispatch/qr-print-data", asyncRoute(async (req, res) => {
  const batchNo = cleanString(req.query.batchNo || req.query.batch_no);
  const copies = parseQrLabelCopies(req.query.copies || req.query.quantity || req.query.qty);
  const copiesByProduct = parseQrProductCopies(req.query.productCopies || req.query.product_copies);
  const requested = cleanString(req.query.serials)
    .split(",")
    .map(cleanSerialNo)
    .filter(Boolean);
  const clauses = [];
  const params = [];
  if (batchNo) {
    clauses.push("s.batch_no = ?");
    params.push(batchNo);
  } else if (requested.length) {
    clauses.push(`s.serial_no IN (${requested.map(() => "?").join(",")})`);
    params.push(...requested);
  } else {
    return res.status(400).json({ error: "batchNo or serials query is required." });
  }
  const result = await query(
    `SELECT s.*, p.name AS product_name, p.model_no, d.dealer_no, d.name AS dealer_name,
            c.name AS customer_name, c.mobile AS customer_mobile
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = s.dealer_id
     LEFT JOIN customers c ON c.id = s.dispatched_customer_id
     WHERE ${clauses.join(" AND ")}
     ORDER BY s.serial_no ASC
     LIMIT 500`,
    params
  );
  const title = batchNo ? `Dispatch QR Sheet - ${batchNo}` : "Dispatch QR Sheet";
  const rows = expandQrPrintRows(result.rows, copies, copiesByProduct).map((serial) => ({
    serialNo: serial.serial_no,
    productId: serial.product_id,
    productName: serial.product_name || "Product",
    modelNo: serial.model_no,
    dealerId: serial.dealer_id,
    dealerNo: serial.dealer_no,
    dealerName: serial.dealer_name,
    customerId: serial.dispatched_customer_id,
    customerName: serial.customer_name,
    customerMobile: serial.customer_mobile,
    qrPayload: serial.qr_payload || dispatchUnitQrPayload({
      productId: serial.product_id,
      productName: serial.product_name,
      modelNo: serial.model_no,
      serialNo: serial.serial_no,
      dealerId: serial.dealer_id,
      dealerNo: serial.dealer_no,
      dealerName: serial.dealer_name,
      customerId: serial.dispatched_customer_id,
      customerName: serial.customer_name,
      customerMobile: serial.customer_mobile,
      dispatchType: serial.dispatched_customer_id ? "selfSale" : "",
    }),
  }));
  res.json({
    batchNo,
    title,
    count: rows.length,
    label: { widthMm: 60, heightMm: 40 },
    rows,
  });
}));

app.get("/dispatch/qr-print-sheet", asyncRoute(async (req, res) => {
  const batchNo = cleanString(req.query.batchNo || req.query.batch_no);
  const copies = parseQrLabelCopies(req.query.copies || req.query.quantity || req.query.qty);
  const copiesByProduct = parseQrProductCopies(req.query.productCopies || req.query.product_copies);
  const requested = cleanString(req.query.serials)
    .split(",")
    .map(cleanSerialNo)
    .filter(Boolean);
  const clauses = [];
  const params = [];
  if (batchNo) {
    clauses.push("s.batch_no = ?");
    params.push(batchNo);
  } else if (requested.length) {
    clauses.push(`s.serial_no IN (${requested.map(() => "?").join(",")})`);
    params.push(...requested);
  } else {
    return res.status(400).json({ error: "batchNo or serials query is required." });
  }
  const result = await query(
    `SELECT s.*, p.name AS product_name, p.model_no, d.dealer_no, d.name AS dealer_name,
            c.name AS customer_name, c.mobile AS customer_mobile
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = s.dealer_id
     LEFT JOIN customers c ON c.id = s.dispatched_customer_id
     WHERE ${clauses.join(" AND ")}
     ORDER BY s.serial_no ASC
     LIMIT 500`,
    params
  );
  const title = batchNo ? `Dispatch QR Sheet - ${batchNo}` : "Dispatch QR Sheet";
  res.type("html").send(buildDispatchQrPrintHtml(result.rows, title, copies, copiesByProduct));
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

app.post("/dealer-stock/claim-scan", asyncRoute(async (req, res) => {
  const dealerId = cleanString(req.body.dealerId || req.body.dealer_id);
  const serialNo = cleanSerialNo(req.body.serialNo || req.body.serial_no);
  if (!dealerId || !serialNo) {
    return res.status(400).json({ error: "Dealer and serial number are required." });
  }
  const dealer = await resolveDealerRecord(dealerId);
  if (!dealer) {
    return res.status(404).json({ error: "Dealer not found." });
  }
  const serialResult = await query(
    `SELECT
       s.*,
       p.name AS product_name,
       p.model_no,
       p.category,
       w.id AS warranty_id,
       w.customer_id AS warranty_customer_id,
       w.status AS warranty_status
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN warranties w ON w.serial_id = s.id
     WHERE LOWER(TRIM(s.serial_no)) = LOWER(TRIM(?))
     ORDER BY w.created_at DESC
     LIMIT 1`,
    [serialNo]
  );
  if (!serialResult.rowCount) {
    return res.status(404).json({ error: "Serial number not found." });
  }
  const serial = serialResult.rows[0];
  if (serial.dealer_id && String(serial.dealer_id) !== String(dealer.id)) {
    return res.status(403).json({ error: "This product is already assigned to another dealer." });
  }
  const alreadyAssigned = serial.dealer_id && String(serial.dealer_id) === String(dealer.id);
  if (!alreadyAssigned) {
    await query(
      `UPDATE serial_numbers
       SET dealer_id = ?,
           dispatch_status = 'Dispatched',
           dispatched_at = COALESCE(dispatched_at, NOW()),
           dispatch_date = COALESCE(dispatch_date, CURDATE())
       WHERE id = ?`,
      [dealer.id, serial.id]
    );
  }
  const updated = await query(
    `SELECT
       s.*,
       p.name AS product_name,
       p.model_no,
       p.category
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     WHERE s.id = ?
     LIMIT 1`,
    [serial.id]
  );
  res.json({
    ok: true,
    claimed: !alreadyAssigned,
    serial: updated.rows[0] || serial,
    message: alreadyAssigned
      ? "Product is already saved in your stock. Scan again to activate warranty."
      : "Product saved in your dealer stock. Scan this QR again to activate warranty.",
  });
}));

app.get("/complaints/customer/:customerId", asyncRoute(async (req, res) => {
  await ensureComplaintsSchema();
  await ensureTasksSchema();
  await ensureFeedbackSchema();
  await ensureQuotationsSchema();
  await ensureReplaceReturnSchema();
  await syncReplacementDeliveryForCustomer(req.params.customerId);
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
       ${COMPLAINT_LATEST_QUOTATION_FIELDS},
       ${COMPLAINT_REPLACEMENT_FIELDS}
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(c.dealer_id, w.dealer_id, s.dealer_id)
     ${COMPLAINT_LATEST_TASK_JOIN}
     ${COMPLAINT_FEEDBACK_JOIN}
     ${COMPLAINT_LATEST_QUOTATION_JOIN}
     ${COMPLAINT_REPLACEMENT_JOIN}
     WHERE c.customer_id = ?
     ORDER BY c.created_at DESC`,
    [req.params.customerId]
  );
  res.json({ complaints: result.rows });
}));

async function syncReplacementDeliveryForCustomer(customerId) {
  await ensureReplaceReturnSchema();
  await ensureComplaintsSchema();
  const pending = await query(
    `SELECT rr.id, rr.complaint_id, rr.replacement_serial_id, rr.warranty_id, rr.status,
            c.status AS complaint_status
     FROM replace_return_cases rr
     INNER JOIN complaints c ON c.id = rr.complaint_id
     WHERE rr.customer_id = ? AND rr.status = 'Delivered to Customer'`,
    [customerId]
  );
  for (const row of pending.rows) {
    if (String(row.complaint_status || "") !== "Replacement Completed") {
      await query("UPDATE complaints SET status = 'Replacement Completed' WHERE id = ?", [row.complaint_id]);
    }
    if (row.warranty_id && row.replacement_serial_id) {
      await query("UPDATE warranties SET serial_id = ? WHERE id = ?", [row.replacement_serial_id, row.warranty_id]);
    }
  }
}

app.get("/complaints/customer/:customerId/replacement-cases", asyncRoute(async (req, res) => {
  await ensureReplaceReturnSchema();
  await ensureComplaintsSchema();
  const customerId = cleanString(req.params.customerId);
  if (!customerId) {
    return res.status(400).json({ error: "Customer id is required." });
  }
  await syncReplacementDeliveryForCustomer(customerId);
  const result = await query(
    `SELECT ${REPLACE_RETURN_DETAIL_SELECT}
     ${REPLACE_RETURN_DETAIL_JOINS}
     WHERE rr.customer_id = ?
     ORDER BY rr.created_at DESC`,
    [customerId]
  );
  res.json({ cases: result.rows });
}));

app.get("/complaints/dealer/:dealerId", asyncRoute(async (req, res) => {
  await ensureComplaintsSchema();
  await ensureTasksSchema();
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
       ${COMPLAINT_LATEST_TASK_FIELDS},
       ${COMPLAINT_LATEST_QUOTATION_FIELDS}
     FROM complaints c
     LEFT JOIN warranties w ON w.id = c.warranty_id
     LEFT JOIN customers cust ON cust.id = c.customer_id
     LEFT JOIN serial_numbers s ON s.id = w.serial_id
     LEFT JOIN products p ON p.id = s.product_id
     LEFT JOIN dealers d ON d.id = COALESCE(c.dealer_id, w.dealer_id, s.dealer_id)
     ${COMPLAINT_LATEST_TASK_JOIN}
     ${COMPLAINT_FEEDBACK_JOIN}
     ${COMPLAINT_LATEST_QUOTATION_JOIN}
     WHERE COALESCE(c.dealer_id, w.dealer_id, s.dealer_id) = ?
       AND c.created_by_role = 'Dealer'
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
  await ensureWorkflowAuditSchema();
  await ensureTasksSchema();
  const complaintKey = cleanString(req.params.id);
  const technicianId = cleanString(req.body.technicianId || req.body.technician_id);
  const workType = cleanString(req.body.workType || req.body.work_type) || "Warranty Repair";
  const dueAt = cleanString(req.body.dueAt || req.body.due_at) || null;
  const payableAmount = Number(req.body.payableAmount || req.body.payable_amount || 0);
  const assignedByRole = cleanString(req.body.assignedByRole || req.body.assigned_by_role || req.body.requesterRole) || "Front Desk";
  const assignedById = cleanString(req.body.assignedById || req.body.assigned_by_id || req.body.userId || req.body.user_id) || null;

  const complaintId = await resolveComplaintId(complaintKey);
  if (!complaintId || !technicianId) {
    return res.status(400).json({ error: "Complaint and technician are required." });
  }
  const complaint = await query("SELECT * FROM complaints WHERE id = ? LIMIT 1", [complaintId]);
  if (!complaint.rowCount) {
    return res.status(404).json({ error: "Complaint not found." });
  }
  const technician = await query("SELECT id, created_by_dealer_id FROM technicians WHERE id = ? AND approval_status = 'Approved' LIMIT 1", [technicianId]);
  if (!technician.rowCount) {
    return res.status(404).json({ error: "Approved technician not found." });
  }
  const isDealerAssignment = assignedByRole === "Dealer";
  const isDeskAssignment = assignedByRole === "Front Desk" || assignedByRole === "Admin";
  if (isDealerAssignment) {
    return res.status(403).json({ error: "Technician assignment is handled by Front Desk or Admin." });
  }
  if (!isDealerAssignment && !isDeskAssignment) {
    return res.status(403).json({ error: "Only Front Desk or Admin can assign technicians." });
  }

  const existingTask = await query(
    `SELECT
       t.id,
       t.technician_id,
       t.status,
       tech.name AS technician_name,
       assigned_user.name AS assigned_by_name,
       t.assigned_by_role
     FROM tasks t
     LEFT JOIN technicians tech ON tech.id = t.technician_id
     LEFT JOIN users assigned_user ON assigned_user.id = t.assigned_by_id
     WHERE t.complaint_id = ?
     ORDER BY t.created_at DESC
     LIMIT 1`,
    [complaintId]
  );
  if (
    existingTask.rowCount &&
    existingTask.rows[0]?.technician_id &&
    !isTaskStatusReassignable(existingTask.rows[0]?.status)
  ) {
    const row = existingTask.rows[0];
    const by = row.assigned_by_name || row.assigned_by_role || "Front Desk/Admin";
    return res.status(409).json({
      error: `Complaint already assigned to ${row.technician_name || "technician"} by ${by}. Reassign tabhi hoga jab technician reject kare.`,
      assignedTechnicianName: row.technician_name || null,
      assignedByName: row.assigned_by_name || null,
      assignedByRole: row.assigned_by_role || null,
      taskStatus: row.status || null,
    });
  }
  const oldComplaintStatus = complaint.rows[0]?.status || null;
  await withTransaction(async (tx) => {
    await tx("UPDATE complaints SET status = 'Assigned to Technician' WHERE id = ?", [complaintId]);
    await recordStatusHistory({
      complaintId,
      oldStatus: oldComplaintStatus,
      newStatus: "Assigned to Technician",
      changedByRole: assignedByRole,
      changedById: assignedById,
      remarks: "Technician assigned",
    }, tx);
    await tx(
      `INSERT INTO complaint_assignments
         (complaint_id, technician_id, assigned_by_role, assigned_by_id, status, remarks)
       VALUES (?, ?, ?, ?, 'Assigned', ?)`,
      [complaintId, technicianId, assignedByRole, assignedById, `Assigned for ${workType}`]
    );
    if (existingTask.rowCount) {
      await tx(
        `UPDATE tasks
         SET technician_id = ?,
             work_type = ?,
             due_at = ?,
             status = 'Assigned',
             payable_amount = ?,
             assigned_by_role = ?,
             assigned_by_id = ?
         WHERE id = ?`,
        [
          technicianId,
          workType,
          dueAt,
          Number.isFinite(payableAmount) ? payableAmount : 0,
          assignedByRole,
          assignedById,
          existingTask.rows[0].id
        ]
      );
    } else {
      await tx(
        `INSERT INTO tasks
         (task_no, complaint_id, technician_id, work_type, due_at, status, payable_amount, assigned_by_role, assigned_by_id)
         VALUES (?, ?, ?, ?, ?, 'Assigned', ?, ?, ?)`,
        [
          `TASK-${Date.now()}`,
          complaintId,
          technicianId,
          workType,
          dueAt,
          Number.isFinite(payableAmount) ? payableAmount : 0,
          assignedByRole,
          assignedById
        ]
      );
    }
    await createWorkflowMessage({
      complaintId,
      senderRole: assignedByRole,
      senderId: assignedById,
      receiverRole: "Technician",
      receiverId: technicianId,
      message: `Complaint assigned for ${workType}.`,
    }, tx);
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
  await ensureNotificationsSchema();
  const ctx = await getComplaintNotifyContext(complaintId);
  const techRow = await query("SELECT user_id, name FROM technicians WHERE id = ? LIMIT 1", [technicianId]);
  if (techRow.rows[0]?.user_id) {
    await createNotification({
      userId: techRow.rows[0].user_id,
      recipientRole: "Technician",
      type: "task_assigned",
      title: "New complaint assignment",
      message: `Complaint ${ctx?.complaint_no || ""} assigned to you. Accept or reject in Alerts.`,
      entityType: "task",
      entityId: taskResult.rows[0]?.id || null,
    });
  }
  if (ctx?.customer_id) {
    await createNotification({
      customerId: ctx.customer_id,
      type: "technician_assigned",
      title: "Technician allocated",
      message: `${techRow.rows[0]?.name || "A technician"} was assigned to your complaint ${ctx.complaint_no || ""}.`,
      entityType: "complaint",
      entityId: complaintId,
    });
  }
  if (assignedByRole === "Dealer" && ctx?.dealer_id) {
    await createNotification({
      userId: ctx.dealer_user_id || null,
      recipientRole: "Dealer",
      type: "technician_assigned",
      title: "Technician assigned",
      message: `You assigned ${techRow.rows[0]?.name || "technician"} to ${ctx.complaint_no || "complaint"}.`,
      entityType: "complaint",
      entityId: complaintId,
    });
  }
  await createNotification({
    recipientRole: "Front Desk",
    type: "technician_assigned",
    title: "Technician assigned to complaint",
    message: `${ctx?.complaint_no || "Complaint"} assigned to ${techRow.rows[0]?.name || "technician"}.`,
    entityType: "complaint",
    entityId: complaintId,
  });
  res.json({
    complaint: complaintRow.rows[0],
    task: taskResult.rowCount ? taskResult.rows[0] : null,
  });
}));

app.get("/complaints/:id/audit", asyncRoute(async (req, res) => {
  await ensureWorkflowAuditSchema();
  const complaintId = await resolveComplaintId(req.params.id);
  if (!complaintId) {
    return res.status(400).json({ error: "Complaint id is required." });
  }
  const [history, messages, assignments] = await Promise.all([
    query(
      `SELECT * FROM status_history WHERE complaint_id = ? ORDER BY created_at ASC LIMIT 200`,
      [complaintId]
    ),
    query(
      `SELECT * FROM messages_or_comments WHERE complaint_id = ? ORDER BY created_at ASC LIMIT 200`,
      [complaintId]
    ),
    query(
      `SELECT ca.*, tech.name AS technician_name
       FROM complaint_assignments ca
       LEFT JOIN technicians tech ON tech.id = ca.technician_id
       WHERE ca.complaint_id = ?
       ORDER BY ca.assigned_at DESC
       LIMIT 50`,
      [complaintId]
    ),
  ]);
  res.json({
    statusHistory: history.rows,
    messages: messages.rows,
    assignments: assignments.rows,
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
    if (customerPayload) {
      const cleanCustomerMobile = normalizeMobileValue(customerPayload.mobile);
      const cleanCustomerEmail = normalizeEmail(customerPayload.email);
      const cleanCustomerPassword = typeof customerPayload.password === "string" ? customerPayload.password : "";
      const existingCustomer = cleanCustomerMobile.length >= 10
        ? await query(
            `SELECT
               c.id,
               c.user_id,
               u.password_hash
             FROM customers c
             LEFT JOIN users u ON u.id = c.user_id
             WHERE ${sqlNormalizeMobileColumn("c.mobile")} = ?
             LIMIT 1`,
            [cleanCustomerMobile]
          )
        : { rowCount: 0, rows: [] };
      const hasExistingLogin = Boolean(
        existingCustomer.rowCount &&
          existingCustomer.rows[0]?.user_id &&
          existingCustomer.rows[0]?.password_hash &&
          String(existingCustomer.rows[0].password_hash).trim()
      );
      if (!hasExistingLogin) {
        if (!cleanCustomerEmail) {
          return res.status(400).json({ error: "Login Email ID is required for a new customer account." });
        }
        if (!cleanCustomerPassword || cleanCustomerPassword.length < 8) {
          return res.status(400).json({ error: "Customer login password must be at least 8 characters." });
        }
      }
      const profile = await findOrCreateCustomer({
        name: customerPayload.name,
        mobile: customerPayload.mobile,
        email: customerPayload.email,
        address: customerPayload.address,
        city: customerPayload.city,
        state: customerPayload.state,
        pincode: customerPayload.pincode,
        password: customerPayload.password,
        createdByDealerId: actingDealerId || null,
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
  let resolvedDealerId = actingDealerId || null;
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
    const dealerLookup = await query(
      `SELECT COALESCE(w.dealer_id, s.dealer_id) AS dealer_id
       FROM warranties w
       LEFT JOIN serial_numbers s ON s.id = w.serial_id
       WHERE w.id = ?
       LIMIT 1`,
      [resolvedWarrantyId]
    );
    resolvedDealerId = dealerLookup.rows[0]?.dealer_id || resolvedDealerId;
  }

  if (!isStaffCreator && !resolvedWarrantyId) {
    return res.status(400).json({ error: "Select an active warranty product before creating a complaint." });
  }
  if (!isStaffCreator && !resolvedDealerId) {
    return res.status(400).json({
      error: "This product is not linked to a dealer. Warranty must be activated from your purchase dealer.",
    });
  }

  const initialStatus = "Created";
  const complaintSourceRole = creatorRole || "Customer";
  await ensureWorkflowAuditSchema();
  await query(
    `INSERT INTO complaints
     (complaint_no, warranty_id, customer_id, dealer_id, problem_type, description, priority, product_name, model_no, warranty_start_date, warranty_end_date, warranty_status, status, created_by_role)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      cleanComplaintNo,
      resolvedWarrantyId,
      resolvedCustomerId,
      complaintSourceRole === "Customer" ? null : resolvedDealerId,
      cleanProblemType,
      typeof description === "string" && description.trim() ? description.trim() : null,
      typeof priority === "string" && priority.trim() ? priority.trim() : "Normal",
      cleanProductName,
      cleanModelNo,
      cleanWarrantyStartDate,
      cleanWarrantyEndDate,
      cleanWarrantyStatus,
      initialStatus,
      complaintSourceRole
    ]
  );
  const result = await query("SELECT * FROM complaints WHERE complaint_no = ? LIMIT 1", [cleanComplaintNo]);
  const saved = result.rows[0];
  if (saved?.id) {
    await recordStatusHistory({
      complaintId: saved.id,
      oldStatus: null,
      newStatus: initialStatus,
      changedByRole: creatorRole || "Customer",
      changedById: resolvedCustomerId,
      remarks: "Complaint created",
    });
  }
  await ensureNotificationsSchema();
  const ctx = saved?.id ? await getComplaintNotifyContext(saved.id) : null;
  if (resolvedCustomerId) {
    await createNotification({
      customerId: resolvedCustomerId,
      type: "complaint_created",
      title: "Complaint registered",
      message: `Your complaint ${cleanComplaintNo} was saved. Front Desk will assign a technician.`,
      entityType: "complaint",
      entityId: saved?.id || null,
    });
  }
  if (complaintSourceRole === "Dealer" && ctx?.dealer_id) {
    await createNotification({
      userId: ctx.dealer_user_id || null,
      recipientRole: "Dealer",
      type: "new_complaint",
      title: "New customer complaint",
      message: `Complaint ${cleanComplaintNo} - ${cleanProblemType}. Assign a technician in Complaints.`,
      entityType: "complaint",
      entityId: saved?.id || null,
    });
  }
  await createNotification({
    recipientRole: "Front Desk",
    type: "new_complaint",
    title: "New complaint logged",
    message: `Complaint ${cleanComplaintNo} created for ${ctx?.product_name || "product"}.`,
    entityType: "complaint",
    entityId: saved?.id || null,
  });
  await createNotification({
    recipientRole: "Admin",
    type: "new_complaint",
    title: "New complaint logged",
    message: `Complaint ${cleanComplaintNo} created for ${ctx?.product_name || "product"}.`,
    entityType: "complaint",
    entityId: saved?.id || null,
  });
  res.status(201).json({ complaint: saved });
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

async function runRuntimeSchemaChecks() {
  try {
    await ensureSerialNumbersSchema();
    await ensureCustomersVillageSchema();
    await ensureProductCategoriesSchema();
    await ensureProductsQrSchema();
    await ensureDealerRewardsSchema();
    await ensureComplaintsSchema();
    await ensureFeedbackSchema();
    await ensureTasksSchema();
    await ensureWorkTypeCostsSchema();
    await ensurePaymentsSchema();
    await ensureQuotationsSchema();
    await ensureNotificationsSchema();
    await purgeExpiredNotifications();
    await ensurePushTokensSchema();
    await ensureWorkflowAuditSchema();
  } catch (error) {
    console.warn("Runtime schema check skipped:", error?.message || error);
  }
}

app.listen(port, "0.0.0.0", () => {
  console.log(`Hitaishi CRM API listening on http://localhost:${port}`);
  console.log(`Admin website: http://localhost:${port}/admin/`);
  console.log(`Health check: http://localhost:${port}/health`);
  console.log("Stop with Ctrl+C. Changes need server restart.");

  runRuntimeSchemaChecks();
});

setInterval(() => {
  purgeExpiredNotifications().catch((error) => {
    console.warn("Notification cleanup skipped:", error?.message || error);
  });
}, 60 * 60 * 1000);

