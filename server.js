import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import { query, withTransaction } from "./db.js";

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

function cleanString(value) {
  return typeof value === "string" ? value.trim() : "";
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

app.post("/serial-numbers", asyncRoute(async (req, res) => {
  const productId = cleanString(req.body.productId || req.body.product_id);
  const modelNo = cleanString(req.body.modelNo || req.body.model_no);
  const dealerNo = cleanString(req.body.dealerNo || req.body.dealer_no);
  const serialNo = cleanString(req.body.serialNo || req.body.serial_no);

  if (!serialNo) {
    return res.status(400).json({ error: "Serial number is required." });
  }

  let product = null;
  if (productId) {
    const result = await query("SELECT id FROM products WHERE id = ? LIMIT 1", [productId]);
    product = result.rows[0] || null;
  } else if (modelNo) {
    const result = await query("SELECT id FROM products WHERE LOWER(TRIM(model_no)) = LOWER(?) LIMIT 1", [modelNo]);
    product = result.rows[0] || null;
  }

  let dealer = null;
  if (dealerNo) {
    const result = await query("SELECT id FROM dealers WHERE LOWER(TRIM(dealer_no)) = LOWER(?) AND status = 'Active' LIMIT 1", [dealerNo]);
    dealer = result.rows[0] || null;
    if (!dealer) {
      return res.status(400).json({ error: "Active dealer not found for this dealer number." });
    }
  }

  await query(
    "INSERT INTO serial_numbers (product_id, dealer_id, serial_no, qr_status, dispatch_status) VALUES (?, ?, ?, 'Printed', ?)",
    [product?.id || null, dealer?.id || null, serialNo, dealer ? "Dispatched" : "Pending"]
  );
  const result = await query(
    `SELECT s.*, p.name AS product_name, p.model_no
     FROM serial_numbers s
     LEFT JOIN products p ON p.id = s.product_id
     WHERE s.serial_no = ?
     LIMIT 1`,
    [serialNo]
  );
  res.status(201).json({ serial: result.rows[0] });
}));

app.post("/serial-numbers/generate-qr", asyncRoute(async (req, res) => {
  const serialNumbers = Array.isArray(req.body?.serialNumbers)
    ? req.body.serialNumbers.map(cleanString).filter(Boolean)
    : [];

  const result = serialNumbers.length
    ? await query(
        `UPDATE serial_numbers
         SET qr_status = 'Printed'
         WHERE serial_no IN (${serialNumbers.map(() => "?").join(",")})`,
        serialNumbers
      )
    : await query("UPDATE serial_numbers SET qr_status = 'Printed' WHERE qr_status = 'Not Printed'");

  res.json({
    ok: true,
    generated: result.affectedRows,
    message: result.affectedRows
      ? `${result.affectedRows} QR code(s) generated.`
      : "No pending serials found for QR generation."
  });
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

app.patch("/serial-numbers/:serialNo/qr", asyncRoute(async (req, res) => {
  const serialNo = cleanString(req.params.serialNo);
  if (!serialNo) {
    return res.status(400).json({ error: "Serial number is required." });
  }
  const result = await query("UPDATE serial_numbers SET qr_status = 'Printed' WHERE serial_no = ?", [serialNo]);
  if (!result.affectedRows) {
    return res.status(404).json({ error: "Serial number not found." });
  }
  res.json({ ok: true });
}));

app.post("/dispatch-mapping", asyncRoute(async (req, res) => {
  const dealerNo = cleanString(req.body.dealerNo || req.body.dealer_no);
  const serialNumbers = Array.isArray(req.body.serialNumbers)
    ? req.body.serialNumbers.map(cleanString).filter(Boolean)
    : cleanString(req.body.serialNo || req.body.serial_no)
      ? [cleanString(req.body.serialNo || req.body.serial_no)]
      : [];

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
     SET dealer_id = ?, dispatch_status = 'Dispatched'
     WHERE serial_no IN (${placeholders})`,
    [dealer.rows[0].id, ...serialNumbers]
  );

  res.json({ ok: true, mapped: result.affectedRows });
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
