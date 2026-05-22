import crypto from "crypto";
import dotenv from "dotenv";
import { query, pool } from "./db.js";

dotenv.config();

function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

/** Fixed admin record: login ID admin / password admin123 (sha256 matches API). Reserved mobile avoids clashes. */
const ADMIN_MOBILE = "9000000001";
const ADMIN_EMAIL = "admin";
const ADMIN_PASS = "admin123";

async function main() {
  const existing = await query(
    "SELECT id FROM users WHERE role = 'Admin' AND LOWER(TRIM(COALESCE(email,''))) = ? LIMIT 1",
    [ADMIN_EMAIL]
  );

  const hash = hashPassword(ADMIN_PASS);

  if (existing.rowCount > 0) {
    await query("UPDATE users SET password_hash = ?, mobile = ?, name = ?, email = ?, status = 'Active' WHERE id = ?", [
      hash,
      ADMIN_MOBILE,
      "Administrator",
      ADMIN_EMAIL,
      existing.rows[0].id,
    ]);
    console.log("Admin user updated. Login ID: admin  |  Password: admin123");
  } else {
    await query(
      "INSERT INTO users (role, name, mobile, email, password_hash, status) VALUES ('Admin', 'Administrator', ?, ?, ?, 'Active')",
      [ADMIN_MOBILE, ADMIN_EMAIL, hash]
    );
    console.log("Admin user created. Login ID: admin  |  Password: admin123");
  }
}

await main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
await pool.end();
