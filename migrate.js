import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { pool, rawQuery } from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const schemaPath = path.join(__dirname, "schema.sql");

try {
  const schema = fs.readFileSync(schemaPath, "utf8");
  await rawQuery(schema);
  console.log("MySQL database schema migrated successfully.");
} catch (error) {
  console.error("Database migration failed.");
  console.error(error);
  process.exitCode = 1;
} finally {
  await pool.end();
}
