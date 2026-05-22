import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

export const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  namedPlaceholders: false,
  multipleStatements: true,
  connectTimeout: Number(process.env.DB_CONNECT_TIMEOUT_MS || 8000)
});

export async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return {
    rows: Array.isArray(rows) ? rows : [],
    rowCount: Array.isArray(rows) ? rows.length : rows.affectedRows || 0,
    insertId: rows?.insertId,
    affectedRows: rows?.affectedRows || 0
  };
}

export async function rawQuery(sql, params = []) {
  const [rows] = await pool.query(sql, params);
  return rows;
}
