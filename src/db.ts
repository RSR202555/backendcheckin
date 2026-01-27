import dotenv from 'dotenv';

dotenv.config();

import { Pool } from 'pg';

const connectionString = process.env.DATABASE_URL;

const pool = connectionString
  ? new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false },
    })
  : new Pool({
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT || 5432),
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
    });

async function query(sql: string, params?: any[]) {
  const result = await pool.query(sql, params);
  if (result.command === 'SELECT') {
    return [result.rows] as const;
  }
  return [{ affectedRows: result.rowCount }] as const;
}

export default { query };
