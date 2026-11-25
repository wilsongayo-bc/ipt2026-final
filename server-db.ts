import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {DatabaseSync, type SQLInputValue} from 'node:sqlite';
import {fileURLToPath} from 'node:url';
import mysql, {type Pool, type ResultSetHeader, type RowDataPacket} from 'mysql2/promise';

export type DatabaseEngine = 'sqlite' | 'mysql';

export interface MysqlSafeStatus {
  configured: boolean;
  host?: string;
  port?: number;
  database?: string;
  user?: string;
  ssl: boolean;
}

export interface DatabaseStatusInfo {
  activeEngine: DatabaseEngine;
  mysql: MysqlSafeStatus;
}

interface MysqlResolvedConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
  ssl: boolean;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dataDir = path.join(__dirname, 'data');
const configFilePath = path.join(dataDir, 'db-config.json');

fs.mkdirSync(dataDir, {recursive: true});

const sqliteDb = new DatabaseSync(path.join(dataDir, 'auth.db'));
sqliteDb.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    age INTEGER,
    role TEXT NOT NULL CHECK(role IN ('SuperAdmin', 'Admin', 'User')),
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    is_disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS action_tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('verify', 'reset')),
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    priority TEXT NOT NULL DEFAULT 'Medium' CHECK(priority IN ('Low', 'Medium', 'High')),
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Done')),
    due_date TEXT,
    is_disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

let activeEngine: DatabaseEngine = 'sqlite';
let mysqlPool: Pool | null = null;
let mysqlConfigKey = '';

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) {
    return false;
  }
  const [salt, originalHex] = parts;
  const derived = crypto.scryptSync(password, salt, 64);
  const original = Buffer.from(originalHex, 'hex');
  if (derived.length !== original.length) {
    return false;
  }
  return crypto.timingSafeEqual(derived, original);
}

function resolveMysqlConfig(): MysqlResolvedConfig | null {
  const mysqlUrl = process.env.MYSQL_URL?.trim();
  if (mysqlUrl) {
    try {
      const parsed = new URL(mysqlUrl);
      if (parsed.protocol !== 'mysql:' && parsed.protocol !== 'mysql2:') {
        return null;
      }
      const database = parsed.pathname.replace(/^\/+/, '');
      const host = parsed.hostname;
      const user = decodeURIComponent(parsed.username);
      const password = decodeURIComponent(parsed.password);
      const port = parsed.port ? Number(parsed.port) : 3306;
      const sslParam = parsed.searchParams.get('ssl')?.toLowerCase();
      const sslMode = parsed.searchParams.get('sslmode')?.toLowerCase();
      const ssl =
        process.env.MYSQL_SSL === 'true' ||
        sslParam === 'true' ||
        sslMode === 'require' ||
        sslMode === 'verify-ca' ||
        sslMode === 'verify-full';

      if (!host || !user || !database || !Number.isInteger(port) || port <= 0) {
        return null;
      }
      return {host, port, user, password, database, ssl};
    } catch {
      return null;
    }
  }

  const host = process.env.MYSQL_HOST?.trim() || '';
  const user = process.env.MYSQL_USER?.trim() || '';
  const password = process.env.MYSQL_PASSWORD ?? '';
  const database = process.env.MYSQL_DATABASE?.trim() || '';
  const port = Number(process.env.MYSQL_PORT || 3306);
  const ssl = process.env.MYSQL_SSL === 'true';

  if (!host || !user || !database || !Number.isInteger(port) || port <= 0) {
    return null;
  }

  return {host, port, user, password, database, ssl};
}

export function getMysqlSafeStatus(): MysqlSafeStatus {
  const cfg = resolveMysqlConfig();
  if (!cfg) {
    return {configured: false, ssl: false};
  }
  return {
    configured: true,
    host: cfg.host,
    port: cfg.port,
    database: cfg.database,
    user: cfg.user,
    ssl: cfg.ssl,
  };
}

function createMysqlPoolFromConfig(cfg: MysqlResolvedConfig): Pool {
  return mysql.createPool({
    host: cfg.host,
    port: cfg.port,
    user: cfg.user,
    password: cfg.password,
    database: cfg.database,
    waitForConnections: true,
    connectionLimit: 10,
    connectTimeout: 8000,
    supportBigNumbers: true,
    ...(cfg.ssl
      ? {
          ssl: {
            rejectUnauthorized: process.env.MYSQL_SSL_REJECT_UNAUTHORIZED !== 'false',
          },
        }
      : {}),
  });
}

async function getOrCreateMysqlPool(): Promise<Pool> {
  const cfg = resolveMysqlConfig();
  if (!cfg) {
    throw new Error(
      'Online MySQL is not configured. Set MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, and MYSQL_DATABASE (or MYSQL_URL) in environment secrets.',
    );
  }
  const key = `${cfg.host}:${cfg.port}/${cfg.database}:${cfg.user}:${cfg.ssl}`;
  if (!mysqlPool || mysqlConfigKey !== key) {
    if (mysqlPool) {
      await mysqlPool.end().catch(() => undefined);
    }
    mysqlPool = createMysqlPoolFromConfig(cfg);
    mysqlConfigKey = key;
  }
  return mysqlPool;
}

async function initMysqlSchema(pool: Pool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(160) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      age INT NULL,
      role VARCHAR(20) NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      is_active TINYINT(1) NOT NULL DEFAULT 0,
      is_disabled TINYINT(1) NOT NULL DEFAULT 0,
      created_at VARCHAR(64) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS action_tokens (
      token VARCHAR(128) NOT NULL PRIMARY KEY,
      user_id INT NOT NULL,
      type VARCHAR(20) NOT NULL,
      expires_at BIGINT NOT NULL,
      CONSTRAINT fk_action_tokens_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      title VARCHAR(160) NOT NULL,
      description TEXT NOT NULL,
      priority VARCHAR(20) NOT NULL DEFAULT 'Medium',
      status VARCHAR(20) NOT NULL DEFAULT 'Pending',
      due_date VARCHAR(32) NULL,
      is_disabled TINYINT(1) NOT NULL DEFAULT 0,
      created_at VARCHAR(64) NOT NULL,
      updated_at VARCHAR(64) NOT NULL,
      CONSTRAINT fk_tasks_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
}

function readPersistedEngine(): DatabaseEngine {
  try {
    if (fs.existsSync(configFilePath)) {
      const parsed = JSON.parse(fs.readFileSync(configFilePath, 'utf8')) as {
        activeEngine?: unknown;
      };
      if (parsed.activeEngine === 'mysql' || parsed.activeEngine === 'sqlite') {
        return parsed.activeEngine;
      }
    }
  } catch {
    // Ignore malformed config file and fall back to env/default
  }
  return process.env.DB_ENGINE === 'mysql' ? 'mysql' : 'sqlite';
}

function writePersistedEngine(engine: DatabaseEngine): void {
  fs.writeFileSync(
    configFilePath,
    JSON.stringify({activeEngine: engine}, null, 2),
    'utf8',
  );
}

function normalizeSqliteParams(params: unknown[]): SQLInputValue[] {
  return params.map((p) => (p === undefined ? null : (p as SQLInputValue)));
}

type MysqlParamValue = string | number | boolean | Date | Buffer | null;

function normalizeMysqlParams(params: unknown[]): MysqlParamValue[] {
  return params.map((p) => (p === undefined ? null : (p as MysqlParamValue)));
}

async function ensureDemoSuperAdminOnEngine(engine: DatabaseEngine): Promise<void> {
  const seedPassword = process.env.DEMO_SUPERADMIN_PASSWORD || 'Super.1234';
  const now = new Date().toISOString();

  if (engine === 'sqlite') {
    const existing = sqliteDb
      .prepare('SELECT id FROM users WHERE email = ?')
      .get('super@admin.com') as {id: number} | undefined;
    if (!existing) {
      sqliteDb
        .prepare(
          `INSERT INTO users (name, email, role, password_hash, is_active, is_disabled, created_at)
           VALUES (?, ?, ?, ?, 1, 0, ?)`,
        )
        .run('Super Admin', 'super@admin.com', 'SuperAdmin', hashPassword(seedPassword), now);
    }
    return;
  }

  const pool = await getOrCreateMysqlPool();
  const [rows] = await pool.execute<RowDataPacket[]>(
    'SELECT id FROM users WHERE email = ? LIMIT 1',
    ['super@admin.com'],
  );
  if (rows.length === 0) {
    await pool.execute(
      `INSERT INTO users (name, email, role, password_hash, is_active, is_disabled, created_at)
       VALUES (?, ?, ?, ?, 1, 0, ?)`,
      ['Super Admin', 'super@admin.com', 'SuperAdmin', hashPassword(seedPassword), now],
    );
  }
}

export async function initializeDatabase(): Promise<void> {
  await ensureDemoSuperAdminOnEngine('sqlite');
  const preferred = readPersistedEngine();

  if (preferred === 'mysql' && resolveMysqlConfig()) {
    try {
      const pool = await getOrCreateMysqlPool();
      await pool.query('SELECT 1');
      await initMysqlSchema(pool);
      await ensureDemoSuperAdminOnEngine('mysql');
      activeEngine = 'mysql';
      return;
    } catch (err) {
      console.warn(
        'Online MySQL unavailable at startup; falling back to local SQLite:',
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  activeEngine = 'sqlite';
}

export function getDatabaseStatus(): DatabaseStatusInfo {
  return {
    activeEngine,
    mysql: getMysqlSafeStatus(),
  };
}

export async function testMysqlConnection(): Promise<{
  latencyMs: number;
  mysql: MysqlSafeStatus;
}> {
  const status = getMysqlSafeStatus();
  if (!status.configured) {
    throw new Error(
      'Online MySQL is not configured. Add MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, and MYSQL_DATABASE (or MYSQL_URL) in environment secrets.',
    );
  }

  const start = Date.now();
  const pool = await getOrCreateMysqlPool();
  await pool.query('SELECT 1');
  return {
    latencyMs: Date.now() - start,
    mysql: status,
  };
}

export async function switchDatabaseEngine(
  targetEngine: DatabaseEngine,
): Promise<DatabaseStatusInfo> {
  if (targetEngine === 'sqlite') {
    await ensureDemoSuperAdminOnEngine('sqlite');
    activeEngine = 'sqlite';
    writePersistedEngine('sqlite');
    return getDatabaseStatus();
  }

  const pool = await getOrCreateMysqlPool();
  await pool.query('SELECT 1');
  await initMysqlSchema(pool);
  await ensureDemoSuperAdminOnEngine('mysql');
  activeEngine = 'mysql';
  writePersistedEngine('mysql');
  return getDatabaseStatus();
}

export async function dbGet<T>(
  sql: string,
  ...params: unknown[]
): Promise<T | undefined> {
  if (activeEngine === 'sqlite') {
    return sqliteDb
      .prepare(sql)
      .get(...normalizeSqliteParams(params)) as unknown as T | undefined;
  }
  const pool = await getOrCreateMysqlPool();
  const [rows] = await pool.execute<RowDataPacket[]>(
    sql,
    normalizeMysqlParams(params),
  );
  return rows[0] as unknown as T | undefined;
}

export async function dbAll<T>(sql: string, ...params: unknown[]): Promise<T[]> {
  if (activeEngine === 'sqlite') {
    return sqliteDb
      .prepare(sql)
      .all(...normalizeSqliteParams(params)) as unknown as T[];
  }
  const pool = await getOrCreateMysqlPool();
  const [rows] = await pool.execute<RowDataPacket[]>(
    sql,
    normalizeMysqlParams(params),
  );
  return rows as unknown as T[];
}

export async function dbRun(
  sql: string,
  ...params: unknown[]
): Promise<{lastInsertRowid: number; changes: number}> {
  if (activeEngine === 'sqlite') {
    const result = sqliteDb
      .prepare(sql)
      .run(...normalizeSqliteParams(params));
    return {
      lastInsertRowid: Number(result.lastInsertRowid ?? 0),
      changes: Number(result.changes ?? 0),
    };
  }
  const pool = await getOrCreateMysqlPool();
  const [result] = await pool.execute<ResultSetHeader>(
    sql,
    normalizeMysqlParams(params),
  );
  return {
    lastInsertRowid: Number(result.insertId ?? 0),
    changes: Number(result.affectedRows ?? 0),
  };
}
