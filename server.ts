import 'dotenv/config';
import express, {type NextFunction, type Request, type Response} from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {fileURLToPath} from 'node:url';

type UserRole = 'SuperAdmin' | 'Admin' | 'User';
type TaskPriority = 'Low' | 'Medium' | 'High';
type TaskStatus = 'Pending' | 'Done';

interface DbUserRow {
  id: number;
  name: string;
  email: string;
  age: number | null;
  role: UserRole;
  password_hash: string;
  is_active: number;
  is_disabled: number;
  created_at: string;
}

interface SafeUser {
  id: number;
  name: string;
  email: string;
  age?: number;
  role: UserRole;
  isActive: boolean;
  isDisabled: boolean;
  createdAt: string;
}

interface DbTaskJoinRow {
  id: number;
  user_id: number;
  assignee_name: string;
  assignee_email: string;
  assignee_role: UserRole;
  title: string;
  description: string;
  priority: TaskPriority;
  status: TaskStatus;
  due_date: string | null;
  is_disabled: number;
  created_at: string;
  updated_at: string;
}

interface SafeTask {
  id: number;
  userId: number;
  assigneeName: string;
  assigneeEmail: string;
  title: string;
  description: string;
  priority: TaskPriority;
  status: TaskStatus;
  dueDate?: string;
  isDisabled: boolean;
  createdAt: string;
  updatedAt: string;
}

interface DbTokenRow {
  token: string;
  user_id: number;
  type: 'verify' | 'reset';
  expires_at: number;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_TTL_SECONDS = 60 * 60 * 24; // 24 hours

// Initialize local SQLite database
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, {recursive: true});
const db = new DatabaseSync(path.join(dataDir, 'auth.db'));
db.exec(`
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

function toSafeTask(row: DbTaskJoinRow): SafeTask {
  return {
    id: row.id,
    userId: row.user_id,
    assigneeName: row.assignee_name,
    assigneeEmail: row.assignee_email,
    title: row.title,
    description: row.description,
    priority: row.priority,
    status: row.status,
    ...(row.due_date ? {dueDate: row.due_date} : {}),
    isDisabled: row.is_disabled === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toSafeUser(row: DbUserRow): SafeUser {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    ...(row.age !== null ? {age: row.age} : {}),
    role: row.role,
    isActive: row.is_active === 1,
    isDisabled: row.is_disabled === 1,
    createdAt: row.created_at,
  };
}

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password: string, storedHash: string): boolean {
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

// Seed requested demonstration SuperAdmin user if missing
function ensureDemoSuperAdmin(): void {
  const existing = db
    .prepare('SELECT id FROM users WHERE email = ?')
    .get('super@admin.com') as {id: number} | undefined;
  if (!existing) {
    const seedPassword = process.env.DEMO_SUPERADMIN_PASSWORD || 'Super.1234';
    db.prepare(
      `INSERT INTO users (name, email, role, password_hash, is_active, is_disabled, created_at)
       VALUES (?, ?, ?, ?, 1, 0, ?)`,
    ).run(
      'Super Admin',
      'super@admin.com',
      'SuperAdmin',
      hashPassword(seedPassword),
      new Date().toISOString(),
    );
  }
}
ensureDemoSuperAdmin();

function base64UrlEncode(input: Buffer | string): string {
  return Buffer.from(input)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}

function base64UrlDecode(input: string): string {
  const padded = input
    .replaceAll('-', '+')
    .replaceAll('_', '/')
    .padEnd(Math.ceil(input.length / 4) * 4, '=');
  return Buffer.from(padded, 'base64').toString('utf8');
}

function signJwt(user: DbUserRow): string {
  const header = base64UrlEncode(JSON.stringify({alg: 'HS256', typ: 'JWT'}));
  const payload = base64UrlEncode(
    JSON.stringify({
      sub: user.id,
      email: user.email,
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS,
    }),
  );
  const signature = base64UrlEncode(
    crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${header}.${payload}`)
      .digest(),
  );
  return `${header}.${payload}.${signature}`;
}

function verifyJwt(token: string): {sub: number; email: string} | null {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }
  const [header, payload, signature] = parts;
  const expectedSig = base64UrlEncode(
    crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${header}.${payload}`)
      .digest(),
  );
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  try {
    const parsed = JSON.parse(base64UrlDecode(payload)) as {
      sub?: number;
      email?: string;
      exp?: number;
    };
    if (
      typeof parsed.sub !== 'number' ||
      typeof parsed.email !== 'string' ||
      typeof parsed.exp !== 'number'
    ) {
      return null;
    }
    if (parsed.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return {sub: parsed.sub, email: parsed.email};
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  if (!cookieHeader) {
    return {};
  }
  const cookies: Record<string, string> = {};
  for (const part of cookieHeader.split(';')) {
    const eqIndex = part.indexOf('=');
    if (eqIndex > 0) {
      const key = part.slice(0, eqIndex).trim();
      const val = part.slice(eqIndex + 1).trim();
      cookies[key] = decodeURIComponent(val);
    }
  }
  return cookies;
}

function setSessionCookie(res: Response, token: string): void {
  res.setHeader(
    'Set-Cookie',
    `auth_session=${encodeURIComponent(token)}; Path=/; Max-Age=${TOKEN_TTL_SECONDS}; HttpOnly; Secure; SameSite=None; Partitioned`,
  );
}

function clearSessionCookie(res: Response): void {
  res.setHeader(
    'Set-Cookie',
    'auth_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None; Partitioned',
  );
}

function createActionToken(
  userId: number,
  type: 'verify' | 'reset',
  ttlMs: number,
): string {
  db.prepare('DELETE FROM action_tokens WHERE user_id = ? AND type = ?').run(
    userId,
    type,
  );
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare(
    'INSERT INTO action_tokens (token, user_id, type, expires_at) VALUES (?, ?, ?, ?)',
  ).run(token, userId, type, Date.now() + ttlMs);
  return token;
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPassword(password: string): boolean {
  return password.length >= 8 && /^(?=.*[A-Za-z])(?=.*\d)/.test(password);
}

function sendError(
  res: Response,
  status: number,
  code: string,
  message: string,
  extraData?: Record<string, unknown>,
): void {
  res.status(status).json({
    success: false,
    error: {code, message},
    ...(extraData ? {data: extraData} : {}),
  });
}

function verifySameOrigin(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin;
  if (!origin) {
    next();
    return;
  }
  try {
    const originHost = new URL(origin).host;
    const forwardedHost =
      (req.headers['x-forwarded-host'] as string | undefined)?.split(',')[0]?.trim() ||
      req.headers.host;
    if (forwardedHost && originHost !== forwardedHost) {
      sendError(res, 403, 'INVALID_ORIGIN', 'Cross-origin request blocked');
      return;
    }
  } catch {
    sendError(res, 403, 'INVALID_ORIGIN', 'Invalid origin header');
    return;
  }
  next();
}

async function startServer(): Promise<void> {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({limit: '100kb'}));

  // Register
  app.post('/api/auth/register', (req: Request, res: Response) => {
    const body = req.body as {
      name?: unknown;
      email?: unknown;
      password?: unknown;
      age?: unknown;
    };

    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const age =
      typeof body.age === 'number' && Number.isFinite(body.age)
        ? Math.floor(body.age)
        : undefined;

    if (name.length < 2) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Name must be at least 2 characters');
      return;
    }
    if (!isValidEmail(email)) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Please provide a valid email address');
      return;
    }
    if (!isValidPassword(password)) {
      sendError(
        res,
        400,
        'VALIDATION_ERROR',
        'Password must be at least 8 characters and include a letter and a number',
      );
      return;
    }
    if (age !== undefined && (age < 13 || age > 120)) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Age must be between 13 and 120');
      return;
    }

    const existing = db
      .prepare('SELECT id FROM users WHERE email = ?')
      .get(email) as {id: number} | undefined;
    if (existing) {
      sendError(
        res,
        409,
        'EMAIL_EXISTS',
        'An account with this email already exists',
      );
      return;
    }

    // First registered user (excluding seeded SuperAdmin) receives 'Admin'; subsequent receive 'User'
    const existingAdmin = db
      .prepare("SELECT id FROM users WHERE role = 'Admin' LIMIT 1")
      .get() as {id: number} | undefined;
    const assignedRole: UserRole = existingAdmin ? 'User' : 'Admin';

    const insertResult = db
      .prepare(
        `INSERT INTO users (name, email, age, role, password_hash, is_active, is_disabled, created_at)
         VALUES (?, ?, ?, ?, ?, 0, 0, ?)`,
      )
      .run(
        name,
        email,
        age ?? null,
        assignedRole,
        hashPassword(password),
        new Date().toISOString(),
      );

    const userId = Number(insertResult.lastInsertRowid);
    const token = createActionToken(userId, 'verify', 1000 * 60 * 60 * 24);

    res.status(201).json({
      success: true,
      data: {
        message: `Registration successful (${assignedRole} role assigned)! Click the verification preview link below to activate your account.`,
        userId,
        role: assignedRole,
        previewUrl: `/verify-email?token=${token}`,
      },
    });
  });

  // Verify email
  app.get('/api/auth/verify-email', (req: Request, res: Response) => {
    const token = typeof req.query.token === 'string' ? req.query.token.trim() : '';
    if (!token) {
      sendError(res, 400, 'INVALID_TOKEN', 'Verification token is missing');
      return;
    }

    const record = db
      .prepare('SELECT token, user_id, type, expires_at FROM action_tokens WHERE token = ?')
      .get(token) as unknown as DbTokenRow | undefined;

    if (!record || record.type !== 'verify' || record.expires_at < Date.now()) {
      db.prepare('DELETE FROM action_tokens WHERE token = ?').run(token);
      sendError(
        res,
        400,
        'INVALID_TOKEN',
        'Verification link is invalid or has expired',
      );
      return;
    }

    const user = db
      .prepare('SELECT id FROM users WHERE id = ?')
      .get(record.user_id) as {id: number} | undefined;

    if (!user) {
      db.prepare('DELETE FROM action_tokens WHERE token = ?').run(token);
      sendError(res, 404, 'USER_NOT_FOUND', 'User account no longer exists');
      return;
    }

    db.prepare('UPDATE users SET is_active = 1 WHERE id = ?').run(user.id);
    db.prepare('DELETE FROM action_tokens WHERE token = ?').run(token);

    res.json({
      success: true,
      message: 'Your email has been verified! You can now sign in to your account.',
    });
  });

  // Login
  app.post('/api/auth/login', (req: Request, res: Response) => {
    const body = req.body as {email?: unknown; password?: unknown};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (!isValidEmail(email) || password.length < 8) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Valid email and password are required');
      return;
    }

    const user = db
      .prepare('SELECT * FROM users WHERE email = ?')
      .get(email) as unknown as DbUserRow | undefined;

    if (!user || !verifyPassword(password, user.password_hash)) {
      sendError(res, 401, 'INVALID_CREDENTIALS', 'Invalid email or password');
      return;
    }

    if (user.is_disabled === 1) {
      sendError(
        res,
        403,
        'ACCOUNT_DISABLED',
        'Your account has been disabled by an administrator.',
      );
      return;
    }

    if (user.is_active !== 1) {
      const verifyToken = createActionToken(
        user.id,
        'verify',
        1000 * 60 * 60 * 24,
      );
      sendError(
        res,
        403,
        'EMAIL_NOT_VERIFIED',
        'Please verify your email before logging in.',
        {previewUrl: `/verify-email?token=${verifyToken}`},
      );
      return;
    }

    const token = signJwt(user);
    setSessionCookie(res, token);

    res.json({
      success: true,
      data: {
        token,
        user: toSafeUser(user),
      },
    });
  });

  // Forgot password
  app.post('/api/auth/forgot-password', (req: Request, res: Response) => {
    const body = req.body as {email?: unknown};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';

    if (!isValidEmail(email)) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Please enter a valid email address');
      return;
    }

    const user = db
      .prepare('SELECT id FROM users WHERE email = ?')
      .get(email) as {id: number} | undefined;

    if (!user) {
      res.json({
        success: true,
        message:
          'If an account exists for that email, a password reset link has been sent.',
      });
      return;
    }

    const resetToken = createActionToken(user.id, 'reset', 1000 * 60 * 60);
    res.json({
      success: true,
      message:
        'Password reset link generated! Use the preview link below to set a new password.',
      data: {
        previewUrl: `/reset-password?token=${resetToken}`,
      },
    });
  });

  // Reset password
  app.post('/api/auth/reset-password', (req: Request, res: Response) => {
    const body = req.body as {token?: unknown; newPassword?: unknown};
    const token = typeof body.token === 'string' ? body.token.trim() : '';
    const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';

    if (!token) {
      sendError(res, 400, 'INVALID_TOKEN', 'Reset token is missing');
      return;
    }
    if (!isValidPassword(newPassword)) {
      sendError(
        res,
        400,
        'VALIDATION_ERROR',
        'New password must be at least 8 characters and include a letter and a number',
      );
      return;
    }

    const record = db
      .prepare('SELECT token, user_id, type, expires_at FROM action_tokens WHERE token = ?')
      .get(token) as unknown as DbTokenRow | undefined;

    if (!record || record.type !== 'reset' || record.expires_at < Date.now()) {
      db.prepare('DELETE FROM action_tokens WHERE token = ?').run(token);
      sendError(
        res,
        400,
        'INVALID_TOKEN',
        'Reset link is invalid or has expired',
      );
      return;
    }

    const user = db
      .prepare('SELECT id FROM users WHERE id = ?')
      .get(record.user_id) as {id: number} | undefined;

    if (!user) {
      db.prepare('DELETE FROM action_tokens WHERE token = ?').run(token);
      sendError(res, 404, 'USER_NOT_FOUND', 'User account no longer exists');
      return;
    }

    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(
      hashPassword(newPassword),
      user.id,
    );
    db.prepare('DELETE FROM action_tokens WHERE token = ?').run(token);

    res.json({
      success: true,
      message: 'Your password has been updated. You can now sign in.',
    });
  });

  function authenticateRequest(
    req: Request,
    res: Response,
  ): {user: DbUserRow; token: string} | null {
    const authHeader = req.headers.authorization;
    let token: string | undefined;

    if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    } else {
      const cookies = parseCookies(req.headers.cookie);
      token = cookies.auth_session;
    }

    if (!token) {
      sendError(res, 401, 'UNAUTHORIZED', 'Authentication required');
      return null;
    }

    const payload = verifyJwt(token);
    if (!payload) {
      clearSessionCookie(res);
      sendError(res, 401, 'INVALID_TOKEN', 'Session expired or invalid');
      return null;
    }

    const user = db
      .prepare('SELECT * FROM users WHERE id = ?')
      .get(payload.sub) as unknown as DbUserRow | undefined;

    if (!user || user.is_disabled === 1) {
      clearSessionCookie(res);
      sendError(
        res,
        401,
        user?.is_disabled === 1 ? 'ACCOUNT_DISABLED' : 'UNAUTHORIZED',
        user?.is_disabled === 1
          ? 'Your account has been disabled by an administrator.'
          : 'Account not found',
      );
      return null;
    }

    return {user, token};
  }

  function requireAdmin(req: Request, res: Response): DbUserRow | null {
    const auth = authenticateRequest(req, res);
    if (!auth) {
      return null;
    }
    if (auth.user.role !== 'Admin' && auth.user.role !== 'SuperAdmin') {
      sendError(res, 403, 'FORBIDDEN', 'Administrator access required');
      return null;
    }
    return auth.user;
  }

  // Current authenticated user
  app.get('/api/auth/me', (req: Request, res: Response) => {
    const auth = authenticateRequest(req, res);
    if (!auth) {
      return;
    }

    res.json({
      success: true,
      data: {
        token: auth.token,
        user: toSafeUser(auth.user),
      },
    });
  });

  // Logout
  app.post('/api/auth/logout', verifySameOrigin, (_req: Request, res: Response) => {
    clearSessionCookie(res);
    res.json({
      success: true,
      message: 'Logged out successfully',
    });
  });

  // === USER MANAGEMENT (Admin & SuperAdmin) ===

  app.get('/api/users', (req: Request, res: Response) => {
    const actor = requireAdmin(req, res);
    if (!actor) {
      return;
    }

    const rows = (
      actor.role === 'SuperAdmin'
        ? db.prepare('SELECT * FROM users ORDER BY id ASC').all()
        : db
            .prepare("SELECT * FROM users WHERE role != 'SuperAdmin' ORDER BY id ASC")
            .all()
    ) as unknown as DbUserRow[];

    res.json({
      success: true,
      data: rows.map(toSafeUser),
    });
  });

  app.post('/api/users', verifySameOrigin, (req: Request, res: Response) => {
    const actor = requireAdmin(req, res);
    if (!actor) {
      return;
    }

    const body = req.body as {
      name?: unknown;
      email?: unknown;
      password?: unknown;
      role?: unknown;
      age?: unknown;
    };

    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const role = body.role ?? 'User';
    const age =
      typeof body.age === 'number' && Number.isFinite(body.age)
        ? Math.floor(body.age)
        : undefined;

    if (name.length < 2) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Name must be at least 2 characters');
      return;
    }
    if (!isValidEmail(email)) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Please provide a valid email address');
      return;
    }
    if (!isValidPassword(password)) {
      sendError(
        res,
        400,
        'VALIDATION_ERROR',
        'Password must be at least 8 characters and include a letter and a number',
      );
      return;
    }
    if (role !== 'Admin' && role !== 'User') {
      sendError(
        res,
        400,
        'VALIDATION_ERROR',
        "Role must be 'Admin' or 'User'",
      );
      return;
    }
    if (age !== undefined && (age < 13 || age > 120)) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Age must be between 13 and 120');
      return;
    }

    const existing = db
      .prepare('SELECT id FROM users WHERE email = ?')
      .get(email) as {id: number} | undefined;
    if (existing) {
      sendError(
        res,
        409,
        'EMAIL_EXISTS',
        'An account with this email already exists',
      );
      return;
    }

    const insertResult = db
      .prepare(
        `INSERT INTO users (name, email, age, role, password_hash, is_active, is_disabled, created_at)
         VALUES (?, ?, ?, ?, ?, 1, 0, ?)`,
      )
      .run(
        name,
        email,
        age ?? null,
        role,
        hashPassword(password),
        new Date().toISOString(),
      );

    const created = db
      .prepare('SELECT * FROM users WHERE id = ?')
      .get(Number(insertResult.lastInsertRowid)) as unknown as DbUserRow;

    res.status(201).json({
      success: true,
      message: `Created verified ${role} account for ${created.name}.`,
      data: toSafeUser(created),
    });
  });

  app.patch('/api/users/:id/role', verifySameOrigin, (req: Request, res: Response) => {
    const actor = requireAdmin(req, res);
    if (!actor) {
      return;
    }

    const targetId = Number(req.params.id);
    if (!Number.isInteger(targetId) || targetId <= 0) {
      sendError(res, 400, 'INVALID_ID', 'Valid user ID is required');
      return;
    }

    const body = req.body as {role?: unknown};
    if (
      body.role !== 'SuperAdmin' &&
      body.role !== 'Admin' &&
      body.role !== 'User'
    ) {
      sendError(
        res,
        400,
        'VALIDATION_ERROR',
        "Role must be 'SuperAdmin', 'Admin', or 'User'",
      );
      return;
    }

    const targetUser = db
      .prepare('SELECT * FROM users WHERE id = ?')
      .get(targetId) as unknown as DbUserRow | undefined;

    if (!targetUser) {
      sendError(res, 404, 'USER_NOT_FOUND', 'User not found');
      return;
    }

    if (targetUser.id === actor.id && body.role !== actor.role) {
      sendError(
        res,
        400,
        'SELF_DEMOTION_FORBIDDEN',
        `You cannot change your own role from ${actor.role}.`,
      );
      return;
    }

    if (
      actor.role !== 'SuperAdmin' &&
      (targetUser.role === 'SuperAdmin' || body.role === 'SuperAdmin')
    ) {
      sendError(
        res,
        403,
        'SUPERADMIN_REQUIRED',
        'Only a SuperAdmin can assign or modify the SuperAdmin role.',
      );
      return;
    }

    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(
      body.role,
      targetUser.id,
    );

    const updated = db
      .prepare('SELECT * FROM users WHERE id = ?')
      .get(targetUser.id) as unknown as DbUserRow;

    res.json({
      success: true,
      message: `Updated ${updated.name}'s role to ${body.role}.`,
      data: toSafeUser(updated),
    });
  });

  app.patch('/api/users/:id/status', verifySameOrigin, (req: Request, res: Response) => {
    const actor = requireAdmin(req, res);
    if (!actor) {
      return;
    }

    const targetId = Number(req.params.id);
    if (!Number.isInteger(targetId) || targetId <= 0) {
      sendError(res, 400, 'INVALID_ID', 'Valid user ID is required');
      return;
    }

    const body = req.body as {isDisabled?: unknown};
    if (typeof body.isDisabled !== 'boolean') {
      sendError(res, 400, 'VALIDATION_ERROR', 'isDisabled must be a boolean');
      return;
    }

    const targetUser = db
      .prepare('SELECT * FROM users WHERE id = ?')
      .get(targetId) as unknown as DbUserRow | undefined;

    if (!targetUser) {
      sendError(res, 404, 'USER_NOT_FOUND', 'User not found');
      return;
    }

    if (
      (targetUser.role === 'Admin' || targetUser.role === 'SuperAdmin') &&
      body.isDisabled
    ) {
      sendError(
        res,
        400,
        'ADMIN_DISABLE_FORBIDDEN',
        `${targetUser.role} accounts cannot be disabled.`,
      );
      return;
    }

    db.prepare('UPDATE users SET is_disabled = ? WHERE id = ?').run(
      body.isDisabled ? 1 : 0,
      targetUser.id,
    );

    const updated = db
      .prepare('SELECT * FROM users WHERE id = ?')
      .get(targetUser.id) as unknown as DbUserRow;

    res.json({
      success: true,
      message: `${updated.name} has been ${body.isDisabled ? 'disabled' : 'enabled'}.`,
      data: toSafeUser(updated),
    });
  });

  // === TASK MANAGEMENT ===

  const TASK_JOIN_SELECT = `
    SELECT
      t.id,
      t.user_id,
      u.name AS assignee_name,
      u.email AS assignee_email,
      u.role AS assignee_role,
      t.title,
      t.description,
      t.priority,
      t.status,
      t.due_date,
      t.is_disabled,
      t.created_at,
      t.updated_at
    FROM tasks t
    JOIN users u ON u.id = t.user_id
  `;

  app.get('/api/tasks', (req: Request, res: Response) => {
    const auth = authenticateRequest(req, res);
    if (!auth) {
      return;
    }

    const actor = auth.user;
    let rows: DbTaskJoinRow[];

    if (actor.role === 'SuperAdmin') {
      rows = db
        .prepare(`${TASK_JOIN_SELECT} ORDER BY t.id DESC`)
        .all() as unknown as DbTaskJoinRow[];
    } else if (actor.role === 'Admin') {
      rows = db
        .prepare(`${TASK_JOIN_SELECT} WHERE u.role != 'SuperAdmin' ORDER BY t.id DESC`)
        .all() as unknown as DbTaskJoinRow[];
    } else {
      rows = db
        .prepare(`${TASK_JOIN_SELECT} WHERE t.user_id = ? ORDER BY t.id DESC`)
        .all(actor.id) as unknown as DbTaskJoinRow[];
    }

    res.json({
      success: true,
      data: rows.map(toSafeTask),
    });
  });

  app.post('/api/tasks', verifySameOrigin, (req: Request, res: Response) => {
    const auth = authenticateRequest(req, res);
    if (!auth) {
      return;
    }

    const actor = auth.user;
    const isAdminActor = actor.role === 'Admin' || actor.role === 'SuperAdmin';
    const body = req.body as {
      title?: unknown;
      description?: unknown;
      priority?: unknown;
      dueDate?: unknown;
      userId?: unknown;
    };

    const title = typeof body.title === 'string' ? body.title.trim() : '';
    const description =
      typeof body.description === 'string' ? body.description.trim() : '';
    const priority = body.priority ?? 'Medium';
    const dueDate =
      typeof body.dueDate === 'string' && body.dueDate.trim().length > 0
        ? body.dueDate.trim()
        : null;

    if (title.length < 2 || title.length > 140) {
      sendError(
        res,
        400,
        'VALIDATION_ERROR',
        'Task title must be between 2 and 140 characters',
      );
      return;
    }
    if (priority !== 'Low' && priority !== 'Medium' && priority !== 'High') {
      sendError(
        res,
        400,
        'VALIDATION_ERROR',
        "Priority must be 'Low', 'Medium', or 'High'",
      );
      return;
    }
    if (dueDate !== null && !/^\d{4}-\d{2}-\d{2}$/.test(dueDate)) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Due date must be YYYY-MM-DD');
      return;
    }

    let assigneeId = actor.id;
    if (body.userId !== undefined && body.userId !== null) {
      const requestedUserId = Number(body.userId);
      if (!Number.isInteger(requestedUserId) || requestedUserId <= 0) {
        sendError(res, 400, 'VALIDATION_ERROR', 'Invalid assignee userId');
        return;
      }
      if (!isAdminActor && requestedUserId !== actor.id) {
        sendError(
          res,
          403,
          'FORBIDDEN',
          'Users can only create tasks assigned to themselves.',
        );
        return;
      }
      assigneeId = requestedUserId;
    }

    const assignee = db
      .prepare('SELECT * FROM users WHERE id = ?')
      .get(assigneeId) as unknown as DbUserRow | undefined;

    if (!assignee || assignee.is_disabled === 1) {
      sendError(
        res,
        400,
        'INVALID_ASSIGNEE',
        'Assignee user does not exist or is disabled.',
      );
      return;
    }

    if (actor.role === 'Admin' && assignee.role === 'SuperAdmin') {
      sendError(
        res,
        403,
        'FORBIDDEN',
        'Cannot assign tasks to a SuperAdmin account.',
      );
      return;
    }

    const now = new Date().toISOString();
    const insertResult = db
      .prepare(
        `INSERT INTO tasks (user_id, title, description, priority, status, due_date, is_disabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'Pending', ?, 0, ?, ?)`,
      )
      .run(assigneeId, title, description, priority, dueDate, now, now);

    const created = db
      .prepare(`${TASK_JOIN_SELECT} WHERE t.id = ?`)
      .get(Number(insertResult.lastInsertRowid)) as unknown as DbTaskJoinRow;

    res.status(201).json({
      success: true,
      message: 'Task created successfully.',
      data: toSafeTask(created),
    });
  });

  app.patch('/api/tasks/:id', verifySameOrigin, (req: Request, res: Response) => {
    const auth = authenticateRequest(req, res);
    if (!auth) {
      return;
    }

    const actor = auth.user;
    const isAdminActor = actor.role === 'Admin' || actor.role === 'SuperAdmin';
    const taskId = Number(req.params.id);
    if (!Number.isInteger(taskId) || taskId <= 0) {
      sendError(res, 400, 'INVALID_ID', 'Valid task ID is required');
      return;
    }

    const existing = db
      .prepare(`${TASK_JOIN_SELECT} WHERE t.id = ?`)
      .get(taskId) as unknown as DbTaskJoinRow | undefined;

    if (!existing) {
      sendError(res, 404, 'TASK_NOT_FOUND', 'Task not found');
      return;
    }

    if (!isAdminActor) {
      if (existing.user_id !== actor.id) {
        sendError(res, 403, 'FORBIDDEN', 'You can only edit your own tasks.');
        return;
      }
      if (existing.is_disabled === 1) {
        sendError(
          res,
          403,
          'TASK_DISABLED',
          'Disabled tasks cannot be modified. Contact an administrator.',
        );
        return;
      }
    } else if (actor.role === 'Admin' && existing.assignee_role === 'SuperAdmin') {
      sendError(res, 403, 'FORBIDDEN', 'Cannot modify SuperAdmin tasks.');
      return;
    }

    const body = req.body as {
      title?: unknown;
      description?: unknown;
      priority?: unknown;
      status?: unknown;
      dueDate?: unknown;
      userId?: unknown;
    };

    const nextTitle =
      body.title !== undefined
        ? typeof body.title === 'string'
          ? body.title.trim()
          : ''
        : existing.title;
    const nextDescription =
      body.description !== undefined
        ? typeof body.description === 'string'
          ? body.description.trim()
          : ''
        : existing.description;
    const nextPriority = body.priority ?? existing.priority;
    const nextStatus = body.status ?? existing.status;
    let nextDueDate = existing.due_date;
    if (body.dueDate !== undefined) {
      if (body.dueDate === null || body.dueDate === '') {
        nextDueDate = null;
      } else if (typeof body.dueDate === 'string') {
        nextDueDate = body.dueDate.trim();
      } else {
        sendError(res, 400, 'VALIDATION_ERROR', 'Invalid dueDate');
        return;
      }
    }

    if (nextTitle.length < 2 || nextTitle.length > 140) {
      sendError(
        res,
        400,
        'VALIDATION_ERROR',
        'Task title must be between 2 and 140 characters',
      );
      return;
    }
    if (
      nextPriority !== 'Low' &&
      nextPriority !== 'Medium' &&
      nextPriority !== 'High'
    ) {
      sendError(
        res,
        400,
        'VALIDATION_ERROR',
        "Priority must be 'Low', 'Medium', or 'High'",
      );
      return;
    }
    if (nextStatus !== 'Pending' && nextStatus !== 'Done') {
      sendError(
        res,
        400,
        'VALIDATION_ERROR',
        "Status must be 'Pending' or 'Done'",
      );
      return;
    }
    if (nextDueDate !== null && !/^\d{4}-\d{2}-\d{2}$/.test(nextDueDate)) {
      sendError(res, 400, 'VALIDATION_ERROR', 'Due date must be YYYY-MM-DD');
      return;
    }

    let nextUserId = existing.user_id;
    if (body.userId !== undefined && body.userId !== null) {
      const requestedUserId = Number(body.userId);
      if (!Number.isInteger(requestedUserId) || requestedUserId <= 0) {
        sendError(res, 400, 'VALIDATION_ERROR', 'Invalid assignee userId');
        return;
      }
      if (!isAdminActor && requestedUserId !== actor.id) {
        sendError(res, 403, 'FORBIDDEN', 'Users cannot reassign tasks.');
        return;
      }
      if (requestedUserId !== existing.user_id) {
        const targetAssignee = db
          .prepare('SELECT * FROM users WHERE id = ?')
          .get(requestedUserId) as unknown as DbUserRow | undefined;
        if (!targetAssignee || targetAssignee.is_disabled === 1) {
          sendError(
            res,
            400,
            'INVALID_ASSIGNEE',
            'Assignee user does not exist or is disabled.',
          );
          return;
        }
        if (actor.role === 'Admin' && targetAssignee.role === 'SuperAdmin') {
          sendError(
            res,
            403,
            'FORBIDDEN',
            'Cannot assign tasks to a SuperAdmin account.',
          );
          return;
        }
        nextUserId = requestedUserId;
      }
    }

    db.prepare(
      `UPDATE tasks
       SET user_id = ?, title = ?, description = ?, priority = ?, status = ?, due_date = ?, updated_at = ?
       WHERE id = ?`,
    ).run(
      nextUserId,
      nextTitle,
      nextDescription,
      nextPriority,
      nextStatus,
      nextDueDate,
      new Date().toISOString(),
      taskId,
    );

    const updated = db
      .prepare(`${TASK_JOIN_SELECT} WHERE t.id = ?`)
      .get(taskId) as unknown as DbTaskJoinRow;

    res.json({
      success: true,
      message: 'Task updated.',
      data: toSafeTask(updated),
    });
  });

  app.patch('/api/tasks/:id/status', verifySameOrigin, (req: Request, res: Response) => {
    const actor = requireAdmin(req, res);
    if (!actor) {
      return;
    }

    const taskId = Number(req.params.id);
    if (!Number.isInteger(taskId) || taskId <= 0) {
      sendError(res, 400, 'INVALID_ID', 'Valid task ID is required');
      return;
    }

    const body = req.body as {isDisabled?: unknown};
    if (typeof body.isDisabled !== 'boolean') {
      sendError(res, 400, 'VALIDATION_ERROR', 'isDisabled must be a boolean');
      return;
    }

    const existing = db
      .prepare(`${TASK_JOIN_SELECT} WHERE t.id = ?`)
      .get(taskId) as unknown as DbTaskJoinRow | undefined;

    if (!existing) {
      sendError(res, 404, 'TASK_NOT_FOUND', 'Task not found');
      return;
    }

    if (actor.role === 'Admin' && existing.assignee_role === 'SuperAdmin') {
      sendError(res, 403, 'FORBIDDEN', 'Cannot modify SuperAdmin tasks.');
      return;
    }

    db.prepare('UPDATE tasks SET is_disabled = ?, updated_at = ? WHERE id = ?').run(
      body.isDisabled ? 1 : 0,
      new Date().toISOString(),
      taskId,
    );

    const updated = db
      .prepare(`${TASK_JOIN_SELECT} WHERE t.id = ?`)
      .get(taskId) as unknown as DbTaskJoinRow;

    res.json({
      success: true,
      message: `Task "${updated.title}" has been ${body.isDisabled ? 'disabled' : 'enabled'}.`,
      data: toSafeTask(updated),
    });
  });

  // Frontend middleware / static serving
  if (process.env.NODE_ENV !== 'production') {
    const {createServer: createViteServer} = await import('vite');
    const vite = await createViteServer({
      server: {middlewareMode: true},
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (req: Request, res: Response) => {
      if (req.path.startsWith('/api/')) {
        sendError(res, 404, 'NOT_FOUND', 'API route not found');
        return;
      }
      const indexFile = path.join(distDir, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.sendFile(indexFile);
      } else {
        res.status(404).send('Build output not found');
      }
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server listening on http://0.0.0.0:${PORT}`);
  });
}

void startServer();
