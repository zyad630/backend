// server.js
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import axios from "axios";
import cron from "node-cron";

// Load environment variables
dotenv.config();

// Initialize Express
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Security Middleware
// Behind Railway/NGINX proxies, trust first proxy to read X-Forwarded-For safely
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'x-api-key',
    'Accept',
    'Accept-Language',
    'X-Requested-With',
    'X-Request-ID'
  ],
  exposedHeaders: ['Content-Type'],
  credentials: false
}));

// Handle preflight requests
app.options('*', cors());
app.use(bodyParser.json({
  limit: '10kb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// 🗑️ حذف موعد (Soft Delete)
app.delete("/api/meetings/:id", checkApiKey, async (req, res) => {
  try {
    const { id } = req.params;
    const now = new Date().toISOString();
    
    const existing = await db.get("SELECT id FROM meetings WHERE id = ? AND deleted_at IS NULL", [id]);
    if (!existing) return res.status(404).json({ success: false, error: 'لم يتم العثور على الموعد' });

    await db.run(
      "UPDATE meetings SET deleted_at = ?, updated_at = ? WHERE id = ?",
      [now, now, id]
    );
    
    res.json({ success: true });
  } catch (e) {
    console.error('Error soft deleting meeting:', e);
    res.status(500).json({ success: false, error: 'خطأ أثناء حذف الموعد' });
  }
});

// Send structured reminder for a specific task id using tiered templates
app.post("/api/tasks/:id/remind", checkApiKey, async (req, res) => {
  try {
    const id = req.params.id;
    const task = await db.get(`SELECT t.*, s.name AS student_name, s.phone AS student_phone FROM tasks t JOIN students s ON s.id = t.student_id WHERE t.id = ?`, [id]);
    if (!task) return res.status(404).json({ success: false, error: 'TASK_NOT_FOUND' });
    if (!task.student_phone) return res.status(400).json({ success: false, error: 'TASK_PHONE_MISSING' });

    const currentCount = Number(task.reminder_count || 0);
    const text = buildReminderText(task.student_name, task.task, currentCount);

    await sendWhatsApp(task.student_phone, text);
    const nowIso = new Date().toISOString();
    await db.run(`UPDATE tasks SET last_followup_at = ?, reminder_count = ? WHERE id = ?`, [nowIso, currentCount + 1, id]);
    const updated = await db.get(`SELECT * FROM tasks WHERE id = ?`, [id]);
    return res.json({ success: true, data: updated });
  } catch (e) {
    console.error('remind task error', e?.response?.data || e.message);
    return res.status(502).json({ success: false, error: 'FAILED_TO_SEND_WHATSAPP' });
  }
});

// ♻️ استعادة موعد من سلة المحذوفات
app.post("/api/meetings/:id/restore", checkApiKey, async (req, res) => {
  try {
    const { id } = req.params;
    const now = new Date().toISOString();
    
    const existing = await db.get("SELECT id FROM meetings WHERE id = ? AND deleted_at IS NOT NULL", [id]);
    if (!existing) return res.status(404).json({ success: false, error: 'لم يتم العثور على الموعد المحذوف' });

    await db.run(
      "UPDATE meetings SET deleted_at = NULL, updated_at = ? WHERE id = ?",
      [now, id]
    );
    
    res.json({ success: true });
  } catch (e) {
    console.error('Error restoring meeting:', e);
    res.status(500).json({ success: false, error: 'خطأ أثناء استعادة الموعد' });
  }
});

// 🗑️ حذف موعد نهائياً (Permanent Delete)
app.delete("/api/meetings/:id/permanent", checkApiKey, async (req, res) => {
  try {
    const { id } = req.params;
    await db.run("DELETE FROM meetings WHERE id = ?", [id]);
    res.json({ success: true });
  } catch (e) {
    console.error('Error permanently deleting meeting:', e);
    res.status(500).json({ success: false, error: 'خطأ أثناء الحذف النهائي للموعد' });
  }
});

// تفريغ سلة المحذوفات (حذف جميع المواعيد المحذوفة نهائياً)
app.post("/api/meetings/empty-trash", checkApiKey, async (req, res) => {
  try {
    await db.run("DELETE FROM meetings WHERE deleted_at IS NOT NULL");
    res.json({ success: true });
  } catch (e) {
    console.error('Error emptying trash:', e);
    res.status(500).json({ success: false, error: 'خطأ أثناء تفريغ سلة المحذوفات' });
  }
});
app.use(limiter);

// Environment variables
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "data.db");
const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;
const WHATSAPP_PHONE_ID = process.env.WHATSAPP_PHONE_ID;
const WHATSAPP_VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
const DEFAULT_WHATSAPP_TO = process.env.DEFAULT_WHATSAPP_TO; // optional: force all sends to this E.164 digits-only number
const WHATSAPP_TEMPLATE_NAME = process.env.WHATSAPP_TEMPLATE_NAME || null;
const WHATSAPP_TEMPLATE_LANG = process.env.WHATSAPP_TEMPLATE_LANG || 'en_US';
const APP_SECRET = process.env.APP_SECRET || null;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || null;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'amjd';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'za123';
const AUTH_SECRET = process.env.AUTH_SECRET || API_KEY;

if (!API_KEY) {
  console.error('FATAL: API_KEY is not defined in environment variables');
  process.exit(1);
}

let db;

// Database initialization
(async () => {
  db = await open({
    filename: DB_FILE,
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS meetings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      service TEXT,
      person TEXT,
      phone TEXT,
      location TEXT,
      notes TEXT,
      priority TEXT,
      date TEXT,
      time TEXT,
      status TEXT DEFAULT 'قيد الانتظار',
      is_archived INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT,
      completed_at TEXT,
      todoist_task_id TEXT
    )
  `);

  // Ensure student/tasks tables for WhatsApp task follow-ups
  await db.exec(`
    CREATE TABLE IF NOT EXISTS students (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      phone TEXT
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id INTEGER,
      task TEXT,
      status TEXT DEFAULT 'pending',
      note TEXT,
      last_followup_at TEXT,
      followup_interval_hours INTEGER DEFAULT 24,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(student_id) REFERENCES students(id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      direction TEXT, -- in | out
      phone TEXT,
      type TEXT, -- text/template
      body TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS whatsapp_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT,
      step TEXT,
      service TEXT,
      person TEXT,
      date TEXT,
      time TEXT,
      location TEXT,
      notes TEXT,
      pending_hour TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS blocked_phones (
      phone TEXT PRIMARY KEY,
      reason TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Migrate existing tables to include missing columns
  const existingCols = await db.all(`PRAGMA table_info(meetings)`);
  const colNames = new Set(existingCols.map(c => c.name));
  const addCol = async (name, type, defaultExpr = null) => {
    if (!colNames.has(name)) {
      await db.exec(`ALTER TABLE meetings ADD COLUMN ${name} ${type} ${defaultExpr ? 'DEFAULT ' + defaultExpr : ''}`);
    }
  };
  await addCol('phone', 'TEXT');
  await addCol('location', 'TEXT');
  await addCol('notes', 'TEXT');
  await addCol('priority', 'TEXT');
  await addCol('is_archived', 'INTEGER', '0');
  await addCol('updated_at', 'TEXT');
  await addCol('completed_at', 'TEXT');
  await addCol('deleted_at', 'TEXT');
  await addCol('todoist_task_id', 'TEXT');

  // ensure tasks has reminder_count column
  const taskCols = await db.all(`PRAGMA table_info(tasks)`);
  const taskColNames = new Set(taskCols.map(c => c.name));
  if (!taskColNames.has('reminder_count')) {
    await db.exec(`ALTER TABLE tasks ADD COLUMN reminder_count INTEGER DEFAULT 0`);
  }

  // ensure whatsapp_sessions has pending_hour column
  const wsCols = await db.all(`PRAGMA table_info(whatsapp_sessions)`);
  const wsColNames = new Set(wsCols.map(c => c.name));
  if (!wsColNames.has('pending_hour')) {
    await db.exec(`ALTER TABLE whatsapp_sessions ADD COLUMN pending_hour TEXT`);
  }

  console.log("✅ Database ready.");

  // Simple helpers for auth token (HMAC-signed, 1 hour expiry)
  function createAuthToken(username) {
    const exp = Date.now() + 60 * 60 * 1000; // 1 hour
    const payload = { sub: username, exp };
    const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url');
    return `${data}.${sig}`;
  }

  function verifyAuthToken(token) {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [data, sig] = parts;
    const expected = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    let payload;
    try {
      payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    } catch {
      return null;
    }
    if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
    return payload;
  }

  // تشغيل السيرفر
  app.listen(PORT, () => {
    console.log(`✅ Backend running on port ${PORT}`);
    console.log(`🔐 API_KEY (use in n8n x-api-key): ${API_KEY}`);
  });
})();

// ===== Auth endpoints for admin login (simple, token-based) =====

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
      return res.status(401).json({ success: false, error: 'بيانات الدخول غير صحيحة' });
    }

    const token = (function createToken() {
      const exp = Date.now() + 60 * 60 * 1000; // 1 hour
      const payload = { sub: ADMIN_USERNAME, exp };
      const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const sig = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url');
      return `${data}.${sig}`;
    })();

    return res.json({
      success: true,
      token,
      user: { username: ADMIN_USERNAME }
    });
  } catch (e) {
    console.error('auth login error', e);
    return res.status(500).json({ success: false, error: 'خطأ في تسجيل الدخول' });
  }
});

app.post('/auth/logout', (req, res) => {
  // Token is stored client-side only; just respond OK
  return res.json({ success: true });
});

app.get('/auth/me', (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const parts = auth.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return res.status(401).json({ success: false, error: 'غير مصرح' });
    }
    const token = parts[1];
    const payload = (function verify(tokenStr) {
      if (!tokenStr || typeof tokenStr !== 'string') return null;
      const [data, sig] = tokenStr.split('.');
      if (!data || !sig) return null;
      const expected = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url');
      if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
      let pl;
      try {
        pl = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
      } catch {
        return null;
      }
      if (!pl || typeof pl.exp !== 'number' || Date.now() > pl.exp) return null;
      return pl;
    })(token);

    if (!payload) {
      return res.status(401).json({ success: false, error: 'غير مصرح' });
    }

    return res.json({ success: true, user: { username: ADMIN_USERNAME } });
  } catch (e) {
    console.error('auth me error', e);
    return res.status(500).json({ success: false, error: 'خطأ في التحقق' });
  }
});

// Helper to check API key already exists: checkApiKey

// Normalize E.164-like phone: remove spaces/+; if starts with '00' convert to international by removing '00'
function normalizePhone(input) {
  if (!input) return input;
  let p = String(input).trim();
  p = p.replace(/\s+/g, '');
  if (p.startsWith('+')) p = p.slice(1);
  if (p.startsWith('00')) p = p.slice(2);
  return p;
}

// --- Helpers to normalize human-friendly date/time into strict formats ---

// Normalize various date inputs (e.g. 31-12-2025, 31/12, 31 12 2025, 31 12, بكرة/بكره, بعد بكره, الشهر الجاي يوم 9, السبت الجاي) to YYYY-MM-DD
function normalizeUserDate(raw) {
  if (!raw) return { ok: false };
  const text = String(raw).trim().toLowerCase();

  const today = new Date();
  const pad = (n) => (n < 10 ? '0' + n : '' + n);

  // relative words
  if (/(بكرة|بكره|غدا|غداً)/.test(text)) {
    const d = new Date(today);
    d.setDate(d.getDate() + 1);
    return { ok: true, value: `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}` };
  }
  if (/بعد ?بكر(ة|ه)?/.test(text)) {
    const d = new Date(today);
    d.setDate(d.getDate() + 2);
    return { ok: true, value: `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}` };
  }

  // الشهر الجاي مع يوم محدد: "الشهر الجاي يوم 9"
  const nextMonthDayMatch = text.match(/الشهر\s+(الجاي|القادم)[^\d]*(\d{1,2})/);
  if (nextMonthDayMatch) {
    const day = parseInt(nextMonthDayMatch[2], 10);
    if (day >= 1 && day <= 31) {
      const d = new Date(today);
      d.setMonth(d.getMonth() + 1);
      d.setDate(day);
      if (!isNaN(d.getTime())) {
        return { ok: true, value: `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}` };
      }
    }
  }

  // weekdays: السبت الجاي، الاحد القادم ...
  const weekdayMap = {
    'السبت': 6,
    'الاحد': 0, 'الأحد': 0,
    'الاثنين': 1, 'الإثنين': 1,
    'الثلاثاء': 2,
    'الاربعاء': 3, 'الأربعاء': 3,
    'الخميس': 4,
    'الجمعة': 5
  };
  const weekdayMatch = text.match(/(السبت|الاحد|الأحد|الاثنين|الإثنين|الثلاثاء|الاربعاء|الأربعاء|الخميس|الجمعة)(\s+الجاى|\s+الجاي|\s+القادم)?/);
  if (weekdayMatch) {
    const targetDow = weekdayMap[weekdayMatch[1]];
    if (typeof targetDow === 'number') {
      const d = new Date(today);
      const currentDow = d.getDay();
      let diff = targetDow - currentDow;
      if (diff <= 0) diff += 7; // next occurrence
      d.setDate(d.getDate() + diff);
      return { ok: true, value: `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}` };
    }
  }

  // numeric formats
  // YYYY-MM-DD or YYYY/MM/DD or "YYYY MM DD"
  let m = text.match(/^(\d{4})[-\/\s](\d{1,2})[-\/\s](\d{1,2})$/);
  if (m) {
    const y = parseInt(m[1], 10);
    const mo = parseInt(m[2], 10) - 1;
    const da = parseInt(m[3], 10);
    const d = new Date(y, mo, da);
    if (!isNaN(d.getTime())) {
      return { ok: true, value: `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}` };
    }
  }

  // DD-MM-YYYY or DD/MM/YYYY or "DD MM YYYY"
  m = text.match(/^(\d{1,2})[-\/\s](\d{1,2})[-\/\s](\d{4})$/);
  if (m) {
    const y = parseInt(m[3], 10);
    const mo = parseInt(m[2], 10) - 1;
    const da = parseInt(m[1], 10);
    const d = new Date(y, mo, da);
    if (!isNaN(d.getTime())) {
      return { ok: true, value: `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}` };
    }
  }

  // DD-MM or DD/MM or "DD MM" -> assume current year
  m = text.match(/^(\d{1,2})[-\/\s](\d{1,2})$/);
  if (m) {
    const y = today.getFullYear();
    const mo = parseInt(m[2], 10) - 1;
    const da = parseInt(m[1], 10);
    const d = new Date(y, mo, da);
    if (!isNaN(d.getTime())) {
      return { ok: true, value: `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}` };
    }
  }

  return { ok: false };
}

// Normalize time expressions into HH:mm 24h (e.g. 9:30, 9 ونص, 11 الصبح, 7 بالليل)
function normalizeUserTime(raw) {
  if (!raw) return { ok: false };
  const text = String(raw).trim().toLowerCase();
  const pad = (n) => (n < 10 ? '0' + n : '' + n);

  // detect am/pm words
  let isMorning = /(صباح|الصبح|am)/.test(text);
  let isEvening = /(مساء|المساء|ليل|بالليل|pm)/.test(text);

  // 9:30, 09:30 etc
  let m = text.match(/^(\d{1,2})[:٫\.,](\d{1,2})/);
  if (m) {
    let h = parseInt(m[1], 10);
    let min = parseInt(m[2], 10);
    if (isNaN(min)) min = 0;
    if (h <= 12 && isEvening) {
      if (h < 12) h += 12;
    } else if (h === 12 && isMorning) {
      h = 0;
    }
    if (h >= 0 && h <= 23 && min >= 0 && min <= 59) {
      return { ok: true, value: `${pad(h)}:${pad(min)}` };
    }
  }

  // "9 ونص" / "9 و نص" / "9 ونصف"
  m = text.match(/^(\d{1,2})\s*(و)?\s*(نص|نصف)/);
  if (m) {
    let h = parseInt(m[1], 10);
    if (h <= 12 && isEvening) {
      if (h < 12) h += 12;
    } else if (h === 12 && isMorning) {
      h = 0;
    }
    if (h >= 0 && h <= 23) {
      return { ok: true, value: `${pad(h)}:30` };
    }
  }

  // "11 الصبح" / "7 بالليل" / just hour
  m = text.match(/^(\d{1,2})/);
  if (m) {
    let h = parseInt(m[1], 10);
    if (h <= 12 && isEvening) {
      if (h < 12) h += 12;
    } else if (h === 12 && isMorning) {
      h = 0;
    }
    if (h >= 0 && h <= 23) {
      return { ok: true, value: `${pad(h)}:00` };
    }
  }

  return { ok: false };
}

// WhatsApp helper
async function sendWhatsApp(to, text) {
  if (!WHATSAPP_TOKEN || !WHATSAPP_PHONE_ID) throw new Error("WhatsApp config missing");
  const url = `https://graph.facebook.com/v17.0/${WHATSAPP_PHONE_ID}/messages`;
  const body = {
    messaging_product: "whatsapp",
    to,
    type: "text",
    text: { body: text }
  };
  const maxAttempts = 3;
  let attempt = 0;
  let lastErr;
  while (attempt < maxAttempts) {
    try {
      attempt++;
      await axios.post(url, body, {
        headers: {
          Authorization: `Bearer ${WHATSAPP_TOKEN}`,
          "Content-Type": "application/json"
        },
        timeout: 15000
      });
      if (attempt > 1) console.info(`[whatsapp] sent after retry x${attempt - 1} -> ${to}`);
      // Log outbound message
      try { await db.run(`INSERT INTO messages (direction, phone, type, body) VALUES ('out', ?, 'text', ?)`, [to, text]); } catch (e) {}
      return;
    } catch (err) {
      lastErr = err;
      const code = err?.response?.status;
      const data = err?.response?.data;
      console.warn(`[whatsapp] send attempt ${attempt} failed`, code || '', data || err.message);
      // Fallback: try template once if session closed and template is configured
      const canTemplate = !!WHATSAPP_TEMPLATE_NAME;
      const isSessionClosed = code === 400 || code === 470 || (data?.error?.code === 470);
      if (attempt === 1 && canTemplate && isSessionClosed) {
        try {
          const tUrl = `https://graph.facebook.com/v17.0/${WHATSAPP_PHONE_ID}/messages`;
          const tBody = {
            messaging_product: "whatsapp",
            to,
            type: "template",
            template: { name: WHATSAPP_TEMPLATE_NAME, language: { code: WHATSAPP_TEMPLATE_LANG } }
          };
          await axios.post(tUrl, tBody, {
            headers: { Authorization: `Bearer ${WHATSAPP_TOKEN}`, "Content-Type": "application/json" },
            timeout: 15000
          });
          try { await db.run(`INSERT INTO messages (direction, phone, type, body) VALUES ('out', ?, 'template', ?)`, [to, WHATSAPP_TEMPLATE_NAME]); } catch (e) {}
          return;
        } catch (te) {
          console.warn('[whatsapp] template fallback failed', te?.response?.status || '', te?.response?.data || te.message);
        }
      }
      // simple backoff
      await new Promise(r => setTimeout(r, 500 * attempt));
    }
  }
  throw lastErr || new Error('sendWhatsApp failed');
}

// Helper: ask ChatGPT-like assistant for natural Arabic replies
async function askChatAssistant(userText, extraContext = '') {
  if (!OPENAI_API_KEY) {
    throw new Error('OPENAI_API_KEY missing');
  }

  const prompt = `
انت سكرتير شخصي لمركز تعليمي على واتساب، مهمتك تنظيم المواعيد والرد على التذكيرات بالكلام فقط.
السيرفر هو اللي بيسجّل ويحفظ المواعيد فعليًا، إنت بس بتسأل وتجاوب.

🟩 (A) الأسلوب العام
- لهجة مصرية بسيطة، مهنية، محترمة.
- جُمل قصيرة وواضحة.
- الرد لازم يكون ردًا مباشرًا على آخر رسالة من العميل.
- ممنوع تغيّر الموضوع أو تجاوب على سؤال تاني.
- لو السؤال مش واضح أو ناقص → اطلب توضيح قصير بدل ما تخمّن.
- ممنوع تستخدم: باشا، فندم، يا غالي، يا نجم، يا معلم.
- ممنوع تكون لغتك رسمية تقيلة أو معقدة.
- مسموح Emoji بسيط أحيانًا بس ما تكثرش.

🟩 (B) الحجز والمواعيد
- لو فهمت من كلامه إنه عايز يحجز (عايز أحجز / احجزلي / عايز معاد...) → رد بسيط مثل: "تمام، نوع المعاد إيه؟".
- بعد ما يحدد النوع (درس، استشارة، متابعة...) → اسأله في رسالة لوحدها عن اليوم.
- لو كتب تاريخ بس → رد: "تمام، الساعة كام؟".
- لو كتب وقت بس → رد: "تمام، اليوم كام؟".
- لو كتب تاريخ + وقت معًا → اكتفِ بتأكيد الفهم بجملة بسيطة زي: "تمام، فهمت اليوم والساعة." من غير ما تقول إنك سجّلت المعاد.

🟩 (C) رسائل التذكير عن المهام
- لو الرسالة الحالية واضحة إنها رد على تذكير بمهمة (مثلاً نعم/لا على سؤال عن إنجاز مهمة) استخدم أسلوب قصير ولطيف لتأكيد فهمك (إنها تمت أو لسه)، ولا تفتح موضوع حجز جديد من نفسك.

🟩 (D) خارج نطاق الشغل
- لو سأل عن مواضيع خارج الحجز (سياسة، دين، أسعار تفصيلية، معلومات عامة...) → ردود مثل:
  - "أنا مسؤول هنا عن تنظيم المواعيد والمهام بس. تحب أحددلك معاد؟".
  - "اختصاصي هنا تنظيم المواعيد. تحب أظبطلك معاد أو تذكير؟".
- لو بدأ يسأل أسئلة شخصية عنك → "خلينا في تنظيم المواعيد علشان أقدر أساعدك.".

🟩 (E) كلام مش مفهوم
- استخدم ردود قصيرة مثل:
  - "مش واضح… تعيده بطريقة تانية؟".
  - "محتاج توضيح بسيط.".
  - "مش فاهم الجزء الأخير.".

🟩 (F) قواعد صارمة عليك
- ممنوع تطوّل الكلام.
- ممنوع تتفلسف أو تدي نصائح عامة.
- ممنوع تخرج عن موضوع المواعيد والحجز والمهام.
- ممنوع تدي أي معلومات شخصية عن نفسك.
- ممنوع تقول أو تلمّح إنك ذكاء اصطناعي أو بوت.
- ممنوع تستخدم أسلوب معقد أو رسمي زيادة.
- ممنوع تتكلم مع العميل كإنه صاحبك جدًا (خليك مهني ولطيف بس).
- ممنوع تكتب فورمات تواريخ غريبة؛ خليك طبيعي، والنظام هيحوّلها داخليًا.
- ممنوع تقول جمل صريحة إنك "سجّلت" أو "اتسجل" أو "ثبّت" المعاد؛ التسجيل الفعلي عند السيرفر.

🟩 (G) القاعدة الذهبية
- كل رسالة تحتوي فكرة واحدة أو سؤال واحد فقط.
- تأكد أن الرد يجاوب على آخر سؤال للعميل بشكل مباشر.

السياق الإضافي (من النظام أو الكود): ${extraContext || 'لا يوجد'}.

رسالة العميل: ${userText}
`;

  try {
    const resp = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-4.1-mini',
        messages: [
          { role: 'system', content: 'أنت بوت واتساب لطيف يساعد الطلاب في الحجز والمتابعة والرد على الاستفسارات التعليمية.' },
          { role: 'user', content: prompt }
        ],
        temperature: 0.4,
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json',
        },
        timeout: 15000,
      }
    );

    const answer = resp.data?.choices?.[0]?.message?.content?.trim() || '';
    return answer || 'تمام، فهمت عليك. وضّح لي بس نقطة أو نقطتين أكتر علشان أظبط لك الرد.';
  } catch (err) {
    console.error('askChatAssistant error', err?.response?.data || err.message);
    // Fallback to a safe generic reply if OpenAI fails
    return 'تمام، وصلت رسالتك 👍\nحالياً في مشكلة بسيطة في المساعد الذكي، لكن فريق العمل هيتابع رسالتك ويرد عليك في أقرب وقت.';
  }
}

async function classifyIntentWithLLM(text) {
  if (!OPENAI_API_KEY) {
    return { intent: 'rule_based' };
  }

  const systemPrompt = 'أنت مصنّف نوايا رسائل على واتساب لمركز تعليمي. مطلوب منك فقط تحديد نوع الرسالة بشكل بسيط، بدون رد على العميل.';
  const userPrompt = `
الرسالة من العميل:
"${String(text || '').trim()}"

صنِّف النية الرئيسية للرسالة إلى واحدة فقط من القيم التالية:
- booking: لو واضح إنه عايز يحجز أو يعدّل/يلغي معاد.
- smalltalk: لو دردشة عامة أو هزار مش له علاقة مباشرة بالحجز (مثلاً "هو الدكتور نايم ولا إيه"، "إيه الأخبار"...).
- complaint: لو شكوى أو تضايق من خدمة أو تأخير.
- other: أي شيء غير ذلك.

أرجع فقط JSON بالشكل التالي:
{
  "intent": "booking" | "smalltalk" | "complaint" | "other"
}`;

  try {
    const resp = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-4.1-mini',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0,
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json',
        },
        timeout: 8000,
      }
    );

    const content = resp.data?.choices?.[0]?.message?.content?.trim();
    try {
      const parsed = JSON.parse(content);
      const intent = parsed.intent || 'other';
      return { intent };
    } catch {
      return { intent: 'other' };
    }
  } catch (err) {
    console.error('classifyIntentWithLLM error', err?.response?.data || err.message);
    return { intent: 'other' };
  }
}

// Helper: ask LLM for a short clarification question for a specific step
async function askStepClarifier(step, userText) {
  if (!OPENAI_API_KEY) {
    // Fallback generic messages per step
    if (step === 'service') return 'محتاج أعرف نوع الخدمة أو الاستفسار اللي حابب تحجز له (مثلاً جلسة، استشارة، درس...).';
    if (step === 'person') return 'محتاج اسم الشخص اللي نحجزله علشان أكمّل الحجز.';
    if (step === 'date') return 'محتاج اليوم يكون أوضح شوية (مثلاً 15/10 أو السبت الجاي).';
    if (step === 'time') return 'محتاج الساعة تكون واضحة (مثلاً 5 الصبح أو 7 بالليل).';
    return 'محتاج توضيح بسيط علشان أكمّل معاك.';
  }

  const systemPrompt = 'أنت سكرتير واتساب بالعربي المصري، وظيفتك تسأل سؤال توضيحي قصير عن خطوة واحدة فقط في الحجز (service, person, date, time). لازم يكون الرد جملة أو جملتين بالكتير، بدون أي زخرفة، وبسؤال واحد واضح.';

  const userPrompt = `
الخطوة الحالية: ${step}
رسالة العميل: ${userText}

اكتب ردًا واحدًا فقط عبارة عن سؤال توضيحي قصير باللهجة المصرية عن نفس الخطوة، بدون تغيير الموضوع، وبدون ذكر أنك بوت أو نظام.`;

  try {
    const resp = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-4.1-mini',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.4,
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json',
        },
        timeout: 15000,
      }
    );

    const answer = resp.data?.choices?.[0]?.message?.content?.trim();
    if (answer) return answer;
  } catch (err) {
    console.error('askStepClarifier error', err?.response?.data || err.message);
  }

  // Fallbacks if API failed
  if (step === 'service') return 'وضحلي نوع الخدمة أو الحاجة اللي حابب تحجز لها.';
  if (step === 'person') return 'محتاج اسم الشخص اللي نحجزله علشان أسجّل المعاد.';
  if (step === 'date') return 'محتاج اليوم يكون واضح (مثلاً 15/10 أو السبت الجاي).';
  if (step === 'time') return 'محتاج الساعة تكون واضحة (مثلاً 5 الصبح أو 7 بالليل).';
  return 'محتاج توضيح بسيط علشان أكمّل معاك.';
}

async function validatePersonNameWithLLM(rawName) {
  if (!OPENAI_API_KEY) {
    const trimmed = String(rawName || '').trim();
    if (trimmed.length < 2) {
      return {
        ok: false,
        cleanedName: null,
        message: 'محتاج اسم الشخص اللي نحجزله يكون أوضح شوية (مثلاً اسم واحد أو اسمين بالعربي).'
      };
    }
    return { ok: true, cleanedName: trimmed, message: null };
  }

  const systemPrompt = 'أنت مساعد يتحقق من أن النص اسم شخص حقيقي ومناسب للحجز. تعمل بالعربي المصري. لا تسمح بالأسماء التهريجية أو الشتائم أو الجمل الكاملة. لا تشرح كثيرًا، فقط قرر هل يصلح كاسم أم لا.';
  const userPrompt = `
النص: "${String(rawName || '').trim()}"

قرر:
- هل يمكن اعتباره اسم شخص طبيعي (مثلاً: أحمد، محمد علي، سارة محمد)؟
- لو لا، اكتب رسالة قصيرة تطلب من العميل يكتب اسم واضح ومهذب.

أرجع فقط JSON بهذا الشكل:
{
  "ok": true أو false,
  "cleanedName": "الاسم بعد التنضيف أو null",
  "message": "رسالة قصيرة للعميل لو ok = false أو null لو ok = true"
}`;

  try {
    const resp = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-4.1-mini',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0,
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json',
        },
        timeout: 15000,
      }
    );

    const content = resp.data?.choices?.[0]?.message?.content?.trim();
    try {
      const parsed = JSON.parse(content);
      return {
        ok: !!parsed.ok,
        cleanedName: parsed.cleanedName || null,
        message: parsed.message || null,
      };
    } catch {
      return {
        ok: false,
        cleanedName: null,
        message: 'محتاج اسم واضح للشخص اللي نحجزله (مثلاً أحمد محمد).',
      };
    }
  } catch (err) {
    console.error('validatePersonNameWithLLM error', err?.response?.data || err.message);
    const trimmed = String(rawName || '').trim();
    if (trimmed.length < 2) {
      return {
        ok: false,
        cleanedName: null,
        message: 'محتاج اسم واضح للشخص اللي نحجزله (مثلاً أحمد محمد).',
      };
    }
    return { ok: true, cleanedName: trimmed, message: null };
  }
}

// Helper: reminder text templates based on reminder_count (0 = first reminder)
function buildReminderText(studentName, task, reminderCount) {
  const name = studentName || 'صديقي';
  const baseTask = task || 'المهمة المطلوبة';
  if (reminderCount <= 0) {
    return `مرحبًا ${name} 👋\nهذا تذكير لطيف بالمهمة: "${baseTask}".\nهل قمت بإنجازها؟ رجاءً رد بـ نعم أو لا. شكرًا لك.`;
  }
  if (reminderCount === 1) {
    return `مرحبًا مرة أخرى ${name} 😊\nنذكّرك بالمهمة: "${baseTask}".\nإذا أنجزتها رد بـ نعم، وإذا احتجت وقتًا إضافيًا أخبرنا.`;
  }
  return `${name} العزيز، هذا تذكير إضافي بالمهمة: "${baseTask}".\nنحن نهتم بتقدمك، فضلاً أخبرنا هل أنهيتها أم لا.`;
}

// GET webhook verification for Meta
app.get("/api/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode && token === WHATSAPP_VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.status(403).send("Forbidden");
});

// Also support verification on the same WhatsApp webhook path used for POST callbacks
app.get("/api/whatsapp/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode && token === WHATSAPP_VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.status(403).send("Forbidden");
});

// Assign a task to a student (creates student if not exists)
app.post("/api/assignTask", checkApiKey, async (req, res) => {
  try {
    const { studentId, name, phone, task, followupHours = 24 } = req.body || {};
    if ((!studentId && (!name || !phone)) || !task) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }

    // normalize and validate phone E.164 (digits only). Accepts + prefixed.
    let normPhone = phone ? String(phone).replace(/\s+/g, '') : phone;
    if (normPhone && normPhone.startsWith('+')) normPhone = normPhone.slice(1);
    if (normPhone && !/^\d{10,15}$/.test(normPhone)) {
      return res.status(400).json({ success: false, error: "Invalid phone format (use E.164 digits, e.g. 2010xxxxxxx)" });
    }

    const fh = Number(followupHours);
    if (!Number.isFinite(fh) || fh < 1 || fh > 168) {
      return res.status(400).json({ success: false, error: "followupHours must be between 1 and 168" });
    }

    let sid = studentId;
    if (!sid) {
      const insertStudent = await db.run(`INSERT INTO students (name, phone) VALUES (?, ?)`, [name, normPhone]);
      sid = insertStudent.lastID;
    }

    // send initial assignment message first; if it fails, abort assignment
    if (normPhone) {
      const msg = `مرحبًا ${name || 'صديق'}، تم تعيين مهمة لك: "${task}". من فضلك رد بـ نعم إذا أنجزتها أو لا إن لم تنجزها.`;
      try {
        await sendWhatsApp(normPhone, msg);
      } catch (e) {
        console.error("assignTask send error", e?.response?.data || e.message);
        return res.status(502).json({ success: false, error: 'FAILED_TO_SEND_WHATSAPP' });
      }
    }

    const r = await db.run(
      `INSERT INTO tasks (student_id, task, followup_interval_hours, status, last_followup_at) VALUES (?, ?, ?, 'pending', ?)`,
      [sid, task, fh, new Date().toISOString()]
    );
    const newTask = await db.get(`SELECT * FROM tasks WHERE id = ?`, [r.lastID]);

    return res.json({ success: true, data: newTask });
  } catch (e) {
    console.error("assignTask error", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// List tasks with student info
app.get("/api/tasks", checkApiKey, async (req, res) => {
  try {
    const rows = await db.all(`
      SELECT t.*, s.name, s.phone FROM tasks t
      LEFT JOIN students s ON s.id = t.student_id
      ORDER BY t.created_at DESC
    `);
    res.json({ success: true, data: rows });
  } catch (e) {
    console.error("tasks list error", e);
    res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// List WhatsApp messages (in/out) with optional filters
app.get("/api/messages", checkApiKey, async (req, res) => {
  try {
    const { phone, direction, limit = 100 } = req.query;
    const conds = [];
    const params = [];
    if (phone) {
      conds.push("phone = ?");
      params.push(String(phone));
    }
    if (direction && (direction === 'in' || direction === 'out')) {
      conds.push("direction = ?");
      params.push(direction);
    }
    const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
    const lim = Math.max(1, Math.min(Number(limit) || 100, 500));
    const rows = await db.all(`SELECT * FROM messages ${where} ORDER BY created_at DESC LIMIT ?`, [...params, lim]);
    res.json({ success: true, data: rows });
  } catch (e) {
    console.error('messages list error', e);
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// Update task status
app.post("/api/tasks/:id/status", checkApiKey, async (req, res) => {
  try {
    const id = req.params.id;
    const { status, note } = req.body || {};
    if (!status) return res.status(400).json({ success: false, error: "Missing status" });
    await db.run(`UPDATE tasks SET status = ?, note = ? WHERE id = ?`, [status, note || null, id]);
    const task = await db.get(`SELECT * FROM tasks WHERE id = ?`, [id]);
    res.json({ success: true, data: task });
  } catch (e) {
    console.error("update task status error", e);
    res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// WhatsApp send endpoint
app.post("/api/whatsapp/send", checkApiKey, async (req, res) => {
  const { phone, message } = req.body || {};
  if ((!phone && !DEFAULT_WHATSAPP_TO) || !message) return res.status(400).json({ success: false, error: "phone & message required" });
  try {
    const target = normalizePhone(DEFAULT_WHATSAPP_TO || phone);
    if (!/^\d{10,15}$/.test(target)) {
      return res.status(400).json({ success: false, error: "Invalid phone format (use E.164 digits, e.g. 2010xxxxxxx)" });
    }
    await sendWhatsApp(target, message);
    res.json({ success: true });
  } catch (err) {
    console.error("whatsapp send error:", err?.response?.data || err.message);
    res.status(500).json({ success: false, error: "failed to send" });
  }
});

// WhatsApp webhook receive
app.post("/api/whatsapp/webhook", async (req, res) => {
  try {
    if (APP_SECRET) {
      const sig = req.headers['x-hub-signature-256'];
      if (!sig) return res.sendStatus(401);
      const expected = 'sha256=' + crypto.createHmac('sha256', APP_SECRET).update(req.rawBody || Buffer.from('')).digest('hex');
      if (sig !== expected) return res.sendStatus(401);
    }
    const entry = req.body.entry?.[0];
    const changes = entry?.changes?.[0];
    const value = changes?.value;
    const message = value?.messages?.[0];
    if (!message) return res.sendStatus(200);

    const from = message.from;
    const text = message.text?.body || "";
    console.info(`[webhook] msg from ${from}: ${text}`);

     // Log inbound message
    try { await db.run(`INSERT INTO messages (direction, phone, type, body) VALUES ('in', ?, 'text', ?)`, [from, text]); } catch (e) {}
    const low = text.trim().toLowerCase();

    // Check if phone is blocked for abusive language
    const blocked = await db.get(`SELECT phone FROM blocked_phones WHERE phone = ?`, [from]);
    if (blocked) {
      // Ignore any further messages from this number
      return res.sendStatus(200);
    }

    const session = await db.get(
      `SELECT * FROM whatsapp_sessions WHERE phone = ? ORDER BY id DESC LIMIT 1`,
      [from]
    );

    // Direct Islamic greeting reply
    if (/(^|\s)(السلام عليكم|سلام عليكم)(\s|$)/.test(text)) {
      await sendWhatsApp(from, "وعليكم السلام ورحمة الله وبركاته\nإزاي أقدر أساعدك؟");
      return res.sendStatus(200);
    }

    // Detect abusive / bad language (basic list) and block user
    const badWords = [
      'زب', 'طيز', 'خرا', 'قحبة', 'شرموط', 'متنايل', 'يلعن', 'كس ام', 'كسم', 'fuck', 'shit'
    ];
    if (badWords.some(w => low.includes(w))) {
      try {
        await db.run(
          `INSERT OR IGNORE INTO blocked_phones (phone, reason) VALUES (?, ?)` ,
          [from, 'abusive_language']
        );
      } catch (e) {}
      await sendWhatsApp(from, "هبلغ المسؤول عن الأسلوب ده، ومش هقدر أكمل معاك الرد.");
      return res.sendStatus(200);
    }

    // If message is purely English/Latin letters (no Arabic), ask to use Arabic
    const hasArabic = /[\u0600-\u06FF]/.test(text);
    const hasLatin = /[A-Za-z]/.test(text);
    if (!hasArabic && hasLatin && !session) {
      await sendWhatsApp(from, "لو تقدر تكتب بالعربي يكون أسهل عليا أظبطلك المواعيد.");
      return res.sendStatus(200);
    }

    if (low.includes('الغاء') || low.includes('إلغاء') || low.includes('cancel')) {
      if (session) {
        await db.run(`DELETE FROM whatsapp_sessions WHERE id = ?`, [session.id]);
      }
      await sendWhatsApp(from, "تمام، اتلغى. لو حابب نحجز من الأول قوللي عايز أحجز.");
      return res.sendStatus(200);
    }

    if (!session) {
      // استخدم LLM لتصنيف نية الرسالة أولاً
      const { intent } = await classifyIntentWithLLM(text);

      // Block obvious food/restaurant requests (outside scope of the center) بناءً على قواعد سريعة
      const foodKeywords = [
        'أكل', 'اكل', 'وجبة', 'وجبات', 'مطعم', 'مطاعم', 'تيك اواي', 'تيك-اواي',
        'burger', 'بيتزا', 'pizza', 'بورجر', 'شاورما', 'كباب', 'grill', 'مطع', 'اكل كويس'
      ];
      const foodIntent = foodKeywords.some(w => low.includes(w));

      if (foodIntent && intent !== 'booking') {
        await sendWhatsApp(from, "أنا مسؤول هنا عن تنظيم المواعيد بس. تحب أحددلك معاد؟");
        return res.sendStatus(200);
      }

      if (intent === 'booking') {
        const nowIso = new Date().toISOString();

        // حاول نفهم من نفس الرسالة اليوم والساعة لو اتكتبوا في الجملة
        const dateGuess = normalizeUserDate(text);
        const timeGuess = normalizeUserTime(text);

        // تخمين بسيط لنوع الخدمة من الكلمات
        let serviceGuess = 'موعد';
        if (low.includes('ميتنج') || low.includes('meeting')) serviceGuess = 'ميتنج';
        else if (low.includes('استشارة') || low.includes('consult')) serviceGuess = 'استشارة';
        else if (low.includes('جلسة') || low.includes('سيشن') || low.includes('session')) serviceGuess = 'جلسة';

        if (dateGuess.ok && timeGuess.ok) {
          // كل البيانات موجودة ما عدا الاسم → نبدأ من سؤال الاسم مباشرة
          await db.run(
            `INSERT INTO whatsapp_sessions (phone, step, service, date, time, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [from, 'ask_person', serviceGuess, dateGuess.value, timeGuess.value, nowIso, nowIso]
          );
          await sendWhatsApp(from, "تمام، الاسم اللي نحجز بيه إيه؟");
          return res.sendStatus(200);
        }

        // لو المعلومات مش كاملة نرجع للفلو العادي خطوة خطوة
        await db.run(
          `INSERT INTO whatsapp_sessions (phone, step, created_at, updated_at) VALUES (?, ?, ?, ?)`,
          [from, 'ask_service', nowIso, nowIso]
        );
        await sendWhatsApp(from, "تمام، تحب تستفسر عن إيه أو تحجز على إيه؟");
        return res.sendStatus(200);
      }
    }

    if (session) {
      const nowIso = new Date().toISOString();
      let step = session.step || 'ask_service';
      let service = session.service;
      let person = session.person;
      let date = session.date;
      let time = session.time;
      let location = session.location;
      let pendingHour = session.pending_hour;

      if (step === 'ask_service') {
        const rawService = text.trim();
        const rawLow = rawService.toLowerCase();

        // لو الرد رفض صريح أو كلمة قصيرة جدًا نطلب توضيح بدال ما نكمل
        if (/^لا$/.test(rawLow) || rawService.length < 2) {
          const clarifyMsg = await askStepClarifier('service', text);
          await sendWhatsApp(from, clarifyMsg);
          return res.sendStatus(200);
        }

        service = rawService;
        step = 'ask_person';
        await db.run(
          `UPDATE whatsapp_sessions SET service = ?, step = ?, updated_at = ? WHERE id = ?`,
          [service, step, nowIso, session.id]
        );
        await sendWhatsApp(from, "تمام، الاسم اللي نحجز بيه إيه؟");
        return res.sendStatus(200);
      }

      if (step === 'ask_person') {
        const rawPerson = text.trim();
        const rawLow = rawPerson.toLowerCase();

        if (/^لا$/.test(rawLow)) {
          const clarifyMsg = await askStepClarifier('person', text);
          await sendWhatsApp(from, clarifyMsg);
          return res.sendStatus(200);
        }

        const nameCheck = await validatePersonNameWithLLM(rawPerson);
        if (!nameCheck.ok) {
          const msg = nameCheck.message || 'محتاج اسم الشخص اللي نحجزله يكون واضح ومهذب.';
          await sendWhatsApp(from, msg);
          return res.sendStatus(200);
        }

        person = nameCheck.cleanedName || rawPerson;
        // لو التاريخ والساعة كانوا متسجلين من أول رسالة، ما نسألهمش تاني
        if (session.date && session.time) {
          step = 'ask_location';
          await db.run(
            `UPDATE whatsapp_sessions SET person = ?, step = ?, updated_at = ? WHERE id = ?`,
            [person, step, nowIso, session.id]
          );
          await sendWhatsApp(from, "لو حابب تحدد مكان أو فرع معين للمعاد اكتبلي، ولو مش فارق معاك المكان قول مفيش مكان محدد.");
          return res.sendStatus(200);
        }

        // لو معانا تاريخ بس، نروح نسأل على الساعة
        if (session.date && !session.time) {
          step = 'ask_time';
          await db.run(
            `UPDATE whatsapp_sessions SET person = ?, step = ?, updated_at = ? WHERE id = ?`,
            [person, step, nowIso, session.id]
          );
          await sendWhatsApp(from, "تمام، الساعة كام؟");
          return res.sendStatus(200);
        }

        // الحالة الافتراضية: لسه محتاجين التاريخ
        step = 'ask_date';
        await db.run(
          `UPDATE whatsapp_sessions SET person = ?, step = ?, updated_at = ? WHERE id = ?`,
          [person, step, nowIso, session.id]
        );
        await sendWhatsApp(from, "تمام، اليوم كام؟");
        return res.sendStatus(200);
      }

      if (step === 'ask_date') {
        const rawDate = text.trim();
        // لو المستخدم بيرفض التاريخ أو بيطلب تغييره من غير ما يحدد بديل واضح
        const rawLow = rawDate.toLowerCase();
        if (/^لا$/.test(rawLow) || rawLow.includes('مش اليوم ده') || rawLow.includes('غير اليوم') || rawLow.includes('غير المعاد') || rawLow.includes('مش عايز التاريخ ده')) {
          await sendWhatsApp(from, "ولا يهمك، حدّدلي اليوم الجديد اللي يناسبك (مثلاً 15/10 أو السبت الجاي).");
          return res.sendStatus(200);
        }

        // لو الرسالة فيها تاريخ ووقت معًا (مثلاً: ما أنا قولتلك بكره الساعة 9)
        const combinedDate = normalizeUserDate(rawDate);
        const combinedTime = normalizeUserTime(rawDate);

        if (combinedDate.ok && combinedTime.ok) {
          date = combinedDate.value;
          time = combinedTime.value;
          step = 'ask_location';
          await db.run(
            `UPDATE whatsapp_sessions SET date = ?, time = ?, step = ?, updated_at = ? WHERE id = ?`,
            [date, time, step, nowIso, session.id]
          );
          await sendWhatsApp(from, "لو حابب تحدد مكان أو فرع معين للمعاد اكتبلي، ولو مش فارق معاك المكان قول مفيش مكان محدد.");
          return res.sendStatus(200);
        }

        // حالة خاصة: الشهر الجاي فقط بدون يوم
        if (/الشهر\s+الجاي|الشهر\s+القادم/.test(rawDate)) {
          await sendWhatsApp(from, "الشهر الجاي كبير، محتاج اليوم كمان (مثلاً 10 أو 15).");
          return res.sendStatus(200);
        }

        const normalized = combinedDate.ok ? combinedDate : normalizeUserDate(rawDate);

        if (!normalized.ok) {
          await sendWhatsApp(from, "أنا محتاج التاريخ يكون أوضح شوية (اليوم والشهر على الأقل).");
          return res.sendStatus(200);
        }

        date = normalized.value;
        step = 'ask_time';
        await db.run(
          `UPDATE whatsapp_sessions SET date = ?, step = ?, updated_at = ? WHERE id = ?`,
          [date, step, nowIso, session.id]
        );
        await sendWhatsApp(from, "تمام، الساعة كام؟");
        return res.sendStatus(200);
      }

      if (step === 'ask_time') {
        const rawTime = text.trim();
        const rawLow = rawTime.toLowerCase();

        // لو المستخدم بيرفض الساعة الحالية أو بيطلب تغييرها من غير ما يحدد ساعة بديلة
        if (/^لا$/.test(rawLow) || rawLow.includes('مش الساعة دي') || rawLow.includes('غير الساعة') || rawLow.includes('غير المعاد') || rawLow.includes('مش عايز الساعة دي')) {
          await sendWhatsApp(from, "تمام، اختارلي ساعة تانية تناسبك (مثلاً 5 الصبح أو 7 بالليل).");
          return res.sendStatus(200);
        }

        // لو المستخدم كتب رقم ساعة واحد بس بدون تحديد صباح/مساء (1-11)
        const onlyHourMatch = rawLow.match(/^(\d{1,2})$/);
        if (onlyHourMatch) {
          const hourNum = parseInt(onlyHourMatch[1], 10);
          if (hourNum >= 1 && hourNum <= 11) {
            await sendWhatsApp(from, "تحب الساعة تكون صباحًا ولا مساءً؟");
            return res.sendStatus(200);
          }
        }

        const hasMorning = /(صباح|الصبح|am)/.test(rawLow);
        const hasEvening = /(مساء|المساء|ليل|بالليل|pm)/.test(rawLow);

        if (pendingHour && (hasMorning || hasEvening)) {
          let h = parseInt(String(pendingHour), 10);
          if (Number.isNaN(h)) {
            pendingHour = null;
          } else {
            if (h <= 12 && hasEvening) {
              if (h < 12) h += 12;
            } else if (h === 12 && hasMorning) {
              h = 0;
            }
            const pad = (n) => (n < 10 ? '0' + n : '' + n);
            time = `${pad(h)}:00`;
            step = 'ask_location';
            pendingHour = null;
            await db.run(
              `UPDATE whatsapp_sessions SET time = ?, step = ?, pending_hour = NULL, updated_at = ? WHERE id = ?`,
              [time, step, nowIso, session.id]
            );
            await sendWhatsApp(from, "لو حابب تحدد مكان أو فرع معين للمعاد اكتبلي، ولو مش فارق معاك المكان قول مفيش مكان محدد.");
            return res.sendStatus(200);
          }
        }

        // لو المستخدم رجع كتب اليوم والساعة معًا هنا، نحاول نفهم الاثنين
        const combinedDate = normalizeUserDate(rawTime);
        const normalizedTime = normalizeUserTime(rawTime);

        if (!date && combinedDate.ok && normalizedTime.ok) {
          date = combinedDate.value;
          time = normalizedTime.value;
          step = 'ask_location';
          pendingHour = null;
          await db.run(
            `UPDATE whatsapp_sessions SET date = ?, time = ?, step = ?, pending_hour = NULL, updated_at = ? WHERE id = ?`,
            [date, time, step, nowIso, session.id]
          );
          await sendWhatsApp(from, "لو حابب تحدد مكان أو فرع معين للمعاد اكتبلي، ولو مش فارق معاك المكان قول مفيش مكان محدد.");
          return res.sendStatus(200);
        }

        if (!normalizedTime.ok) {
          await sendWhatsApp(from, "مش واضح… توضحلي الساعة؟");
          return res.sendStatus(200);
        }

        time = normalizedTime.value;
        step = 'ask_location';
        pendingHour = null;
        await db.run(
          `UPDATE whatsapp_sessions SET time = ?, step = ?, pending_hour = NULL, updated_at = ? WHERE id = ?`,
          [time, step, nowIso, session.id]
        );
        await sendWhatsApp(from, "لو حابب تحدد مكان أو فرع معين للمعاد اكتبلي، ولو مش فارق معاك المكان قول مفيش مكان محدد.");
        return res.sendStatus(200);
      }

      if (step === 'ask_location') {
        location = text.trim().includes('لا يوجد') ? null : text.trim();

        const statusArabic = 'قيد الانتظار';
        const isArchived = 0;
        const createdAt = nowIso;
        const updatedAt = nowIso;
        const completedAt = null;
        const todoistId = null;

        await db.run(
          `INSERT INTO meetings 
            (name, service, person, phone, location, notes, priority, date, time, status, is_archived, created_at, updated_at, completed_at, todoist_task_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            null,
            session.service,
            session.person,
            from,
            location,
            session.notes || null,
            null,
            session.date,
            session.time,
            statusArabic,
            isArchived,
            createdAt,
            updatedAt,
            completedAt,
            todoistId
          ]
        );

        await db.run(`DELETE FROM whatsapp_sessions WHERE id = ?`, [session.id]);

        // توضيح بسيط للصباح/المساء في رسالة التأكيد
        let periodLabel = '';
        try {
          const hour = parseInt(String(session.time || '00:00').split(':')[0], 10);
          if (!isNaN(hour)) {
            periodLabel = hour < 12 ? ' صباحًا' : ' مساءً';
          }
        } catch {}

        const confirmation = `اتسجل المعاد:
الخدمة: ${session.service || '-'}
الاسم: ${session.person || '-'}
اليوم: ${session.date}
الساعة: ${session.time}${periodLabel}`;

        await sendWhatsApp(from, confirmation);
        return res.sendStatus(200);
      }
    }

    let newStatus = null;
    let note = null;
    if (["نعم","yes","تمام","خلصت","تم"].some(w => low.includes(w))) {
      newStatus = "done";
    } else if (["لا","not","no","مش","لأ"].some(w => low.includes(w))) {
      newStatus = "failed";
      note = text;
    } else {
      note = text;
    }

    const task = await db.get(
      `SELECT t.* FROM tasks t JOIN students s ON s.id = t.student_id WHERE s.phone = ? ORDER BY t.created_at DESC LIMIT 1`,
      [from]
    );

    if (task) {
      if (newStatus) {
        await db.run(`UPDATE tasks SET status = ?, note = ? WHERE id = ?`, [newStatus, note, task.id]);
      } else {
        await db.run(`UPDATE tasks SET note = ? WHERE id = ?`, [note, task.id]);
      }
      // hours are managed from dashboard only; do not parse numbers from messages
    } else {
      // إذا لم يوجد طالب مرتبط بهذا الرقم ننشئ طالبًا جديدًا باسم رقم الهاتف
      const st = await db.run(`INSERT INTO students (name, phone) VALUES (?, ?)`, [from, from]);
      await db.run(`INSERT INTO tasks (student_id, task, status, note) VALUES (?, ?, ?, ?)`, [st.lastID, "message from user", newStatus || "pending", note]);
    }
    // لو كانت رسالة قصيرة وواضحة كرد على التذكير (نعم/لا)، نكتفي بتأكيد بسيط ولا نبدأ أي حوار حجز
    const trimmed = text.trim();
    const isShortYesNo = trimmed.length <= 6 && (newStatus === 'done' || newStatus === 'failed');

    if (task && isShortYesNo) {
      let reply;
      if (newStatus === 'done') {
        reply = `تمام، هاعتبر المهمة "${task.task}" منتهية. شكرًا إنك وضحت.`;
      } else {
        reply = `تمام، هاعتبر المهمة "${task.task}" لسه ما خلصتش. لو حابب نحددلك وقت أو تذكير تاني قولي.`;
      }
      await sendWhatsApp(from, reply);
      return res.sendStatus(200);
    }

    // اعتمد على ChatGPT ليكون هو السكرتير الشخصي في الردود العامة الأخرى
    const extraContext = newStatus
      ? `حالة آخر مهمة لهذا الرقم الآن هي: ${newStatus === 'done' ? 'منتهية' : 'لم تكتمل'}.`
      : '';

    const reply = await askChatAssistant(text, extraContext);

    await sendWhatsApp(from, reply);
    res.sendStatus(200);
  } catch (e) {
    console.error("webhook error", e?.response?.data || e.message);
    res.sendStatus(500);
  }
});

// Cron: hourly follow-up for pending tasks
cron.schedule("0 * * * *", async () => {
  try {
    const pending = await db.all(`SELECT t.*, s.phone, s.name FROM tasks t JOIN students s ON s.id = t.student_id WHERE t.status = 'pending'`);
    const now = Date.now();
    for (const t of pending) {
      const last = new Date(t.last_followup_at || t.created_at).getTime();
      const hoursSince = (now - last) / (1000 * 60 * 60);
      if (hoursSince >= (t.followup_interval_hours || 24)) {
        const text = `مرحبًا ${t.name || "صديق"}, هل أنهيت المهمة: "${t.task}"؟ رد بـ نعم أو لا.`;
        try {
          await sendWhatsApp(t.phone, text);
          await db.run(`UPDATE tasks SET last_followup_at = ? WHERE id = ?`, [new Date().toISOString(), t.id]);
        } catch (e) {
          console.error("Failed follow-up send", e?.response?.data || e.message);
        }
      }
    }
  } catch (e) {
    console.error("Cron job error", e);
  }
});

// 🔒 Middleware for API Key validation
function checkApiKey(req, res, next) {
  try {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({ 
        success: false,
        error: 'مفتاح API مطلوب',
        code: 'API_KEY_REQUIRED'
      });
    }
    
    if (apiKey !== API_KEY) {
      return res.status(403).json({ 
        success: false,
        error: 'مفتاح API غير صالح',
        code: 'INVALID_API_KEY'
      });
    }
    
    next();
  } catch (error) {
    console.error('API Key validation error:', error);
    res.status(500).json({
      success: false,
      error: 'خطأ في التحقق من الصلاحية',
      code: 'AUTH_VALIDATION_ERROR'
    });
  }
}

// 📥 Endpoint to add a meeting (received from n8n)
app.post(
  "/api/meetings",
  checkApiKey,
  [
    body('name').optional().isString(),
    body('service').trim().notEmpty().withMessage('الخدمة مطلوبة'),
    body('person').trim().notEmpty().withMessage('اسم الشخص مطلوب'),
    body('date').isISO8601().withMessage('صيغة التاريخ غير صالحة'),
    body('time').matches(/^([01]\d|2[0-3]):([0-5]\d)$/).withMessage('صيغة الوقت غير صالحة'),
    body('phone').optional().isString(),
    body('location').optional().isString(),
    body('notes').optional().isString(),
    body('priority').optional().isIn(['low','medium','high']).withMessage('الأولوية غير صالحة'),
    body('status').optional().isIn(['pending','in_progress','completed','cancelled']).withMessage('الحالة غير صالحة'),
  ],
  async (req, res) => {
    try {
      // Validate request
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array(),
          code: 'VALIDATION_ERROR'
        });
      }

      const { name, service, person, date, time, phone, location, notes, priority, status, todoist_task_id } = req.body;

      const statusMap = {
        pending: 'قيد الانتظار',
        in_progress: 'مؤكد',
        completed: 'مكتمل',
        cancelled: 'ملغي',
      };
      const priorityMap = {
        low: 'منخفض',
        medium: 'متوسط',
        high: 'عالي',
      };
      const statusArabic = status ? (statusMap[status] || status) : 'قيد الانتظار';
      const priorityArabic = priority ? (priorityMap[priority] || priority) : null;

      const nowIso = new Date().toISOString();
      const isArchived = statusArabic === 'مكتمل' ? 1 : 0;

      // Check for duplicate meeting
      const existingMeeting = await db.get(
        'SELECT id FROM meetings WHERE date = ? AND time = ? AND person = ?',
        [date, time, person]
      );

      if (existingMeeting) {
        return res.status(409).json({
          success: false,
          error: 'هناك موعد موجود بالفعل في هذا الوقت',
          code: 'DUPLICATE_MEETING'
        });
      }

      // Insert new meeting
      const result = await db.run(
        `INSERT INTO meetings 
          (name, service, person, phone, location, notes, priority, date, time, status, is_archived, created_at, updated_at, completed_at, todoist_task_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          name || null,
          service,
          person,
          phone || null,
          location || null,
          notes || null,
          priorityArabic,
          date,
          time,
          statusArabic,
          isArchived,
          nowIso,
          nowIso,
          statusArabic === 'مكتمل' ? nowIso : null,
          todoist_task_id || null
        ]
      );

      res.status(201).json({ 
        success: true, 
        message: 'تمت إضافة الاجتماع بنجاح',
        data: {
          id: result.lastID,
          name: name || null,
          service,
          person,
          phone: phone || null,
          location: location || null,
          notes: notes || null,
          priority: priorityArabic,
          date,
          time,
          status: statusArabic,
          is_archived: isArchived,
          created_at: nowIso,
          updated_at: nowIso,
          completed_at: statusArabic === 'مكتمل' ? nowIso : null,
          todoist_task_id: todoist_task_id || null
        }
      });
    } catch (error) {
      console.error('Error adding meeting:', error);
      res.status(500).json({ 
        success: false,
        error: 'حدث خطأ أثناء إضافة الاجتماع',
        code: 'SERVER_ERROR',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// 📤 endpoint لعرض جميع المواعيد مع فلاتر اختيارية (startDate, endDate, status)
app.get("/api/meetings", checkApiKey, async (req, res) => {
  try {
    const { startDate, endDate, status, includeDeleted } = req.query;

    // Build conditions without embedding the WHERE keyword to avoid duplication
    const conditions = [];
    const params = [];

    // deleted_at filtering
    if (includeDeleted === 'true') {
      conditions.push("deleted_at IS NOT NULL");
    } else if (includeDeleted === 'all') {
      // no condition -> include all
    } else {
      // default: only non-deleted
      conditions.push("deleted_at IS NULL");
    }

    if (startDate) {
      conditions.push("date >= ?");
      params.push(startDate);
    }
    if (endDate) {
      conditions.push("date <= ?");
      params.push(endDate);
    }
    if (status) {
      conditions.push("status = ?");
      params.push(status);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const rows = await db.all(`SELECT * FROM meetings ${where} ORDER BY date ASC, time ASC`, params);
    res.json(rows);
  } catch (e) {
    console.error('Error fetching meetings:', e);
    res.status(500).json({ success: false, error: 'خطأ أثناء جلب المواعيد' });
  }
});

// 🔄 endpoint لتحديث حالة الاجتماع (تأكيد / إلغاء) مع ضبط الأرشفة والتواريخ
app.post("/api/meetings/:id/status", checkApiKey, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!status) return res.status(400).json({ success: false, error: "Missing status" });

    const nowIso = new Date().toISOString();
    // إذا الحالة أصبحت 'مكتمل' نؤرشف الموعد ونضبط completed_at، غير ذلك نزيل الأرشفة ونفرغ completed_at
    const isArchived = status === 'مكتمل' ? 1 : 0;
    const completedAt = status === 'مكتمل' ? nowIso : null;

    await db.run(
      "UPDATE meetings SET status = ?, is_archived = ?, updated_at = ?, completed_at = ? WHERE id = ?",
      [status, isArchived, nowIso, completedAt, id]
    );

    const updated = await db.get("SELECT * FROM meetings WHERE id = ?", [id]);
    res.json({ success: true, data: updated });
  } catch (e) {
    console.error('Error updating meeting status:', e);
    res.status(500).json({ success: false, error: 'خطأ أثناء تحديث الحالة' });
  }
});

// 🧱 تقديم ملفات الواجهة (frontend)
app.use("/", express.static(path.join(__dirname, "../frontend/dist")));

// ⚙️ fallback لأي مسار غير معروف
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/dist", "index.html"));
});
