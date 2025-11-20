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
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT
    );
  `);

  // Migrate existing table to include missing columns
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

  console.log("✅ Database ready.");

  // تشغيل السيرفر
  app.listen(PORT, () => {
    console.log(`✅ Backend running on port ${PORT}`);
    console.log(`🔐 API_KEY (use in n8n x-api-key): ${API_KEY}`);
  });
})();

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
انت سكرتير شخصي لمركز تعليمي على واتساب.
- تتكلم عربي طبيعي وبسيط (مصري خفيف)، من غير تكلف ولا أسلوب روبوت.
- ردودك تكون كأنك واحد صاحب بيتكلم مع صاحبه: ممكن تبدأ مثلاً بـ "ازيك" أو "عامل ايه" لو مناسب، من غير جمل رسمية زي "أهلاً وسهلاً" أو "مع مين".
- ردودك قصيرة وواضحة، من غير قوالب ثابتة طويلة.
- لو بتحجز معاد، اسأل عن التفاصيل (نوع الخدمة، اليوم، الساعة) بطريقة طبيعية زي: "تحب نخلي الميعاد امتى؟ والساعة كام تقريباً؟" مع ذكر مثال واحد للتاريخ 2025-12-31 والوقت 09:30 عشان النظام يفهم.
- لما التأكيد يتم، تقدر تقول جملة خفيفة زي "تمام، اعتبر الميعاد اتظبط، وتعلم في الخير" مع ملخص بسيط للميعاد من غير فورمات رسمية.
- لو الطلب خارج التعليم أو الحجز (زي طلب أكل) وضّح بهدوء إن شغلك تعليم وحجز مواعيد بس.
- بالنسبة للمكان، اعتبره معلومة اختيارية: اسأل عنه بطريقة لطيفة لو حاسس إنه مهم، ولو المستخدم ما ذكرش مكان مش لازم تعيد السؤال كتير.
- لو فيه سياق إضافي: ${extraContext || 'لا يوجد'}.

رسالة المستخدم: ${userText}
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

    const session = await db.get(
      `SELECT * FROM whatsapp_sessions WHERE phone = ? ORDER BY id DESC LIMIT 1`,
      [from]
    );

    if (low.includes('الغاء') || low.includes('إلغاء') || low.includes('cancel')) {
      if (session) {
        await db.run(`DELETE FROM whatsapp_sessions WHERE id = ?`, [session.id]);
      }
      const cancelReply = await askChatAssistant(
        text,
        'المستخدم طلب إلغاء أي حجز أو إجراء جارٍ الآن. وضّح له بهدوء إن العملية اتلغت ولو احتاج يبدأ من جديد تقوله يكتب إنه عايز يحجز.'
      );
      await sendWhatsApp(from, cancelReply);
      return res.sendStatus(200);
    }

    if (!session) {
      // Detect booking intent with broader phrases (doctor/teacher/session/etc.)
      const bookingKeywords = [
        'حجز',
        'ميتنج',
        'meeting',
        'موعد',
        'ميعاد',
        'استشارة',
        'consult',
        'دكتور',
        'طبيب',
        'مدرس',
        'استاذ',
        'محاضرة',
        'جلسة',
        'سيشن',
        'lecture',
        'session',
      ];

      // Block obvious food/restaurant requests (outside scope of the center)
      const foodKeywords = [
        'أكل', 'اكل', 'وجبة', 'وجبات', 'مطعم', 'مطاعم', 'تيك اواي', 'تيك-اواي',
        'burger', 'بيتزا', 'pizza', 'بورجر', 'شاورما', 'كباب', 'grill', 'مطع', 'اكل كويس'
      ];

      const bookingIntent = bookingKeywords.some(w => low.includes(w));
      const foodIntent = foodKeywords.some(w => low.includes(w));

      if (foodIntent && !bookingIntent) {
        const foodReply = await askChatAssistant(
          text,
          'الرسالة تبدو كطلب أكل أو مطعم. وضّح بهدوء إن دورك سكرتير لمركز تعليمي فقط، وتقدر تساعده في المواعيد أو الأسئلة التعليمية.'
        );
        await sendWhatsApp(from, foodReply);
        return res.sendStatus(200);
      }

      if (bookingIntent) {
        const nowIso = new Date().toISOString();
        await db.run(
          `INSERT INTO whatsapp_sessions (phone, step, created_at, updated_at) VALUES (?, ?, ?, ?)`,
          [from, 'ask_service', nowIso, nowIso]
        );
        const startReply = await askChatAssistant(
          text,
          'ابدأ حوار حجز معاد بأسلوب بسيط كأنك سكرتير شخصي: سلم عليه بشكل عادي واسأله حابب يحجز على ايه أو محتاج ايه بالظبط (استشارة، درس، متابعة... إلخ) من غير جمل رسمية.'
        );
        await sendWhatsApp(from, startReply);
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

      if (step === 'ask_service') {
        service = text.trim();
        step = 'ask_person';
        await db.run(
          `UPDATE whatsapp_sessions SET service = ?, step = ?, updated_at = ? WHERE id = ?`,
          [service, step, nowIso, session.id]
        );
        const askPersonReply = await askChatAssistant(
          text,
          `تم تسجيل نوع الخدمة كالتالي: "${service}". اسأل المستخدم بأسلوب لطيف عن الاسم اللي هتسجل به الميعاد (اسمه أو اسم ابنه مثلاً)، من غير استخدام عبارات ثقيلة زي "مع مين".`
        );
        await sendWhatsApp(from, askPersonReply);
        return res.sendStatus(200);
      }

      if (step === 'ask_person') {
        person = text.trim();
        step = 'ask_date';
        await db.run(
          `UPDATE whatsapp_sessions SET person = ?, step = ?, updated_at = ? WHERE id = ?`,
          [person, step, nowIso, session.id]
        );
        const askDateReply = await askChatAssistant(
          text,
          'اسأل المستخدم بطريقة عادية عن اليوم/التاريخ اللي حابب يخلي فيه الميعاد، بس وضّح إنك محتاج تكتبه بصيغة YYYY-MM-DD واديله مثال واحد زي 2025-12-31 من غير ما تحسسه إنه بيتعامل مع نظام.'
        );
        await sendWhatsApp(from, askDateReply);
        return res.sendStatus(200);
      }

      if (step === 'ask_date') {
        const rawDate = text.trim();
        // Validate date format YYYY-MM-DD
        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        const isFormatValid = dateRegex.test(rawDate);
        const parsed = new Date(rawDate);
        const isRealDate = !isNaN(parsed.getTime());

        if (!isFormatValid || !isRealDate) {
          const invalidDateReply = await askChatAssistant(
            text,
            'التاريخ اللي المستخدم كتبه مش مفهوم للنظام. اعتذر له بشكل بسيط، وقل له إنك محتاج التاريخ مكتوب بالصيغة دي YYYY-MM-DD مع مثال 2025-12-31، واطلب منه يعيد كتابته من غير رسمية أو توتر.'
          );
          await sendWhatsApp(from, invalidDateReply);
          return res.sendStatus(200);
        }

        date = rawDate;
        step = 'ask_time';
        await db.run(
          `UPDATE whatsapp_sessions SET date = ?, step = ?, updated_at = ? WHERE id = ?`,
          [date, step, nowIso, session.id]
        );
        const askTimeReply = await askChatAssistant(
          text,
          'اسأل المستخدم عن الوقت اللي يناسبه للميعاد بأسلوب عادي زي "تحب الساعة كام تقريباً؟"، واذكر إنك محتاج تكتبه بصيغة 24 ساعة HH:mm مع مثال 09:30 أو 14:45 عشان النظام يفهم.'
        );
        await sendWhatsApp(from, askTimeReply);
        return res.sendStatus(200);
      }

      if (step === 'ask_time') {
        const rawTime = text.trim();
        // Validate time format HH:mm (24h)
        const timeRegex = /^([01]\d|2[0-3]):([0-5]\d)$/;
        if (!timeRegex.test(rawTime)) {
          const invalidTimeReply = await askChatAssistant(
            text,
            'الوقت اللي المستخدم كتبه مش واضح للنظام. اعتذر له ببساطة، وقل له إنك محتاج الوقت مكتوب بصيغة 24 ساعة HH:mm مع مثال 09:30 أو 14:45، واطلب منه يعيد كتابة الوقت بأسلوب هادي.'
          );
          await sendWhatsApp(from, invalidTimeReply);
          return res.sendStatus(200);
        }

        time = rawTime;
        step = 'ask_location';
        await db.run(
          `UPDATE whatsapp_sessions SET time = ?, step = ?, updated_at = ? WHERE id = ?`,
          [time, step, nowIso, session.id]
        );
        const askLocationReply = await askChatAssistant(
          text,
          'اسأل المستخدم بشكل اختياري عن المكان لو حابب يحدد (مثلاً الفرع أو أونلاين)، ووضّح إن لو مش فارق معاه المكان يقدر يقول مفيش مشكلة، من غير جملة حرفية "اكتب لا يوجد".'
        );
        await sendWhatsApp(from, askLocationReply);
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

        const confirmReply = await askChatAssistant(
          text,
          `تم الآن إنشاء حجز في النظام بهذه البيانات: الخدمة: ${session.service}, الاسم: ${session.person}, التاريخ: ${session.date}, الوقت: ${session.time}, المكان: ${location || 'غير محدد'}. ارسل للمستخدم رسالة تأكيد بأسلوب شخصي وخفيف، مثلاً إن الميعاد اتظبط وتقدر تقول جملة زي "تعلم في الخير" مع تلخيص بسيط للميعاد من غير فورمات رسمية طويلة.`
        );

        await sendWhatsApp(from, confirmReply);
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

    // اعتمد على ChatGPT ليكون هو السكرتير الشخصي في أغلب الردود
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
