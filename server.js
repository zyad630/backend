// server.js
import express from "express";
import bodyParser from "body-parser";
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
app.use(bodyParser.json({ limit: '10kb' }));
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
app.use(limiter);

// Environment variables
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "data.db");
const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;
const WHATSAPP_PHONE_ID = process.env.WHATSAPP_PHONE_ID;
const WHATSAPP_VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;

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

  console.log("✅ Database ready.");

  // تشغيل السيرفر
  app.listen(PORT, () => {
    console.log(`✅ Backend running on port ${PORT}`);
    console.log(`🔐 API_KEY (use in n8n x-api-key): ${API_KEY}`);
  });
})();

// Helper to check API key already exists: checkApiKey

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
      return;
    } catch (err) {
      lastErr = err;
      const code = err?.response?.status;
      const data = err?.response?.data;
      console.warn(`[whatsapp] send attempt ${attempt} failed`, code || '', data || err.message);
      // simple backoff
      await new Promise(r => setTimeout(r, 500 * attempt));
    }
  }
  throw lastErr || new Error('sendWhatsApp failed');
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
  if (!phone || !message) return res.status(400).json({ success: false, error: "phone & message required" });
  try {
    await sendWhatsApp(phone, message);
    res.json({ success: true });
  } catch (err) {
    console.error("whatsapp send error:", err?.response?.data || err.message);
    res.status(500).json({ success: false, error: "failed to send" });
  }
});

// WhatsApp webhook receive
app.post("/api/whatsapp/webhook", async (req, res) => {
  try {
    const entry = req.body.entry?.[0];
    const changes = entry?.changes?.[0];
    const value = changes?.value;
    const message = value?.messages?.[0];
    if (!message) return res.sendStatus(200);

    const from = message.from;
    const text = message.text?.body || "";
    console.info(`[webhook] msg from ${from}: ${text}`);

    let newStatus = null;
    let note = null;
    const low = text.trim().toLowerCase();
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
    } else {
      const st = await db.run(`INSERT INTO students (name, phone) VALUES (?, ?)`, ["whatsapp_user", from]);
      await db.run(`INSERT INTO tasks (student_id, task, status, note) VALUES (?, ?, ?, ?)`, [st.lastID, "message from user", newStatus || "pending", note]);
    }

    await sendWhatsApp(from, "تم تسجيل ردك، شكرًا 👍");
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
    
    // Only include non-deleted items by default
    let whereClause = "WHERE deleted_at IS NULL";
    const params = [];
    
    // If specifically requesting deleted items
    if (includeDeleted === 'true') {
      whereClause = "WHERE deleted_at IS NOT NULL";
    } else if (includeDeleted === 'all') {
      // Show all items (including deleted) - useful for admin views
      whereClause = "";
    }

    const clauses = [];
    if (whereClause) {
      clauses.push(whereClause);
    }

    if (startDate) {
      clauses.push("date >= ?");
      params.push(startDate);
    }
    if (endDate) {
      clauses.push("date <= ?");
      params.push(endDate);
    }
    if (status) {
      clauses.push("status = ?");
      params.push(status);
    }

    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
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
