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
app.use(limiter);

// Environment variables
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "data.db");

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
  await addCol('todoist_task_id', 'TEXT');

  console.log("✅ Database ready.");

  // تشغيل السيرفر
  app.listen(PORT, () => {
    console.log(`✅ Backend running on port ${PORT}`);
    console.log(`🔐 API_KEY (use in n8n x-api-key): ${API_KEY}`);
  });
})();

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

// 📤 endpoint لعرض جميع المواعيد
app.get("/api/meetings", checkApiKey, async (req, res) => {
  const rows = await db.all("SELECT * FROM meetings ORDER BY created_at DESC");
  res.json(rows);
});

// 🔄 endpoint لتحديث حالة الاجتماع (تأكيد / إلغاء)
app.post("/api/meetings/:id/status", checkApiKey, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!status) return res.status(400).json({ success: false, error: "Missing status" });

  await db.run("UPDATE meetings SET status = ? WHERE id = ?", [status, id]);
  res.json({ success: true });
});

// 🧱 تقديم ملفات الواجهة (frontend)
app.use("/", express.static(path.join(__dirname, "../frontend/dist")));

// ⚙️ fallback لأي مسار غير معروف
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/dist", "index.html"));
});
