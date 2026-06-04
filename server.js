require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { Pool } = require('pg');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const app = express();
const port = process.env.PORT || 3000;

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.connect()
  .then(() => console.log('✅ Подключено к PostgreSQL'))
  .catch(err => { console.error('❌ Ошибка подключения:', err); process.exit(1); });

// Настройка приложения
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
}));

// Загрузка файлов (домашки)
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'russian-with-masha/homeworks',
    allowed_formats: ['jpg', 'jpeg', 'png', 'heic', 'webp', 'mp3', 'mp4', 'm4a', 'ogg', 'webm', 'aac'],
  },
});
const upload = multer({ storage });

// Middleware
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) {
    return res.status(403).send('❌ Доступ запрещён');
  }
  next();
}

// ─── ГЛАВНАЯ ───────────────────────────────────────────
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/cabinet');
  res.redirect('/login');
});

// ─── РЕГИСТРАЦИЯ ───────────────────────────────────────
app.get('/register', async (req, res) => {
  const coursesResult = await pool.query('SELECT * FROM courses ORDER BY title');
  res.render('register', { courses: coursesResult.rows, error: null, success: null });
});

app.post('/register', async (req, res) => {
  const { name, email, password, course_id } = req.body;
  const coursesResult = await pool.query('SELECT * FROM courses ORDER BY title');
  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows[0]) {
      return res.render('register', { courses: coursesResult.rows, error: 'Cet email est déjà utilisé', success: null });
    }
    const hashed = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString('hex');
    const userResult = await pool.query(
      'INSERT INTO users (name, email, password, verification_token, is_verified) VALUES ($1, $2, $3, $4, FALSE) RETURNING id',
      [name, email, hashed, token]
    );
    const userId = userResult.rows[0].id;
    await pool.query(
      'INSERT INTO user_courses (user_id, course_id, lessons_available) VALUES ($1, $2, 1)',
      [userId, course_id]
    );

    const verifyUrl = `${process.env.APP_URL}/verify/${token}`;
    await transporter.sendMail({
      from: `"Russian with Masha" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Confirmez votre inscription — Russian with Masha',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px;">
          <h2 style="color:#1c1e21;">Bonjour ${name} 👋</h2>
          <p style="color:#65676b;margin:16px 0;">Merci de vous être inscrit(e) à Russian with Masha!</p>
          <p style="color:#65676b;margin:16px 0;">Cliquez sur le bouton ci-dessous pour confirmer votre adresse email:</p>
          <a href="${verifyUrl}" style="display:inline-block;background:#FFD966;color:#241c15;padding:14px 28px;border-radius:10px;text-decoration:none;font-weight:700;margin:16px 0;">Confirmer mon email</a>
          <p style="color:#65676b;font-size:13px;margin-top:24px;">Ce lien expire dans 24 heures.</p>
        </div>
      `
    });

    res.render('register', { courses: coursesResult.rows, error: null, success: 'Inscription réussie! Vérifiez votre email pour confirmer votre compte.' });
  } catch (err) {
    console.error(err);
    res.render('register', { courses: coursesResult.rows, error: 'Une erreur est survenue', success: null });
  }
});

// ─── ЛОГИН ─────────────────────────────────────────────
app.get('/login', (req, res) => {
  res.render('login', { error: null, query: req.query });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.render('login', { error: 'Utilisateur non trouvé' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.render('login', { error: 'Mot de passe incorrect' });
    if (!user.is_verified) return res.render('login', { error: 'Veuillez confirmer votre email avant de vous connecter' });
    req.session.user = { id: user.id, email: user.email, name: user.name, is_admin: user.is_admin };
    return res.redirect(user.is_admin ? '/admin' : '/cabinet');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Произошла ошибка' });
  }
});

// ─── ПОДТВЕРЖДЕНИЕ EMAIL ───────────────────────────────
app.get('/verify/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const result = await pool.query(
      'UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = $1 RETURNING id',
      [token]
    );
    if (!result.rows[0]) {
      return res.send('❌ Lien invalide ou expiré');
    }
    res.redirect('/login?verified=1');
  } catch (err) {
    console.error(err);
    res.send('❌ Une erreur est survenue');
  }
});

// ─── ВЫХОД ─────────────────────────────────────────────
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ─── ЛИЧНЫЙ КАБИНЕТ ────────────────────────────────────
app.get('/cabinet', requireLogin, async (req, res) => {
  const user = req.session.user;
  try {
    const coursesResult = await pool.query(`
      SELECT c.id, c.title, c.description, c.total_lessons, uc.lessons_available,
        COUNT(DISTINCT h.lesson_id) FILTER (WHERE h.grade IS NOT NULL) as completed
      FROM user_courses uc
      JOIN courses c ON c.id = uc.course_id
      LEFT JOIN homeworks h ON h.course_id = c.id AND h.user_id = $1
      WHERE uc.user_id = $1
      GROUP BY c.id, c.title, c.description, c.total_lessons, uc.lessons_available
    `, [user.id]);

    res.render('cabinet', { user, courses: coursesResult.rows });
  } catch (err) {
    console.error(err);
    res.send('❌ Ошибка загрузки кабинета');
  }
});

// ─── СТРАНИЦА КУРСА ────────────────────────────────────
app.get('/cabinet/course/:course_id', requireLogin, async (req, res) => {
  const user = req.session.user;
  const { course_id } = req.params;
  try {
    const courseResult = await pool.query(`
      SELECT c.id, c.title, c.description, c.total_lessons, uc.lessons_available,
        COUNT(DISTINCT h.lesson_id) FILTER (WHERE h.grade IS NOT NULL) as completed
      FROM user_courses uc
      JOIN courses c ON c.id = uc.course_id
      LEFT JOIN homeworks h ON h.course_id = c.id AND h.user_id = $1
      WHERE uc.user_id = $1 AND c.id = $2
      GROUP BY c.id, c.title, c.description, c.total_lessons, uc.lessons_available
    `, [user.id, course_id]);

    if (!courseResult.rows[0]) return res.redirect('/cabinet');
    const course = courseResult.rows[0];

    const homeworksResult = await pool.query(
      'SELECT * FROM homeworks WHERE user_id = $1 AND course_id = $2 ORDER BY submitted_at DESC',
      [user.id, course_id]
    );

    res.render('course', { user, course, homeworks: homeworksResult.rows });
  } catch (err) {
    console.error(err);
    res.send('❌ Ошибка загрузки курса');
  }
});

// ─── УРОК ──────────────────────────────────────────────
app.get('/lesson/:course/:id', requireLogin, async (req, res) => {
  const { course, id } = req.params;
  const user = req.session.user;
  try {
    const ucResult = await pool.query(
      'SELECT lessons_available FROM user_courses WHERE user_id = $1 AND course_id = $2',
      [user.id, course]
    );
    if (!ucResult.rows[0]) return res.status(403).send('❌ Нет доступа к этому курсу');
    const lessonsAvailable = ucResult.rows[0].lessons_available;
    if (parseInt(id) > lessonsAvailable) {
      return res.status(403).send('❌ Этот урок ещё не открыт');
    }
    const lessonPath = path.join(__dirname, 'courses', course, `lesson${id}`, 'index.html');
    if (fs.existsSync(lessonPath)) {
      res.sendFile(lessonPath);
    } else {
      res.status(404).send('❌ Файл урока не найден');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('❌ Ошибка сервера');
  }
});

// ─── ДОМАШКИ ───────────────────────────────────────────
app.post('/homework/upload', requireLogin, (req, res, next) => {
  upload.single('photo')(req, res, (err) => {
    if (err) {
      console.error('Multer/Cloudinary ошибка:', err.message, err);
      return res.status(500).send('❌ Ошибка загрузки файла: ' + err.message);
    }
    next();
  });
}, async (req, res) => {
  const { course_id, lesson_id } = req.body;
  const user = req.session.user;
  try {
    // Проверяем лимит — максимум 2 домашки на урок
    const countResult = await pool.query(
      'SELECT COUNT(*) FROM homeworks WHERE user_id = $1 AND course_id = $2 AND lesson_id = $3',
      [user.id, course_id, lesson_id]
    );
    if (parseInt(countResult.rows[0].count) >= 2) {
      return res.redirect(`/cabinet/course/${course_id}#devoirs`);
    }
    await pool.query(
      'INSERT INTO homeworks (user_id, course_id, lesson_id, file_path) VALUES ($1, $2, $3, $4)',
      [user.id, course_id, lesson_id, req.file.path]
    );
    res.redirect(`/cabinet/course/${course_id}#devoirs`);
  } catch (err) {
    console.error('Детали ошибки:', err.message, err.stack);
    res.status(500).send('❌ Ошибка: ' + err.message);
  }
});
// ─── УДАЛЕНИЕ ДОМАШКИ ──────────────────────────────────
app.post('/homework/delete', requireLogin, async (req, res) => {
  const { homework_id, course_id } = req.body;
  const user = req.session.user;
  try {
    // Можно удалить только если нет оценки
    const hw = await pool.query(
      'SELECT * FROM homeworks WHERE id = $1 AND user_id = $2',
      [homework_id, user.id]
    );
    if (!hw.rows[0]) return res.redirect(`/cabinet/course/${course_id}#devoirs`);
    if (hw.rows[0].grade) return res.redirect(`/cabinet/course/${course_id}#devoirs`);
    
    // Удаляем из Cloudinary
    const publicId = hw.rows[0].file_path.split('/').slice(-2).join('/').split('.')[0];
    await cloudinary.uploader.destroy(publicId);
    
    // Удаляем из базы
    await pool.query('DELETE FROM homeworks WHERE id = $1', [homework_id]);
    res.redirect(`/cabinet/course/${course_id}#devoirs`);
  } catch (err) {
    console.error(err);
    res.redirect(`/cabinet/course/${course_id}#devoirs`);
  }
});

// ─── АДМИНКА ───────────────────────────────────────────
app.get('/admin', requireAdmin, async (req, res) => {
  try {
    const usersResult = await pool.query(`
      SELECT u.id, u.name, u.email, u.created_at,
             json_agg(json_build_object('course_id', uc.course_id, 'title', c.title, 'lessons_available', uc.lessons_available)) as courses
      FROM users u
      LEFT JOIN user_courses uc ON uc.user_id = u.id
      LEFT JOIN courses c ON c.id = uc.course_id
      WHERE u.is_admin = FALSE
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `);
    const homeworksResult = await pool.query(`
      SELECT h.*, u.name, u.email FROM homeworks h
      JOIN users u ON u.id = h.user_id
      ORDER BY h.submitted_at DESC
    `);
    res.render('admin', { users: usersResult.rows, homeworks: homeworksResult.rows, message: null });
  } catch (err) {
    console.error(err);
    res.send('❌ Ошибка загрузки админки');
  }
});

app.post('/admin/lessons', requireAdmin, async (req, res) => {
  const { user_id, course_id, lessons_available } = req.body;
  try {
    await pool.query(
      'UPDATE user_courses SET lessons_available = $1 WHERE user_id = $2 AND course_id = $3',
      [lessons_available, user_id, course_id]
    );
    res.redirect('/admin');
  } catch (err) {
    console.error(err);
    res.redirect('/admin');
  }
});

app.post('/admin/homework/grade', requireAdmin, async (req, res) => {
  const { homework_id, grade, comment } = req.body;
  try {
    await pool.query(
      'UPDATE homeworks SET grade = $1, comment = $2 WHERE id = $3',
      [grade, comment, homework_id]
    );
    res.redirect('/admin');
  } catch (err) {
    console.error(err);
    res.redirect('/admin');
  }
});

app.post('/admin/homework/delete', requireAdmin, async (req, res) => {
  const { homework_id } = req.body;
  try {
    const hw = await pool.query('SELECT * FROM homeworks WHERE id = $1', [homework_id]);
    if (hw.rows[0]) {
      const publicId = hw.rows[0].file_path.split('/').slice(-2).join('/').split('.')[0];
      await cloudinary.uploader.destroy(publicId);
      await pool.query('DELETE FROM homeworks WHERE id = $1', [homework_id]);
    }
    res.redirect('/admin');
  } catch (err) {
    console.error(err);
    res.redirect('/admin');
  }
});

// ─── СБРОС ПАРОЛЯ ──────────────────────────────────────
app.get('/forgot', (req, res) => {
  res.render('forgot', { error: null, success: null });
});

app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) {
      return res.render('forgot', { error: null, success: 'Si cet email existe, vous recevrez un lien de réinitialisation.' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 час
    await pool.query(
      'UPDATE users SET reset_token = $1, reset_expires = $2 WHERE email = $3',
      [token, expires, email]
    );
    const resetUrl = `${process.env.APP_URL}/reset/${token}`;
    await transporter.sendMail({
      from: `"Russian with Masha" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Réinitialisation de mot de passe — Russian with Masha',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px;">
          <h2 style="color:#1c1e21;">Réinitialisation de mot de passe</h2>
          <p style="color:#65676b;margin:16px 0;">Cliquez sur le bouton ci-dessous pour réinitialiser votre mot de passe:</p>
          <a href="${resetUrl}" style="display:inline-block;background:#FFD966;color:#241c15;padding:14px 28px;border-radius:10px;text-decoration:none;font-weight:700;margin:16px 0;">Réinitialiser mon mot de passe</a>
          <p style="color:#65676b;font-size:13px;margin-top:24px;">Ce lien expire dans 1 heure.</p>
        </div>
      `
    });
    res.render('forgot', { error: null, success: 'Si cet email existe, vous recevrez un lien de réinitialisation.' });
  } catch (err) {
    console.error(err);
    res.render('forgot', { error: 'Une erreur est survenue', success: null });
  }
});

app.get('/reset/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_expires > NOW()',
      [token]
    );
    if (!result.rows[0]) return res.send('❌ Lien invalide ou expiré');
    res.render('reset', { token, error: null });
  } catch (err) {
    console.error(err);
    res.send('❌ Une erreur est survenue');
  }
});

app.post('/reset/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_expires > NOW()',
      [token]
    );
    if (!result.rows[0]) return res.send('❌ Lien invalide ou expiré');
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL, reset_expires = NULL WHERE reset_token = $2',
      [hashed, token]
    );
    res.redirect('/login?reset=1');
  } catch (err) {
    console.error(err);
    res.send('❌ Une erreur est survenue');
  }
});

// ─── ЗАПУСК ────────────────────────────────────────────
app.listen(port, () => {
  console.log(`✅ Сервер запущен: http://localhost:${port}`);
});