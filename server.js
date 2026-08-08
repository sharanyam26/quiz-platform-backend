require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to PostgreSQL using the DATABASE_URL from .env
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Middleware: verifies the JWT token and attaches user info to req.user
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // expects "Bearer <token>"

  if (!token) {
    return res.status(401).json({ success: false, error: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'Invalid or expired token' });
    }
    req.user = decoded; // { id, role }
    next();
  });
}

// Middleware: only allows ADMIN role through
function requireAdmin(req, res, next) {
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }
  next();
}

// Test route: just returns a simple message
app.get('/', (req, res) => {
  res.send('Quiz Platform API is running');
});

// Test route: actually queries the database
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ success: true, time: result.rows[0].now });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Register a new student
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ success: false, error: 'All fields are required' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
      [name, email, hashedPassword, 'STUDENT']
    );

    res.status(201).json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Test route: any logged-in user can access
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({ success: true, message: `Hello user ${req.user.id}, your role is ${req.user.role}` });
});

// Test route: only ADMIN can access
app.get('/api/admin-only', verifyToken, requireAdmin, (req, res) => {
  res.json({ success: true, message: 'Welcome, admin!' });
});
// Admin dashboard stats
app.get('/api/admin/stats', verifyToken, requireAdmin, async (req, res) => {
  try {
    const totalStudents = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'STUDENT'");
    const totalQuizzes = await pool.query('SELECT COUNT(*) FROM quizzes');
    const publishedQuizzes = await pool.query("SELECT COUNT(*) FROM quizzes WHERE status = 'PUBLISHED'");
    const draftQuizzes = await pool.query("SELECT COUNT(*) FROM quizzes WHERE status = 'DRAFT'");
    const totalQuestions = await pool.query('SELECT COUNT(*) FROM questions');
    const totalAttempts = await pool.query('SELECT COUNT(*) FROM attempts');
    const avgScore = await pool.query('SELECT AVG(percentage) FROM attempts');
    const passedAttempts = await pool.query("SELECT COUNT(*) FROM attempts WHERE status = 'PASSED'");
    const failedAttempts = await pool.query("SELECT COUNT(*) FROM attempts WHERE status = 'FAILED'");

    res.json({
      success: true,
      stats: {
        totalStudents: parseInt(totalStudents.rows[0].count),
        totalQuizzes: parseInt(totalQuizzes.rows[0].count),
        publishedQuizzes: parseInt(publishedQuizzes.rows[0].count),
        draftQuizzes: parseInt(draftQuizzes.rows[0].count),
        totalQuestions: parseInt(totalQuestions.rows[0].count),
        totalAttempts: parseInt(totalAttempts.rows[0].count),
        averageScore: parseFloat(avgScore.rows[0].avg) || 0,
        passedAttempts: parseInt(passedAttempts.rows[0].count),
        failedAttempts: parseInt(failedAttempts.rows[0].count),
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});// Get all students (Admin only)
app.get('/api/users', verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, role, status, created_at 
       FROM users 
       WHERE role = 'STUDENT' 
       ORDER BY created_at DESC`
    );
    res.json({ success: true, users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get a single student's profile (Admin only)
app.get('/api/users/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, role, status, created_at FROM users WHERE id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Activate/deactivate a student (Admin only)
app.patch('/api/users/:id/status', verifyToken, requireAdmin, async (req, res) => {
  const { status } = req.body; // expects 'ACTIVE' or 'INACTIVE'

  if (!['ACTIVE', 'INACTIVE'].includes(status)) {
    return res.status(400).json({ success: false, error: 'Status must be ACTIVE or INACTIVE' });
  }

  try {
    const result = await pool.query(
      'UPDATE users SET status = $1 WHERE id = $2 RETURNING id, name, email, status',
      [status, req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Delete a student (Admin only)
app.delete('/api/users/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    res.json({ success: true, message: 'User deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});
// Create a quiz (Admin only)
app.post('/api/quizzes', verifyToken, requireAdmin, async (req, res) => {
  const { title, description, category_id, difficulty, duration, passing_score, max_attempts } = req.body;

  if (!title || !duration || !passing_score) {
    return res.status(400).json({ success: false, error: 'Title, duration, and passing_score are required' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO quizzes (title, description, category_id, difficulty, duration, passing_score, max_attempts, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'DRAFT') RETURNING *`,
      [title, description, category_id, difficulty, duration, passing_score, max_attempts || 1]
    );
    res.status(201).json({ success: true, quiz: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get all quizzes (students see only PUBLISHED, admins see all)
app.get('/api/quizzes', verifyToken, async (req, res) => {
  try {
    let result;
    if (req.user.role === 'ADMIN') {
      result = await pool.query('SELECT * FROM quizzes ORDER BY created_at DESC');
    } else {
      result = await pool.query("SELECT * FROM quizzes WHERE status = 'PUBLISHED' ORDER BY created_at DESC");
    }
    res.json({ success: true, quizzes: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get a single quiz by id
app.get('/api/quizzes/:id', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM quizzes WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Quiz not found' });
    }
    res.json({ success: true, quiz: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Edit a quiz (Admin only)
app.put('/api/quizzes/:id', verifyToken, requireAdmin, async (req, res) => {
  const { title, description, category_id, difficulty, duration, passing_score, max_attempts } = req.body;

  try {
    const result = await pool.query(
      `UPDATE quizzes SET title=$1, description=$2, category_id=$3, difficulty=$4, duration=$5, 
       passing_score=$6, max_attempts=$7, updated_at=NOW() WHERE id=$8 RETURNING *`,
      [title, description, category_id, difficulty, duration, passing_score, max_attempts, req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Quiz not found' });
    }
    res.json({ success: true, quiz: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Delete a quiz (Admin only)
app.delete('/api/quizzes/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM quizzes WHERE id = $1 RETURNING id', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Quiz not found' });
    }
    res.json({ success: true, message: 'Quiz deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Publish/unpublish a quiz (Admin only)
app.patch('/api/quizzes/:id/publish', verifyToken, requireAdmin, async (req, res) => {
  const { status } = req.body; // expects 'PUBLISHED', 'DRAFT', or 'UNPUBLISHED'

  if (!['PUBLISHED', 'DRAFT', 'UNPUBLISHED'].includes(status)) {
    return res.status(400).json({ success: false, error: 'Invalid status' });
  }

  try {
    const result = await pool.query(
      'UPDATE quizzes SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
      [status, req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Quiz not found' });
    }
    res.json({ success: true, quiz: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});