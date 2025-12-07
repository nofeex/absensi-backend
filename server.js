// ============================================
// FILE: server.js
// Backend API menggunakan Node.js + Express + MySQL
// ============================================

const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// TAMBAHKAN: Environment variables
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia-super-aman-123';

// Database - dari environment variables
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'mysql.railway.internal',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'nhTulsvlhvWViwVkCJrSpdJoINCGzAiJ',
  database: process.env.DB_NAME || 'absensi_tamu',
  port: process.env.DB_PORT || 3306
});

// CORS - izinkan domain Hostinger
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// ============================================
// ROUTES
// ============================================

// 1. LOGIN ADMIN
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;

  const query = 'SELECT * FROM admin WHERE username = ?';
  db.query(query, [username], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const admin = results[0];
    const isValidPassword = await bcrypt.compare(password, admin.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET);
    res.json({ token, username: admin.username });
  });
});

// 2. SUBMIT DATA TAMU (Public - tidak perlu login)
app.post('/api/guests', (req, res) => {
  const { nama, instansi, no_hp, signature } = req.body;

  if (!nama || !instansi || !no_hp) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const query = 'INSERT INTO tamu (nama, instansi, no_hp, signature, created_at) VALUES (?, ?, ?, ?, NOW())';
  db.query(query, [nama, instansi, no_hp, signature || null], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ 
      message: 'Guest registered successfully',
      id: result.insertId 
    });
  });
});

// 3. GET ALL GUESTS (Admin only)
app.get('/api/guests', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM tamu ORDER BY created_at DESC';
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// 4. DELETE GUEST (Admin only)
app.delete('/api/guests/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const query = 'DELETE FROM tamu WHERE id = ?';
  
  db.query(query, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Guest not found' });
    }
    res.json({ message: 'Guest deleted successfully' });
  });
});

// 5. GET STATISTICS (Admin only)
app.get('/api/stats', authenticateToken, (req, res) => {
  const queries = {
    total: 'SELECT COUNT(*) as total FROM tamu',
    withSignature: 'SELECT COUNT(*) as count FROM tamu WHERE signature IS NOT NULL',
    today: 'SELECT COUNT(*) as count FROM tamu WHERE DATE(created_at) = CURDATE()'
  };

  const stats = {};
  let completed = 0;

  Object.keys(queries).forEach(key => {
    db.query(queries[key], (err, results) => {
      if (!err) {
        stats[key] = results[0].total || results[0].count;
      }
      completed++;
      if (completed === Object.keys(queries).length) {
        res.json(stats);
      }
    });
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});


