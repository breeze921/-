const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'XiGuangBaoZhuang2026!@#';

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('数据库连接失败:', err.message);
  } else {
    console.log('✅ 数据库连接成功');
    initDatabase();
  }
});

function initDatabase() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      phone TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT,
      nickname TEXT,
      username TEXT,
      role TEXT DEFAULT 'user',
      isAdmin INTEGER DEFAULT 0,
      createdAt TEXT,
      lastLogin TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS stats (
      userId TEXT PRIMARY KEY,
      calculateCount INTEGER DEFAULT 0,
      copyCount INTEGER DEFAULT 0,
      onlineMinutes REAL DEFAULT 0,
      lastActiveAt TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS announcements (
      id TEXT PRIMARY KEY,
      title TEXT,
      content TEXT,
      isImportant INTEGER DEFAULT 0,
      createdAt TEXT
    )
  `);

  createDefaultAdmin();
}

async function createDefaultAdmin() {
  db.get('SELECT * FROM users WHERE phone = ?', ['13800000000'], async (err, row) => {
    if (err) return;
    if (!row) {
      const hashedPwd = await bcrypt.hash('123456', 10);
      db.run(`
        INSERT INTO users (id, phone, password, name, nickname, username, role, isAdmin, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, ['admin_001', '13800000000', hashedPwd, '超级管理员', '超级管理员', '13800000000', 'admin', 1, new Date().toISOString()]);
      console.log('✅ 默认管理员创建成功: 13800000000 / 123456');
    }
  });

  db.get('SELECT * FROM users WHERE phone = ?', ['13277205591'], async (err, row) => {
    if (err) return;
    if (!row) {
      const hashedPwd = await bcrypt.hash('hdkdd520', 10);
      db.run(`
        INSERT INTO users (id, phone, password, name, nickname, username, role, isAdmin, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, ['admin_002', '13277205591', hashedPwd, '黄何', '黄何', '13277205591', 'admin', 1, new Date().toISOString()]);
      console.log('✅ 管理员黄何创建成功: 13277205591 / hdkdd520');
    }
  });
}

function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: '未授权' });
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: '无效token' });
    }
    req.userId = decoded.userId;
    next();
  });
}

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    
    db.get('SELECT * FROM users WHERE phone = ?', [phone], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: '数据库错误' });
      }
      
      if (!user) {
        return res.status(401).json({ error: '手机号或密码错误' });
      }
      
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return res.status(401).json({ error: '手机号或密码错误' });
      }
      
      const token = generateToken(user.id);
      
      db.run('UPDATE users SET lastLogin = ? WHERE id = ?', [new Date().toISOString(), user.id]);
      
      const userData = {
        id: user.id,
        phone: user.phone,
        name: user.name,
        nickname: user.nickname,
        username: user.username,
        role: user.role,
        isAdmin: user.isAdmin === 1,
        createdAt: user.createdAt
      };
      
      res.json({ token, user: userData });
    });
  } catch (error) {
    res.status(500).json({ error: '服务器错误' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, password, name } = req.body;
    
    db.get('SELECT * FROM users WHERE phone = ?', [phone], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: '数据库错误' });
      }
      
      if (user) {
        return res.status(400).json({ error: '该手机号已被注册' });
      }
      
      const hashedPwd = await bcrypt.hash(password, 10);
      const userId = 'user_' + Date.now();
      
      db.run(`
        INSERT INTO users (id, phone, password, name, nickname, username, role, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [userId, phone, hashedPwd, name, name, phone, 'user', new Date().toISOString()], (err) => {
        if (err) {
          return res.status(500).json({ error: '注册失败' });
        }
        
        const token = generateToken(userId);
        const userData = {
          id: userId,
          phone,
          name,
          nickname: name,
          username: phone,
          role: 'user',
          isAdmin: false,
          createdAt: new Date().toISOString()
        };
        
        res.json({ token, user: userData });
      });
    });
  } catch (error) {
    res.status(500).json({ error: '服务器错误' });
  }
});

app.get('/api/auth/me', verifyToken, (req, res) => {
  db.get('SELECT * FROM users WHERE id = ?', [req.userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: '用户不存在' });
    }
    
    const userData = {
      id: user.id,
      phone: user.phone,
      name: user.name,
      nickname: user.nickname,
      username: user.username,
      role: user.role,
      isAdmin: user.isAdmin === 1,
      createdAt: user.createdAt
    };
    
    res.json({ user: userData });
  });
});

app.put('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const { name, nickname, password } = req.body;
    const updates = [];
    const params = [];
    
    if (name) {
      updates.push('name = ?');
      params.push(name);
    }
    if (nickname) {
      updates.push('nickname = ?');
      params.push(nickname);
    }
    if (password) {
      const hashedPwd = await bcrypt.hash(password, 10);
      updates.push('password = ?');
      params.push(hashedPwd);
    }
    
    params.push(req.userId);
    
    db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, (err) => {
      if (err) {
        return res.status(500).json({ error: '更新失败' });
      }
      
      db.get('SELECT * FROM users WHERE id = ?', [req.userId], (err, user) => {
        const userData = {
          id: user.id,
          phone: user.phone,
          name: user.name,
          nickname: user.nickname,
          username: user.username,
          role: user.role,
          isAdmin: user.isAdmin === 1,
          createdAt: user.createdAt
        };
        res.json({ user: userData });
      });
    });
  } catch (error) {
    res.status(500).json({ error: '服务器错误' });
  }
});

app.get('/api/auth/users', verifyToken, (req, res) => {
  db.all('SELECT * FROM users', (err, users) => {
    if (err) {
      return res.status(500).json({ error: '数据库错误' });
    }
    
    const result = users.map(user => ({
      id: user.id,
      phone: user.phone,
      name: user.name,
      nickname: user.nickname,
      username: user.username,
      role: user.role,
      isAdmin: user.isAdmin === 1,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
      stats: { calculateCount: 0, copyCount: 0, onlineDuration: 0 }
    }));
    
    res.json({ users: result });
  });
});

app.post('/api/auth/users', verifyToken, async (req, res) => {
  try {
    const { phone, password, name } = req.body;
    
    db.get('SELECT * FROM users WHERE phone = ?', [phone], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: '数据库错误' });
      }
      
      if (user) {
        return res.status(400).json({ error: '该手机号已存在' });
      }
      
      const hashedPwd = await bcrypt.hash(password, 10);
      const userId = 'user_' + Date.now();
      
      db.run(`
        INSERT INTO users (id, phone, password, name, nickname, username, role, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [userId, phone, hashedPwd, name, name, phone, 'user', new Date().toISOString()], (err) => {
        if (err) {
          return res.status(500).json({ error: '添加失败' });
        }
        res.status(201).json({ success: true });
      });
    });
  } catch (error) {
    res.status(500).json({ error: '服务器错误' });
  }
});

app.delete('/api/auth/users/:id', verifyToken, (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
    if (err) {
      return res.status(500).json({ error: '删除失败' });
    }
    res.json({ success: true });
  });
});

app.post('/api/auth/stats/:userId/:statType', verifyToken, (req, res) => {
  const { userId, statType } = req.params;
  
  db.get('SELECT * FROM stats WHERE userId = ?', [userId], (err, stat) => {
    if (err) {
      return res.status(500).json({ error: '数据库错误' });
    }
    
    if (!stat) {
      db.run(`
        INSERT INTO stats (userId, calculateCount, copyCount, onlineMinutes, lastActiveAt)
        VALUES (?, ?, ?, ?, ?)
      `, [userId, statType === 'calculate' ? 1 : 0, statType === 'copy' ? 1 : 0, 0, new Date().toISOString()]);
    } else {
      if (statType === 'calculate') {
        db.run('UPDATE stats SET calculateCount = calculateCount + 1, lastActiveAt = ? WHERE userId = ?', [new Date().toISOString(), userId]);
      } else if (statType === 'copy') {
        db.run('UPDATE stats SET copyCount = copyCount + 1, lastActiveAt = ? WHERE userId = ?', [new Date().toISOString(), userId]);
      }
    }
    
    res.json({ success: true });
  });
});

app.post('/api/auth/reset-password/:userId', verifyToken, async (req, res) => {
  try {
    const { newPassword } = req.body;
    const hashedPwd = await bcrypt.hash(newPassword, 10);
    
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPwd, req.params.userId], (err) => {
      if (err) {
        return res.status(500).json({ error: '重置失败' });
      }
      res.json({ success: true });
    });
  } catch (error) {
    res.status(500).json({ error: '服务器错误' });
  }
});

app.use(express.static('public'));

app.get('/', (req, res) => {
  res.send('曦光包装袋报价器后端服务运行中...');
});

app.listen(PORT, () => {
  console.log(`🚀 服务器运行在 http://localhost:${PORT}`);
  console.log('📡 API接口已就绪');
});
