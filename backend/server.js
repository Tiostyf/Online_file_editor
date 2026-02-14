import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import multer from 'multer';
import compression from 'compression';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import sharp from 'sharp';
import { PDFDocument } from 'pdf-lib';
import archiver from 'archiver';
import { Sequelize, DataTypes, Op } from 'sequelize';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

// ========== MIDDLEWARE ==========
app.use(cors({
  origin: function (origin, callback) {
    const allowed = ['http://localhost:5173', 'http://localhost:5174'];
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json({ limit: '150mb' }));
app.use(express.urlencoded({ extended: true, limit: '150mb' }));
app.use(compression());

// ========== STATIC FOLDERS ==========
const uploadDir = path.join(__dirname, 'uploads');
const processedDir = path.join(__dirname, 'processed');
[uploadDir, processedDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});
app.use('/uploads', express.static(uploadDir));
app.use('/processed', express.static(processedDir));

// ========== SEQUELIZE SETUP (SQLite) ==========
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: process.env.DB_STORAGE || './database.sqlite',
  logging: false,
  define: {
    timestamps: true,
    underscored: true
  }
});

// ========== MODELS ==========
const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING(30),
    allowNull: false,
    unique: true,
    validate: { len: [3, 30] }
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: { isEmail: true }
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: { len: [6] }
  },
  profile: {
    type: DataTypes.JSON,
    defaultValue: {}
  },
  preferences: {
    type: DataTypes.JSON,
    defaultValue: { theme: 'light', notifications: true }
  },
  stats: {
    type: DataTypes.JSON,
    defaultValue: {
      totalFiles: 0,
      totalSize: 0,
      totalCompressed: 0,
      spaceSaved: 0,
      totalDownloads: 0
    }
  }
});

const File = sequelize.define('File', {
  filename: {
    type: DataTypes.STRING,
    allowNull: false
  },
  originalName: {
    type: DataTypes.STRING,
    allowNull: false
  },
  size: {
    type: DataTypes.BIGINT,
    allowNull: false
  },
  compressedSize: {
    type: DataTypes.BIGINT,
    allowNull: false
  },
  type: {
    type: DataTypes.STRING,
    allowNull: false
  },
  downloadCount: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  compressionRatio: {
    type: DataTypes.FLOAT
  },
  toolUsed: {
    type: DataTypes.STRING
  }
});

// Associations
User.hasMany(File, { foreignKey: 'ownerId', as: 'files' });
File.belongsTo(User, { foreignKey: 'ownerId', as: 'owner' });

// ========== DATABASE SYNC ==========
const initDB = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ SQLite Connected');
    await sequelize.sync({ alter: true });
    console.log('   Database synced');
  } catch (e) {
    console.error('❌ Database error:', e.message);
    process.exit(1);
  }
};
initDB();

// ========== MULTER ==========
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9.\-]/g, '_');
    cb(null, `${Date.now()}-${Math.random().toString(36).substr(2, 9)}-${safe}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 150 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, true)
});

// ========== AUTH MIDDLEWARE ==========
const auth = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    if (!authHeader) {
      return res.status(401).json({ success: false, message: 'No authorization header' });
    }

    let token;
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    } else {
      token = authHeader.trim();
    }

    if (!token || token === 'null' || token === 'undefined' || token === '') {
      return res.status(401).json({ success: false, message: 'Token is empty' });
    }

    const tokenParts = token.split('.');
    if (tokenParts.length !== 3) {
      return res.status(401).json({ success: false, message: 'Invalid token format' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
    const user = await User.findByPk(decoded.userId, {
      attributes: { exclude: ['password'] }
    });

    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (e) {
    console.error('Auth error:', e.message);
    if (e.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }
    if (e.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired' });
    }
    res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

// ========== HELPER ==========
const updateStats = async (userId, orig, comp) => {
  const user = await User.findByPk(userId);
  if (!user) return;

  const stats = user.stats || {};
  stats.totalFiles = (stats.totalFiles || 0) + 1;
  stats.totalSize = (stats.totalSize || 0) + orig;
  stats.totalCompressed = (stats.totalCompressed || 0) + comp;
  stats.spaceSaved = (stats.spaceSaved || 0) + (orig - comp);

  await user.update({ stats });
};

// ========== ROUTES ==========
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server running',
    db: 'OK'
  });
});

// ----- REGISTER -----
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, fullName = '', company = '' } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'Username, email, and password are required' });
    }
    if (username.length < 3) return res.status(400).json({ success: false, message: 'Username must be at least 3 characters' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });

    const existing = await User.findOne({
      where: {
        [Op.or]: [{ email }, { username }]
      }
    });
    if (existing) {
      return res.status(400).json({
        success: false,
        message: existing.email === email ? 'Email already in use' : 'Username already taken'
      });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      email,
      password: hashed,
      profile: { fullName, company }
    });

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        profile: user.profile,
        stats: user.stats,
        preferences: user.preferences
      }
    });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ success: false, message: 'Server error during registration' });
  }
});

// ----- LOGIN -----
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const user = await User.findOne({ where: { email: email.toLowerCase().trim() } });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid email or password' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ success: false, message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        profile: user.profile,
        stats: user.stats,
        preferences: user.preferences
      }
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

// ----- PROFILE -----
app.get('/api/profile', auth, async (req, res) => {
  try {
    const files = await File.findAll({ where: { ownerId: req.user.id } });
    const stats = {
      totalFiles: files.length,
      totalSize: files.reduce((s, f) => s + f.size, 0),
      totalCompressed: files.reduce((s, f) => s + f.compressedSize, 0),
      spaceSaved: files.reduce((s, f) => s + (f.size - f.compressedSize), 0),
      totalDownloads: files.reduce((s, f) => s + f.downloadCount, 0)
    };

    res.json({
      success: true,
      user: {
        id: req.user.id,
        username: req.user.username,
        email: req.user.email,
        profile: req.user.profile,
        preferences: req.user.preferences,
        stats
      }
    });
  } catch (e) {
    console.error('Profile fetch error:', e);
    res.status(500).json({ success: false, message: 'Failed to fetch profile' });
  }
});

// ----- UPDATE PROFILE -----
app.put('/api/profile', auth, async (req, res) => {
  try {
    const updates = req.body;
    const allowed = ['fullName', 'company', 'phone', 'location', 'theme', 'notifications'];
    const profileUpdate = {};
    const prefsUpdate = {};

    allowed.forEach(f => {
      if (updates[f] !== undefined) {
        if (['theme', 'notifications'].includes(f)) {
          prefsUpdate[f] = updates[f];
        } else {
          profileUpdate[f] = updates[f];
        }
      }
    });

    const user = await User.findByPk(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Merge JSON fields
    const newProfile = { ...user.profile, ...profileUpdate };
    const newPrefs = { ...user.preferences, ...prefsUpdate };

    await user.update({ profile: newProfile, preferences: newPrefs });

    const files = await File.findAll({ where: { ownerId: user.id } });
    const stats = {
      totalFiles: files.length,
      totalSize: files.reduce((s, f) => s + f.size, 0),
      totalCompressed: files.reduce((s, f) => s + f.compressedSize, 0),
      spaceSaved: files.reduce((s, f) => s + (f.size - f.compressedSize), 0),
      totalDownloads: files.reduce((s, f) => s + f.downloadCount, 0)
    };

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        profile: user.profile,
        preferences: user.preferences,
        stats
      }
    });
  } catch (e) {
    console.error('Profile update error:', e);
    res.status(500).json({ success: false, message: 'Profile update failed' });
  }
});

// ----- PROCESS FILES -----
app.post('/api/process', auth, upload.array('files'), async (req, res) => {
  try {
    const files = req.files;
    if (!files?.length) {
      return res.status(400).json({ success: false, message: 'No files uploaded' });
    }

    const { tool, compressLevel, format, order } = req.body;

    const validTools = ['compress', 'merge', 'convert', 'enhance', 'preview'];
    if (!validTools.includes(tool)) {
      return res.status(400).json({
        success: false,
        message: `Invalid tool: ${tool}. Valid tools are: ${validTools.join(', ')}`
      });
    }

    // Preview tool
    if (tool === 'preview') {
      const fileInfo = files.map(f => ({
        name: f.originalname,
        size: f.size,
        type: f.mimetype,
        url: `/uploads/${f.filename}`
      }));
      return res.json({
        success: true,
        files: fileInfo,
        message: 'Files ready for preview'
      });
    }

    // Tool-specific validations
    if (tool === 'merge' && files.length < 2) {
      return res.status(400).json({ success: false, message: 'Merge requires at least 2 files' });
    }

    if (['convert', 'enhance'].includes(tool) && files.length !== 1) {
      return res.status(400).json({
        success: false,
        message: `${tool.charAt(0).toUpperCase() + tool.slice(1)} requires exactly 1 file`
      });
    }

    if (tool === 'convert' && !format) {
      return res.status(400).json({ success: false, message: 'Format is required for conversion' });
    }

    let outPath, mime, compSize;
    const origSize = files.reduce((s, f) => s + f.size, 0);
    let fileName = '';

    if (tool === 'compress') {
      const level = Math.max(1, Math.min(9, parseInt(compressLevel) || 6));
      outPath = path.join(processedDir, `${Date.now()}-compressed.zip`);
      const output = fs.createWriteStream(outPath);
      const archive = archiver('zip', { zlib: { level } });

      await new Promise((resolve, reject) => {
        archive.pipe(output);
        files.forEach(f => archive.file(f.path, { name: f.originalname }));
        archive.on('error', reject);
        output.on('close', resolve);
        archive.finalize();
      });

      compSize = fs.statSync(outPath).size;
      fileName = files.length === 1
        ? `${path.parse(files[0].originalname).name}_compressed.zip`
        : `batch_${Date.now()}.zip`;
      mime = 'application/zip';

    } else if (tool === 'merge') {
      const nonPdfFiles = files.filter(f => f.mimetype !== 'application/pdf');
      if (nonPdfFiles.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'All files must be PDFs for merging'
        });
      }

      const pdfDoc = await PDFDocument.create();
      const orderArr = order ? JSON.parse(order) : files.map(f => f.originalname);

      for (const name of orderArr) {
        const file = files.find(f => f.originalname === name);
        if (!file) continue;

        const srcBytes = fs.readFileSync(file.path);
        const src = await PDFDocument.load(srcBytes);
        const pages = await pdfDoc.copyPages(src, src.getPageIndices());
        pages.forEach(p => pdfDoc.addPage(p));
      }

      const pdfBytes = await pdfDoc.save();
      outPath = path.join(processedDir, `${Date.now()}-merged.pdf`);
      fs.writeFileSync(outPath, pdfBytes);
      compSize = pdfBytes.length;
      fileName = 'merged.pdf';
      mime = 'application/pdf';

    } else if (tool === 'convert') {
      const file = files[0];
      const ext = format.toLowerCase();

      const validImageFormats = ['jpg', 'jpeg', 'png', 'webp'];
      const validAudioFormats = ['mp3', 'wav'];

      if (![...validImageFormats, ...validAudioFormats].includes(ext)) {
        return res.status(400).json({
          success: false,
          message: 'Unsupported format. Use: jpg, png, webp, mp3, wav'
        });
      }

      outPath = path.join(processedDir, `${Date.now()}-converted.${ext}`);

      if (validImageFormats.includes(ext)) {
        await sharp(file.path)
          .toFormat(ext === 'jpg' ? 'jpeg' : ext)
          .toFile(outPath);
        mime = `image/${ext === 'jpg' ? 'jpeg' : ext}`;
      } else {
        fs.copyFileSync(file.path, outPath);
        mime = `audio/${ext}`;
      }

      compSize = fs.statSync(outPath).size;
      fileName = `${path.parse(file.originalname).name}_converted.${ext}`;

    } else if (tool === 'enhance') {
      const file = files[0];

      if (!file.mimetype.startsWith('image/')) {
        return res.status(400).json({
          success: false,
          message: 'Only images can be enhanced'
        });
      }

      outPath = path.join(processedDir, `${Date.now()}-enhanced.webp`);
      await sharp(file.path)
        .rotate()
        .sharpen()
        .modulate({ brightness: 1.1, saturation: 1.2 })
        .webp({ quality: 90 })
        .toFile(outPath);

      compSize = fs.statSync(outPath).size;
      fileName = `${path.parse(file.originalname).name}_enhanced.webp`;
      mime = 'image/webp';
    }

    // Save file record
    const processed = await File.create({
      filename: path.basename(outPath),
      originalName: fileName,
      size: origSize,
      compressedSize: compSize,
      type: mime,
      ownerId: req.user.id,
      compressionRatio: origSize > 0 ? Number(((origSize - compSize) / origSize * 100).toFixed(2)) : 0,
      toolUsed: tool
    });

    await updateStats(req.user.id, origSize, compSize);

    res.json({
      success: true,
      url: `/processed/${path.basename(outPath)}`,
      fileName,
      size: compSize,
      originalSize: origSize,
      savings: origSize - compSize,
      tool: tool
    });

  } catch (e) {
    console.error('Process error:', e);
    res.status(500).json({
      success: false,
      message: e.message || 'File processing failed'
    });
  } finally {
    // Cleanup uploaded files
    if (req.files) {
      req.files.forEach(f => {
        try {
          fs.unlinkSync(f.path);
        } catch (cleanupError) {
          console.warn('Cleanup error:', cleanupError.message);
        }
      });
    }
  }
});

// ----- HISTORY -----
app.get('/api/history', auth, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 10;
    const offset = (page - 1) * limit;

    const { count, rows: files } = await File.findAndCountAll({
      where: { ownerId: req.user.id },
      order: [['createdAt', 'DESC']],
      limit,
      offset
    });

    res.json({
      success: true,
      files,
      total: count,
      page,
      pages: Math.ceil(count / limit)
    });
  } catch (e) {
    console.error('History error:', e);
    res.status(500).json({ success: false, message: 'Failed to fetch history' });
  }
});

// ----- DOWNLOAD FILE -----
app.get('/api/download/:filename', auth, async (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(processedDir, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, message: 'File not found' });
    }

    // Increment file download count
    const file = await File.findOne({ where: { filename } });
    if (file) {
      file.downloadCount += 1;
      await file.save();
    }

    // Increment user totalDownloads in stats JSON
    const user = await User.findByPk(req.user.id);
    if (user) {
      const stats = { ...user.stats };
      stats.totalDownloads = (stats.totalDownloads || 0) + 1;
      await user.update({ stats });
    }

    res.download(filePath);
  } catch (e) {
    console.error('Download error:', e);
    res.status(500).json({ success: false, message: 'Download failed' });
  }
});

// ========== START SERVER ==========
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log('\n🚀 FileMaster Pro Backend STARTED (SQLite)');
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/api/health`);
});