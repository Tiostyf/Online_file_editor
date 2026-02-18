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
import mongoose from 'mongoose';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

// ========== MIDDLEWARE ==========
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
];

if (process.env.CLIENT_URL) {
  allowedOrigins.push(process.env.CLIENT_URL);
}
if (process.env.RENDER_EXTERNAL_URL) {
  allowedOrigins.push(process.env.RENDER_EXTERNAL_URL);
}

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
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

// ========== STATIC FOLDERS (for uploads & processed files) ==========
const uploadDir = path.join(__dirname, 'uploads');
const processedDir = path.join(__dirname, 'processed');
[uploadDir, processedDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});
app.use('/uploads', express.static(uploadDir));
app.use('/processed', express.static(processedDir));

// ========== MONGODB CONNECTION ==========
// Use MONGODB_URI from .env (must include database name, e.g., "filecompressor")
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error('❌ MONGODB_URI is not defined in .env');
  process.exit(1);
}
mongoose.connect(mongoUri)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB error:', err.message);
    process.exit(1);
  });

// ========== MONGOOSE MODELS ==========
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3 },
  email:    { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  profile:  { type: Object, default: {} },
  preferences: {
    type: Object,
    default: { theme: 'light', notifications: true }
  },
  stats: {
    type: Object,
    default: {
      totalFiles: 0,
      totalSize: 0,
      totalCompressed: 0,
      spaceSaved: 0,
      totalDownloads: 0
    }
  }
}, { timestamps: true });

const fileSchema = new mongoose.Schema({
  filename:       { type: String, required: true },
  originalName:   { type: String, required: true },
  size:           { type: Number, required: true },
  compressedSize: { type: Number, required: true },
  type:           { type: String, required: true },
  downloadCount:  { type: Number, default: 0 },
  compressionRatio: Number,
  toolUsed:       String,
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);

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

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');

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
  const user = await User.findById(userId);
  if (!user) return;

  const stats = user.stats || {};
  stats.totalFiles = (stats.totalFiles || 0) + 1;
  stats.totalSize = (stats.totalSize || 0) + orig;
  stats.totalCompressed = (stats.totalCompressed || 0) + comp;
  stats.spaceSaved = (stats.spaceSaved || 0) + (orig - comp);

  user.stats = stats;
  await user.save();
};

// ========== API ROUTES ==========
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
      $or: [{ email: email.toLowerCase() }, { username }]
    });
    if (existing) {
      return res.status(400).json({
        success: false,
        message: existing.email === email.toLowerCase() ? 'Email already in use' : 'Username already taken'
      });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password: hashed,
      profile: { fullName, company }
    });

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
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

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid email or password' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ success: false, message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
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
    const files = await File.find({ ownerId: req.user._id });
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
        id: req.user._id,
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

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.profile = { ...user.profile, ...profileUpdate };
    user.preferences = { ...user.preferences, ...prefsUpdate };
    await user.save();

    const files = await File.find({ ownerId: user._id });
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
        id: user._id,
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

    const processed = await File.create({
      filename: path.basename(outPath),
      originalName: fileName,
      size: origSize,
      compressedSize: compSize,
      type: mime,
      ownerId: req.user._id,
      compressionRatio: origSize > 0 ? Number(((origSize - compSize) / origSize * 100).toFixed(2)) : 0,
      toolUsed: tool
    });

    await updateStats(req.user._id, origSize, compSize);

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
    const skip = (page - 1) * limit;

    const total = await File.countDocuments({ ownerId: req.user._id });
    const files = await File.find({ ownerId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    res.json({
      success: true,
      files,
      total,
      page,
      pages: Math.ceil(total / limit)
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

    const file = await File.findOne({ filename });
    if (file) {
      file.downloadCount += 1;
      await file.save();
    }

    const user = await User.findById(req.user._id);
    if (user) {
      const stats = { ...user.stats };
      stats.totalDownloads = (stats.totalDownloads || 0) + 1;
      user.stats = stats;
      await user.save();
    }

    res.download(filePath);
  } catch (e) {
    console.error('Download error:', e);
    res.status(500).json({ success: false, message: 'Download failed' });
  }
});

// ========== NO CATCH‑ALL ROUTE (API ONLY) ==========
// Any request that doesn't match an API route will automatically get a 404.

// ========== START SERVER ==========
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log('\n🚀 FileMaster Pro Backend STARTED (MongoDB, API‑only mode)');
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/api/health`);
});