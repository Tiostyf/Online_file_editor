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


// ================= MIDDLEWARE =================

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
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true
}));

app.use(express.json({ limit: '150mb' }));
app.use(express.urlencoded({ extended: true, limit: '150mb' }));
app.use(compression());


// ================= FOLDERS =================

const uploadDir = path.join(__dirname, 'uploads');
const processedDir = path.join(__dirname, 'processed');

[uploadDir, processedDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

app.use('/uploads', express.static(uploadDir));
app.use('/processed', express.static(processedDir));


// ================= DATABASE =================

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: process.env.DB_STORAGE || './database.sqlite',
  logging: false,
  define: {
    timestamps: true,
    underscored: true
  }
});


// ================= MODELS =================

const User = sequelize.define("User", {

  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },

  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },

  password: {
    type: DataTypes.STRING,
    allowNull: false
  },

  profile: {
    type: DataTypes.JSON,
    defaultValue: {}
  },

  preferences: {
    type: DataTypes.JSON,
    defaultValue: {
      theme: "light",
      notifications: true
    }
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


const File = sequelize.define("File", {

  filename: DataTypes.STRING,

  originalName: DataTypes.STRING,

  size: DataTypes.BIGINT,

  compressedSize: DataTypes.BIGINT,

  type: DataTypes.STRING,

  downloadCount: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },

  compressionRatio: DataTypes.FLOAT,

  toolUsed: DataTypes.STRING

});


User.hasMany(File, { foreignKey: "ownerId" });
File.belongsTo(User, { foreignKey: "ownerId" });


// ================= INIT DB =================

await sequelize.sync();

console.log("✅ Database Ready");


// ================= MULTER =================

const storage = multer.diskStorage({

  destination: (req, file, cb) => cb(null, uploadDir),

  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9.\-]/g, "_");
    cb(null, Date.now() + "-" + safe);
  }

});

const upload = multer({ storage });


// ================= AUTH MIDDLEWARE =================

const auth = async (req, res, next) => {

  try {

    const header = req.headers.authorization;

    if (!header) {
      return res.status(401).json({
        success: false,
        message: "No token"
      });
    }

    const token = header.replace("Bearer ", "");

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "secret"
    );

    const user = await User.findByPk(decoded.userId);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found"
      });
    }

    req.user = user;

    next();

  } catch {

    res.status(401).json({
      success: false,
      message: "Invalid token"
    });

  }

};


// ================= ROUTES =================


// Health

app.get("/api/health", (req, res) => {

  res.json({
    success: true,
    message: "Server running"
  });

});


// ================= SIGNUP (UPDATED) =================

app.post("/api/signup", async (req, res) => {

  try {

    const { username, email, password, fullName, company } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields required"
      });
    }

    const exists = await User.findOne({
      where: {
        [Op.or]: [{ email }, { username }]
      }
    });

    if (exists) {
      return res.status(400).json({
        success: false,
        message: "User already exists"
      });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      username,
      email,
      password: hashed,
      profile: {
        fullName,
        company
      }
    });

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "7d" }
    );

    res.json({

      success: true,

      token,

      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        profile: user.profile
      }

    });

  } catch (e) {

    res.status(500).json({
      success: false,
      message: e.message
    });

  }

});


// ================= LOGIN =================

app.post("/api/login", async (req, res) => {

  try {

    const { email, password } = req.body;

    const user = await User.findOne({
      where: { email }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password
    );

    if (!valid) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "7d" }
    );

    res.json({

      success: true,

      token,

      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }

    });

  } catch (e) {

    res.status(500).json({
      success: false,
      message: e.message
    });

  }

});


// ================= START SERVER =================

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {

  console.log("🚀 Server running on:");
  console.log("http://localhost:" + PORT);

});
