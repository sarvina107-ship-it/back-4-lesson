require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const cors = require('cors');
const path = require('path');
const dns = require('dns');

// DNS serverlarini sozlash (Windows va ba'zi provayderlarda MongoDB SRV muammosini oldini olish uchun)
try {
  dns.setServers(['8.8.8.8', '8.8.4.4']);
} catch (e) {
  // Ignore if not supported in environment
}

const app = express();
const PORT = process.env.PORT || 4322;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://sarvina107_db_user:JNVM00fwUlOhyRq2@cluster0.7pbwg1k.mongodb.net/auth_db?retryWrites=true&w=majority';
const JWT_SECRET = process.env.JWT_SECRET || 'only-for-local-development-change-me';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refresh-secret-only-for-local-development';
const ACCESS_TOKEN_EXPIRES_IN = '5m';
const REFRESH_TOKEN_EXPIRES_IN = '7d';

app.use(cors());
app.use(express.json());

// ==================== MONGOOSE SCHEMAS & MODELS ====================

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, 'Email kiritilishi shart.'],
      unique: true,
      lowercase: true,
      trim: true
    },
    passwordHash: {
      type: String,
      required: [true, 'Parol kiritilishi shart.']
    },
    firstName: { type: String, default: '' },
    lastName: { type: String, default: '' },
    username: { type: String, default: '' },
    role: {
      type: String,
      enum: ['admin', 'user'],
      default: 'user'
    },
    phone: { type: String, default: '' },
    avatarUrl: {
      type: String,
      default: 'https://i.pravatar.cc/300'
    },
    dateOfBirth: { type: String, default: '' },
    gender: {
      type: String,
      enum: ['male', 'female', 'other'],
      default: 'male'
    },
    address: {
      city: { type: String, default: 'Toshkent' },
      district: { type: String, default: 'Yunusobod' },
      country: { type: String, default: 'Uzbekistan' }
    },
    isVerified: { type: Boolean, default: true },
    isActive: { type: Boolean, default: true },
    lastLoginAt: { type: Date, default: null }
  },
  {
    timestamps: true
  }
);

const refreshTokenSchema = new mongoose.Schema(
  {
    token: {
      type: String,
      required: true,
      unique: true
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now,
      expires: 60 * 60 * 24 * 7 // 7 kundan so'ng MongoDB avtomatik o'chiradi (TTL)
    }
  }
);

const User = mongoose.model('User', userSchema);
const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema);

// MongoDB Connection
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB Atlas-ga muvaffaqiyatli ulandi!');
  })
  .catch((err) => {
    console.error('❌ MongoDB ulanishda xatolik:', err.message);
  });

// ==================== SWAGGER CONFIGURATION ====================

const swaggerOptions = {
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'Users Authentication & Registration API (MongoDB)',
      version: '1.0.0',
      description: 'MongoDB bilan integratsiya qilingan JWT orqali Ro‘yxatdan o‘tish (Register), Login, 5 daqiqalik Access Token va Refresh Token tizimi.'
    },
    servers: [
      {
        url: '/',
        description: 'Server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        RegisterRequest: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: {
              type: 'string',
              format: 'email',
              example: 'sarvina@example.com'
            },
            password: {
              type: 'string',
              minLength: 6,
              example: 'Sarvina12345'
            },
            firstName: {
              type: 'string',
              example: 'Sarvina'
            },
            lastName: {
              type: 'string',
              example: 'Alimova'
            },
            username: {
              type: 'string',
              example: 'sarvina_dev'
            },
            phone: {
              type: 'string',
              example: '+998901234567'
            },
            gender: {
              type: 'string',
              enum: ['male', 'female', 'other'],
              example: 'female'
            },
            city: {
              type: 'string',
              example: 'Toshkent'
            }
          }
        },
        LoginRequest: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: {
              type: 'string',
              format: 'email',
              example: 'sarvina@example.com'
            },
            password: {
              type: 'string',
              example: 'Sarvina12345'
            }
          }
        },
        RefreshRequest: {
          type: 'object',
          required: ['refreshToken'],
          properties: {
            refreshToken: {
              type: 'string',
              example: 'eyJhbGciOiJIUzI1NiIsIn...'
            }
          }
        },
        LogoutRequest: {
          type: 'object',
          required: ['refreshToken'],
          properties: {
            refreshToken: {
              type: 'string',
              example: 'eyJhbGciOiJIUzI1NiIsIn...'
            }
          }
        },
        User: {
          type: 'object',
          properties: {
            _id: { type: 'string', example: '65f123456789abcdef123456' },
            email: { type: 'string', example: 'sarvina@example.com' },
            firstName: { type: 'string', example: 'Sarvina' },
            lastName: { type: 'string', example: 'Alimova' },
            username: { type: 'string', example: 'sarvina_dev' },
            role: { type: 'string', example: 'user' },
            phone: { type: 'string', example: '+998901234567' },
            avatarUrl: { type: 'string', format: 'uri' },
            dateOfBirth: { type: 'string', format: 'date' },
            gender: { type: 'string', example: 'female' },
            address: {
              type: 'object',
              properties: {
                city: { type: 'string', example: 'Toshkent' },
                district: { type: 'string', example: 'Yunusobod' },
                country: { type: 'string', example: 'Uzbekistan' }
              }
            },
            isVerified: { type: 'boolean', example: true },
            isActive: { type: 'boolean', example: true },
            createdAt: { type: 'string', format: 'date-time' },
            updatedAt: { type: 'string', format: 'date-time' },
            lastLoginAt: {
              type: 'string',
              format: 'date-time',
              nullable: true
            }
          }
        },
        AuthResponse: {
          type: 'object',
          properties: {
            message: { type: 'string', example: 'Muvaffaqiyatli bajarildi.' },
            tokenType: { type: 'string', example: 'Bearer' },
            accessToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsIn...' },
            expiresIn: { type: 'string', example: '5m' },
            refreshToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsIn...' },
            user: { $ref: '#/components/schemas/User' }
          }
        },
        RefreshResponse: {
          type: 'object',
          properties: {
            message: { type: 'string', example: 'Token yangilandi.' },
            tokenType: { type: 'string', example: 'Bearer' },
            accessToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsIn...' },
            expiresIn: { type: 'string', example: '5m' },
            refreshToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsIn...' }
          }
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            message: { type: 'string', example: 'Xatolik haqida xabar' }
          }
        }
      }
    }
  },
  apis: [path.join(__dirname, 'server.js'), './server.js']
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, { explorer: true }));
app.get('/docs', (req, res) => res.redirect('/api-docs'));
app.get('/swagger', (req, res) => res.redirect('/api-docs'));

// ==================== HELPER FUNCTIONS ====================

function publicUser(user) {
  const userObj = user.toObject ? user.toObject() : { ...user };
  delete userObj.passwordHash;
  delete userObj.__v;
  return userObj;
}

async function generateTokens(user) {
  const accessToken = jwt.sign(
    { sub: user._id.toString(), email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
  );

  const refreshToken = jwt.sign(
    { sub: user._id.toString() },
    JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
  );

  // Bazaga refresh tokenni saqlash
  await RefreshToken.create({
    token: refreshToken,
    userId: user._id
  });

  return { accessToken, refreshToken };
}

function requireAuth(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Bearer token yuboring.' });
  }

  const token = authorization.slice(7);
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token yaroqsiz yoki muddati tugagan (5 daqiqa o\'tgan).' });
  }
}

// ==================== ROUTES ====================

/**
 * @swagger
 * /:
 *   get:
 *     summary: API holatini tekshirish
 *     tags: [General]
 *     responses:
 *       200:
 *         description: API ishlamoqda
 */
app.get('/', (req, res) => {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.get('host');
  res.json({
    message: 'API ishlayapti (MongoDB Atlas)',
    swaggerUi: `${protocol}://${host}/api-docs`,
    endpoints: [
      'POST /register',
      'POST /login',
      'POST /refresh',
      'POST /logout',
      'GET /me',
      'GET /users'
    ]
  });
});

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Yangi foydalanuvchini ro'yxatdan o'tkazish (MongoDB-ga saqlash)
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RegisterRequest'
 *     responses:
 *       201:
 *         description: Ro'yxatdan o'tish muvaffaqiyatli
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       400:
 *         description: Noto'g'ri so'rov yoki email allaqachon mavjud
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         description: Server xatoligi
 */
app.post('/register', async (req, res) => {
  try {
    const {
      email,
      password,
      firstName = '',
      lastName = '',
      username = '',
      phone = '',
      gender = 'female',
      city = 'Toshkent'
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'email va password kiritilishi majburiy.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Parol kamida 6 ta belgidan iborat bo\'lishi kerak.' });
    }

    // Email mavjudligini tekshirish
    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({ message: 'Bu email bilan foydalanuvchi allaqachon ro‘yxatdan o‘tgan.' });
    }

    // Parolni hash qilish
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Foydalanuvchini MongoDB-da yaratish
    const newUser = new User({
      email: normalizedEmail,
      passwordHash,
      firstName,
      lastName,
      username: username || normalizedEmail.split('@')[0],
      phone,
      gender,
      address: {
        city: city || 'Toshkent',
        district: 'Markaz',
        country: 'Uzbekistan'
      },
      isVerified: true,
      isActive: true,
      lastLoginAt: new Date()
    });

    const savedUser = await newUser.save();

    // Tokenlarni yaratish va saqlash
    const tokens = await generateTokens(savedUser);

    res.status(201).json({
      message: 'Foydalanuvchi muvaffaqiyatli ro‘yxatdan o‘tdi va MongoDB-ga saqlandi.',
      tokenType: 'Bearer',
      accessToken: tokens.accessToken,
      expiresIn: ACCESS_TOKEN_EXPIRES_IN,
      refreshToken: tokens.refreshToken,
      user: publicUser(savedUser)
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Ro‘yxatdan o‘tishda xatolik yuz berdi: ' + error.message });
  }
});

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login qilish, 5 daqiqalik Access Token va Refresh Token olish
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Login muvaffaqiyatli
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       400:
 *         description: Email yoki password yuborilmagan
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       401:
 *         description: Email yoki parol xato
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       403:
 *         description: Foydalanuvchi faol emas
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'email va password majburiy.' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({ message: 'Email yoki parol xato.' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Email yoki parol xato.' });
    }

    if (!user.isActive) {
      return res.status(403).json({ message: 'Foydalanuvchi faol emas (bloklangan).' });
    }

    // Oxirgi kirish vaqtini yangilash
    user.lastLoginAt = new Date();
    await user.save();

    const tokens = await generateTokens(user);

    res.json({
      message: 'Login muvaffaqiyatli.',
      tokenType: 'Bearer',
      accessToken: tokens.accessToken,
      expiresIn: ACCESS_TOKEN_EXPIRES_IN,
      refreshToken: tokens.refreshToken,
      user: publicUser(user)
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Serverda xatolik yuz berdi: ' + error.message });
  }
});

/**
 * @swagger
 * /refresh:
 *   post:
 *     summary: Refresh token orqali yangi 5 daqiqalik Access Token olish (Token Rotation)
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RefreshRequest'
 *     responses:
 *       200:
 *         description: Yangi token muvaffaqiyatli berildi
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/RefreshResponse'
 *       400:
 *         description: Refresh token yuborilmagan
 *       401:
 *         description: Refresh token yaroqsiz yoki muddati tugagan
 *       403:
 *         description: Refresh token bazada topilmadi yoki bekor qilingan
 */
app.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'refreshToken majburiy.' });
    }

    // Refresh token bazada borligini tekshirish
    const tokenDoc = await RefreshToken.findOne({ token: refreshToken });
    if (!tokenDoc) {
      return res.status(403).json({ message: 'Refresh token bazada topilmadi yoki bekor qilingan.' });
    }

    let payload;
    try {
      payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    } catch (err) {
      // Muddati o'tgan bo'lsa bazadan o'chirish
      await RefreshToken.deleteOne({ token: refreshToken });
      return res.status(401).json({ message: 'Refresh token muddati tugagan yoki noto‘g‘ri.' });
    }

    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(404).json({ message: 'Foydalanuvchi topilmadi.' });
    }
    if (!user.isActive) {
      return res.status(403).json({ message: 'Foydalanuvchi faol emas.' });
    }

    // Eski refresh tokenni o'chirish (Token Rotation)
    await RefreshToken.deleteOne({ token: refreshToken });

    // Yangi juftlik yaratish
    const newTokens = await generateTokens(user);

    res.json({
      message: 'Token muvaffaqiyatli yangilandi.',
      tokenType: 'Bearer',
      accessToken: newTokens.accessToken,
      expiresIn: ACCESS_TOKEN_EXPIRES_IN,
      refreshToken: newTokens.refreshToken
    });
  } catch (error) {
    console.error('Refresh error:', error);
    res.status(500).json({ message: 'Serverda xatolik yuz berdi: ' + error.message });
  }
});

/**
 * @swagger
 * /logout:
 *   post:
 *     summary: Tizimdan chiqish (Refresh tokenni MongoDB-dan o'chirish)
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LogoutRequest'
 *     responses:
 *       200:
 *         description: Muvaffaqiyatli chiqildi
 *       400:
 *         description: Refresh token yuborilmagan
 */
app.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ message: 'refreshToken majburiy.' });
    }

    await RefreshToken.deleteOne({ token: refreshToken });
    res.json({ message: 'Muvaffaqiyatli chiqildi, refresh token bazadan o‘chirildi.' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Server xatoligi: ' + error.message });
  }
});

/**
 * @swagger
 * /me:
 *   get:
 *     summary: Joriy foydalanuvchi profilini olish
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Foydalanuvchi ma'lumotlari
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *       401:
 *         description: Token noto'g'ri yoki yuborilmagan
 *       404:
 *         description: Foydalanuvchi topilmadi
 */
app.get('/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.auth.sub);
    if (!user) {
      return res.status(404).json({ message: 'Foydalanuvchi topilmadi.' });
    }

    res.json({ user: publicUser(user) });
  } catch (error) {
    console.error('Get me error:', error);
    res.status(500).json({ message: 'Server xatoligi: ' + error.message });
  }
});

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Barcha foydalanuvchilar ro'yxatini olish (MongoDB-dan)
 *     tags: [Users]
 *     responses:
 *       200:
 *         description: Barcha foydalanuvchilar ro'yxati
 */
app.get('/users', async (req, res) => {
  try {
    const usersList = await User.find().select('-passwordHash -__v');
    res.json({
      count: usersList.length,
      users: usersList
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Server xatoligi: ' + error.message });
  }
});

app.use((req, res) => res.status(404).json({ message: 'Route topilmadi.' }));

app.listen(PORT, () => {
  console.log(`🚀 Server ishga tushdi: http://localhost:${PORT}`);
  console.log(`📚 Swagger UI ochish uchun: http://localhost:${PORT}/api-docs`);
});

