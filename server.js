const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// CORS Configuration
const corsOptions = {
  origin: [
    'https://orzu-academy.vercel.app',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://alixonovshukurullo13:1CSsM3G5oRI1sZUG@cluster0.wdxm5vr.mongodb.net/';
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  login: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Review Schema
const reviewSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  text: { type: String, required: true, trim: true },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Review = mongoose.model('Review', reviewSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Register Route
app.post('/register', async (req, res) => {
  const { email, login, password } = req.body;

  // Validation
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'To‘g‘ri email manzilini kiriting' });
  }
  if (!login || login.length < 3) {
    return res.status(400).json({ error: 'Login kamida 3 belgidan iborat bo‘lishi kerak' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Parol kamida 6 belgidan iborat bo‘lishi kerak' });
  }

  try {
    // Check for existing user
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ error: 'Bu email allaqachon ro‘yxatdan o‘tgan' });
    }
    const existingLogin = await User.findOne({ login });
    if (existingLogin) {
      return res.status(400).json({ error: 'Bu login allaqachon ro‘yxatdan o‘tgan' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({ email, login, password: hashedPassword });
    await user.save();

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({
      message: 'Muvaffaqiyatli ro‘yxatdan o‘tdingiz!',
      token,
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server xatosi, iltimos keyinroq urinib ko‘ring' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { login, password } = req.body;

  // Validation
  if (!login || login.length < 3) {
    return res.status(400).json({ error: 'Login kamida 3 belgidan iborat bo‘lishi kerak' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Parol kamida 6 belgidan iborat bo‘lishi kerak' });
  }

  try {
    // Find user
    const user = await User.findOne({ login });
    if (!user) {
      return res.status(400).json({ error: 'Login yoki parol noto‘g‘ri' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Login yoki parol noto‘g‘ri' });
    }

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
      message: 'Muvaffaqiyatli kirdingiz!',
      token,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server xatosi, iltimos keyinroq urinib ko‘ring' });
  }
});

// Get User Info Route
app.get('/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token topilmadi' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('login email');
    if (!user) return res.status(404).json({ error: 'Foydalanuvchi topilmadi' });
    res.json({ login: user.login, email: user.email });
  } catch (error) {
    res.status(401).json({ error: 'Noto‘g‘ri token' });
  }
});

// Submit Review Route
app.post('/reviews', async (req, res) => {
  const { name, text } = req.body;

  // Validation
  if (!name || name.trim().length < 2) {
    return res.status(400).json({ error: 'Ism kamida 2 belgidan iborat bo‘lishi kerak' });
  }
  if (!text || text.trim().length < 10) {
    return res.status(400).json({ error: 'Fikr kamida 10 belgidan iborat bo‘lishi kerak' });
  }

  try {
    // Optional: Require authentication
    // const token = req.headers.authorization?.split(' ')[1];
    // if (!token) return res.status(401).json({ error: 'Token topilmadi' });
    // const decoded = jwt.verify(token, JWT_SECRET);
    // const user = await User.findById(decoded.userId);
    // if (!user) return res.status(404).json({ error: 'Foydalanuvchi topilmadi' });

    const review = new Review({
      name: name.trim(),
      text: text.trim(),
    });
    await review.save();
    res.status(201).json(review);
  } catch (error) {
    console.error('Review submission error:', error);
    res.status(500).json({ error: 'Server xatosi, iltimos keyinroq urinib ko‘ring' });
  }
});

// Get Reviews Route
app.get('/reviews', async (req, res) => {
  try {
    const reviews = await Review.find().sort({ createdAt: -1 }); // Сортировка по убыванию даты
    res.json(reviews);
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ error: 'Fikrlarni yuklashda xato' });
  }
});


// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});