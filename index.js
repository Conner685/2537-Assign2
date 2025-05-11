// index.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');
const User = require('./models/User');

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: process.env.SESSION_CODE,
  resave: false,
  saveUninitialized: false
}));

// Connect to MongoDB
const mongoURI = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@${process.env.MONGO_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;
mongoose.connect(mongoURI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware to protect routes
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.type !== 'admin') return res.status(403).render('403', { user: req.session.user });
  next();
}

// Routes

// Home
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Sign Up
app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

app.post('/signup', async (req, res) => {
  const schema = Joi.object({
    name: Joi.string().min(1).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    return res.render('signup', { error: "All fields are required and must be valid." });
  }

  const existingUser = await User.findOne({ email: value.email });
  if (existingUser) {
    return res.render('signup', { error: "Email already registered." });
  }

  const hashedPassword = await bcrypt.hash(value.password, 10);
  const newUser = new User({
    name: value.name,
    email: value.email,
    password: hashedPassword,
    type: 'user'
  });

  await newUser.save();
  req.session.user = { name: newUser.name, type: newUser.type, _id: newUser._id };
  res.redirect('/members');
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    return res.render('login', { error: 'Please enter a valid email and password.' });
  }

  const user = await User.findOne({ email: value.email });
  const validPassword = user && await bcrypt.compare(value.password, user.password);

  if (!user || !validPassword) {
    return res.render('login', { error: 'Email or password incorrect.' });
  }

  req.session.user = { name: user.name, type: user.type, _id: user._id };
  res.redirect('/members');
});


// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Members
app.get('/members', requireLogin, (req, res) => {
  const images = ['/images/Ugly_fish.jpg', '/images/Dotted_fish.webp', '/images/Surprise_Fish.png'];
  res.render('members', { user: req.session.user, images });
});

// Admin
app.get('/admin', requireAdmin, async (req, res) => {
  const users = await User.find().lean();
  res.render('admin', { user: req.session.user, users });
});

app.get('/admin/promote', requireAdmin, async (req, res) => {
  const schema = Joi.object({
    user: Joi.string().hex().length(24).required()
  });
  const { error } = schema.validate(req.query);
  if (error) return res.status(400).send("Invalid user ID");

  await User.updateOne({ _id: req.query.user }, { $set: { type: 'admin' } });
  res.redirect('/admin');
});

app.get('/admin/demote', requireAdmin, async (req, res) => {
  const schema = Joi.object({
    user: Joi.string().hex().length(24).required()
  });
  const { error } = schema.validate(req.query);
  if (error) return res.status(400).send("Invalid user ID");

  await User.updateOne({ _id: req.query.user }, { $set: { type: 'user' } });
  res.redirect('/admin');
});

// 403 Forbidden
app.get('/403', (req, res) => {
  res.status(403).render('403', { user: req.session.user });
});

// 404 Not Found
app.use((req, res) => {
  res.status(404).render('404', { user: req.session.user });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running on port ${PORT}`);
});
