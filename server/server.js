import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { MongoClient, ObjectId } from 'mongodb';
import nodemailer from 'nodemailer';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// MongoDB setup
const client = new MongoClient(process.env.MONGODB_URI);
let usersCollection;

async function connectDB() {
  await client.connect();
  const db = client.db('saaslink');
  usersCollection = db.collection('users');
  console.log('Connected to MongoDB');
}
connectDB().catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Middleware
app.use(cors({
  origin: "https://sanjayraj-19.github.io",
  credentials: true
}));
app.use(express.json());

// JWT middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Session middleware (needed for Passport)
app.use(session({
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set to true if using HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());

// Serialize/deserialize user (minimal, just for OAuth flow)
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.OAUTH_CALLBACK_URL + "/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  // Find or create user in DB
  let user = await usersCollection.findOne({ email: profile.emails[0].value });
  if (!user) {
    user = {
      email: profile.emails[0].value,
      name: profile.displayName,
      profilePic: profile.photos[0]?.value,
      createdAt: new Date(),
      oauthProvider: 'google'
    };
    await usersCollection.insertOne(user);
  }
  return done(null, user);
}));

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required.' });

    const existing = await usersCollection.findOne({ email });
    if (existing)
      return res.status(409).json({ error: 'Email already registered.' });

    const hashed = await bcrypt.hash(password, 12);
    const user = { email, password: hashed, name: name || "", createdAt: new Date() };
    await usersCollection.insertOne(user);

    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed.' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required.' });

    const user = await usersCollection.findOne({ email });
    if (!user)
      return res.status(401).json({ error: 'Invalid credentials.' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(401).json({ error: 'Invalid credentials.' });

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Login failed.' });
  }
});

// Get profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({
      email: user.email,
      name: user.name || "",
      profilePic: user.profilePic || "",
      selectedBundle: user.selectedBundle || null,
      customBundle: user.customBundle || [],
      createdAt: user.createdAt,
      modifiedAt: user.modifiedAt
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Update profile (optional, for profile editing)
app.put('/api/profile', authenticateToken, async (req, res) => {
  const updates = { ...req.body, modifiedAt: new Date() };
  await usersCollection.updateOne(
    { _id: new ObjectId(req.user.userId) },
    { $set: updates }
  );
  res.json({ message: "Profile updated" });
});

// Survey submission endpoint
app.post('/api/survey', authenticateToken, async (req, res) => {
  try {
    const survey = req.body;
    const db = client.db('saaslink');
    await db.collection('surveys').insertOne({ ...survey, userId: req.user.userId, submittedAt: new Date() });

    // Mark user as having completed the survey
    await usersCollection.updateOne(
      { _id: new ObjectId(req.user.userId) },
      { $set: { surveyCompleted: true } }
    );

    // Send email to zapbundle@gmail.com
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const mailOptions = {
      from: `"ZapBundle Survey" <${process.env.EMAIL_USER}>`,
      to: 'zapbundle@gmail.com',
      subject: `New Survey Submission from ${survey.company_name || survey.email}`,
      html: `
        <h2>New Survey Submission</h2>
        <b>Company Name:</b> ${survey.company_name || '-'}<br>
        <b>Email:</b> ${survey.email}<br>
        <b>Company Type:</b> ${survey.company_type}<br>
        <b>Number of SaaS Tools:</b> ${survey.saas_count}<br>
        <b>Types of SaaS Tools:</b> ${[...(survey.saas_types || []), survey.saas_types_other].filter(Boolean).join(', ')}<br>
        <b>Monthly Spend:</b> ${survey.monthly_spend}<br>
        <b>Biggest Challenge:</b> ${survey.challenge || survey.challenge_other}<br>
        <b>Interested in Bundles:</b> ${survey.interest_bundles}<br>
        <b>Early Access:</b> ${survey.early_access}<br>
        <br>
        <i>Submitted at: ${new Date().toLocaleString()}</i>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: "Survey submitted and emailed!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Survey submission failed." });
  }
});

// Check email availability
app.get('/api/check-email', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.json({ available: false });
  const existing = await usersCollection.findOne({ email });
  res.json({ available: !existing });
});

// Google OAuth routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login-failed' }),
  async (req, res) => {
    // Issue JWT and redirect to frontend with token
    const token = jwt.sign({ userId: req.user._id, email: req.user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`https://sanjayraj-19.github.io/FrontEndZapBundle/oauth-success.html?token=${token}`);
  }
);

// Optional: login failed route
app.get('/login-failed', (req, res) => {
  res.send('Login failed. Please try again.');
});

// Health check
app.get('/', (req, res) => {
  res.send('SaaSLink backend is running.');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});