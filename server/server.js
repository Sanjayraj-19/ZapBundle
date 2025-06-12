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
import crypto from 'crypto';
import validator from 'email-validator';

// Helper function to generate a 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper function to hash OTP for secure storage
async function hashOTP(otp) {
  return await bcrypt.hash(otp, 8); // Using fewer rounds for OTP as it's temporary
}

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// MongoDB setup
const client = new MongoClient(process.env.MONGODB_URI);
let usersCollection;

async function connectDB() {
  try {
    await client.connect();
    const db = client.db('saaslink');
    usersCollection = db.collection('users');
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    // Don't exit the process, just log the error
    console.log('Server will continue without MongoDB connection');
  }
}
connectDB();

// Middleware - Enhanced CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'https://sanjayraj-19.github.io',
      'https://sanjayraj-19.github.io/ZapBundle',
      'http://localhost:5500',
      'http://127.0.0.1:5500',
      'http://localhost:3000',
      'http://127.0.0.1:3000'
    ];
    
    // Check if the origin is in the allowed list or contains sanjayraj-19.github.io
    if (allowedOrigins.includes(origin) || origin.includes('sanjayraj-19.github.io')) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['Content-Length', 'X-Foo', 'X-Bar'],
  maxAge: 86400 // 24 hours
}));

// Additional CORS headers middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Log all requests for debugging
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url} from origin: ${origin || 'no-origin'}`);
  
  // Set CORS headers explicitly
  if (origin && (origin.includes('sanjayraj-19.github.io') || origin.includes('localhost') || origin.includes('127.0.0.1'))) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Max-Age', '86400');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    console.log('Handling OPTIONS preflight request from:', origin);
    return res.status(200).end();
  }
  
  next();
});
app.use(express.json());

// Test endpoint for debugging CORS
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'API is working', 
    timestamp: new Date().toISOString(),
    origin: req.headers.origin || 'no-origin',
    method: req.method,
    headers: req.headers
  });
});

// CORS test endpoint
app.get('/api/cors-test', (req, res) => {
  res.json({ 
    message: 'CORS is working correctly',
    origin: req.headers.origin,
    timestamp: new Date().toISOString()
  });
});

// Simple test endpoint without dependencies
app.get('/test', (req, res) => {
  res.send('Simple test working');
});

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
    // Generate default profile picture if Google doesn't provide one
    let profilePic = profile.photos[0]?.value;
    
    if (!profilePic) {
      // Use a letter avatar with user's initial
      const initial = profile.displayName.charAt(0).toUpperCase();
      const colors = ['#4f46e5', '#06b6d4', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6', '#ef4444', '#14b8a6'];
      const randomColor = colors[Math.floor(Math.random() * colors.length)];
      
      // Create SVG letter avatar
      profilePic = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' fill='${randomColor.replace('#', '%23')}'/%3E%3Ctext x='50' y='50' font-family='Arial' font-size='50' font-weight='bold' fill='white' text-anchor='middle' dominant-baseline='central'%3E${initial}%3C/text%3E%3C/svg%3E`;
    }
    
    user = {
      email: profile.emails[0].value,
      name: profile.displayName,
      profilePic: profilePic,
      createdAt: new Date(),
      verified: true, // Google OAuth users are automatically verified
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
      
    // Validate email format
    if (!validator.validate(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    
    // Check for disposable/temporary email domains
    const disposableDomains = [
      'mailinator.com', 'tempmail.com', 'temp-mail.org', 'guerrillamail.com',
      'throwawaymail.com', '10minutemail.com', 'yopmail.com', 'mailnesia.com',
      'fakeinbox.com', 'sharklasers.com', 'guerrillamail.info', 'mailexpire.com',
      'maildrop.cc', 'dispostable.com', 'mintemail.com', 'temp-mail.ru',
      'getnada.com', 'tempmailo.com', 'emailna.co', 'emailondeck.com',
      'mohmal.com', 'tempr.email', 'tempmail.de', 'generator.email'
    ];
    
    const emailDomain = email.split('@')[1];
    if (disposableDomains.includes(emailDomain.toLowerCase())) {
      return res.status(400).json({ error: 'Please use a permanent email address. Temporary emails are not allowed.' });
    }

    const existing = await usersCollection.findOne({ email });
    if (existing)
      return res.status(409).json({ error: 'Email already registered.' });
      
    // Generate OTP for email verification
    const otp = generateOTP();
    const hashedOTP = await hashOTP(otp);
    
    // Set OTP expiration (10 minutes)
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 10);
    
    // Generate default profile picture
    let profilePic = '';
    
    // Option 1: Letter avatar with user's initial
    const initial = (name || email).charAt(0).toUpperCase();
    const colors = ['#4f46e5', '#06b6d4', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6', '#ef4444', '#14b8a6'];
    const randomColor = colors[Math.floor(Math.random() * colors.length)];
    
    // Create SVG letter avatar
    profilePic = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' fill='${randomColor.replace('#', '%23')}'/%3E%3Ctext x='50' y='50' font-family='Arial' font-size='50' font-weight='bold' fill='white' text-anchor='middle' dominant-baseline='central'%3E${initial}%3C/text%3E%3C/svg%3E`;
    
    // Save user with verification pending status and default profile picture
    const hashed = await bcrypt.hash(password, 12);
    const user = { 
      email, 
      password: hashed, 
      name: name || "", 
      profilePic: profilePic,
      createdAt: new Date(),
      verified: false,
      verificationOTP: hashedOTP,
      verificationOTPExpires: otpExpiry,
      otpAttempts: 0, // Track failed attempts
      lastOTPSent: new Date() // Track when OTP was last sent for rate limiting
    };
    
    await usersCollection.insertOne(user);
    
    // Send verification email with OTP
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER || 'zapbundle@gmail.com',
        pass: process.env.EMAIL_PASS || '' // You'll need to set this in your .env file
      },
      debug: true, // Enable debug output
      logger: true // Log information about the transport mechanism
    });
    
    // Log for debugging
    console.log('Generated OTP for', email, ':', otp);
    
    // Verify the connection configuration
    try {
      await transporter.verify();
      console.log('SMTP connection verified successfully');
    } catch (error) {
      console.error('SMTP connection error:', error);
      // Fall back to console log if email sending fails
      console.log('Verification OTP for', email, ':', otp);
    }
    
    const mailOptions = {
      from: `"SaaSBundilo" <zapbundle@gmail.com>`,
      to: email,
      subject: '🔐 Your Verification Code for SaaSBundilo',
      html: `
        <div style="font-family: 'Poppins', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 0; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); background-color: #ffffff;">
          <!-- Header with gradient background -->
          <div style="background: linear-gradient(135deg, #6366f1 0%, #06b6d4 100%); padding: 40px 20px; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 700;">SaaSBundilo</h1>
            <h2 style="color: white; margin: 10px 0; font-size: 24px; font-weight: 700;">Verify Your Email</h2>
            <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; margin-top: 10px;">Enter the code below to verify your account</p>
          </div>
          
          <!-- Content area -->
          <div style="padding: 40px 30px;">
            <h2 style="color: #1e293b; font-size: 22px; margin-top: 0;">Hello ${name || 'there'}! 👋</h2>
            
            <p style="color: #475569; font-size: 16px; line-height: 1.6; margin-bottom: 25px;">
              Thanks for joining SaaSBundilo! We're excited to have you on board.
            </p>
            
            <div style="background-color: #f8fafc; border-left: 4px solid #6366f1; padding: 20px; margin-bottom: 25px; border-radius: 6px;">
              <p style="color: #1e293b; font-size: 16px; margin: 0 0 15px 0; font-weight: 600;">Why verify?</p>
              <ul style="color: #475569; padding-left: 20px; margin: 0;">
                <li style="margin-bottom: 8px;">Secure your account</li>
                <li style="margin-bottom: 8px;">Access all features</li>
                <li>Get started right away</li>
              </ul>
            </div>
            
            <!-- OTP Display -->
            <div style="text-align: center; margin: 35px 0;">
              <p style="color: #475569; font-size: 16px; margin-bottom: 15px;">Your verification code is:</p>
              <div style="font-size: 32px; letter-spacing: 5px; font-weight: bold; color: #1e293b; background-color: #f1f5f9; padding: 15px; border-radius: 10px; display: inline-block;">
                ${otp}
              </div>
              <p style="color: #64748b; font-size: 14px; margin-top: 15px;">
                This code will expire in 10 minutes.
              </p>
            </div>
            
            <p style="color: #64748b; font-size: 14px; line-height: 1.6; margin-top: 30px;">
              If you didn't sign up for SaaSBundilo, you can safely ignore this email.
            </p>
          </div>
          
          <!-- Footer -->
          <div style="background-color: #f1f5f9; padding: 30px; text-align: center; border-top: 1px solid #e2e8f0;">
            <p style="color: #64748b; font-size: 14px; margin: 0;">
              Need help? Reply to this email or contact us at <a href="mailto:support@saasbundilo.com" style="color: #6366f1; text-decoration: none;">support@saasbundilo.com</a>
            </p>
            <p style="color: #94a3b8; font-size: 12px; margin: 20px 0 0 0;">
              &copy; 2024 SaaSBundilo. All rights reserved.
            </p>
          </div>
        </div>
      `
    };
    
    try {
      await transporter.sendMail(mailOptions);
      console.log('Verification email with OTP sent to:', email);
      res.status(201).json({ 
        message: 'Registration initiated. Please check your email for the verification code.',
        email: email, // Return email to help with the verification flow
        redirectUrl: `${process.env.FRONTEND_URL || 'https://sanjayraj-19.github.io/ZapBundle'}/verify-otp.html?email=${encodeURIComponent(email)}`
      });
    } catch (emailError) {
      console.error('Failed to send verification email:', emailError);
      
      // Return success but mention potential email delivery issues
      res.status(201).json({ 
        message: 'Account created, but there was an issue sending the verification email. Please try again later or contact support.',
        email: email,
        otp: otp, // Only in development - remove in production
        redirectUrl: `${process.env.FRONTEND_URL || 'https://sanjayraj-19.github.io/ZapBundle'}/verify-otp.html?email=${encodeURIComponent(email)}`
      });
    }
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed: ' + err.message });
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
      
    // Check if user has verified their email
    if (user.verified === false) {
      return res.status(403).json({ error: 'Please verify your email before logging in.' });
    }

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
      selectedBundles: user.selectedBundles || [],
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
    const { answers, completedAt, isComplete } = req.body;
    const db = client.db('saaslink');
    
    // Get user info
    const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) });
    
    // Check if user already has a survey
    const existingSurvey = await db.collection('surveys').findOne({ 
      userId: req.user.userId 
    });
    
    const surveyData = {
      answers, 
      userId: req.user.userId, 
      userEmail: user.email,
      userName: user.name,
      isComplete: isComplete || false,
      lastUpdated: new Date(),
      completedAt: isComplete ? (completedAt || new Date()) : null
    };
    
    if (existingSurvey) {
      // Update existing survey
      await db.collection('surveys').updateOne(
        { userId: req.user.userId },
        { 
          $set: surveyData
        }
      );
    } else {
      // Create new survey
      surveyData.createdAt = new Date();
      await db.collection('surveys').insertOne(surveyData);
    }

    // Only mark user as completed if survey is actually complete
    console.log('📋 Survey submission - isComplete:', isComplete);
    console.log('📋 User ID:', req.user.userId);
    console.log('📋 Answers received:', Object.keys(answers));
    
    if (isComplete) {
      console.log('✅ Marking user as survey completed');
      await usersCollection.updateOne(
        { _id: new ObjectId(req.user.userId) },
        { $set: { surveyCompleted: true, surveyCompletedAt: new Date() } }
      );
      console.log('✅ User survey completion updated in database');
    } else {
      console.log('❌ Survey not complete, not updating user status');
    }

    // Format answers for email
    let answersHTML = '';
    Object.keys(answers).forEach(questionId => {
      const questionNum = parseInt(questionId);
      const surveyQuestions = [
        { id: 1, question: "What type of business do you run?" },
        { id: 2, question: "What's your monthly budget for SaaS tools?" },
        { id: 3, question: "Which categories of SaaS tools do you use most?" },
        { id: 4, question: "What's your biggest challenge with current SaaS subscriptions?" },
        { id: 5, question: "How did you hear about SaaSBundilo?" },
        { id: 6, question: "Any specific SaaS tools you'd like to see in our bundles?" }
      ];
      
      const question = surveyQuestions.find(q => q.id === questionNum);
      if (question && answers[questionId]) {
        const answer = Array.isArray(answers[questionId]) ? answers[questionId].join(', ') : answers[questionId];
        answersHTML += `<b>${question.question}</b><br>${answer}<br><br>`;
      }
    });

    // Send email to zapbundle@gmail.com
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const mailOptions = {
      from: `"SaaSBundilo Survey" <${process.env.EMAIL_USER}>`,
      to: 'zapbundle@gmail.com',
      subject: `New Survey Submission from ${user.name || user.email}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #6366f1;">New Survey Submission</h2>
          <hr>
          <p><b>User:</b> ${user.name || 'N/A'}</p>
          <p><b>Email:</b> ${user.email}</p>
          <p><b>Completed At:</b> ${new Date(completedAt || new Date()).toLocaleString()}</p>
          <hr>
          <h3>Survey Responses:</h3>
          ${answersHTML}
          <hr>
          <p style="color: #666; font-size: 12px;">
            <i>Submitted via SaaSBundilo Survey System at ${new Date().toLocaleString()}</i>
          </p>
        </div>
      `
    };

    try {
      await transporter.sendMail(mailOptions);
      console.log('Survey notification email sent successfully');
    } catch (emailError) {
      console.error('Failed to send survey notification email:', emailError);
      // Don't fail the request if email fails
    }

    res.json({ message: "Survey submitted successfully!", isComplete: isComplete });
  } catch (err) {
    console.error('Survey submission error:', err);
    res.status(500).json({ error: "Survey submission failed." });
  }
});

// Get user's survey data
app.get('/api/survey', authenticateToken, async (req, res) => {
  try {
    const db = client.db('saaslink');
    
    // Get user's existing survey
    const survey = await db.collection('surveys').findOne({ 
      userId: req.user.userId 
    });
    
    console.log('Survey data for user', req.user.userId, ':', survey);
    
    if (survey) {
      res.json({
        answers: survey.answers || {},
        isComplete: survey.isComplete || false,
        completedAt: survey.completedAt,
        lastUpdated: survey.lastUpdated
      });
    } else {
      res.json({
        answers: {},
        isComplete: false,
        completedAt: null,
        lastUpdated: null
      });
    }
  } catch (err) {
    console.error('Get survey error:', err);
    res.status(500).json({ error: "Failed to get survey data." });
  }
});

// Reset survey data (for debugging)
app.delete('/api/survey/reset', authenticateToken, async (req, res) => {
  try {
    const db = client.db('saaslink');
    
    // Delete user's survey
    await db.collection('surveys').deleteOne({ 
      userId: req.user.userId 
    });
    
    // Reset user's survey completion status
    await usersCollection.updateOne(
      { _id: new ObjectId(req.user.userId) },
      { 
        $unset: { 
          surveyCompleted: "",
          surveyCompletedAt: ""
        }
      }
    );
    
    res.json({ message: "Survey data reset successfully" });
  } catch (err) {
    console.error('Reset survey error:', err);
    res.status(500).json({ error: "Failed to reset survey data." });
  }
});

// Check email availability
app.get('/api/check-email', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.json({ available: false });
  const existing = await usersCollection.findOne({ email });
  res.json({ available: !existing });
});

// Email verification with OTP
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ error: "Email and verification code required" });
    }
    
    // Find user with matching email
    const user = await usersCollection.findOne({ 
      email,
      verified: false,
      verificationOTPExpires: { $gt: new Date() } // OTP must not be expired
    });
    
    if (!user) {
      return res.status(400).json({ error: "Invalid email or expired verification code" });
    }
    
    // Check if max attempts exceeded (5 attempts)
    if (user.otpAttempts >= 5) {
      return res.status(400).json({ 
        error: "Too many failed attempts. Please request a new verification code.",
        maxAttemptsReached: true
      });
    }
    
    // Verify OTP
    const isValidOTP = await bcrypt.compare(otp, user.verificationOTP);
    
    if (!isValidOTP) {
      // Increment failed attempts
      await usersCollection.updateOne(
        { _id: user._id },
        { $inc: { otpAttempts: 1 } }
      );
      
      return res.status(400).json({ 
        error: "Invalid verification code",
        attemptsLeft: 5 - (user.otpAttempts + 1)
      });
    }
    
    // Update user to verified status
    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { verified: true },
        $unset: { 
          verificationOTP: "", 
          verificationOTPExpires: "",
          otpAttempts: ""
        }
      }
    );
    
    // Send welcome email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER || 'zapbundle@gmail.com',
        pass: process.env.EMAIL_PASS || '' // You'll need to set this in your .env file
      },
      debug: true,
      logger: true
    });
    
    // Verify the connection configuration
    try {
      await transporter.verify();
      console.log('SMTP connection verified successfully for welcome email');
    } catch (error) {
      console.error('SMTP connection error for welcome email:', error);
    }
    
    const mailOptions = {
      from: `"SaaSBundilo" <zapbundle@gmail.com>`,
      to: user.email,
      subject: '🎉 Welcome to SaaSBundilo - Your SaaS Journey Begins!',
      html: `
        <div style="font-family: 'Poppins', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 0; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); background-color: #ffffff;">
          <!-- Header with confetti background -->
          <div style="background: linear-gradient(135deg, #6366f1 0%, #ec4899 100%); padding: 40px 20px; text-align: center; position: relative; overflow: hidden;">
            <!-- Confetti elements (SVG pattern) -->
            <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.2; background-image: url('data:image/svg+xml;utf8,<svg width=\"60\" height=\"60\" viewBox=\"0 0 60 60\" xmlns=\"http://www.w3.org/2000/svg\"><g fill=\"none\" fill-rule=\"evenodd\"><g fill=\"%23ffffff\" fill-opacity=\"0.8\"><path d=\"M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z\"/></g></g></svg>');"></div>
            <img src="https://saasbundilo.com/logo.png" alt="SaaSBundilo" style="width: 90px; height: 90px; border-radius: 16px; background: white; padding: 10px; margin-bottom: 20px; box-shadow: 0 8px 15px rgba(0, 0, 0, 0.2); position: relative; z-index: 2;">
            <h1 style="color: white; margin: 0; font-size: 32px; font-weight: 700; position: relative; z-index: 2;">Welcome to SaaSBundilo!</h1>
            <p style="color: rgba(255, 255, 255, 0.9); font-size: 18px; margin-top: 10px; position: relative; z-index: 2;">Your email is verified and your account is ready!</p>
          </div>
          
          <!-- Content area -->
          <div style="padding: 40px 30px;">
            <h2 style="color: #1e293b; font-size: 24px; margin-top: 0;">Hello ${user.name || 'there'}! 🎉</h2>
            
            <p style="color: #475569; font-size: 16px; line-height: 1.6; margin-bottom: 25px;">
              Thank you for joining the SaaSBundilo community! We're excited to help you discover and save on premium SaaS subscriptions. Your account has been successfully activated.
            </p>
            
            <div style="background-color: #f0f9ff; border-radius: 12px; padding: 25px; margin-bottom: 30px;">
              <h3 style="color: #0c4a6e; margin-top: 0; font-size: 18px;">What you can do now:</h3>
              <ul style="color: #0e7490; padding-left: 25px; margin-bottom: 0;">
                <li style="margin-bottom: 12px; padding-left: 5px;">
                  <span style="font-weight: 600;">Explore Bundles:</span> Browse our curated SaaS bundles with up to 40% discounts
                </li>
                <li style="margin-bottom: 12px; padding-left: 5px;">
                  <span style="font-weight: 600;">Get Recommendations:</span> Receive personalized SaaS suggestions for your business
                </li>
                <li style="margin-bottom: 12px; padding-left: 5px;">
                  <span style="font-weight: 600;">Manage Subscriptions:</span> Track all your SaaS tools in one dashboard
                </li>
                <li style="padding-left: 5px;">
                  <span style="font-weight: 600;">Save Money:</span> Consolidate your tech stack and reduce costs
                </li>
              </ul>
            </div>
            
            <!-- Featured Bundles Preview -->
            <div style="margin-bottom: 35px;">
              <h3 style="color: #1e293b; font-size: 20px; margin-bottom: 15px;">Popular Bundles You Might Like:</h3>
              <div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 15px;">
                <div style="flex: 1; min-width: 150px; background: linear-gradient(145deg, #f8fafc, #e2e8f0); padding: 15px; border-radius: 10px; text-align: center;">
                  <div style="font-weight: 600; color: #0f172a; margin-bottom: 5px;">Marketing Suite</div>
                  <div style="color: #64748b; font-size: 13px;">5 premium tools</div>
                  <div style="color: #10b981; font-weight: 700; margin-top: 5px;">Save 35%</div>
                </div>
                <div style="flex: 1; min-width: 150px; background: linear-gradient(145deg, #f8fafc, #e2e8f0); padding: 15px; border-radius: 10px; text-align: center;">
                  <div style="font-weight: 600; color: #0f172a; margin-bottom: 5px;">Dev Toolkit</div>
                  <div style="color: #64748b; font-size: 13px;">7 premium tools</div>
                  <div style="color: #10b981; font-weight: 700; margin-top: 5px;">Save 42%</div>
                </div>
              </div>
            </div>
            
            <!-- CTA Button -->
            <div style="text-align: center; margin: 35px 0;">
              <a href="${process.env.FRONTEND_URL || 'http://localhost:5500'}/index.html" style="display: inline-block; background: linear-gradient(135deg, #6366f1 0%, #ec4899 100%); color: white; padding: 16px 40px; text-decoration: none; border-radius: 50px; font-weight: 600; font-size: 18px; box-shadow: 0 4px 15px rgba(236, 72, 153, 0.25); transition: all 0.3s;">
                Explore SaaS Bundles
              </a>
            </div>
          </div>
          
          <!-- Footer -->
          <div style="background-color: #f1f5f9; padding: 30px; text-align: center; border-top: 1px solid #e2e8f0;">
            <p style="color: #64748b; font-size: 14px; margin: 0 0 10px 0;">
              Need help? Reply to this email or contact us at <a href="mailto:support@saasbundilo.com" style="color: #6366f1; text-decoration: none;">support@saasbundilo.com</a>
            </p>
            <div style="margin: 20px 0;">
              <a href="https://twitter.com/saasbundilo" style="display: inline-block; margin: 0 10px;"><img src="https://saasbundilo.com/twitter.png" alt="Twitter" style="width: 24px; height: 24px;"></a>
              <a href="https://linkedin.com/company/saasbundilo" style="display: inline-block; margin: 0 10px;"><img src="https://saasbundilo.com/linkedin.png" alt="LinkedIn" style="width: 24px; height: 24px;"></a>
              <a href="https://facebook.com/saasbundilo" style="display: inline-block; margin: 0 10px;"><img src="https://saasbundilo.com/facebook.png" alt="Facebook" style="width: 24px; height: 24px;"></a>
            </div>
            <p style="color: #94a3b8; font-size: 12px; margin: 20px 0 0 0;">
              &copy; 2025 SaaSBundilo. All rights reserved.<br>
              123 SaaS Street, San Francisco, CA 94103
            </p>
          </div>
        </div>
      `
    };
    
    try {
      await transporter.sendMail(mailOptions);
      console.log('Welcome email sent to:', user.email);
    } catch (emailError) {
      console.error('Failed to send welcome email:', emailError);
      // Continue with verification even if welcome email fails
    }
    
    // Generate a login token for the user so they're automatically logged in
    const authToken = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({ 
      success: true, 
      message: "Email verified successfully. You are now logged in.",
      token: authToken,
      email: user.email
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed. Please try again later." });
  }
});

// Resend OTP for email verification
app.post('/api/resend-verification-otp', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }
    
    // Find user with matching email
    const user = await usersCollection.findOne({ 
      email,
      verified: false
    });
    
    if (!user) {
      return res.status(404).json({ error: "User not found or already verified" });
    }
    
    // Check for rate limiting (at least 60 seconds between OTP requests)
    const lastOTPTime = user.lastOTPSent || new Date(0);
    const timeSinceLastOTP = new Date() - lastOTPTime;
    const cooldownPeriod = 60 * 1000; // 60 seconds in milliseconds
    
    if (timeSinceLastOTP < cooldownPeriod) {
      const timeRemaining = Math.ceil((cooldownPeriod - timeSinceLastOTP) / 1000);
      return res.status(429).json({ 
        error: `Please wait ${timeRemaining} seconds before requesting a new code`,
        cooldownSeconds: timeRemaining
      });
    }
    
    // Generate new OTP
    const otp = generateOTP();
    const hashedOTP = await hashOTP(otp);
    
    // Set OTP expiration (10 minutes)
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 10);
    
    // Update user with new OTP
    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { 
          verificationOTP: hashedOTP,
          verificationOTPExpires: otpExpiry,
          lastOTPSent: new Date(),
          otpAttempts: 0 // Reset attempts counter
        }
      }
    );
    
    // Send verification email with OTP
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER || 'zapbundle@gmail.com',
        pass: process.env.EMAIL_PASS || ''
      },
      debug: true,
      logger: true
    });
    
    // Log for debugging
    console.log('Generated new OTP for', email, ':', otp);
    
    const mailOptions = {
      from: `"SaaSBundilo" <zapbundle@gmail.com>`,
      to: email,
      subject: '🔐 Your New Verification Code for SaaSBundilo',
      html: `
        <div style="font-family: 'Poppins', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 0; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); background-color: #ffffff;">
          <!-- Header with gradient background -->
          <div style="background: linear-gradient(135deg, #6366f1 0%, #06b6d4 100%); padding: 40px 20px; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 700;">SaaSBundilo</h1>
            <h2 style="color: white; margin: 10px 0; font-size: 24px; font-weight: 700;">New Verification Code</h2>
            <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; margin-top: 10px;">Enter the code below to verify your account</p>
          </div>
          
          <!-- Content area -->
          <div style="padding: 40px 30px;">
            <h2 style="color: #1e293b; font-size: 22px; margin-top: 0;">Hello ${user.name || 'there'}! 👋</h2>
            
            <p style="color: #475569; font-size: 16px; line-height: 1.6; margin-bottom: 25px;">
              You requested a new verification code. Here it is:
            </p>
            
            <!-- OTP Display -->
            <div style="text-align: center; margin: 35px 0;">
              <p style="color: #475569; font-size: 16px; margin-bottom: 15px;">Your new verification code is:</p>
              <div style="font-size: 32px; letter-spacing: 5px; font-weight: bold; color: #1e293b; background-color: #f1f5f9; padding: 15px; border-radius: 10px; display: inline-block;">
                ${otp}
              </div>
              <p style="color: #64748b; font-size: 14px; margin-top: 15px;">
                This code will expire in 10 minutes.
              </p>
            </div>
            
            <p style="color: #64748b; font-size: 14px; line-height: 1.6; margin-top: 30px;">
              If you didn't request this code, you can safely ignore this email.
            </p>
          </div>
          
          <!-- Footer -->
          <div style="background-color: #f1f5f9; padding: 30px; text-align: center; border-top: 1px solid #e2e8f0;">
            <p style="color: #64748b; font-size: 14px; margin: 0;">
              Need help? Reply to this email or contact us at <a href="mailto:support@saasbundilo.com" style="color: #6366f1; text-decoration: none;">support@saasbundilo.com</a>
            </p>
            <p style="color: #94a3b8; font-size: 12px; margin: 20px 0 0 0;">
              &copy; 2024 SaaSBundilo. All rights reserved.
            </p>
          </div>
        </div>
      `
    };
    
    try {
      await transporter.sendMail(mailOptions);
      console.log('New verification email with OTP sent to:', email);
      res.status(200).json({ 
        message: 'New verification code sent. Please check your email.',
        email: email
      });
    } catch (emailError) {
      console.error('Failed to send verification email:', emailError);
      
      // Return success but mention potential email delivery issues
      res.status(200).json({ 
        message: 'New verification code generated, but there was an issue sending the email. Please try again later.',
        email: email,
        otp: otp // Only in development - remove in production
      });
    }
  } catch (err) {
    console.error('Resend OTP error:', err);
    res.status(500).json({ error: 'Failed to resend verification code. Please try again later.' });
  }
});

// Legacy email verification endpoint (keep for backward compatibility)
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: "Verification token required" });
    
    // Find user with matching token
    const user = await usersCollection.findOne({ 
      verificationToken: token,
      verificationExpires: { $gt: new Date() } // Token must not be expired
    });
    
    if (!user) {
      return res.status(400).json({ error: "Invalid or expired verification token" });
    }
    
    // Update user to verified status
    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { verified: true },
        $unset: { verificationToken: "", verificationExpires: "" }
      }
    );
    
    // Generate a login token for the user so they're automatically logged in
    const authToken = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({ 
      success: true, 
      message: "Email verified successfully. You are now logged in.",
      token: authToken,
      email: user.email
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed. Please try again later." });
  }
});

// Forgot password - request OTP
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }
    
    // Find user with matching email
    const user = await usersCollection.findOne({ email });
    
    if (!user) {
      // For security reasons, don't reveal if the email exists or not
      return res.status(200).json({ 
        message: "If your email is registered, you will receive a password reset code."
      });
    }
    
    // Check for rate limiting (at least 60 seconds between OTP requests)
    const lastOTPTime = user.passwordResetLastSent || new Date(0);
    const timeSinceLastOTP = new Date() - lastOTPTime;
    const cooldownPeriod = 60 * 1000; // 60 seconds in milliseconds
    
    if (timeSinceLastOTP < cooldownPeriod) {
      const timeRemaining = Math.ceil((cooldownPeriod - timeSinceLastOTP) / 1000);
      return res.status(429).json({ 
        error: `Please wait ${timeRemaining} seconds before requesting a new code`,
        cooldownSeconds: timeRemaining
      });
    }
    
    // Generate OTP for password reset
    const otp = generateOTP();
    const hashedOTP = await hashOTP(otp);
    
    // Set OTP expiration (10 minutes)
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 10);
    
    // Update user with password reset OTP
    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { 
          passwordResetOTP: hashedOTP,
          passwordResetOTPExpires: otpExpiry,
          passwordResetLastSent: new Date(),
          passwordResetAttempts: 0 // Reset attempts counter
        }
      }
    );
    
    // Send password reset email with OTP
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER || 'zapbundle@gmail.com',
        pass: process.env.EMAIL_PASS || ''
      },
      debug: true,
      logger: true
    });
    
    // Log for debugging
    console.log('Generated password reset OTP for', email, ':', otp);
    
    const mailOptions = {
      from: `"SaaSBundilo" <zapbundle@gmail.com>`,
      to: email,
      subject: '🔐 Reset Your Password - SaaSBundilo',
      html: `
        <div style="font-family: 'Poppins', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 0; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); background-color: #ffffff;">
          <!-- Header with gradient background -->
          <div style="background: linear-gradient(135deg, #6366f1 0%, #06b6d4 100%); padding: 40px 20px; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 700;">SaaSBundilo</h1>
            <h2 style="color: white; margin: 10px 0; font-size: 24px; font-weight: 700;">Password Reset</h2>
            <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; margin-top: 10px;">Enter the code below to reset your password</p>
          </div>
          
          <!-- Content area -->
          <div style="padding: 40px 30px;">
            <h2 style="color: #1e293b; font-size: 22px; margin-top: 0;">Hello ${user.name || 'there'}! 👋</h2>
            
            <p style="color: #475569; font-size: 16px; line-height: 1.6; margin-bottom: 25px;">
              We received a request to reset your password. If you didn't make this request, you can safely ignore this email.
            </p>
            
            <!-- OTP Display -->
            <div style="text-align: center; margin: 35px 0;">
              <p style="color: #475569; font-size: 16px; margin-bottom: 15px;">Your password reset code is:</p>
              <div style="font-size: 32px; letter-spacing: 5px; font-weight: bold; color: #1e293b; background-color: #f1f5f9; padding: 15px; border-radius: 10px; display: inline-block;">
                ${otp}
              </div>
              <p style="color: #64748b; font-size: 14px; margin-top: 15px;">
                This code will expire in 10 minutes.
              </p>
            </div>
            
            <p style="color: #64748b; font-size: 14px; line-height: 1.6; margin-top: 30px;">
              If you didn't request a password reset, please secure your account by changing your password.
            </p>
          </div>
          
          <!-- Footer -->
          <div style="background-color: #f1f5f9; padding: 30px; text-align: center; border-top: 1px solid #e2e8f0;">
            <p style="color: #64748b; font-size: 14px; margin: 0;">
              Need help? Reply to this email or contact us at <a href="mailto:support@saasbundilo.com" style="color: #6366f1; text-decoration: none;">support@saasbundilo.com</a>
            </p>
            <p style="color: #94a3b8; font-size: 12px; margin: 20px 0 0 0;">
              &copy; 2024 SaaSBundilo. All rights reserved.
            </p>
          </div>
        </div>
      `
    };
    
    try {
      await transporter.sendMail(mailOptions);
      console.log('Password reset email with OTP sent to:', email);
    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
      // Continue anyway for security reasons
    }
    
    // For security reasons, always return the same response
    res.status(200).json({ 
      message: "If your email is registered, you will receive a password reset code."
    });
  } catch (err) {
    console.error('Password reset request error:', err);
    res.status(500).json({ error: 'Failed to process password reset request. Please try again later.' });
  }
});

// Verify password reset OTP
app.post('/api/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ error: "Email and verification code required" });
    }
    
    // Find user with matching email
    const user = await usersCollection.findOne({ 
      email,
      passwordResetOTPExpires: { $gt: new Date() } // OTP must not be expired
    });
    
    if (!user) {
      return res.status(400).json({ error: "Invalid email or expired verification code" });
    }
    
    // Check if max attempts exceeded (5 attempts)
    if (user.passwordResetAttempts >= 5) {
      return res.status(400).json({ 
        error: "Too many failed attempts. Please request a new verification code.",
        maxAttemptsReached: true
      });
    }
    
    // Verify OTP
    const isValidOTP = await bcrypt.compare(otp, user.passwordResetOTP);
    
    if (!isValidOTP) {
      // Increment failed attempts
      await usersCollection.updateOne(
        { _id: user._id },
        { $inc: { passwordResetAttempts: 1 } }
      );
      
      return res.status(400).json({ 
        error: "Invalid verification code",
        attemptsLeft: 5 - (user.passwordResetAttempts + 1)
      });
    }
    
    // Generate a temporary token for password reset
    const resetToken = jwt.sign(
      { userId: user._id, email: user.email, purpose: 'password-reset' },
      JWT_SECRET,
      { expiresIn: '10m' } // Token valid for 10 minutes
    );
    
    res.json({ 
      success: true, 
      message: "Verification successful. You can now reset your password.",
      resetToken,
      email: user.email
    });
  } catch (err) {
    console.error('OTP verification error:', err);
    res.status(500).json({ error: "Verification failed. Please try again later." });
  }
});

// Reset password with token
app.post('/api/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    
    if (!resetToken || !newPassword) {
      return res.status(400).json({ error: "Reset token and new password required" });
    }
    
    // Verify the reset token
    let decoded;
    try {
      decoded = jwt.verify(resetToken, JWT_SECRET);
      
      // Check if token was issued for password reset
      if (decoded.purpose !== 'password-reset') {
        return res.status(400).json({ error: "Invalid reset token" });
      }
    } catch (tokenError) {
      return res.status(400).json({ error: "Invalid or expired reset token" });
    }
    
    // Check password strength
    if (newPassword.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters long" });
    }
    
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    
    // Update user's password and remove reset OTP data
    await usersCollection.updateOne(
      { _id: new ObjectId(decoded.userId) },
      { 
        $set: { password: hashedPassword },
        $unset: { 
          passwordResetOTP: "", 
          passwordResetOTPExpires: "",
          passwordResetAttempts: "",
          passwordResetLastSent: ""
        }
      }
    );
    
    res.json({ 
      success: true, 
      message: "Password has been reset successfully. You can now log in with your new password."
    });
  } catch (err) {
    console.error('Password reset error:', err);
    res.status(500).json({ error: "Password reset failed. Please try again later." });
  }
});

// Google OAuth routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login-failed' }),
  async (req, res) => {
    // Issue JWT and redirect to frontend with token
    const token = jwt.sign({ userId: req.user._id, email: req.user.email }, JWT_SECRET, { expiresIn: '7d' });
    const frontendUrl = process.env.FRONTEND_URL || 'https://sanjayraj-19.github.io/ZapBundle';
    res.redirect(`${frontendUrl}/oauth-success.html?token=${token}`);
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

// Register bundle
app.post('/api/register-bundle', authenticateToken, async (req, res) => {
  const { bundle } = req.body;
  if (!bundle) return res.status(400).json({ error: "Bundle name required." });
  try {
    await usersCollection.updateOne(
      { _id: new ObjectId(req.user.userId) },
      { $addToSet: { selectedBundles: bundle } }
    );
    res.json({ message: "Bundle registered." });
  } catch (err) {
    res.status(500).json({ error: "Failed to register bundle." });
  }
});

// Remove bundle
app.post('/api/remove-bundle', authenticateToken, async (req, res) => {
  const { bundle } = req.body;
  if (!bundle) return res.status(400).json({ error: "Bundle name required." });
  try {
    await usersCollection.updateOne(
      { _id: new ObjectId(req.user.userId) },
      { $pull: { selectedBundles: bundle } }
    );
    res.json({ message: "Bundle removed." });
  } catch (err) {
    res.status(500).json({ error: "Failed to remove bundle." });
  }
});

// Get user's bundles (placeholder endpoint)
app.get('/api/bundles', authenticateToken, async (req, res) => {
  try {
    const db = client.db('saaslink');
    
    // Get user's bundles (for now, return empty array since bundles feature isn't implemented yet)
    // In the future, this would fetch actual bundles from a bundles collection
    const userBundles = [];
    
    // You can add actual bundle logic here later
    // const userBundles = await db.collection('bundles').find({ 
    //   userId: req.user.userId 
    // }).toArray();
    
    res.json(userBundles);
  } catch (err) {
    console.error('Get bundles error:', err);
    res.status(500).json({ error: "Failed to get bundles." });
  }
});

// Debug endpoint to check and fix survey status
app.post('/api/survey/check-status', authenticateToken, async (req, res) => {
  try {
    const db = client.db('saaslink');
    
    // Get user's survey data
    const survey = await db.collection('surveys').findOne({ 
      userId: req.user.userId 
    });
    
    // Get user profile
    const user = await usersCollection.findOne({ 
      _id: new ObjectId(req.user.userId) 
    });
    
    console.log('🔍 Debug - Survey data:', survey);
    console.log('🔍 Debug - User surveyCompleted:', user.surveyCompleted);
    
    if (survey && survey.isComplete && !user.surveyCompleted) {
      // Fix the mismatch - survey is complete but user not marked as completed
      console.log('🔧 Fixing survey completion status mismatch');
      await usersCollection.updateOne(
        { _id: new ObjectId(req.user.userId) },
        { $set: { surveyCompleted: true, surveyCompletedAt: new Date() } }
      );
      
      res.json({ 
        fixed: true, 
        message: 'Survey completion status fixed',
        surveyComplete: true
      });
    } else {
      res.json({ 
        fixed: false, 
        surveyExists: !!survey,
        surveyComplete: survey ? survey.isComplete : false,
        userMarkedComplete: user.surveyCompleted,
        message: 'No fix needed or survey not complete'
      });
    }
  } catch (err) {
    console.error('Survey status check error:', err);
    res.status(500).json({ error: "Failed to check survey status." });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});