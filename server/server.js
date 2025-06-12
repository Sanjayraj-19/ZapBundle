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
  origin: ["https://sanjayraj-19.github.io", "http://localhost:5500"],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Set additional headers for CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});
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
      
    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 24); // Token valid for 24 hours
    
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
      verificationToken,
      verificationExpires: tokenExpiry
    };
    
    await usersCollection.insertOne(user);
    
    // Send verification email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER || 'zapbundle@gmail.com',
        pass: process.env.EMAIL_PASS || '' // You'll need to set this in your .env file
      },
      debug: true, // Enable debug output
      logger: true // Log information about the transport mechanism
    });
    
    // Build the verification URL for GitHub Pages with proper path joining
    let frontendUrl = process.env.FRONTEND_URL || 'https://sanjayraj-19.github.io/FrontEndZapBundle';
    
    // Ensure URL doesn't end with a slash before adding path
    if (frontendUrl.endsWith('/')) {
      frontendUrl = frontendUrl.slice(0, -1);
    }
    
    // SUPER SIMPLIFIED: Use the simplest possible URL with the simple verify page
    const verificationUrl = `${frontendUrl}/verify-simple.html?token=${verificationToken}`;
    
    // Log for debugging
    console.log('Generated verification URL:', verificationUrl);
    
    // Verify the connection configuration
    try {
      await transporter.verify();
      console.log('SMTP connection verified successfully');
    } catch (error) {
      console.error('SMTP connection error:', error);
      // Fall back to console log if email sending fails
      console.log('Verification token for', email, ':', verificationToken);
      console.log('Verification URL:', verificationUrl);
    }
    
    const mailOptions = {
      from: `"SaaSBundilo" <zapbundle@gmail.com>`,
      to: email,
      subject: '🚀 One Last Step to Unlock SaaS Savings!',
      html: `
        <div style="font-family: 'Poppins', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 0; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); background-color: #ffffff;">
          <!-- Header with gradient background -->
          <div style="background: linear-gradient(135deg, #6366f1 0%, #06b6d4 100%); padding: 40px 20px; text-align: center;">
            <img src="https://saasbundilo.com/logo.png" alt="SaaSBundilo" style="width: 80px; height: 80px; border-radius: 16px; background: white; padding: 10px; margin-bottom: 20px; box-shadow: 0 8px 15px rgba(0, 0, 0, 0.2);">
            <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 700;">Verify Your Email</h1>
            <p style="color: rgba(255, 255, 255, 0.9); font-size: 16px; margin-top: 10px;">You're just one click away from saving on SaaS!</p>
          </div>
          
          <!-- Content area -->
          <div style="padding: 40px 30px;">
            <h2 style="color: #1e293b; font-size: 22px; margin-top: 0;">Hello ${name || 'there'}! 👋</h2>
            
            <p style="color: #475569; font-size: 16px; line-height: 1.6; margin-bottom: 25px;">
              Thanks for joining SaaSBundilo! We're excited to help you discover and save on premium SaaS subscriptions.
            </p>
            
            <div style="background-color: #f8fafc; border-left: 4px solid #6366f1; padding: 20px; margin-bottom: 25px; border-radius: 6px;">
              <p style="color: #1e293b; font-size: 16px; margin: 0 0 15px 0; font-weight: 600;">Why verify?</p>
              <ul style="color: #475569; padding-left: 20px; margin: 0;">
                <li style="margin-bottom: 8px;">Unlock exclusive SaaS bundle deals</li>
                <li style="margin-bottom: 8px;">Save up to 40% on your subscriptions</li>
                <li style="margin-bottom: 8px;">Get personalized recommendations</li>
                <li>Manage all your SaaS tools in one place</li>
              </ul>
            </div>
            
            <!-- CTA Button -->
            <div style="text-align: center; margin: 35px 0;">
              <a href="${verificationUrl}" style="display: inline-block; background: linear-gradient(135deg, #6366f1 0%, #06b6d4 100%); color: white; padding: 16px 30px; text-decoration: none; border-radius: 50px; font-weight: 600; font-size: 18px; box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3); transition: all 0.3s;">
                Verify My Email Now
              </a>
            </div>
            
            <p style="color: #64748b; font-size: 14px; line-height: 1.6; margin-top: 30px;">
              This verification link will expire in 24 hours. If you didn't sign up for SaaSBundilo, you can safely ignore this email.
            </p>
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
      console.log('Verification email sent to:', email);
      res.status(201).json({ message: 'Registration initiated. Please check your email to verify your account.' });
    } catch (emailError) {
      console.error('Failed to send verification email:', emailError);
      
      // Create a verification link anyway so user can still verify
      console.log('Verification URL for manual verification:', verificationUrl);
      
      // Return success but mention potential email delivery issues
      res.status(201).json({ 
        message: 'Account created, but there was an issue sending the verification email. Please try again later or contact support.',
        token: verificationToken // Only in development - remove in production
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

// Email verification endpoint
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
      email: user.email  // Include the email to help with multi-device verification
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed. Please try again later." });
  }
});

// Google OAuth routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login-failed' }),
  async (req, res) => {
    // Issue JWT and redirect to frontend with token
    const token = jwt.sign({ userId: req.user._id, email: req.user.email }, JWT_SECRET, { expiresIn: '7d' });
    const frontendUrl = process.env.FRONTEND_URL || 'https://sanjayraj-19.github.io/FrontEndZapBundle';
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

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});