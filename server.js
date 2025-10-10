const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const path = require('path');
require('dotenv').config();
const csrf = require('lusca').csrf;
const app = express();
const PORT = process.env.PORT || 9640;

// Trust proxy - always enable to work with rate limiting
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "data:", "blob:"],
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://api.josephhansen.dev', 'https://josephhansen.dev']
    : ['http://localhost:9640', 'http://127.0.0.1:9640'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Skip rate limiting in development if needed
  skip: process.env.NODE_ENV === 'development' ? () => false : undefined
});
app.use(limiter);

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-this',
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Don't use default session name
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict' // CSRF protection
  }
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Import routes
const mailRoutes = require('./routes/mail');
const imageRoutes = require('./routes/images');
const authRoutes = require('./routes/auth');
const passkeyRoutes = require('./routes/passkey');

// Public routes (no CSRF protection needed)
app.use('/api/mail', mailRoutes);

// CSRF protection middleware (applies to routes below)
// Skip CSRF for passkey authentication endpoints
app.use((req, res, next) => {
  // Skip CSRF for passkey auth endpoints (login flow)
  if (req.path.startsWith('/api/passkey/auth')) {
    return next();
  }
  
  // Apply CSRF protection
  csrf({
    header: 'x-csrf-token',
    cookie: '_csrf'
  })(req, res, next);
});

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
  res.json({ token: req.csrfToken() });
});

// Static file serving for uploads with security headers
app.use('/images', (req, res, next) => {
  // Add security headers for image serving
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'public, max-age=31536000', // 1 year cache
  });
  next();
}, express.static(path.join(__dirname, 'uploads')));
app.use('/admin', (req, res, next) => {
  // Add security headers for admin panel
  res.set({
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  });
  next();
}, express.static(path.join(__dirname, 'public')));

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'josephhansen.dev API Server',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Protected routes (CSRF protection applied)
app.use('/api/images', imageRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/passkey', passkeyRoutes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📧 Mail endpoint: http://localhost:${PORT}/api/mail/send`);
  console.log(`🖼️  Images endpoint: http://localhost:${PORT}/api/images`);
  console.log(`🔐 Admin panel: http://localhost:${PORT}/admin`);
  console.log(`🏥 Health check: http://localhost:${PORT}/`);
});

module.exports = app;