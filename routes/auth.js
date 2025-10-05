const express = require('express');
const bcrypt = require('bcryptjs');
const qrcode = require('qrcode');
const rateLimit = require('express-rate-limit');
const { validateCredentials, generate2FASecret, verify2FAToken, requireAuth } = require('../middleware/auth');
const router = express.Router();

// Strict rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth attempts per windowMs
  message: { error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// POST /api/auth/login - Login with username/password
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    // Input validation
    if (!username || !password || 
        typeof username !== 'string' || typeof password !== 'string' ||
        username.length > 100 || password.length > 100) {
      return res.status(400).json({ error: 'Invalid username or password format' });
    }

    // Sanitize inputs
    const cleanUsername = username.trim();
    const cleanPassword = password;
    
    const isValid = await validateCredentials(cleanUsername, cleanPassword);
    
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Set session
    req.session.authenticated = true;
    req.session.username = username;
    req.session.twoFactorVerified = false;

    res.json({
      success: true,
      message: 'Login successful. 2FA verification required.',
      requires2FA: true
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET /api/auth/setup-2fa - Setup 2FA (first time)
router.get('/setup-2fa', requireAuth, async (req, res) => {
  try {
    // Check if 2FA is already configured
    if (process.env.TOTP_SECRET) {
      return res.status(400).json({ error: '2FA already configured' });
    }

    const secret = generate2FASecret(req.session.username);
    
    // Store secret in session temporarily for verification
    req.session.tempTwoFactorSecret = secret.base32;

    // Generate QR code
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    res.json({
      success: true,
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32,
      instructions: 'Scan the QR code with your authenticator app and verify with a token. Once verified, add TOTP_SECRET to your .env file.'
    });

  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({ error: 'Failed to setup 2FA' });
  }
});

// POST /api/auth/verify-2fa-setup - Verify 2FA setup
router.post('/verify-2fa-setup', authLimiter, requireAuth, async (req, res) => {
  try {
    const { token } = req.body;

    // Input validation
    if (!token || typeof token !== 'string' || !/^\d{6}$/.test(token)) {
      return res.status(400).json({ error: 'Invalid token format. Must be 6 digits.' });
    }

    if (!req.session.tempTwoFactorSecret) {
      return res.status(400).json({ error: 'No 2FA setup in progress' });
    }

    const isValid = verify2FAToken(token, req.session.tempTwoFactorSecret);

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Mark as verified in session
    req.session.twoFactorVerified = true;
    
    res.json({
      success: true,
      message: '2FA setup verified successfully',
      nextSteps: {
        instruction: 'Add this line to your .env file to complete setup:',
        envLine: `TOTP_SECRET=${req.session.tempTwoFactorSecret}`,
        note: 'Restart the server after adding the TOTP_SECRET to .env'
      }
    });
    
    // Clear temp secret after providing instructions
    delete req.session.tempTwoFactorSecret;

  } catch (error) {
    console.error('2FA verification error:', error);
    res.status(500).json({ error: 'Failed to verify 2FA' });
  }
});

// POST /api/auth/verify-2fa - Verify 2FA token
router.post('/verify-2fa', authLimiter, requireAuth, async (req, res) => {
  try {
    const { token } = req.body;

    // Input validation
    if (!token || typeof token !== 'string' || !/^\d{6}$/.test(token)) {
      return res.status(400).json({ error: 'Invalid token format. Must be 6 digits.' });
    }

    const totpSecret = process.env.TOTP_SECRET;
    if (!totpSecret) {
      return res.status(400).json({ error: '2FA not configured. Please setup 2FA first.' });
    }

    const isValid = verify2FAToken(token, totpSecret);

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.session.twoFactorVerified = true;

    res.json({
      success: true,
      message: '2FA verification successful'
    });

  } catch (error) {
    console.error('2FA verification error:', error);
    res.status(500).json({ error: 'Failed to verify 2FA' });
  }
});

// GET /api/auth/status - Check authentication status
router.get('/status', (req, res) => {
  const isAuthenticated = !!(req.session && req.session.authenticated);
  const is2FAVerified = !!(req.session && req.session.twoFactorVerified);
  const has2FASetup = !!process.env.TOTP_SECRET;

  res.json({
    authenticated: isAuthenticated,
    twoFactorVerified: is2FAVerified,
    twoFactorSetup: has2FASetup,
    username: req.session?.username || null,
    needsSetup: isAuthenticated && !has2FASetup,
    needsVerification: isAuthenticated && has2FASetup && !is2FAVerified
  });
});

// POST /api/auth/logout - Logout
router.post('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.error('Logout error:', err);
        return res.status(500).json({ error: 'Failed to logout' });
      }
      res.json({ success: true, message: 'Logged out successfully' });
    });
  } else {
    res.json({ success: true, message: 'Already logged out' });
  }
});

module.exports = router;