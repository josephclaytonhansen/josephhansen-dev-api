const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');

// Check if user is authenticated
const requireAuth = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    return next();
  }
  res.status(401).json({ error: 'Authentication required' });
};

// Check if 2FA is verified
const require2FA = (req, res, next) => {
  if (req.session && req.session.twoFactorVerified) {
    return next();
  }
  res.status(401).json({ error: '2FA verification required' });
};

// Validate login credentials with timing attack protection
const validateCredentials = async (username, password) => {
  const adminUsername = process.env.ADMIN_USERNAME || 'admin';
  const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
  
  console.log('Login attempt for username:', username);
  console.log('Expected username:', adminUsername);
  console.log('Hash configured:', !!adminPasswordHash);
  
  if (!adminPasswordHash) {
    console.error('❌ Admin password hash not configured in .env file');
    throw new Error('Admin password hash not configured');
  }
  
  // Always perform bcrypt comparison to prevent timing attacks
  const isValidUsername = username === adminUsername;
  const isValidPassword = await bcrypt.compare(password, adminPasswordHash);
  
  console.log('Username valid:', isValidUsername);
  console.log('Password valid:', isValidPassword);
  
  return isValidUsername && isValidPassword;
};

// Generate 2FA secret
const generate2FASecret = (username) => {
  return speakeasy.generateSecret({
    name: `josephhansen.dev API (${username})`,
    issuer: 'josephhansen.dev'
  });
};

// Verify 2FA token
const verify2FAToken = (token, secret) => {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 2 // Allow some time drift
  });
};

module.exports = {
  requireAuth,
  require2FA,
  validateCredentials,
  generate2FASecret,
  verify2FAToken
};