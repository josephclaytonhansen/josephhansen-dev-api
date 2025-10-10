const express = require('express');
const router = express.Router();
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { isoUint8Array, isoBase64URL } = require('@simplewebauthn/server/helpers');

// In-memory storage for passkey credentials (in production, use a database)
const userPasskeys = new Map();
const challenges = new Map();

// Configuration
const rpName = 'josephhansen.dev API';
const rpID = process.env.NODE_ENV === 'production' ? 'api.josephhansen.dev' : 'localhost';
const origin = process.env.NODE_ENV === 'production' 
  ? 'https://api.josephhansen.dev' 
  : `http://localhost:${process.env.PORT || 9640}`;

// POST /api/passkey/register/options - Generate registration options
router.post('/register/options', async (req, res) => {
  console.log('=== Passkey Registration Options Request ===');
  console.log('Session:', req.session);
  console.log('Session authenticated:', req.session?.authenticated);
  console.log('Username:', req.session?.username);
  
  try {
    // Only allow authenticated users to register passkeys
    if (!req.session || !req.session.authenticated) {
      console.log('❌ Not authenticated');
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const username = req.session.username || 'admin';
    console.log('✓ Generating options for user:', username);
    
    // Get user's existing passkeys
    const userCredentials = userPasskeys.get(username) || [];
    console.log('Existing passkeys:', userCredentials.length);

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: isoUint8Array.fromUTF8String(username),
      userName: username,
      userDisplayName: username,
      // Don't prompt users for additional information about the authenticator
      attestationType: 'none',
      // Prevent users from re-registering existing authenticators
      excludeCredentials: userCredentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      })),
      authenticatorSelection: {
        // Prefer platform authenticators (Windows Hello, Touch ID, etc.)
        authenticatorAttachment: 'platform',
        requireResidentKey: false,
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    console.log('✓ Options generated:', JSON.stringify(options, null, 2));
    console.log('Challenge:', options.challenge);
    console.log('User:', options.user);

    // Store challenge for verification
    challenges.set(username, options.challenge);

    console.log('✓ Sending options to client');
    res.json(options);
  } catch (error) {
    console.error('❌ Passkey registration options error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to generate registration options', details: error.message });
  }
});

// POST /api/passkey/register/verify - Verify registration response
router.post('/register/verify', async (req, res) => {
  try {
    if (!req.session || !req.session.authenticated) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const username = req.session.username || 'admin';
    const expectedChallenge = challenges.get(username);

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found' });
    }

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo;

      // Get or create user's passkey list
      const userCredentials = userPasskeys.get(username) || [];
      
      // Add new passkey (using properties from credential)
      const newPasskey = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports || [],
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        createdAt: new Date().toISOString(),
      };

      userCredentials.push(newPasskey);
      userPasskeys.set(username, userCredentials);

      // Clear challenge
      challenges.delete(username);

      console.log(`Passkey registered for user: ${username}`);

      res.json({ 
        verified: true,
        message: 'Passkey registered successfully' 
      });
    } else {
      res.status(400).json({ error: 'Passkey verification failed' });
    }
  } catch (error) {
    console.error('Passkey registration verification error:', error);
    res.status(500).json({ error: 'Failed to verify registration' });
  }
});

// POST /api/passkey/auth/options - Generate authentication options
router.post('/auth/options', async (req, res) => {
  try {
    const username = req.body.username || 'admin';
    const userCredentials = userPasskeys.get(username) || [];

    if (userCredentials.length === 0) {
      return res.status(404).json({ error: 'No passkeys registered for this user' });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: userCredentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      })),
      userVerification: 'preferred',
    });

    // Store challenge for verification
    challenges.set(username, options.challenge);

    res.json(options);
  } catch (error) {
    console.error('Passkey authentication options error:', error);
    res.status(500).json({ error: 'Failed to generate authentication options' });
  }
});

// POST /api/passkey/auth/verify - Verify authentication response
router.post('/auth/verify', async (req, res) => {
  try {
    const username = req.body.username || 'admin';
    const expectedChallenge = challenges.get(username);

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found' });
    }

    const userCredentials = userPasskeys.get(username) || [];
    const credentialID = req.body.id;
    
    const passkey = userCredentials.find(cred => 
      Buffer.from(cred.id).toString('base64url') === credentialID
    );

    if (!passkey) {
      return res.status(404).json({ error: 'Passkey not found' });
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: passkey.id,
        publicKey: passkey.publicKey,
        counter: passkey.counter,
        transports: passkey.transports,
      },
    });

    const { verified, authenticationInfo } = verification;

    if (verified) {
      // Update counter
      passkey.counter = authenticationInfo.newCounter;

      // Create session
      req.session.authenticated = true;
      req.session.username = username;
      req.session.twoFactorVerified = true; // Passkey is inherently 2FA

      // Clear challenge
      challenges.delete(username);

      console.log(`Passkey authentication successful for user: ${username}`);

      res.json({ 
        success: true,
        message: 'Authentication successful',
        username 
      });
    } else {
      res.status(400).json({ error: 'Authentication failed' });
    }
  } catch (error) {
    console.error('Passkey authentication verification error:', error);
    res.status(500).json({ error: 'Failed to verify authentication' });
  }
});

// GET /api/passkey/list - List user's registered passkeys
router.get('/list', (req, res) => {
  try {
    if (!req.session || !req.session.authenticated) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const username = req.session.username || 'admin';
    const userCredentials = userPasskeys.get(username) || [];

    const passkeyList = userCredentials.map((cred, index) => ({
      id: Buffer.from(cred.id).toString('base64url'),
      createdAt: cred.createdAt,
      transports: cred.transports,
      name: `Passkey ${index + 1}`,
    }));

    res.json({ passkeys: passkeyList });
  } catch (error) {
    console.error('Passkey list error:', error);
    res.status(500).json({ error: 'Failed to list passkeys' });
  }
});

// DELETE /api/passkey/:id - Remove a passkey
router.delete('/:id', (req, res) => {
  try {
    if (!req.session || !req.session.authenticated) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const username = req.session.username || 'admin';
    const passkeyId = req.params.id;
    const userCredentials = userPasskeys.get(username) || [];

    const index = userCredentials.findIndex(cred => 
      Buffer.from(cred.id).toString('base64url') === passkeyId
    );

    if (index === -1) {
      return res.status(404).json({ error: 'Passkey not found' });
    }

    userCredentials.splice(index, 1);
    userPasskeys.set(username, userCredentials);

    res.json({ success: true, message: 'Passkey removed successfully' });
  } catch (error) {
    console.error('Passkey deletion error:', error);
    res.status(500).json({ error: 'Failed to remove passkey' });
  }
});

module.exports = router;
