const express = require('express');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const router = express.Router();

// Rate limiting for mail endpoint - stricter than general rate limit
const mailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 mail requests per windowMs
  message: { error: 'Too many mail requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Create transporter
const createTransporter = () => {
  const port = parseInt(process.env.SMTP_PORT) || 587;
  
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: port,
    // Port 465 uses secure: true (SSL/TLS), port 587 uses secure: false (STARTTLS)
    secure: port === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    // For port 587, require STARTTLS
    requireTLS: port === 587,
    tls: {
      // Don't fail on invalid certs in development
      rejectUnauthorized: process.env.NODE_ENV === 'production'
    }
  });
};

// Validate email format
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Sanitize input
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return '';
  // Remove potentially dangerous characters and limit length
  return input.replace(/[<>"'&]/g, '').trim().slice(0, 5000);
};

// POST /api/mail/send - Send form submission
router.post('/send', mailLimiter, async (req, res) => {
  try {
    const { name, email, subject, message, referrer, location } = req.body;

    // Validation
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ 
        error: 'Missing required fields: name, email, subject, message' 
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Sanitize inputs
    const sanitizedData = {
      name: sanitizeInput(name),
      email: sanitizeInput(email),
      subject: sanitizeInput(subject),
      message: sanitizeInput(message),
      referrer: sanitizeInput(referrer || 'Unknown'),
      location: sanitizeInput(location || 'contact form')
    };

    // Check if environment is configured
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.FORWARD_TO_EMAIL) {
      return res.status(500).json({ error: 'Mail service not configured' });
    }

    const transporter = createTransporter();

    // Verify transporter
    await transporter.verify();

    // Email content
    const mailOptions = {
      from: `"${sanitizedData.name}" <${process.env.SMTP_USER}>`,
      to: process.env.FORWARD_TO_EMAIL,
      replyTo: sanitizedData.email,
      subject: `Contact Form: ${sanitizedData.subject}`,
      text: `
Name: ${sanitizedData.name}
Email: ${sanitizedData.email}
Subject: ${sanitizedData.subject}

Message:
${sanitizedData.message}

---
Sent via ${sanitizedData.referrer} ${sanitizedData.location}
IP: ${req.ip}
Timestamp: ${new Date().toISOString()}
      `,
      html: `
        <h2>Contact Form Submission</h2>
        <p><strong>Name:</strong> ${sanitizedData.name}</p>
        <p><strong>Email:</strong> ${sanitizedData.email}</p>
        <p><strong>Subject:</strong> ${sanitizedData.subject}</p>
        
        <h3>Message:</h3>
        <div style="background: #f5f5f5; padding: 15px; border-left: 4px solid #007acc;">
          ${sanitizedData.message.replace(/\n/g, '<br>')}
        </div>
        
        <hr>
        <small>
          Sent via ${sanitizedData.referrer} ${sanitizedData.location}<br>
          IP: ${req.ip}<br>
          Timestamp: ${new Date().toISOString()}
        </small>
      `
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);
    
    console.log('Email sent:', info.messageId);
    
    res.json({ 
      success: true, 
      message: 'Email sent successfully',
      messageId: info.messageId
    });

  } catch (error) {
    console.error('Mail error:', error);
    
    // Don't expose internal errors to client
    res.status(500).json({ 
      error: 'Failed to send email. Please try again later.' 
    });
  }
});

// GET /api/mail/test - Test mail configuration (for development)
router.get('/test', async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Not found' });
  }

  try {
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER) {
      return res.status(500).json({ error: 'SMTP not configured' });
    }

    const transporter = createTransporter();
    await transporter.verify();
    
    res.json({ 
      success: true, 
      message: 'SMTP configuration is valid',
      config: {
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: process.env.SMTP_SECURE,
        user: process.env.SMTP_USER ? '***configured***' : 'not set'
      }
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'SMTP configuration test failed',
      details: error.message
    });
  }
});

module.exports = router;