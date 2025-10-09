const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
const { requireAuth, require2FA } = require('../middleware/auth');
const router = express.Router();

// Storage configuration
const storage = multer.memoryStorage();

// File filter with magic number validation
const fileFilter = async (req, file, cb) => {
  const allowedTypes = (process.env.ALLOWED_FILE_TYPES || 'image/jpeg,image/png,image/gif,image/webp').split(',');
  
  // Check MIME type
  if (!allowedTypes.includes(file.mimetype)) {
    return cb(new Error(`File type ${file.mimetype} not allowed. Allowed types: ${allowedTypes.join(', ')}`), false);
  }
  
  // Additional validation will be done in Sharp processing
  cb(null, true);
};

// Multer configuration
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB default
    files: 5 // Max 5 files at once
  }
});

// Get upload directory
const getUploadDir = () => {
  return process.env.UPLOAD_DIR || path.join(__dirname, '../uploads');
};

// Ensure upload directory exists
const ensureUploadDir = async () => {
  const uploadDir = getUploadDir();
  try {
    await fs.access(uploadDir);
  } catch {
    await fs.mkdir(uploadDir, { recursive: true });
  }
  return uploadDir;
};

// Generate unique filename with security checks
const generateFilename = (originalname) => {
  if (!originalname || typeof originalname !== 'string') {
    throw new Error('Invalid filename');
  }
  
  const ext = path.extname(originalname).toLowerCase();
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
  
  if (!allowedExtensions.includes(ext)) {
    throw new Error('Invalid file extension');
  }
  
  return `${uuidv4()}${ext}`;
};

// Get image metadata
const getImageInfo = async (filePath) => {
  try {
    const stats = await fs.stat(filePath);
    const metadata = await sharp(filePath).metadata();
    
    return {
      size: stats.size,
      width: metadata.width,
      height: metadata.height,
      format: metadata.format,
      created: stats.birthtime,
      modified: stats.mtime
    };
  } catch (error) {
    return null;
  }
};

// POST /api/images/upload - Upload image(s)
router.post('/upload', requireAuth, require2FA, (req, res, next) => {
  upload.array('images', 5)(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      // Handle Multer-specific errors with user-friendly messages
      if (err.code === 'LIMIT_FILE_SIZE') {
        const maxSize = parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024;
        const maxSizeMB = (maxSize / (1024 * 1024)).toFixed(0);
        return res.status(400).json({ 
          error: `File too large. Maximum file size is ${maxSizeMB}MB per file.` 
        });
      }
      if (err.code === 'LIMIT_FILE_COUNT') {
        return res.status(400).json({ 
          error: 'Too many files. You can upload a maximum of 5 files at once.' 
        });
      }
      if (err.code === 'LIMIT_UNEXPECTED_FILE') {
        return res.status(400).json({ 
          error: 'Unexpected field name. Please use "images" as the field name.' 
        });
      }
      return res.status(400).json({ 
        error: `Upload error: ${err.message}` 
      });
    } else if (err) {
      // Handle other errors (like file type errors from fileFilter)
      return res.status(400).json({ 
        error: err.message || 'Upload failed' 
      });
    }
    // No error, continue to the route handler
    next();
  });
}, async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }

    const uploadDir = await ensureUploadDir();
    const uploadedFiles = [];

    for (const file of req.files) {
      // Additional file validation
      if (file.size > (parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024)) {
        return res.status(400).json({ error: 'File too large' });
      }
      
      const filename = generateFilename(file.originalname);
      const filepath = path.join(uploadDir, filename);

      // Process and save the image using Sharp for additional validation
      try {
        await sharp(file.buffer)
          .jpeg({ quality: 90 }) // Convert to JPEG with good quality
          .toFile(filepath);
      } catch (sharpError) {
        console.error('Sharp processing error:', sharpError);
        return res.status(400).json({ error: 'Invalid image file or corrupted data' });
      }

      // Get image info
      const info = await getImageInfo(filepath);

      uploadedFiles.push({
        id: path.parse(filename).name, // UUID without extension
        filename: filename,
        originalName: file.originalname,
        url: `/images/${filename}`,
        ...info
      });
    }

    res.json({
      success: true,
      message: `${uploadedFiles.length} file(s) uploaded successfully`,
      files: uploadedFiles
    });

  } catch (error) {
    console.error('Upload error:', error);
    // Don't expose internal error details in production
    const message = process.env.NODE_ENV === 'development' ? error.message : 'Upload failed';
    res.status(500).json({ 
      error: 'Upload failed',
      details: process.env.NODE_ENV === 'development' ? message : undefined
    });
  }
});

// GET /api/images - List all images
router.get('/', requireAuth, require2FA, async (req, res) => {
  try {
    const uploadDir = await ensureUploadDir();
    const files = await fs.readdir(uploadDir);
    
    const images = [];
    
    for (const file of files) {
      if (path.extname(file).toLowerCase().match(/\.(jpg|jpeg|png|gif|webp)$/)) {
        const filepath = path.join(uploadDir, file);
        const info = await getImageInfo(filepath);
        
        if (info) {
          images.push({
            id: path.parse(file).name,
            filename: file,
            url: `/images/${file}`,
            ...info
          });
        }
      }
    }

    // Sort by creation date (newest first)
    images.sort((a, b) => new Date(b.created) - new Date(a.created));

    res.json({
      success: true,
      count: images.length,
      images: images
    });

  } catch (error) {
    console.error('List images error:', error);
    res.status(500).json({ error: 'Failed to list images' });
  }
});

// Validate UUID format to prevent path traversal
const isValidUUID = (uuid) => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
};

// GET /api/images/:id - Get specific image info
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Validate UUID format
    if (!isValidUUID(id)) {
      return res.status(400).json({ error: 'Invalid image ID format' });
    }
    const uploadDir = await ensureUploadDir();
    const files = await fs.readdir(uploadDir);
    
    // Find file with matching UUID
    const matchingFile = files.find(file => 
      path.parse(file).name === id && 
      path.extname(file).toLowerCase().match(/\.(jpg|jpeg|png|gif|webp)$/)
    );

    if (!matchingFile) {
      return res.status(404).json({ error: 'Image not found' });
    }

    const filepath = path.join(uploadDir, matchingFile);
    const info = await getImageInfo(filepath);

    if (!info) {
      return res.status(404).json({ error: 'Image not found or corrupted' });
    }

    res.json({
      success: true,
      image: {
        id: id,
        filename: matchingFile,
        url: `/images/${matchingFile}`,
        ...info
      }
    });

  } catch (error) {
    console.error('Get image error:', error);
    res.status(500).json({ error: 'Failed to get image info' });
  }
});

// POST /api/images/:id/resize - Resize image
router.post('/:id/resize', requireAuth, require2FA, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Validate UUID format
    if (!isValidUUID(id)) {
      return res.status(400).json({ error: 'Invalid image ID format' });
    }
    
    const { width, height, quality = 90, format = 'png' } = req.body;

    if (!width && !height) {
      return res.status(400).json({ error: 'Width or height must be specified' });
    }

    // Validate numeric inputs
    const parsedWidth = width ? parseInt(width) : null;
    const parsedHeight = height ? parseInt(height) : null;
    const parsedQuality = parseInt(quality);
    
    if ((width && (isNaN(parsedWidth) || parsedWidth <= 0 || parsedWidth > 10000)) ||
        (height && (isNaN(parsedHeight) || parsedHeight <= 0 || parsedHeight > 10000))) {
      return res.status(400).json({ error: 'Invalid width or height. Must be between 1 and 10000.' });
    }
    
    if (isNaN(parsedQuality) || parsedQuality < 1 || parsedQuality > 100) {
      return res.status(400).json({ error: 'Quality must be between 1 and 100' });
    }

    const uploadDir = await ensureUploadDir();
    const files = await fs.readdir(uploadDir);
    
    const matchingFile = files.find(file => 
      path.parse(file).name === id && 
      path.extname(file).toLowerCase().match(/\.(jpg|jpeg|png|gif|webp)$/)
    );

    if (!matchingFile) {
      return res.status(404).json({ error: 'Image not found' });
    }

    const filepath = path.join(uploadDir, matchingFile);
    const allowedFormats = ['jpeg', 'png', 'webp'];
    const sanitizedFormat = typeof format === 'string' && allowedFormats.includes(format.toLowerCase())
      ? format.toLowerCase()
      : 'png';
    // Strict mapping: don't accept extension from user input
    const extMap = { jpeg: 'jpg', png: 'png', webp: 'webp' };
    const extension = extMap[sanitizedFormat];
    const newFilename = `${uuidv4()}.${extension}`;
    const newFilepath = path.join(uploadDir, newFilename);

    // Resize image
    const resizeOperation = sharp(filepath)
      .resize(width ? parseInt(width) : null, height ? parseInt(height) : null, {
        fit: 'inside',
        withoutEnlargement: true
      });

    // Apply format-specific options
    if (selectedFormat === 'jpeg') {
      resizeOperation.jpeg({ quality: parseInt(quality) });
    } else if (selectedFormat === 'png') {
      resizeOperation.png({ quality: parseInt(quality) });
    } else if (selectedFormat === 'webp') {
      resizeOperation.webp({ quality: parseInt(quality) });
    }

    await resizeOperation.toFile(newFilepath);

    const info = await getImageInfo(newFilepath);

    res.json({
      success: true,
      message: 'Image resized successfully',
      image: {
        id: path.parse(newFilename).name,
        filename: newFilename,
        url: `/images/${newFilename}`,
        ...info
      }
    });

  } catch (error) {
    console.error('Resize error:', error);
    res.status(500).json({ error: 'Failed to resize image' });
  }
});

// POST /api/images/:id/crop - Crop image
router.post('/:id/crop', requireAuth, require2FA, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Validate UUID format
    if (!isValidUUID(id)) {
      return res.status(400).json({ error: 'Invalid image ID format' });
    }
    
    const { left, top, width, height, quality = 90, format = 'png' } = req.body;

    if (!left || !top || !width || !height) {
      return res.status(400).json({ 
        error: 'Crop parameters required: left, top, width, height' 
      });
    }

    // Validate numeric inputs
    const parsedLeft = parseInt(left);
    const parsedTop = parseInt(top);
    const parsedWidth = parseInt(width);
    const parsedHeight = parseInt(height);
    const parsedQuality = parseInt(quality);
    
    if (isNaN(parsedLeft) || parsedLeft < 0 || parsedLeft > 10000 ||
        isNaN(parsedTop) || parsedTop < 0 || parsedTop > 10000 ||
        isNaN(parsedWidth) || parsedWidth <= 0 || parsedWidth > 10000 ||
        isNaN(parsedHeight) || parsedHeight <= 0 || parsedHeight > 10000) {
      return res.status(400).json({ error: 'Invalid crop parameters. Values must be between 0-10000.' });
    }
    
    if (isNaN(parsedQuality) || parsedQuality < 1 || parsedQuality > 100) {
      return res.status(400).json({ error: 'Quality must be between 1 and 100' });
    }

    const uploadDir = await ensureUploadDir();
    const files = await fs.readdir(uploadDir);
    
    const matchingFile = files.find(file => 
      path.parse(file).name === id && 
      path.extname(file).toLowerCase().match(/\.(jpg|jpeg|png|gif|webp)$/)
    );

    if (!matchingFile) {
      return res.status(404).json({ error: 'Image not found' });
    }

    const filepath = path.join(uploadDir, matchingFile);
    const allowedFormats = ['jpeg', 'png', 'webp'];
    const selectedFormat = allowedFormats.includes(format.toLowerCase()) ? format.toLowerCase() : 'png';
    const extension = selectedFormat === 'jpeg' ? 'jpg' : selectedFormat;
    const newFilename = `${uuidv4()}.${extension}`;
    const newFilepath = path.join(uploadDir, newFilename);

    // Crop image
    const cropOperation = sharp(filepath)
      .extract({
        left: parseInt(left),
        top: parseInt(top),
        width: parseInt(width),
        height: parseInt(height)
      });

    // Apply format-specific options
    if (selectedFormat === 'jpeg') {
      cropOperation.jpeg({ quality: parseInt(quality) });
    } else if (selectedFormat === 'png') {
      cropOperation.png({ quality: parseInt(quality) });
    } else if (selectedFormat === 'webp') {
      cropOperation.webp({ quality: parseInt(quality) });
    }

    await cropOperation.toFile(newFilepath);

    const info = await getImageInfo(newFilepath);

    res.json({
      success: true,
      message: 'Image cropped successfully',
      image: {
        id: path.parse(newFilename).name,
        filename: newFilename,
        url: `/images/${newFilename}`,
        ...info
      }
    });

  } catch (error) {
    console.error('Crop error:', error);
    res.status(500).json({ error: 'Failed to crop image' });
  }
});

// DELETE /api/images/:id - Delete image
router.delete('/:id', requireAuth, require2FA, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Validate UUID format
    if (!isValidUUID(id)) {
      return res.status(400).json({ error: 'Invalid image ID format' });
    }
    const uploadDir = await ensureUploadDir();
    const files = await fs.readdir(uploadDir);
    
    // Find file with matching UUID
    const matchingFile = files.find(file => 
      path.parse(file).name === id && 
      path.extname(file).toLowerCase().match(/\.(jpg|jpeg|png|gif|webp)$/)
    );

    if (!matchingFile) {
      return res.status(404).json({ error: 'Image not found' });
    }

    const filepath = path.join(uploadDir, matchingFile);
    await fs.unlink(filepath);

    res.json({
      success: true,
      message: 'Image deleted successfully',
      deletedFile: matchingFile
    });

  } catch (error) {
    console.error('Delete image error:', error);
    res.status(500).json({ error: 'Failed to delete image' });
  }
});

module.exports = router;