const express = require('express');
const multer = require('multer');
const archiver = require('archiver');
const jwt = require('jsonwebtoken');
const mime = require('mime-types');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// Load configurations
const CONFIG_PATH = path.join(__dirname, 'config.json');

function loadConfig() {
  let config = {};
  if (fs.existsSync(CONFIG_PATH)) {
    try {
      config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    } catch (e) {
      console.error('Error reading config.json, resetting to default', e);
    }
  }

  let configChanged = false;
  if (!config.port) {
    config.port = 8080;
    configChanged = true;
  }
  if (!config.jwtSecret) {
    config.jwtSecret = crypto.randomBytes(32).toString('hex');
    configChanged = true;
  }
  if (!config.sharedPaths) {
    const homeDir = os.homedir();
    config.sharedPaths = [
      { name: 'Home Folder', path: homeDir },
      { name: 'Workspace', path: __dirname }
    ];
    configChanged = true;
  }
  if (config.passwordHash === undefined) {
    config.passwordHash = null; // Set to null for setup mode
    configChanged = true;
  }

  if (configChanged) {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
  }

  return config;
}

let config = loadConfig();

function saveConfig(updatedConfig) {
  config = { ...config, ...updatedConfig };
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
}

// Password helpers
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(salt + ':' + derivedKey.toString('hex'));
    });
  });
}

function verifyPassword(password, hash) {
  return new Promise((resolve, reject) => {
    const [salt, key] = hash.split(':');
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(derivedKey.toString('hex') === key);
    });
  });
}

// Path validation helper (prevents directory traversal)
function validatePath(shareName, subPath) {
  const share = config.sharedPaths.find(p => p.name === shareName);
  if (!share) {
    return { valid: false, error: 'Share name not found' };
  }

  const absoluteRoot = path.resolve(share.path);
  const targetPath = path.resolve(absoluteRoot, subPath || '');

  // Case-insensitive comparison of paths for Windows
  const rootLower = absoluteRoot.toLowerCase();
  const targetLower = targetPath.toLowerCase();

  // Validate that the resolved path is inside the root directory
  const relative = path.relative(rootLower, targetLower);
  const isSafe = relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));

  if (!isSafe) {
    return { valid: false, error: 'Access Denied: Path traversal detected.' };
  }

  return { valid: true, resolvedPath: targetPath, absoluteRoot };
}

// CPU usage calculator helper (Windows compatible)
function getCpuUsage() {
  return new Promise((resolve) => {
    const start = os.cpus();
    setTimeout(() => {
      const end = os.cpus();
      let totalDiff = 0;
      let idleDiff = 0;
      for (let i = 0; i < start.length; i++) {
        const s = start[i].times;
        const e = end[i].times;
        const totalS = s.user + s.nice + s.sys + s.idle + s.irq;
        const totalE = e.user + e.nice + e.sys + e.idle + e.irq;
        totalDiff += (totalE - totalS);
        idleDiff += (e.idle - s.idle);
      }
      if (totalDiff === 0) return resolve(0);
      const usage = 1 - (idleDiff / totalDiff);
      resolve(Math.round(usage * 100));
    }, 200);
  });
}

// Initialize Express App
const app = express();

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());

// Parse token from custom Header or Cookies
app.use((req, res, next) => {
  let token = req.headers.authorization;
  if (token && token.startsWith('Bearer ')) {
    token = token.slice(7);
  } else {
    // Read from cookies manually since we don't have cookie-parser
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
      const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
        const [key, value] = cookie.trim().split('=');
        acc[key] = value;
        return acc;
      }, {});
      token = cookies['token'];
    }
  }
  req.token = token;
  next();
});

// Authentication middleware
function requireAuth(req, res, next) {
  // If passwordHash is null, the server is in Setup Mode
  if (!config.passwordHash) {
    return res.status(403).json({ error: 'Setup required', setupRequired: true });
  }

  if (!req.token) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  try {
    const decoded = jwt.verify(req.token, config.jwtSecret);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
}

// --- API Endpoints ---

// Check auth status
app.get('/api/auth-check', (req, res) => {
  if (!config.passwordHash) {
    return res.json({ setupRequired: true });
  }
  if (!req.token) {
    return res.json({ authenticated: false });
  }
  try {
    jwt.verify(req.token, config.jwtSecret);
    return res.json({ authenticated: true });
  } catch (err) {
    return res.json({ authenticated: false });
  }
});

// Setup master password
app.post('/api/setup', async (req, res) => {
  if (config.passwordHash) {
    return res.status(400).json({ error: 'Server has already been set up.' });
  }

  const { password } = req.body;
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  try {
    const hash = await hashPassword(password);
    saveConfig({ passwordHash: hash });
    res.json({ success: true, message: 'Master password configured successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to hash password' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  if (!config.passwordHash) {
    return res.status(403).json({ error: 'Setup required', setupRequired: true });
  }

  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }

  try {
    const verified = await verifyPassword(password, config.passwordHash);
    if (!verified) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ auth: true }, config.jwtSecret, { expiresIn: '7d' });
    
    // Set cookie
    res.setHeader('Set-Cookie', `token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`);
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  res.json({ success: true });
});

// Get configured shares
app.get('/api/shares', requireAuth, (req, res) => {
  const sharesWithStatus = config.sharedPaths.map(s => {
    return { name: s.name, path: s.path, exists: fs.existsSync(s.path) };
  });
  res.json(sharesWithStatus);
});

// Add a new share
app.post('/api/shares', requireAuth, (req, res) => {
  const { name, path: sharePath } = req.body;
  if (!name || !sharePath) {
    return res.status(400).json({ error: 'Share name and path are required' });
  }

  const resolved = path.resolve(sharePath);
  if (!fs.existsSync(resolved)) {
    return res.status(400).json({ error: `Path does not exist: ${sharePath}` });
  }

  // Check if name is unique
  if (config.sharedPaths.some(s => s.name.toLowerCase() === name.toLowerCase())) {
    return res.status(400).json({ error: 'A share with this name already exists' });
  }

  const updatedShares = [...config.sharedPaths, { name, path: resolved }];
  saveConfig({ sharedPaths: updatedShares });
  res.json({ success: true, shares: updatedShares });
});

// Delete a share configuration
app.delete('/api/shares/:name', requireAuth, (req, res) => {
  const shareName = req.params.name;
  const updatedShares = config.sharedPaths.filter(s => s.name.toLowerCase() !== shareName.toLowerCase());
  
  if (updatedShares.length === config.sharedPaths.length) {
    return res.status(404).json({ error: 'Share config not found' });
  }

  saveConfig({ sharedPaths: updatedShares });
  res.json({ success: true, shares: updatedShares });
});

// List files in a directory
app.get('/api/files', requireAuth, async (req, res) => {
  const shareName = req.query.share;
  const subPath = req.query.path || '';

  const validation = validatePath(shareName, subPath);
  if (!validation.valid) {
    return res.status(403).json({ error: validation.error });
  }

  try {
    const resolvedPath = validation.resolvedPath;
    if (!fs.existsSync(resolvedPath)) {
      return res.status(404).json({ error: 'Directory does not exist' });
    }

    const stat = await fs.promises.stat(resolvedPath);
    if (!stat.isDirectory()) {
      return res.status(400).json({ error: 'Target is not a directory' });
    }

    const entries = await fs.promises.readdir(resolvedPath, { withFileTypes: true });
    const files = [];

    for (const entry of entries) {
      try {
        const filePath = path.join(resolvedPath, entry.name);
        const fileStat = await fs.promises.stat(filePath);
        
        // Hide config.json or server.js if sharing workspace (optional, but let's keep all files visible for personal use)
        files.push({
          name: entry.name,
          isDirectory: entry.isDirectory(),
          size: entry.isDirectory() ? null : fileStat.size,
          mtime: fileStat.mtime,
          mimeType: entry.isDirectory() ? null : (mime.lookup(entry.name) || 'application/octet-stream')
        });
      } catch (err) {
        // Skip files that fail to stat (e.g. system files with permission restrictions)
      }
    }

    // Sort: directories first, then files alphabetically
    files.sort((a, b) => {
      if (a.isDirectory && !b.isDirectory) return -1;
      if (!a.isDirectory && b.isDirectory) return 1;
      return a.name.localeCompare(b.name);
    });

    res.json({
      share: shareName,
      path: subPath,
      files
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to read directory' });
  }
});

// Download or Stream a file (Supports Range requests)
app.get('/api/download', requireAuth, async (req, res) => {
  const shareName = req.query.share;
  const subPath = req.query.path;

  if (!subPath) {
    return res.status(400).json({ error: 'Path is required' });
  }

  const validation = validatePath(shareName, subPath);
  if (!validation.valid) {
    return res.status(403).json({ error: validation.error });
  }

  const resolvedPath = validation.resolvedPath;
  if (!fs.existsSync(resolvedPath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  try {
    const stat = await fs.promises.stat(resolvedPath);
    if (stat.isDirectory()) {
      return res.status(400).json({ error: 'Cannot download a directory. Use /api/zip instead.' });
    }

    const fileSize = stat.size;
    const contentType = mime.lookup(resolvedPath) || 'application/octet-stream';
    const fileName = path.basename(resolvedPath);

    // Check for Range request (important for video/audio streaming)
    const range = req.headers.range;
    if (range) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;

      if (start >= fileSize || end >= fileSize) {
        res.status(416).set({
          'Content-Range': `bytes */${fileSize}`
        }).send();
        return;
      }

      const chunksize = (end - start) + 1;
      const fileStream = fs.createReadStream(resolvedPath, { start, end });
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': contentType,
      };

      res.writeHead(206, head);
      fileStream.pipe(res);
    } else {
      const head = {
        'Content-Length': fileSize,
        'Content-Type': contentType,
        // Send as attachment if 'download' query parameter is true, otherwise render/play inline
        'Content-Disposition': req.query.download === 'true' 
          ? `attachment; filename="${encodeURIComponent(fileName)}"`
          : `inline; filename="${encodeURIComponent(fileName)}"`
      };
      res.writeHead(200, head);
      fs.createReadStream(resolvedPath).pipe(res);
    }
  } catch (err) {
    console.error(err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Download error' });
    }
  }
});

// ZIP whole folders
app.get('/api/zip', requireAuth, async (req, res) => {
  const shareName = req.query.share;
  const subPath = req.query.path || '';

  const validation = validatePath(shareName, subPath);
  if (!validation.valid) {
    return res.status(403).json({ error: validation.error });
  }

  const resolvedPath = validation.resolvedPath;
  if (!fs.existsSync(resolvedPath)) {
    return res.status(404).json({ error: 'Folder not found' });
  }

  try {
    const stat = await fs.promises.stat(resolvedPath);
    if (!stat.isDirectory()) {
      return res.status(400).json({ error: 'Not a directory' });
    }

    const folderName = path.basename(resolvedPath) || shareName;
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(folderName)}.zip"`);
    res.setHeader('Content-Type', 'application/zip');

    const archive = archiver('zip', { zlib: { level: 9 } });
    
    archive.on('error', (err) => {
      throw err;
    });

    archive.pipe(res);
    archive.directory(resolvedPath, false);
    await archive.finalize();
  } catch (err) {
    console.error(err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to archive folder' });
    }
  }
});

// Create folder
app.post('/api/mkdir', requireAuth, async (req, res) => {
  const { share, path: subPath, name } = req.body;
  if (!name) return res.status(400).json({ error: 'Folder name is required' });

  const targetSubPath = path.join(subPath || '', name);
  const validation = validatePath(share, targetSubPath);
  if (!validation.valid) {
    return res.status(403).json({ error: validation.error });
  }

  try {
    if (fs.existsSync(validation.resolvedPath)) {
      return res.status(400).json({ error: 'Folder already exists' });
    }
    await fs.promises.mkdir(validation.resolvedPath, { recursive: true });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create directory' });
  }
});

// Rename file/folder
app.post('/api/rename', requireAuth, async (req, res) => {
  const { share, path: subPath, newName } = req.body;
  if (!newName) return res.status(400).json({ error: 'New name is required' });

  const validation = validatePath(share, subPath);
  if (!validation.valid) {
    return res.status(403).json({ error: validation.error });
  }

  try {
    const oldPath = validation.resolvedPath;
    const parentDir = path.dirname(oldPath);
    const newPath = path.join(parentDir, newName);

    // Verify destination doesn't escape sandbox
    const parentRelative = path.relative(validation.absoluteRoot.toLowerCase(), newPath.toLowerCase());
    const isSafe = parentRelative === '' || (!parentRelative.startsWith('..') && !path.isAbsolute(parentRelative));
    if (!isSafe) {
      return res.status(403).json({ error: 'Access Denied: Renaming outside sandbox.' });
    }

    if (fs.existsSync(newPath)) {
      return res.status(400).json({ error: 'A file/folder with the new name already exists' });
    }

    await fs.promises.rename(oldPath, newPath);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to rename' });
  }
});

// Delete file/folder
app.post('/api/delete', requireAuth, async (req, res) => {
  const { share, path: subPath } = req.body;

  const validation = validatePath(share, subPath);
  if (!validation.valid) {
    return res.status(403).json({ error: validation.error });
  }

  try {
    const resolvedPath = validation.resolvedPath;
    if (!fs.existsSync(resolvedPath)) {
      return res.status(404).json({ error: 'Item not found' });
    }

    await fs.promises.rm(resolvedPath, { recursive: true, force: true });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete item' });
  }
});

// Edit text file (Save contents)
app.post('/api/edit', requireAuth, async (req, res) => {
  const { share, path: subPath, content } = req.body;

  const validation = validatePath(share, subPath);
  if (!validation.valid) {
    return res.status(403).json({ error: validation.error });
  }

  try {
    const resolvedPath = validation.resolvedPath;
    // Check if path is directory
    if (fs.existsSync(resolvedPath)) {
      const stat = await fs.promises.stat(resolvedPath);
      if (stat.isDirectory()) {
        return res.status(400).json({ error: 'Cannot write content to a directory' });
      }
    }

    await fs.promises.writeFile(resolvedPath, content || '', 'utf8');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save file contents' });
  }
});

// Multi-file upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const shareName = req.query.share;
    const subPath = req.query.path || '';

    const validation = validatePath(shareName, subPath);
    if (!validation.valid) {
      return cb(new Error(validation.error));
    }
    cb(null, validation.resolvedPath);
  },
  filename: function (req, file, cb) {
    // Sanitize filename to avoid folder creation inside multer
    const safeName = path.basename(file.originalname);
    cb(null, safeName);
  }
});

const upload = multer({ storage: storage });

app.post('/api/upload', requireAuth, upload.array('files'), (req, res) => {
  res.json({ success: true, files: req.files.map(f => f.filename) });
});

// System telemetry metrics
app.get('/api/system', requireAuth, async (req, res) => {
  try {
    // Memory
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;

    // CPU
    const cpuUsage = await getCpuUsage();

    // Disks details of all shares
    const disks = [];
    for (const share of config.sharedPaths) {
      try {
        if (fs.existsSync(share.path)) {
          const stats = await fs.promises.statfs(share.path);
          const totalSize = stats.blocks * stats.bsize;
          const freeSize = stats.bavail * stats.bsize;
          disks.push({
            name: share.name,
            path: share.path,
            total: totalSize,
            free: freeSize,
            used: totalSize - freeSize
          });
        }
      } catch (e) {
        // Skip drive failures
      }
    }

    // Network IPs
    const interfaces = os.networkInterfaces();
    const networkURLs = [];
    
    // Add localhost URL
    networkURLs.push(`http://localhost:${config.port}`);
    // Add local machine hostname URL
    networkURLs.push(`http://${os.hostname().toLowerCase()}.local:${config.port}`);

    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          networkURLs.push(`http://${iface.address}:${config.port}`);
        }
      }
    }

    res.json({
      cpu: cpuUsage,
      memory: {
        total: totalMem,
        used: usedMem,
        free: freeMem
      },
      disks,
      networkURLs,
      hostname: os.hostname()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch telemetry' });
  }
});

// Serve frontend pre-built folder
const distPath = path.join(__dirname, 'dist');
app.use(express.static(distPath));

// Fallback all non-API paths to frontend index.html (React routing fallback)
app.get(/.*/, (req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return next();
  }
  const indexHtml = path.join(distPath, 'index.html');
  if (fs.existsSync(indexHtml)) {
    res.sendFile(indexHtml);
  } else {
    res.status(200).send(`
      <!DOCTYPE html>
      <html>
      <head><title>Personal File Server</title></head>
      <body style="font-family: sans-serif; background-color: #0f172a; color: #f8fafc; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0;">
        <h1>Personal File Server is Running!</h1>
        <p>The backend is active. Frontend is not compiled yet. Run Vite build to create the frontend assets.</p>
      </body>
      </html>
    `);
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// Start Server
const PORT = config.port;
app.listen(PORT, () => {
  const interfaces = os.networkInterfaces();
  console.log('==================================================');
  console.log(`🚀 Personal File Server running on port ${PORT}`);
  console.log(`   - Local:    http://localhost:${PORT}`);
  console.log(`   - Hostname: http://${os.hostname().toLowerCase()}.local:${PORT}`);
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        console.log(`   - Network:  http://${iface.address}:${PORT}`);
      }
    }
  }
  console.log('==================================================');
});
