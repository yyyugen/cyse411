//Testing for SAST 
//2nd Test

const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// simple in-memory rate limiter
const rateLimitWindowMs = 60 * 1000;
const rateLimitMaxRequests = 20;
const rateLimitStore = new Map();

function rateLimiter(req, res, next) {
  const key = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  const now = Date.now();
  let entry = rateLimitStore.get(key);

  if (!entry || now - entry.start > rateLimitWindowMs) {
    entry = { count: 0, start: now };
  }

  entry.count += 1;
  rateLimitStore.set(key, entry);

  if (entry.count > rateLimitMaxRequests) {
    return res.status(429).json({ error: 'Too many requests, please try again later' });
  }

  next();
}

function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

app.post(
  '/read',
  rateLimiter,
  body('filename')
    .exists()
    .bail()
    .isString()
    .trim()
    .notEmpty()
    .custom(value => {
      if (value.includes('\0')) throw new Error();
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);

    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }

    if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found' });

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

app.post('/read-no-validate', rateLimiter, (req, res) => {
  const filename = req.body.filename || '';
  const safePath = path.resolve(BASE_DIR, filename);

  if (!safePath.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: 'Path traversal detected' });
  }

  if (!fs.existsSync(safePath)) {
    return res.status(404).json({ error: 'File not found', path: safePath });
  }

  const content = fs.readFileSync(safePath, 'utf8');
  res.json({ path: safePath, content });
});

app.post('/setup-sample', rateLimiter, (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };

  Object.keys(samples).forEach(filename => {
    const filePath = path.resolve(BASE_DIR, filename);
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, samples[filename], 'utf8');
  });

  res.json({ ok: true, base: BASE_DIR });
});

if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
