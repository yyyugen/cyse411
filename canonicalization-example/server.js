// This is a test
// Test 2

// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Base directory for safe file access
const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// ------------------------------------------------------------
// Helper: Canonicalize + Validate Path
// ------------------------------------------------------------
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput); // Avoid bypass via encoded traversal
  } catch (e) {
    // ignore decoding errors
  }
  return path.resolve(baseDir, userInput);
}

// ------------------------------------------------------------
// SECURE ROUTE — FIXED PATH TRAVERSAL
// ------------------------------------------------------------
app.post(
  '/read',
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom(value => {
      if (value.includes('\0')) throw new Error('null byte not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const filename = req.body.filename;

    // Canonicalize safely
    const normalized = resolveSafe(BASE_DIR, filename);

    // Prevent escaping from BASE_DIR
    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }

    if (!fs.existsSync(normalized)) {
      return res.status(404).json({ error: 'File not found' });
    }

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

// ------------------------------------------------------------
// VULNERABLE ROUTE — INTENTIONALLY NOT FIXED (for the lab)
// ------------------------------------------------------------
app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';

  // ❗ This is intentionally vulnerable (Semgrep should flag it)
  const joined = path.join(BASE_DIR, filename);

  if (!fs.existsSync(joined)) {
    return res.status(404).json({ error: 'File not found', path: joined });
  }

  const content = fs.readFileSync(joined, 'utf8');
  res.json({ path: joined, content });
});

// ------------------------------------------------------------
// Sample file setup route
// ------------------------------------------------------------
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };

  Object.keys(samples).forEach(filename => {
    const filePath = path.resolve(BASE_DIR, filename);
    const dir = path.dirname(filePath);

    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(filePath, samples[filename], 'utf8');
  });

  res.json({ ok: true, base: BASE_DIR });
});

// ------------------------------------------------------------
// Start server when run directly
// ------------------------------------------------------------
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
