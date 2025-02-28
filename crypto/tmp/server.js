const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { Crypto: AESCrypto } = require('./crypto');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// AES-128-CBC key
const key = crypto.randomBytes(16);
const crypt = new AESCrypto(key);

// Secrets
const tokenCode = '[REDACTED]';
const secretCode = '[REDACTED]';
const flag = '[REDACTED]';

function encrypt(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipherBuffer = crypt.encrypt(iv, Buffer.from(plaintext, 'utf8'));
  const combinedBuffer = Buffer.concat([iv, cipherBuffer]);

  const base64Encoded = combinedBuffer.toString('base64');
  return encodeURIComponent(base64Encoded);
}

function decrypt(base64UrlText) {
  try {
    // 1) URL-decode
    const base64Decoded = decodeURIComponent(base64UrlText);

    // 2) Convert from Base64 to a Buffer of raw bytes
    const combinedBuffer = Buffer.from(base64Decoded, 'base64');
    if (combinedBuffer.length < 16) {
      throw new Error('Combined buffer too short to contain IV + ciphertext');
    }

    // 3) IV is the first 16 bytes, ciphertext is the remainder
    const iv = combinedBuffer.slice(0, 16);
    const cipherBytes = combinedBuffer.slice(16);

    // 4) Decrypt
    const plainBuffer = crypt.decrypt(iv, cipherBytes);
    return { success: true, decrypted: plainBuffer.toString('utf8') };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Serve static files (HTML, CSS, JS) from the 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// Generate an encrypted API token
app.get('/api/token', (req, res) => {
  const encryptedToken = encrypt(tokenCode);
  res.json({ token: encryptedToken });
});

/**
 * Vulnerable endpoint that expects the token as part of the URL.
 * Example call: POST /api/submit/<encryptedToken>
 */
app.post('/api/submit/:token', (req, res, next) => {
  const urlToken = req.params.token;
  if (!urlToken) {
    return res.status(400).json({ error: 'Missing token in URL' });
  }

  const decryptionResult = decrypt(urlToken);
  if (!decryptionResult.success) {
    const err = new Error(`Decryption failed: ${decryptionResult.error}`);
    err.statusCode = 400;
    return next(err);
  }

  const submittedCode = req.body.code;
  if (!submittedCode) {
    return res.status(400).json({ error: 'Missing code in request body' });
  }

  if (submittedCode === secretCode) {
    res.json({ message: `Correct code! Flag: ${flag}` });
  } else {
    res.status(400).json({ error: 'Incorrect code' });
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);

  const status = err.statusCode || 500;
  if (status === 400) {
    res.status(400).json({ error: 'Bad request: invalid token format or data' });
  } else {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});