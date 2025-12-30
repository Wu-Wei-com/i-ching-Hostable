// server.js
'use strict';

const http = require('http');
const { URL } = require('url');

const iChing = require('./index.js');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';

// If set, requests must provide either:
//   - header: x-api-key: <API_KEY>
//   - OR header: authorization: Bearer <API_KEY>
const API_KEY = process.env.API_KEY || '';

// Simple in-memory rate limit (per IP)
const RL_WINDOW_MS = parseInt(process.env.RL_WINDOW_MS || '60000', 10); // 60s
const RL_MAX = parseInt(process.env.RL_MAX || '120', 10);              // 120 req / window
const rate = new Map(); // ip -> { count, resetAt }

function now() { return Date.now(); }

function getClientIp(req) {
  // Caddy will set X-Forwarded-For. Prefer the left-most value.
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) return xff.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function rateLimitOk(ip) {
  const t = now();
  const entry = rate.get(ip);
  if (!entry || t > entry.resetAt) {
    rate.set(ip, { count: 1, resetAt: t + RL_WINDOW_MS });
    return true;
  }
  entry.count += 1;
  return entry.count <= RL_MAX;
}

function setSecurityHeaders(res) {
  // Caddy will also set headers; defense-in-depth.
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', Buffer.byteLength(body));
  setSecurityHeaders(res);
  res.end(body);
}

function sendText(res, status, text) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Length', Buffer.byteLength(text));
  setSecurityHeaders(res);
  res.end(text);
}

function unauthorized(res) {
  sendJson(res, 401, { error: 'unauthorized' });
}

function tooMany(res) {
  sendJson(res, 429, { error: 'rate_limited' });
}

function badRequest(res, msg) {
  sendJson(res, 400, { error: 'bad_request', message: msg });
}

function readJsonBody(req, maxBytes = 32 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('payload_too_large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        if (!raw) return resolve({});
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(new Error('invalid_json'));
      }
    });

    req.on('error', () => reject(new Error('read_error')));
  });
}

function authOk(req) {
  if (!API_KEY) return true;
  const apiKey = req.headers['x-api-key'];
  if (typeof apiKey === 'string' && apiKey === API_KEY) return true;

  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) {
    const token = auth.slice('Bearer '.length);
    if (token === API_KEY) return true;
  }
  return false;
}

const server = http.createServer(async (req, res) => {
  try {
    const ip = getClientIp(req);
    if (!rateLimitOk(ip)) return tooMany(res);

    if (!authOk(req) && req.url !== '/healthz') return unauthorized(res);

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;

    if (req.method === 'GET' && path === '/healthz') {
      return sendJson(res, 200, { ok: true });
    }

    // POST /ask  { "question": "..." }
    if (req.method === 'POST' && path === '/ask') {
      const body = await readJsonBody(req);
      const question = (body.question || '').toString().trim();
      if (!question) return badRequest(res, 'question is required');

      const reading = iChing.ask(question);
      return sendJson(res, 200, reading);
    }

    // GET /hexagram/3
    if (req.method === 'GET' && path.startsWith('/hexagram/')) {
      const n = parseInt(path.split('/')[2], 10);
      if (!Number.isInteger(n) || n < 1 || n > 64) return badRequest(res, 'hexagram number must be 1..64');
      return sendJson(res, 200, iChing.hexagram(n));
    }

    // GET /trigram/8
    if (req.method === 'GET' && path.startsWith('/trigram/')) {
      const n = parseInt(path.split('/')[2], 10);
      if (!Number.isInteger(n) || n < 1 || n > 8) return badRequest(res, 'trigram number must be 1..8');
      return sendJson(res, 200, iChing.trigram(n));
    }

    return sendText(res, 404, 'not found');
  } catch (e) {
    // Avoid leaking internals
    return sendJson(res, 500, { error: 'internal_error' });
  }
});

server.listen(PORT, HOST, () => {
  // Only logs to stdout (picked up by docker logs)
  console.log(`i-ching API listening on http://${HOST}:${PORT}`);
});
