/**
 * index.stable.js — versão mais estável com LocalAuth, QR persistente e reconexão
 *
 * Requisitos:
 * - .env com SESSION_DATA_PATH (ou use .wwebjs_auth)
 * - config.json configurado (admins, whitelist, profanity, thresholds)
 * - opcional: ADMIN_NOTIFY_WEBHOOK — URL para POST quando aparecer QR (payload: { qr: "<dataURI_or_text>" })
 *
 * Observações:
 * - LocalAuth grava sessão em <SESSION_DATA_PATH>. Monte volume para persistência.
 * - Se houver 'auth_failure' persistente, pode ser necessário remover a sessão e reautenticar manualmente.
 */

require('dotenv').config();
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcodeTerminal = require('qrcode-terminal');
const qrcode = require('qrcode'); // para gerar png
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const Database = require('better-sqlite3');
const crypto = require('crypto');

const configPath = path.join(__dirname, 'config.json');
if (!fs.existsSync(configPath)) {
  console.error('Arquivo config.json não encontrado. Copie config.example.json → config.json e ajuste.');
  process.exit(1);
}
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

// Database
const db = new Database(path.join(__dirname, 'bot.sqlite'));
db.prepare(`
  CREATE TABLE IF NOT EXISTS infractions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    chat_id TEXT,
    type TEXT,
    reason TEXT,
    timestamp INTEGER
  )
`).run();

// env
const SESSION_DATA_PATH = process.env.SESSION_DATA_PATH || '.wwebjs_auth';
const VT_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const ADMIN_NOTIFY_WEBHOOK = process.env.ADMIN_NOTIFY_WEBHOOK || '';

const client = new Client({
  authStrategy: new LocalAuth({ clientId: 'bot', dataPath: SESSION_DATA_PATH }),
  puppeteer: {
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--no-zygote',
      '--single-process',
      '--disable-gpu'
    ]
  }
});

let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 8;
const BASE_RECONNECT_MS = 5000; // 5s

function backoffDelay(attempt) {
  // exponential backoff with jitter
  const base = BASE_RECONNECT_MS * Math.pow(2, attempt);
  const jitter = Math.floor(Math.random() * 1000);
  return Math.min(base + jitter, 5 * 60 * 1000); // cap to 5min
}

function nowSec() { return Math.floor(Date.now() / 1000); }
function isAdmin(userId) { return (config.admins || []).includes(userId); }
function getUserMention(userId) { return userId.split('@')[0]; }
function logInfraction(user, chatId, type, reason) {
  db.prepare('INSERT INTO infractions (user, chat_id, type, reason, timestamp) VALUES (?, ?, ?, ?, ?)').run(user, chatId, type, reason, nowSec());
}

// in-memory structures
const floodMap = {};
const mutedUntil = {};

// helpers
const urlRegex = /(https?:\/\/[^
\s]+)/ig;
function containsLink(text = '') { return urlRegex.test(text || ''); }
function extractDomainsFromText(text = '') {
  const matches = Array.from((text || '').matchAll(urlRegex)).map(m => m[0]);
  return matches.map(u => {
    try { return new URL(u).hostname.replace(/^www\./, '').toLowerCase(); } catch { return null; }
  }).filter(Boolean);
}
function isShortener(domain) { return (config.shortenerDomains || []).includes(domain); }
function isWhitelisted(domain) { return (config.whitelistDomains || []).includes(domain); }
function containsProfanity(text = '') {
  if (!text) return false;
  const t = text.toLowerCase();
  return (config.profanity || []).some(p => p && t.includes(p.toLowerCase()));
}

// VirusTotal helpers (v3 basic checks)
async function checkUrlWithVirusTotal(url) {
  if (!VT_KEY) return { ok: null, reason: 'no_key' };
  const id = Buffer.from(url).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { 'x-apikey': VT_KEY }
    });
    const stats = res.data?.data?.attributes?.last_analysis_stats || {};
    return { ok: stats.malicious === 0 && stats.suspicious === 0, stats };
  } catch (err) {
    return { ok: null, error: err?.response?.data || err.message };
  }
}

async function checkFileBufferWithVirusTotal(buffer) {
  if (!VT_KEY) return { ok: null, reason: 'no_key' };
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      headers: { 'x-apikey': VT_KEY }
    });
    const stats = res.data?.data?.attributes?.last_analysis_stats || {};
    return { ok: stats.malicious === 0 && stats.suspicious === 0, stats, sha256 };
  } catch (err) {
    return { ok: null, error: err?.response?.data || err.message, sha256 };
  }
}

// QR helpers: save QR as PNG securely and optionally notify webhook
const QR_PATH = path.join(__dirname, 'qr.png');
async function writeQrFile(qrString) {
  try {
    // generate dataURL png
    const dataUrl = await qrcode.toDataURL(qrString, { margin: 2, scale: 6 });
    const base64 = dataUrl.split(',')[1];
    fs.writeFileSync(QR_PATH, Buffer.from(base64, 'base64'), { mode: 0o600 });
    console.log(`QR salvo em ${QR_PATH} (permissões 0600).`);
    return dataUrl;
  } catch (err) {
    console.error('Erro ao gerar qr.png:', err.message);
    return null;
  }
}

async function notifyAdminWebhook(payload) {
  if (!ADMIN_NOTIFY_WEBHOOK) return;
  try {
    await axios.post(ADMIN_NOTIFY_WEBHOOK, payload, { timeout: 5000 });
  } catch (err) {
    console.error('Falha ao notificar webhook admin:', err.message);
  }
}

// warn / delete helper
async function warnUserDirect(userId, reason) {
  try { await client.sendMessage(userId, `Você recebeu um aviso: ${reason}`); } catch {}
}

async function deleteAndLog(msg, reason, type = 'auto') {
  try { await msg.delete(true); } catch (e) { /* ignore */ }
  const userId = msg.author || msg.from;
  logInfraction(userId, msg.from, type, reason);
  await warnUserDirect(userId, reason);
}

// Command handler (same as MVP)
async function handleCommand(msg, body) {
  const chat = await msg.getChat();
  const author = msg.author || msg.from;
  if (!isAdmin(author)) return;

  const parts = body.trim().split(/\s+/);
  const cmd = parts[0].slice(1).toLowerCase();

  switch (cmd) {
    case 'help':
      await msg.reply('Comandos admin: !help, !kick @num, !ban @num, !mute @num minutos, !unmute @num, !whitelist add dominio, !whitelist remove dominio, !vtstatus url');
      break;
    case 'kick': {
      const target = parts[1];
      if (!target) return msg.reply('Uso: !kick @5511999xxxxxx@c.us');
      try {
        await chat.removeParticipants([target]);
        logInfraction(target, chat.id._serialized, 'kick', 'kick manual');
        await msg.reply(`${target} removido.`);
      } catch (err) { await msg.reply('Erro ao remover: ' + err.message); }
      break;
    }
    case 'ban': {
      const target = parts[1];
      if (!target) return msg.reply('Uso: !ban @numero');
      try {
        await chat.removeParticipants([target]);
        logInfraction(target, chat.id._serialized, 'ban', 'ban manual');
        await msg.reply(`${target} banido.`);
      } catch (err) { await msg.reply('Erro ao banir: ' + err.message); }
      break;
    }
    case 'mute': {
      const target = parts[1];
      const mins = parseInt(parts[2] || '10', 10);
      if (!target) return msg.reply('Uso: !mute @numero minutos');
      mutedUntil[target] = nowSec() + mins * 60;
      await msg.reply(`${target} mutado por ${mins} minutos.`);
      break;
    }
    case 'unmute': {
      const target = parts[1];
      if (!target) return msg.reply('Uso: !unmute @numero');
      delete mutedUntil[target];
      await msg.reply(`${target} desmutado.`);
      break;
    }
    case 'whitelist': {
      const action = parts[1];
      const domain = parts[2];
      if (!action || !domain) return msg.reply('Uso: !whitelist add|remove dominio');
      if (action === 'add') {
        config.whitelistDomains.push(domain);
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
        await msg.reply(`Dominio ${domain} adicionado.`);
      } else if (action === 'remove') {
        config.whitelistDomains = config.whitelistDomains.filter(d => d !== domain);
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
        await msg.reply(`Dominio ${domain} removido.`);
      } else await msg.reply('Ação inválida: add|remove');
      break;
    }
    case 'vtstatus': {
      const url = parts[1];
      if (!url) return msg.reply('Uso: !vtstatus https://...');
      const vt = await checkUrlWithVirusTotal(url);
      await msg.reply(`VirusTotal: ${JSON.stringify(vt)}`);
      break;
    }
    default:
      await msg.reply('Comando desconhecido. !help');
  }
}

async function handleMessage(msg) {
  if (msg.fromMe) return;
  const chat = await msg.getChat();
  if (!chat.isGroup) return;

  const userId = msg.author || msg.from;
  const text = (msg.body || '').trim();

  // Commands
  if (text.startsWith('!')) {
    await handleCommand(msg, text);
    return;
  }

  // If muted, delete message
  if (mutedUntil[userId] && mutedUntil[userId] > nowSec()) {
    await deleteAndLog(msg, 'Usuário mutado - mensagem deletada', 'mute');
    return;
  }

  // Flood detection
  const now = nowSec();
  floodMap[userId] = (floodMap[userId] || []).filter(t => t > now - config.flood.seconds);
  floodMap[userId].push(now);
  if (config.actions.autoKickOnFlood && floodMap[userId].length >= config.flood.count) {
    try {
      await chat.removeParticipants([userId]);
      logInfraction(userId, chat.id._serialized, 'flood', 'Removido por flood automático');
      await client.sendMessage(chat.id._serialized, `@${getUserMention(userId)} removido por flood.`, { mention: [userId] });
      floodMap[userId] = [];
    } catch (err) { console.error('Erro ao expulsar por flood:', err.message); }
    return;
  }

  // Links handling
  if (containsLink(text) && config.actions.autoDeleteLinks) {
    const domains = extractDomainsFromText(text);
    for (const d of domains) {
      if (!isWhitelisted(d) || isShortener(d)) {
        if (config.actions.virusTotalCheck && VT_KEY) {
          const vtRes = await checkUrlWithVirusTotal(text);
          if (vtRes.ok === false || (vtRes.stats && vtRes.stats.malicious > 0)) {
            await deleteAndLog(msg, 'Link malicioso detectado (VirusTotal)', 'link');
            return;
          }
        }
        await deleteAndLog(msg, 'Link bloqueado ou encurtador não permitido', 'link');
        return;
      }
    }
  }

  // Profanity
  if (config.actions.autoDeleteProfanity && containsProfanity(text)) {
    await deleteAndLog(msg, 'Uso de linguagem ofensiva', 'profanity');
    const infractions = db.prepare('SELECT COUNT(*) as c FROM infractions WHERE user = ? AND chat_id = ? AND timestamp > ?')
                         .get(userId, msg.from, nowSec() - 7 * 24 * 3600).c;
    if (infractions >= config.flood.warnsToKick) {
      try {
        await chat.removeParticipants([userId]);
        await client.sendMessage(chat.id._serialized, `@${getUserMention(userId)} removido por infrações repetidas.`, { mention: [userId] });
      } catch (e) {}
    }
    return;
  }

  // Media checks
  if (msg.hasMedia) {
    try {
      const media = await msg.downloadMedia();
      if (media && media.data) {
        const buffer = Buffer.from(media.data, 'base64');
        if (config.actions.virusTotalCheck && VT_KEY) {
          const vtFile = await checkFileBufferWithVirusTotal(buffer);
          if (vtFile.ok === false || (vtFile.stats && vtFile.stats.malicious > 0)) {
            await deleteAndLog(msg, 'Mídia detectada como maliciosa (VirusTotal)', 'media');
            return;
          }
        }
        const qpath = path.join(__dirname, 'quarantine');
        if (!fs.existsSync(qpath)) fs.mkdirSync(qpath);
        const ext = (media.mimetype || 'bin').split('/').pop();
        const filename = `${nowSec()}_${getUserMention(userId)}.${ext}`;
        fs.writeFileSync(path.join(qpath, filename), buffer);
      }
    } catch (err) { console.error('Erro ao processar mídia:', err.message); }
  }
}

// event handlers & reconnection logic
client.on('qr', async qr => {
  try {
    qrcodeTerminal.generate(qr, { small: true });
    console.log('QR recebido. Gerando qr.png e notificando admin (se configurado).');
    const dataUrl = await writeQrFile(qr);
    // Notify webhook with the QR dataURI or raw string (admin can decide)
    await notifyAdminWebhook({ event: 'qr', data_url: dataUrl, timestamp: nowSec() });
    reconnectAttempts = 0; // reset attempts on fresh QR
  } catch (err) {
    console.error('Erro no evento qr:', err.message);
  }
});

client.on('authenticated', () => {
  console.log('Autenticado com sucesso.');
  // remove qr.png after auth to avoid leaving it on disk
  try { if (fs.existsSync(QR_PATH)) fs.unlinkSync(QR_PATH); } catch {}
});

client.on('auth_failure', async msg => {
  console.error('Falha de autenticação:', msg);
  await notifyAdminWebhook({ event: 'auth_failure', message: String(msg), timestamp: nowSec() });
  // try to re-init after small delay; but if persists, manual intervention required
  scheduleReconnect();
});

client.on('ready', () => {
  console.log('Client pronto e operacional.');
  reconnectAttempts = 0;
});

client.on('disconnected', async (reason) => {
  console.warn('Desconectado:', reason);
  await notifyAdminWebhook({ event: 'disconnected', reason, timestamp: nowSec() });
  scheduleReconnect();
});

// schedule reconnect with backoff
function scheduleReconnect() {
  if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
    console.error('Máximo de tentativas de reconexão atingido. Requer intervenção manual.');
    return;
  }
  const delay = backoffDelay(reconnectAttempts);
  reconnectAttempts++;
  console.log(`Tentativa de reconexão #${reconnectAttempts} em ${Math.round(delay/1000)}s...`);
  setTimeout(async () => {
    try {
      // try destroy and re-initialize client
      await client.destroy().catch(()=>{});
      client.initialize();
    } catch (err) {
      console.error('Re-initialize falhou:', err.message);
      scheduleReconnect();
    }
  }, delay);
}

// welcome handler
client.on('group_participants_change', async (chatId, participants, action) => {
  try {
    if (action === 'add') {
      const chat = await client.getChatById(chatId);
      for (const p of participants) {
        await client.sendMessage(chatId, `${config.welcomeMessage}`, { mention: [p] });
      }
    }
  } catch (err) {
    console.error('Erro no welcome:', err.message);
  }
});

client.on('message', async msg => {
  try { await handleMessage(msg); } catch (err) { console.error('handleMessage:', err.message); }
});

// Graceful shutdown
async function shutdown() {
  console.log('Shutdown iniciado...');
  try {
    await client.destroy();
  } catch (e) { /* ignore */ }
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// initialize
client.initialize();
