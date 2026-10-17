/**
 * index.js - legacy MVP entry (kept for reference). Use index.stable.js in production.
 *
 * Basic implementation: auto-delete links, profanity, flood detection, media quarantine.
 */

require('dotenv').config();
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
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

const SESSION_DATA_PATH = process.env.SESSION_DATA_PATH || '.wwebjs_auth';

const client = new Client({
  authStrategy: new LocalAuth({ clientId: 'bot' }),
  puppeteer: { headless: true },
  session: undefined
});

client.on('qr', qr => {
  qrcode.generate(qr, { small: true });
  console.log('QR gerado. Escaneie com o WhatsApp do número que será o bot.');
});

client.on('ready', () => {
  console.log('WhatsApp client pronto.');
});

function nowSec() { return Math.floor(Date.now() / 1000); }
function isAdmin(userId) { return (config.admins || []).includes(userId); }
function getUserMention(userId) { return userId.split('@')[0]; }

function logInfraction(user, chatId, type, reason) {
  db.prepare('INSERT INTO infractions (user, chat_id, type, reason, timestamp) VALUES (?, ?, ?, ?, ?)').run(user, chatId, type, reason, nowSec());
}

// In-memory structures (MVP). Para produção, mover para Redis.
const floodMap = {}; // { userId: [timestamps] }
const mutedUntil = {}; // { userId: unixTimestamp }

// Util helpers
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

async function handleMessage(msg) {
  // ignore own messages
  if (msg.fromMe) return;

  const chat = await msg.getChat();
  if (!chat.isGroup) return; // only groups for now

  const author = msg.author || msg.from; // msg.author exists for group messages
  const userId = author || msg.from;
  // mute enforcement
  if (mutedUntil[userId] && mutedUntil[userId] > nowSec()) {
    try { await msg.delete(true); } catch(e){/* ignore */ }
    return;
  }

  const body = (msg.body || '').trim();

  // Command parsing (admins only)
  if (body.startsWith('!') && isAdminNumber(userId)) {
    await handleCommand(msg, body);
    return;
  }

  // Auto moderation only if enabled
  if (config.antispam && config.antispam.enabled) {
    // Flood detection
    const t = nowSec();
    messageTimes[userId] = (messageTimes[userId] || []).filter(ts => ts > t - config.thresholds.flood_period_seconds);
    messageTimes[userId].push(t);
    if (messageTimes[userId].length >= config.thresholds.flood_count) {
      // Kick user
      try {
        await chat.removeParticipants([userId]);
        logInfraction(userId, chat.id._serialized, 'flood', 'Flood auto-kick');
        await client.sendMessage(chat.id._serialized, `@${userId.split('@')[0]} expulso por flood (auto)`, { mention: [ userId ] });
      } catch(e) { console.error('Erro ao expulsar por flood:', e.message); }
      messageTimes[userId] = [];
      return;
    }
  }

  // Links: delete if not whitelisted or shortener present
  if (containsLink(body)) {
    const m = body.match(urlRegex);
    const domain = extractDomain(m && m[0]);
    if (domain && (!isWhitelisted(domain) || isShortener(domain))) {
      try { await msg.delete(true); } catch(e){ console.error('delete failed', e.message); }
      warnUser(userId, chat, 'Envio de link não permitido ou link encurtado');
      logInfraction(userId, chat.id._serialized, 'link', domain || 'unknown');
      return;
    }
  }

  // Profanity check
  if (containsProfanity(body)) {
    try { await msg.delete(true); } catch(e){ console.error('delete failed', e.message); }
    warnUser(userId, chat, 'Uso de linguagem ofensiva');
    logInfraction(userId, chat.id._serialized, 'profanity', body);
    // optional auto-mute/auto-kick after repeated infractions
    const infractions = db.prepare('SELECT COUNT(*) as c FROM infractions WHERE user = ? AND chat_id = ? AND timestamp > ?')
                         .get(userId, chat.id._serialized, nowSec() - 7*24*3600).c;
    if (infractions >= config.thresholds.warns_to_kick) {
      try {
        await chat.removeParticipants([userId]);
        client.sendMessage(chat.id._serialized, `@${userId.split('@')[0]} expulso por infrações repetidas`, { mention: [ userId ] });
      } catch(e){ console.error('kick failed', e.message); }
    }
    return;
  }

  // other automated behaviors (e.g., quarantine media) can be added here
}

async function handleCommand(msg, body) {
  const chat = await msg.getChat();
  const parts = body.split(/\s+/);
  const cmd = parts[0].slice(1).toLowerCase();

  const author = msg.author || msg.from;
  const userId = author || msg.from;

  switch(cmd) {
    case 'help':
      await msg.reply('Comandos admin: !ban @num, !kick @num, !mute @num <min>, !unmute @num, !whitelist add domain, !whitelist remove domain');
      break;
    case 'kick':
    case 'ban': {
      const target = parts[1];
      if (!target) return await msg.reply('especifique @numero');
      try {
        await chat.removeParticipants([target]);
        logInfraction(target, chat.id._serialized, cmd, 'comando manual');
        await msg.reply(`${target} removido.`);
      } catch(e) { await msg.reply('Erro ao remover: ' + e.message); }
      break;
    }
    case 'mute': {
      const target = parts[1];
      const mins = parseInt(parts[2] || '60', 10);
      if (!target) return msg.reply('especifique @numero');
      mutedUntil[target] = nowSec() + mins*60;
      await msg.reply(`${target} mutado por ${mins} minutos.`);
      break;
    }
    case 'unmute': {
      const target = parts[1];
      if (!target) return msg.reply('especifique @numero');
      delete mutedUntil[target];
      await msg.reply(`${target} desmutado.`);
      break;
    }
    case 'whitelist': {
      const action = parts[1];
      const domain = parts[2];
      if (!action || !domain) return msg.reply('uso: !whitelist add|remove dominio');
      if (action === 'add') {
        config.whitelist_domains.push(domain);
        fs.writeFileSync(path.resolve(__dirname,'config.json'), JSON.stringify(config, null, 2));
        await msg.reply(`Dominio ${domain} adicionado à whitelist.`);
      } else if (action === 'remove') {
        config.whitelist_domains = config.whitelist_domains.filter(d => d !== domain);
        fs.writeFileSync(path.resolve(__dirname,'config.json'), JSON.stringify(config, null, 2));
        await msg.reply(`Dominio ${domain} removido da whitelist.`);
      }
      break;
    }
    default:
      await msg.reply('Comando desconhecido. !help');
  }
}

function warnUser(userId, chat, reason) {
  try {
    client.sendMessage(userId, `Você recebeu um aviso no grupo ${chat.name}: ${reason}`).catch(()=>{});
  } catch(e) {}
}

function logInfraction(user, chatId, type, reason) {
  db.prepare('INSERT INTO infractions (user, chat_id, type, reason, timestamp) VALUES (?, ?, ?, ?, ?)')
    .run(user, chatId, type, reason, nowSec());
}

// welcome on participants added
client.on('group_join', async notification => {
  // whatsapp-web.js may emit 'group_join' or 'group_join' on chat events depending on version.
  console.log('group join event:', notification);
});

// robust event depending on library: listen to 'group_join' or 'group_join' handlers
client.on('group_participants_change', async (chatId, participants, action) => {
  try {
    const chat = await client.getChatById(chatId);
    if (action === 'add') {
      for (let p of participants) {
        await client.sendMessage(chatId, `${config.welcomeMessage}`, { mention: [p] });
      }
    }
  } catch(e) { console.error(e); }
});

// core message handlers
client.on('message', async msg => {
  try {
    await handleMessage(msg);
  } catch(e) { console.error('handleMessage error', e); }
});

client.initialize();
