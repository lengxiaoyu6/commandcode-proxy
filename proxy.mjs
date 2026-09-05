/**
 * Command Code → OpenAI 兼容代理
 * 基于真实 CLI 流量抓包数据构建
 */
import http from 'http';
import crypto from 'crypto';
import { randomUUID } from 'crypto';
import { readFileSync, existsSync, appendFileSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

// ── 配置加载 ──────────────────────────────────────
const __dirname = dirname(fileURLToPath(import.meta.url));

function loadConfig() {
  const defaults = {
    port: 3000,
    host: '0.0.0.0',
    apiBase: 'https://api.commandcode.ai',
    projectSlug: 'cc-proxy',
    logFile: '',
    logLevel: 'info',
    useProviderModels: true,
    modelRefreshIntervalMs: 5 * 60 * 1000,  // 5 minutes
    zdr: false,
    adminPassword: '',  // 管理页密码；留空则 /admin 返回 403
    keysFile: 'keys.json',  // key 存储路径；可绝对路径（容器挂载持久化用）
  };

  const configPath = resolve(__dirname, 'config.json');
  if (existsSync(configPath)) {
    try {
      const user = JSON.parse(readFileSync(configPath, 'utf-8'));
      Object.assign(defaults, user);
    } catch (e) {
      console.error('[config] Failed to parse config.json:', e.message);
    }
  }

  // 环境变量覆写
  if (process.env.PORT) defaults.port = parseInt(process.env.PORT);
  if (process.env.HOST) defaults.host = process.env.HOST;
  if (process.env.CC_API_BASE) defaults.apiBase = process.env.CC_API_BASE;
  if (process.env.PROJECT_SLUG) defaults.projectSlug = process.env.PROJECT_SLUG;
  if (process.env.LOG_FILE) defaults.logFile = process.env.LOG_FILE;
  if (process.env.CC_USE_PROVIDER_MODELS) defaults.useProviderModels = process.env.CC_USE_PROVIDER_MODELS !== 'false';
  if (process.env.CMD_ZDR !== undefined) defaults.zdr = process.env.CMD_ZDR === '1';
  if (process.env.ADMIN_PASSWORD) defaults.adminPassword = process.env.ADMIN_PASSWORD;
  if (process.env.KEYS_FILE) defaults.keysFile = process.env.KEYS_FILE;

  return defaults;
}

const CFG = loadConfig();

// ── 指纹生成（首次运行自动生成，写回 config.json） ──────
// CPU 型号与核心数对应表（仅 Windows x64）
const FINGERPRINT_CPUS = [
  { model: '12th Gen Intel(R) Core(TM) i7-12650H', cores: 10 },
  { model: '12th Gen Intel(R) Core(TM) i5-12400F', cores: 6 },
  { model: '12th Gen Intel(R) Core(TM) i9-12900K', cores: 16 },
  { model: '13th Gen Intel(R) Core(TM) i7-13700K', cores: 16 },
  { model: '13th Gen Intel(R) Core(TM) i5-13600K', cores: 14 },
  { model: '13th Gen Intel(R) Core(TM) i9-13900K', cores: 24 },
  { model: 'Intel(R) Core(TM) Ultra 7 155H', cores: 16 },
  { model: 'Intel(R) Core(TM) Ultra 9 285H', cores: 16 },
  { model: 'Intel(R) Core(TM) i9-14900K', cores: 24 },
  { model: 'Intel(R) Core(TM) i7-14700K', cores: 20 },
  { model: 'AMD Ryzen 7 7800X3D', cores: 8 },
  { model: 'AMD Ryzen 9 7950X', cores: 16 },
  { model: 'AMD Ryzen 5 7600', cores: 6 },
  { model: 'AMD Ryzen 9 7900X', cores: 12 },
  { model: 'AMD Ryzen 7 5800X3D', cores: 8 },
];
const FINGERPRINT_MEMS = [8, 16, 24, 32, 48, 64];
const FINGERPRINT_TZS = [
  'America/New_York', 'America/Chicago', 'America/Los_Angeles', 'America/Toronto',
  'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'Europe/Moscow',
  'Asia/Shanghai', 'Asia/Tokyo', 'Asia/Singapore', 'Asia/Seoul', 'Asia/Hong_Kong',
  'Australia/Sydney', 'Pacific/Auckland',
];
const FINGERPRINT_MAC_COUNT_RANGE = [2, 3, 4, 5]; // 随机 2~5 个 MAC

function generateFingerprint() {
  const cpuEntry = FINGERPRINT_CPUS[Math.floor(Math.random() * FINGERPRINT_CPUS.length)];
  const memGiB = FINGERPRINT_MEMS[Math.floor(Math.random() * FINGERPRINT_MEMS.length)];
  const tz = FINGERPRINT_TZS[Math.floor(Math.random() * FINGERPRINT_TZS.length)];
  const macCount = FINGERPRINT_MAC_COUNT_RANGE[Math.floor(Math.random() * FINGERPRINT_MAC_COUNT_RANGE.length)];

  function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
  function randHex(n) { return crypto.randomBytes(n).toString('hex'); }

  const macHashes = [];
  for (let i = 0; i < macCount; i++) macHashes.push(sha256(randHex(32)));

  const machineIdHash = sha256(randHex(32));
  const osUserHash = sha256(randHex(16));
  const hostnameHash = sha256(randHex(16));
  const gitEmailHash = sha256(randHex(16));

  // thumbmark = 所有组件的联合哈希
  const thumbData = [machineIdHash, ...macHashes, osUserHash, hostnameHash, gitEmailHash, 'win32', '10.0.22631', cpuEntry.model, String(cpuEntry.cores), String(memGiB)].join('|');
  const thumbmark = sha256(thumbData);

  return {
    thumbmark,
    components: {
      machineIdHash,
      macHashes,
      osUserHash,
      hostnameHash,
      gitEmailHash,
      platform: 'win32',
      arch: 'x64',
      osRelease: '10.0.22631',
      cpuModel: cpuEntry.model,
      cpuCount: cpuEntry.cores,
      memGiB,
      isContainer: false,
      timezone: tz,
      runtime: 'cli',
      collectorVersion: 1,
    },
  };
}

let CC_VERSION = '0.32.3';
const CC_VERSION_FALLBACK = '0.32.3';
const CC_VERSION_REFRESH_MS = 24 * 60 * 60 * 1000; // 24h — npm registry 刷新间隔

// ── 动态 CC 版本号（从 npm registry 拉取） ─────────────
async function refreshCCVersion() {
  try {
    const url = 'https://registry.npmjs.org/command-code/latest';
    const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`npm responded with ${res.status}`);
    const pkg = await res.json();
    if (pkg.version && typeof pkg.version === 'string') {
      CC_VERSION = pkg.version;
      log('info', 'CC Version refreshed from npm', { version: CC_VERSION });
    }
  } catch (e) {
    log('warn', 'CC Version fetch failed, using current', { version: CC_VERSION, error: e.message });
  }
}
refreshCCVersion(); // 启动时立即拉取
setInterval(refreshCCVersion, CC_VERSION_REFRESH_MS);

// 请求体大小上限：默认 100MB，可用环境变量 CC_MAX_BODY_MB 覆盖（正整数，单位 MB）
const MAX_BODY_SIZE = (() => {
  const mb = Number.parseInt(process.env.CC_MAX_BODY_MB ?? '', 10);
  return Number.isFinite(mb) && mb > 0 ? mb * 1024 * 1024 : 100 * 1024 * 1024;
})();
const STREAM_IDLE_TIMEOUT_MS = 30000;   // 30s — 流式无新数据中断
const NONSTREAM_IDLE_TIMEOUT_MS = 90000; // 90s — 非流式超时更宽容

// 连续超时计数：连续 3 次超时才提醒压缩上下文，任意成功请求后重置
let consecutiveTimeouts = 0;
const TIMEOUT_REDUCE_CONTEXT_THRESHOLD = 3;

// ── 日志 ─────────────────────────────────────────────
function log(level, msg, data) {
  const line = `[${new Date().toISOString()}] [${level}] ${msg}${data ? ' ' + JSON.stringify(data) : ''}`;
  console.log(line);
  if (CFG.logFile) {
    try { appendFileSync(CFG.logFile, line + '\n', 'utf-8'); } catch {}
  }
}

// ── 管理页（多 Key 用量查询） ─────────────────────
// keys.json 存 key 池（已被 gitignore，勿提交真实 key）：
//   { "keys": [{ "name": "主号", "key": "user_...", "note": "" }] }
// 密码：config.json 的 adminPassword 或环境变量 ADMIN_PASSWORD（留空则禁用管理页）
// key 文件路径：config.json 的 keysFile 或环境变量 KEYS_FILE。
//   容器部署建议挂载数据目录并指向卷内路径，避免 rebuild 丢数据。
const ADMIN_KEYS_FILE = resolve(__dirname, CFG.keysFile || 'keys.json');
const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 登录会话 12h
const adminSessions = new Map(); // sessionToken -> expiresAt

function loadAdminKeys() {
  try {
    if (!existsSync(ADMIN_KEYS_FILE)) return [];
    const raw = JSON.parse(readFileSync(ADMIN_KEYS_FILE, 'utf-8'));
    const arr = Array.isArray(raw) ? raw : raw.keys;
    if (!Array.isArray(arr)) return [];
    return arr
      .filter(e => e && typeof e.key === 'string' && /^user_[A-Za-z0-9_-]+/.test(e.key.trim()))
      .map(e => ({
        name: String(e.name || e.key.slice(0, 12)),
        key: e.key.trim(),
        note: e.note ? String(e.note) : '',
      }));
  } catch (e) {
    log('error', 'Failed to parse keys.json', { error: e.message });
    return [];
  }
}

function saveAdminKeys(keys) {
  const payload = { keys };
  try {
    writeFileSync(ADMIN_KEYS_FILE, JSON.stringify(payload, null, 2) + '\n', 'utf-8');
    return true;
  } catch (e) {
    log('error', 'Failed to write keys.json', { error: e.message });
    return false;
  }
}

function adminEnabled() {
  return typeof CFG.adminPassword === 'string' && CFG.adminPassword.length > 0;
}

function adminPasswordOk(req) {
  const supplied =
    (req.headers['x-admin-password'] || '').trim()
    || (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '').trim()
    || (parseCookies(req).admin || '');
  return supplied.length > 0 && supplied === CFG.adminPassword;
}

function parseCookies(req) {
  const out = {};
  const h = req.headers.cookie || '';
  for (const part of h.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      if (k) out[k] = decodeURIComponent(v);
    }
  }
  return out;
}

function issueAdminSession(res) {
  const token = randomUUID().replace(/-/g, '');
  adminSessions.set(token, Date.now() + ADMIN_SESSION_TTL_MS);
  res.setHeader('Set-Cookie', `admin_session=${token}; HttpOnly; Path=/admin; SameSite=Lax; Max-Age=${Math.floor(ADMIN_SESSION_TTL_MS / 1000)}`);
  return token;
}

function adminSessionOk(req) {
  const token = parseCookies(req).admin_session;
  if (!token) return false;
  const exp = adminSessions.get(token);
  if (!exp) return false;
  if (Date.now() > exp) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

// 定期清理过期 admin 会话
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [token, exp] of adminSessions) {
    if (now > exp) { adminSessions.delete(token); cleaned++; }
  }
  if (cleaned > 0) log('info', 'Admin session cleanup', { cleaned });
}, 60 * 60 * 1000);

// ── 会话管理 ───────────────────────────────────────
// 每个 API Key 独立一个 session，12h 过期 + 1h 随机抖动
// 同一 Key 在同一周期内复用，到期自动换新
const SESSION_DURATION_MS = 12 * 60 * 60 * 1000;    // 12h
const SESSION_JITTER_MS  = 60 * 60 * 1000;           // 1h 抖动范围

const sessionStore = new Map(); // apiKey → { sessionId, expiresAt }

function ensureSession(apiKey) {
  const now = Date.now();
  const entry = sessionStore.get(apiKey);

  if (entry && now < entry.expiresAt) {
    return entry.sessionId;
  }

  // 过期或第一次：生成新 session
  const jitter = Math.floor(Math.random() * SESSION_JITTER_MS);
  const sessionId = randomUUID();
  sessionStore.set(apiKey, { sessionId, expiresAt: now + SESSION_DURATION_MS + jitter });
      log('info', 'Session created', { sessionId: sessionId.slice(0, 8), storeSize: sessionStore.size });
  return sessionId;
}

// 定期清理过期 session 和 key 状态，防止 Map 无限增长
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [key, entry] of sessionStore) {
    if (now >= entry.expiresAt) {
      sessionStore.delete(key);
      keyStateStore.delete(key); // 同时清理该 key 的指纹状态
      cleaned++;
    }
  }
  if (cleaned > 0) log('info', 'Session cleanup', { cleaned, remaining: sessionStore.size });
}, 60 * 60 * 1000); // 每小时

function getSessionId(incomingHeaders, apiKey, promptCacheKey) {
  // 优先从客户端传来的 session 类 header 获取
  const candidates = [
    incomingHeaders['x-session-id'],
    incomingHeaders['x-claude-code-session-id'],
    incomingHeaders['session_id'],
    promptCacheKey,
  ];
  for (const id of candidates) {
    if (id && typeof id === 'string' && id.length >= 8) return id;
  }
  // 按 API Key 分 session
  return ensureSession(apiKey);
}

// 每个请求独立 thread ID
function newThreadId() { return randomUUID(); }

// ── 每 Key 独立状态（fingerprint + 初始化节流） ──
// 每个 API Key 拥有自己的设备指纹和初始化定时器
const keyStateStore = new Map(); // apiKey → { fingerprint, nextInitAt }

function getOrCreateKeyState(apiKey) {
  let state = keyStateStore.get(apiKey);
  if (!state) {
    state = {
      fingerprint: generateFingerprint(),
      nextInitAt: 0,
    };
    keyStateStore.set(apiKey, state);
    log('info', 'Fingerprint generated for key', { keyPrefix: apiKey.slice(0, 8) });
  }
  return state;
}

// ── 初始化预请求（fingerprint + lifecycle，首次 + 每 8h+2h 抖动） ────
const INIT_REFRESH_MS = 8 * 60 * 60 * 1000;    // 8h
const INIT_JITTER_MS  = 2 * 60 * 60 * 1000;    // 2h 抖动

async function ensureInitialized(apiKey, signal) {
  const state = getOrCreateKeyState(apiKey);
  const now = Date.now();
  if (now < state.nextInitAt) return;

  try {
    // 并行发两个预请求
    const headers = {
      'Content-Type': 'application/json',
      'x-cli-environment': 'production',
      'Authorization': `Bearer ${apiKey}`,
      'x-command-code-version': CC_VERSION,
      ...(CFG.zdr ? { 'x-cmd-zdr': '1' } : {}),
    };
    const fingerprint = state.fingerprint || {};

    await Promise.all([
      fetch(`${CFG.apiBase}/alpha/fingerprint/record`, {
        method: 'POST', headers, signal,
        body: JSON.stringify(fingerprint),
      }).then(r => {
        if (!r.ok) log('warn', 'Fingerprint record failed', { status: r.status });
        else log('info', 'Fingerprint recorded');
      }).catch(e => {
        if (e.name !== 'AbortError') log('warn', 'Fingerprint record error', { error: e.message });
      }),

      fetch(`${CFG.apiBase}/alpha/lifecycle-events`, {
        method: 'POST', headers, signal,
        body: JSON.stringify({
          eventType: 'cli_session_exists',
          metadata: {
            sessionId: `sess_${crypto.randomBytes(8).toString('hex')}`,
            cliVersion: CC_VERSION,
            mode: 'interactive',
            os: `${fingerprint.components.platform}-${fingerprint.components.arch}`,
          },
        }),
      }).then(r => {
        if (!r.ok) log('warn', 'Lifecycle event failed', { status: r.status });
        else log('info', 'Lifecycle event sent');
      }).catch(e => {
        if (e.name !== 'AbortError') log('warn', 'Lifecycle event error', { error: e.message });
      }),
    ]);

    // 成功：8h + 2h 随机抖动
    const jitter = Math.floor(Math.random() * INIT_JITTER_MS);
    state.nextInitAt = Date.now() + INIT_REFRESH_MS + jitter;
    log('info', 'Fingerprint/lifecycle next refresh', { nextIn: `${(INIT_REFRESH_MS + jitter) / 3600000}h` });
  } catch (e) {
    if (e.name !== 'AbortError') log('warn', 'Fingerprint/lifecycle refresh error, will retry next request', { error: e.message });
  }
}

// ── 模型列表 ───────────────────────────────────────
const MODELS = [
  // Anthropic
  { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6' },
  { id: 'claude-opus-4-8', name: 'Claude Opus 4.8' },
  { id: 'claude-opus-4-7', name: 'Claude Opus 4.7' },
  { id: 'claude-haiku-4-5-20251001', name: 'Claude Haiku 4.5' },
  // OpenAI
  { id: 'gpt-5.5', name: 'GPT-5.5' },
  { id: 'gpt-5.4', name: 'GPT-5.4' },
  { id: 'gpt-5.4-mini', name: 'GPT-5.4 Mini' },
  { id: 'gpt-5.3-codex', name: 'GPT-5.3 Codex' },
  // DeepSeek
  { id: 'deepseek/deepseek-v4-pro', name: 'DeepSeek V4 Pro' },
  { id: 'deepseek/deepseek-v4-flash', name: 'DeepSeek V4 Flash' },
  // Kimi
  { id: 'moonshotai/Kimi-K2.6', name: 'Kimi K2.6' },
  { id: 'moonshotai/Kimi-K2.5', name: 'Kimi K2.5' },
  // GLM
  { id: 'zai-org/GLM-5.1', name: 'GLM 5.1' },
  { id: 'zai-org/GLM-5', name: 'GLM 5' },
  // MiniMax
  { id: 'MiniMaxAI/MiniMax-M3', name: 'MiniMax M3' },
  { id: 'MiniMaxAI/MiniMax-M2.7', name: 'MiniMax M2.7' },
  { id: 'MiniMaxAI/MiniMax-M2.5', name: 'MiniMax M2.5' },
  // Qwen
  { id: 'Qwen/Qwen3.6-Max-Preview', name: 'Qwen 3.6 Max Preview' },
  { id: 'Qwen/Qwen3.6-Plus', name: 'Qwen 3.6 Plus' },
  { id: 'Qwen/Qwen3.7-Max', name: 'Qwen 3.7 Max' },
  // Step
  { id: 'stepfun/Step-3.7-Flash', name: 'Step 3.7 Flash' },
  { id: 'stepfun/Step-3.5-Flash', name: 'Step 3.5 Flash' },
  // Xiaomi
  { id: 'xiaomi/mimo-v2.5-pro', name: 'MiMo V2.5 Pro' },
  { id: 'xiaomi/mimo-v2.5', name: 'MiMo V2.5' },
  // Gemini
  { id: 'google/gemini-3.5-flash', name: 'Gemini 3.5 Flash' },
  { id: 'google/gemini-3.1-flash-lite', name: 'Gemini 3.1 Flash Lite' },
];

// ── 工具函数 ───────────────────────────────────────

// 从 sessionId 构造一个假的工作目录路径，再按真实 CLI 规则生成 slug
// 结果形如 "d-users-dev-projects-web-app-a3f2" (和真实 CLI 的 slug 格式一致)
function fakeProjectSlug(sessionId) {
  const names = ['app', 'api', 'backend', 'bot', 'cli', 'core', 'data', 'frontend',
    'lib', 'plugin', 'proxy', 'server', 'service', 'tool', 'web', 'worker'];
  const id = String(sessionId || '');
  const head = id.slice(0, 4);
  // sessionId 既可能是随机 UUID（前 4 位十六进制），也可能是客户端自定义的
  // prompt_cache_key（如 "my-stable-cache-key-001"）。后者按 16 进制解析得 NaN，
  // 会让 slug 变成 "…-undefined-my-s"。失败时退化为确定性字符哈希。
  let idx = parseInt(head, 16);
  if (!Number.isFinite(idx)) {
    let h = 0;
    for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
    idx = h;
  }
  const name = names[idx % names.length];
  const suffix = head || '0000';
  // 模拟一个类似 C:\Users\dev\projects\{name}-{suffix} 的路径
  const path = `C:\\Users\\dev\\projects\\${name}-${suffix}`;
  return path
    .toLowerCase()
    .replace(/^[a-z]:/i, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function generateTraceparent() {
  const traceId = crypto.randomBytes(16).toString('hex');
  const parentId = crypto.randomBytes(8).toString('hex');
  return `00-${traceId}-${parentId}-01`;
}

function nowUnix() {
  return Math.floor(Date.now() / 1000);
}

function getDateStr() {
  return new Date().toISOString().slice(0, 10);
}

function getEnvironment() {
  return `${process.platform}-${process.arch}, Node.js ${process.version.slice(1)}`;
}

// ── CC 请求体构建 ─────────────────────────────────

function buildCcRequest(openaiReq) {
  const { model, messages, max_tokens, temperature, tools, stream, reasoning_effort, tool_choice, parallel_tool_calls, prompt_cache_key } = openaiReq;

  // 提取系统提示，OpenAI 的 system 与 developer 均映射为系统提示
  // 数组型 content 必须展开取 text 后拼成「字符串」，而不是转成 JSON 字符串，
  // 更不能输出 Anthropic 风格的 content 块数组：CC 上游要求 params.system 恒为
  // 字符串，传数组会被直接拒绝（真机验证：
  // Validation error: Invalid input: expected string, received array at "params.system"）。
  const systemMsgs = messages.filter(m => m.role === 'system' || m.role === 'developer');
  const systemPrompt = systemMsgs.map(m => {
    if (typeof m.content === 'string') return m.content;
    if (Array.isArray(m.content)) return m.content.map(c => c?.text ?? c?.content ?? '').join('\n');
    return m.content == null ? '' : String(m.content);
  }).join('\n');
  const chatMessages = messages.filter(m => m.role !== 'system' && m.role !== 'developer');

  // Build tool_call_id → tool_name reverse lookup
  const toolNameMap = {};
  for (const msg of chatMessages) {
    if (msg.role === 'assistant' && msg.tool_calls) {
      for (const tc of msg.tool_calls) {
        if (tc.id) {
          toolNameMap[tc.id] = tc.function?.name || '';
        }
      }
    }
  }

  // 转换 messages 为 CC 格式
  const ccMessages = chatMessages.map(msg => {
    if (msg.role === 'user') {
      if (typeof msg.content === 'string') {
        return { role: 'user', content: [{ type: 'text', text: msg.content }] };
      }
      // 多模态：数组 content 原样透传（text + image_url → CC image 格式）
      if (Array.isArray(msg.content)) {
        const parts = msg.content.map(part => {
          if (part.type === 'image_url') {
            const url = part.image_url?.url || '';
            // CC CLI 真实格式: { type: "image", image: "data:image/jpeg;base64,..." }
            return { type: 'image', image: url };
          }
          return part;
        }).filter(Boolean);
        return { role: 'user', content: parts };
      }
      return { role: 'user', content: [{ type: 'text', text: String(msg.content) }] };
    }
    if (msg.role === 'assistant') {
      const parts = [];
      if (msg.content && typeof msg.content === 'string') {
        parts.push({ type: 'text', text: msg.content });
      } else if (msg.content && Array.isArray(msg.content)) {
        for (const part of msg.content) {
          if (part.type === 'text') parts.push(part);
        }
      }
      if (msg.tool_calls) {
        for (const tc of msg.tool_calls) {
          parts.push({
            type: 'tool-call',
            toolCallId: tc.id,
            toolName: tc.function?.name || '',
            input: (typeof tc.function?.arguments === 'string' ? tryParseJSON(tc.function.arguments) : (tc.function?.arguments || {})),
          });
        }
      }
      return { role: 'assistant', content: parts };
    }
    if (msg.role === 'tool') {
      return {
        role: 'tool',
        content: [{
          type: 'tool-result',
          toolCallId: msg.tool_call_id,
          toolName: toolNameMap[msg.tool_call_id] || msg.name || '',
          output: { type: 'text', value: typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content) },
        }],
      };
    }
    // 未知 role 兜底：归一化为 user 并保证 content 为数组，避免 CC 校验拒绝
    return { role: 'user', content: [{ type: 'text', text: String(msg.content ?? '') }] };
  });

  const hasMessageCacheMarker = ccMessages.some(msg =>
    Array.isArray(msg.content) && msg.content.some(part => part?.cache_control));
  if (prompt_cache_key && !hasMessageCacheMarker) {
    const firstUserMessage = ccMessages.find(msg => msg.role === 'user' && Array.isArray(msg.content));
    const cacheBoundary = firstUserMessage?.content.findLast(part => part?.type === 'text');
    if (cacheBoundary) cacheBoundary.cache_control = { type: 'ephemeral' };
  }

  const threadId = newThreadId();

  const body = {
    config: {
      workingDir: process.cwd(),
      date: getDateStr(),
      environment: getEnvironment(),
      structure: [],
      isGitRepo: false,
      currentBranch: '',
      mainBranch: '',
      gitStatus: '',
      recentCommits: [],
    },
    memory: null,
    taste: null,
    skills: '',
    permissionMode: 'standard',
    params: {
      model: model || 'deepseek/deepseek-v4-flash',
      messages: ccMessages,
      max_tokens: Math.min(max_tokens || 64000, 200000),
      stream: true,  // CC API 总是 stream
    },
  };

  // 条件字段
  if (systemPrompt) {
    body.params.system = systemPrompt;
  }
  if (temperature !== undefined) {
    body.params.temperature = temperature;
  }
  if (reasoning_effort !== undefined) {
    body.params.reasoning_effort = reasoning_effort;
  }
  if (tools && tools.length > 0) {
    body.params.tools = tools.map(t => ({
      type: t.type || 'function',
      name: t.function?.name || t.name || '',
      description: t.function?.description || t.description || '',
      input_schema: t.function?.parameters || t.input_schema || { type: 'object', properties: {} },
    }));
  }
  if (tool_choice !== undefined) {
    // OpenAI 格式 → CC (Anthropic 风格) 格式
    if (typeof tool_choice === 'string') {
      const map = { 'auto': 'auto', 'none': 'none', 'required': 'any' };
      body.params.tool_choice = { type: map[tool_choice] || 'auto' };
    } else if (tool_choice.type === 'function') {
      // OpenAI object → Anthropic object
      body.params.tool_choice = { type: 'tool', name: tool_choice.function?.name };
    } else {
      body.params.tool_choice = tool_choice;
    }
  }
  if (parallel_tool_calls !== undefined) {
    body.params.parallel_tool_calls = parallel_tool_calls;
  }

  return body;
}

function tryParseJSON(str) {
  try { return JSON.parse(str); } catch { return {}; }
}

// ── CC NDJSON → OpenAI SSE 转换 ────────────────────

function createSseTranslator(model, completionId, created) {
  let chunkIndex = 0;
  let sentRole = false;
  let finishReason = null;
  let usage = null;
  let toolCallIndex = 0;

  return {
    lastCcEvent: '',
    upstreamError: null,
    inputTokens: 0,
    outputTokens: 0,
    cachedInputTokens: 0,
    /** 解析一行 NDJSON，返回 OpenAI chunk 数组 */
    parseLine(line) {
      const trimmed = line.trim();
      if (!trimmed || trimmed === '[DONE]' || trimmed.startsWith(':')) return null;

      let event;
      try { event = JSON.parse(trimmed); } catch { return null; }
      if (!event.type) return null;
      this.lastCcEvent = event.type;

      const out = [];

      switch (event.type) {
        case 'text-start':
        case 'reasoning-start':
        case 'start':
        case 'start-step':
          // 忽略，无用户可见内容
          break;

        case 'text-delta': {
          const text = event.text || event.delta || '';
          if (!text) break;
          const delta = chunkIndex === 0 ? { role: 'assistant', content: text } : { content: text };
          chunkIndex++;
          sentRole = true;
          out.push(makeChunk(completionId, created, model, delta, null, null));
          break;
        }

        case 'reasoning-delta': {
          const text = event.text || '';
          if (!text) break;
          const delta = chunkIndex === 0
            ? { role: 'assistant', reasoning_content: text }
            : { reasoning_content: text };
          chunkIndex++;
          out.push(makeChunk(completionId, created, model, delta, null, null));
          break;
        }

        case 'tool-call': {
          const id = event.toolCallId || `call_${Date.now()}_${toolCallIndex}`;
          const name = event.toolName || '';
          const args = typeof event.input === 'string' ? event.input : JSON.stringify(event.input || {});
          const tcEntry = { index: toolCallIndex, id, type: 'function', function: { name, arguments: args } };
          const delta = chunkIndex === 0
            ? { role: 'assistant', content: null, tool_calls: [tcEntry] }
            : { tool_calls: [tcEntry] };
          chunkIndex++;
          toolCallIndex++;
          out.push(makeChunk(completionId, created, model, delta, null, null));
          break;
        }

        case 'finish-step': {
          if (event.finishReason) finishReason = mapFinishReason(event.finishReason);
          if (event.usage) {
            usage = event.usage;
            this.inputTokens = event.usage.inputTokens ?? 0;
            this.outputTokens = event.usage.outputTokens ?? 0;
            this.cachedInputTokens = event.usage.cachedInputTokens ?? 0;
          }
          break;
        }

        case 'finish': {
          const fr = finishReason || mapFinishReason(event.finishReason || 'stop');
          const u = event.totalUsage || usage || {};
          normalizeUsage(u);
          this.inputTokens = u.inputTokens ?? 0;
          this.outputTokens = u.outputTokens ?? 0;
          this.cachedInputTokens = u.cachedInputTokens ?? 0;
          const openaiUsage = u ? {
            prompt_tokens: u.inputTokens ?? 0,
            completion_tokens: u.outputTokens ?? 0,
            total_tokens: (u.inputTokens ?? 0) + (u.outputTokens ?? 0),
            prompt_tokens_details: { cached_tokens: u.cachedInputTokens ?? 0 },
          } : undefined;
          out.push(makeChunk(completionId, created, model, {}, fr, openaiUsage));
          break;
        }

        case 'error': {
          const msg = event.error?.message || event.message || 'Unknown error';
          log('warn', 'CC stream error', { message: msg });
          this.upstreamError = mapCcEventError(event);
          // Don't emit a finish_reason chunk — let the natural stream termination
          // handle it. Otherwise a subsequent finish(tool_calls) would be ignored
          // by downstream agent loops that stop at the first finish_reason.
          break;
        }

        case 'reasoning-end': case 'provider-metadata': case 'tool-input-start': case 'tool-input-delta': case 'tool-input-end': case 'tool-error': case 'text-end':
          // Silent - no user-visible content
          break;
        default:
          log('warn', 'Unknown CC event type', { type: event.type });
          break;
      }

      return out.length > 0 ? out : null;
    },

    /** 获取 SSE 结束标记 */
    getDoneEvent() {
      return 'data: [DONE]\n\n';
    },
  };
}

function makeChunk(id, created, model, delta, finishReason, usage) {
  const chunk = {
    id,
    object: 'chat.completion.chunk',
    created,
    model,
    choices: [{ index: 0, delta, finish_reason: finishReason || null }],
  };
  if (usage) chunk.usage = usage;
  return `data: ${JSON.stringify(chunk)}\n\n`;
}

// normalize CC usage stats:
// - outputTokens=0 → zero everything (anti false billing)
function normalizeUsage(u) {
  if (!u) return;
  const ot = Number(u.outputTokens);
  if (!ot) {  // 0, null, undefined, NaN → zero input + cached (anti false billing)
    u.inputTokens = 0;
    u.cachedInputTokens = 0;
  }
}

function mapFinishReason(reason) {
  switch (reason) {
    case 'tool-calls': return 'tool_calls';
    case 'length': return 'length';
    case 'stop': return 'stop';
    default: return reason || 'stop';
  }
}

// ── 错误映射 ───────────────────────────────────────
const CC_STATUS_MAP = {
  400: { status: 400, type: 'invalid_request_error' },
  401: { status: 401, type: 'authentication_error' },
  402: { status: 429, type: 'rate_limit_error' },       // payment required → rate limit
  403: { status: 401, type: 'authentication_error' },
  404: { status: 404, type: 'not_found' },
  422: { status: 400, type: 'invalid_request_error' },
  429: { status: 429, type: 'rate_limit_error' },
  500: { status: 502, type: 'upstream_error' },
  502: { status: 502, type: 'upstream_error' },
  503: { status: 503, type: 'temporarily_unavailable' },
};

function mapCcError(ccStatus, ccBody) {
  const mapped = CC_STATUS_MAP[ccStatus] || { status: 502, type: 'upstream_error' };
  let message = `CC API error (${ccStatus})`;

  if (ccBody) {
    try {
      const parsed = JSON.parse(ccBody);
      message = parsed.error?.message || parsed.message || message;
    } catch {
      message = ccBody.slice(0, 200) || message;
    }
  }

  // CC 429 响应可能带 retry-after
  if (ccStatus === 429) {
    return {
      status: 429,
      body: {
        error: { message, type: 'rate_limit_error' },
        retry_after: 30,
      },
    };
  }

  return { status: mapped.status, body: { error: { message, type: mapped.type } } };
}

function mapCcEventError(event) {
  const message = event.error?.message || event.message || 'Unknown CC error';
  const statusMatch = message.match(/^<(\d{3})>/);
  const ccStatus = statusMatch ? Number(statusMatch[1]) : 502;
  const mapped = CC_STATUS_MAP[ccStatus] || { status: 502, type: 'upstream_error' };

  // 与 mapCcError 保持一致：终态为 429 时带上 retry_after，
  // 否则客户端 SDK 拿不到退避提示（402 也映射成 429，一视同仁）
  if (mapped.status === 429) {
    return {
      status: 429,
      body: { error: { message, type: 'rate_limit_error' }, retry_after: 30 },
    };
  }

  return { status: mapped.status, body: { error: { message, type: mapped.type } } };
}

// ── HTTP 请求处理 ──────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalSize = 0;
    let settled = false;
    let drained = 0;
    // 413 拒绝后转入排空模式：继续读取并丢弃剩余请求体，保持 keep-alive 连接可复用，
    // 让客户端明确收到 413 而不是 Connection reset（issue #7）。
    // 但若客户端无视 413 持续上传超过 DRAIN_LIMIT，则强制掐断，不无限吞带宽。
    const DRAIN_LIMIT = 32 * 1024 * 1024;
    req.on('data', c => {
      if (settled) {
        drained += c.length;
        if (drained > DRAIN_LIMIT) { try { req.destroy(); } catch {} }
        return;
      }
      totalSize += c.length;
      if (totalSize > MAX_BODY_SIZE) {
        settled = true;
        chunks.length = 0;
        const mb = Math.round(MAX_BODY_SIZE / 1024 / 1024);
        const err = new Error(`Request body exceeds ${mb}MB limit`);
        err.statusCode = 413;
        reject(err);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', e => { if (!settled) { settled = true; reject(e); } });
  });
}

function sendJSON(res, status, data) {
  const headers = { 'Content-Type': 'application/json' };
  if (data && data.retry_after !== undefined) {
    headers['Retry-After'] = String(data.retry_after);
  }
  res.writeHead(status, headers);
  res.end(JSON.stringify(data));
}

function getApiKey(headers) {
  // Try Authorization: Bearer header (OpenAI SDK style)
  const auth = headers['authorization'] || headers['Authorization'] || '';
  if (auth.startsWith('Bearer ')) {
    const match = auth.slice(7).match(/user_[a-zA-Z0-9_-]+/);
    if (match) return match[0];
  }
  // Fall back to x-api-key header (Anthropic SDK style)
  const xKey = headers['x-api-key'] || headers['X-Api-Key'] || '';
  if (xKey) {
    const match = xKey.match(/user_[a-zA-Z0-9_-]+/);
    if (match) return match[0];
  }
  return null;
}

// ── 流式转发 ────────────────────────────────────────

async function forwardToCC(body, apiKey, incomingHeaders = {}, signal, promptCacheKey) {
  const url = `${CFG.apiBase}/alpha/generate`;
  const traceparent = generateTraceparent();
  const sessionId = getSessionId(incomingHeaders, apiKey, promptCacheKey);

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${apiKey}`,
    'x-cli-environment': 'production',
    'x-command-code-version': CC_VERSION,
    'x-session-id': sessionId,
    'x-co-flag': 'false',
    'x-taste-learning': 'false',
    'x-project-slug': fakeProjectSlug(sessionId),
    'traceparent': traceparent,
  };

  if (CFG.zdr || incomingHeaders['x-cmd-zdr'] === '1') {
    headers['x-cmd-zdr'] = '1';
  }

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    signal,
  });

  return response;
}

// ── 路由 ────────────────────────────────────────────

async function handleChatCompletions(req, res) {
  let openaiReq;
  try {
    openaiReq = await readBody(req);
  } catch (e) {
    if (e.statusCode === 413) {
      sendJSON(res, 413, { error: { message: e.message, type: 'invalid_request_error' } });
      return;
    }
    sendJSON(res, 400, { error: { message: 'Invalid JSON body', type: 'invalid_request_error' } });
    return;
  }

  const apiKey = getApiKey(req.headers);
  if (!apiKey) {
    sendJSON(res, 401, { error: { message: 'Missing API key. Send in Authorization: Bearer <key> or x-api-key header', type: 'auth_error' } });
    return;
  }

  const stream = openaiReq.stream === true;
  const model = openaiReq.model || 'deepseek/deepseek-v4-flash';
  const completionId = `chatcmpl-${randomUUID().slice(0, 12)}`;
  const created = nowUnix();

  // 构建 CC 请求体
  const ccBody = buildCcRequest(openaiReq);

  // AbortController 用于客户端断连时真正打断 CC 上游（pi-commandcode-provider 模式）
  const abortController = new AbortController();
  let aborted = false;
  // 提前初始化，断连回调/超时 catch 安全引用（避免块级作用域 ReferenceError）
  const startTime = Date.now();
  let bytesReceived = 0; let lastCcEvent = ''; let keepaliveCount = 0; let fullText = '';
  let reader = null;
  let translator = null;

  try {
    // 首次初始化（fingerprint + lifecycle）
    await ensureInitialized(apiKey, abortController.signal);
    // 转发到 CC API（传入客户端 headers，用于提取 session ID）
    const ccResponse = await forwardToCC(ccBody, apiKey, req.headers, abortController.signal, openaiReq.prompt_cache_key);

    if (!ccResponse.ok) {
      const errorText = await ccResponse.text().catch(() => '');
      log('error', 'CC API error', { status: ccResponse.status });
      const mapped = mapCcError(ccResponse.status, errorText);
      sendJSON(res, mapped.status, mapped.body);
      return;
    }

    // 下游断连检测：打断 CC 上游 + 记录日志
    res.on('close', () => {
      if (res.writableEnded) return; // Normal completion, not a disconnect
      aborted = true;
      const reason = lastCcEvent?.startsWith('tool-input') ? 'tool-input-silent-timeout'
        : lastCcEvent?.includes('delta') ? 'streaming-active-disconnect'
        : 'client-hangup';
      abortController.signal.aborted || log('warn', 'Client disconnected', {
        path: '/v1/chat/completions',
        model, completionId, reason,
        streaming: stream,
        elapsedMs: Date.now() - startTime,
        bytesSent: bytesReceived,
        lastCcEvent: lastCcEvent || '(none)',
        keepaliveCount,
        inputTokens: translator?.inputTokens ?? 0,
        outputTokens: translator?.outputTokens ?? 0,
        cachedInputTokens: translator?.cachedInputTokens ?? 0,
      });
      if (!abortController.signal.aborted) {
        // 断连前抢发 usage=0 终止 chunk，避免下游自行估算 token
        try {
          res.write(`data: ${JSON.stringify({
            id: completionId,
            object: 'chat.completion.chunk',
            created,
            model,
            choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
            usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0, prompt_tokens_details: { cached_tokens: 0 } },
          })}\n\n`);
          res.write('data: [DONE]\n\n');
        } catch {}
        try { abortController.abort(); } catch {}
      }
    });

    if (stream) {
      // ── 流式响应 ──
      translator = createSseTranslator(model, completionId, created);
      let buffer = '';
      let started = false; // 延迟写 200 header，超时/output=0 时返回 JSON 429/502 让 SDK 自动重试
      const decoder = new TextDecoder();
      reader = ccResponse.body.getReader();

      try {
        while (true) {
          const result = await Promise.race([
            reader.read(),
            new Promise((_, reject) =>
              setTimeout(() => reject(new Error('STREAM_IDLE_TIMEOUT')), STREAM_IDLE_TIMEOUT_MS)
            ),
          ]);
          const { done, value } = result;
          if (done) break;
          if (aborted) break;
          bytesReceived += value.length;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          let hadOutput = false;
          for (const line of lines) {
            const events = translator.parseLine(line);
            if (events) {
              if (!started) {
                res.writeHead(200, {
                  'Content-Type': 'text/event-stream',
                  'Cache-Control': 'no-cache',
                  'Connection': 'keep-alive',
                  'X-Accel-Buffering': 'no',
                });
                started = true;
              }
              for (const evt of events) res.write(evt);
              hadOutput = true;
            }
            if (translator.lastCcEvent) lastCcEvent = translator.lastCcEvent;
          }
          // silent events 期间发 keepalive，防止客户端超时断开
          if (started && !hadOutput) { try { res.write(': keepalive\n\n'); keepaliveCount++; } catch {} }
        }

        if (!aborted) {
          // 成功完成一次请求，重置连续超时计数
          consecutiveTimeouts = 0;
          // 处理剩余 buffer
          if (buffer.trim()) {
            const events = translator.parseLine(buffer);
            if (events) {
              if (!started) started = true;
              for (const evt of events) res.write(evt);
            }
          }
          if (translator.upstreamError) {
            if (!started) {
              sendJSON(res, translator.upstreamError.status, translator.upstreamError.body);
              return;
            }
            try { res.write(`data: ${JSON.stringify(translator.upstreamError.body)}\n\n`); } catch {}
          // 输出 token 为 0 时记为错误，避免下游异常计费
          } else if (translator.outputTokens === 0) {
            try { if (!abortController.signal.aborted) abortController.abort(); } catch {}
            if (!started) {
              sendJSON(res, 429, { error: { message: 'Empty response from upstream (zero output tokens)', type: 'rate_limit_error' }, retry_after: 10 });
              return;
            }
            try { res.write(`data: ${JSON.stringify({ error: { message: 'Empty response from upstream (zero output tokens)', type: 'rate_limit_error' }, retry_after: 10 })}\n\n`); } catch {}
          } else {
            if (!started) {
              res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no',
              });
              started = true;
            }
            res.write(translator.getDoneEvent());
          }
        }
      } catch (e) {
        if (aborted) {
          // 客户端已断连，只清理（close handler 已调用 abortController.abort()）
          try { reader.cancel(); } catch {}
        } else if (e.message === 'STREAM_IDLE_TIMEOUT') {
          log('warn', 'Stream idle timeout', {
            path: '/v1/chat/completions',
            model,
            streaming: true,
            timeoutMs: STREAM_IDLE_TIMEOUT_MS,
            elapsedMs: Date.now() - startTime,
            id: completionId,
            bytesReceived,
            lastCcEvent: lastCcEvent || '(none)',
            inputTokens: translator.inputTokens,
            outputTokens: translator.outputTokens,
            cachedInputTokens: translator.cachedInputTokens,
          });
          try { reader.cancel(); } catch {}
          try { abortController.abort(); } catch {} // 打断 CC 上游，避免浪费 token
          consecutiveTimeouts++;
          const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
            ? 'Response timeout - try reducing context length (summarize earlier messages)'
            : 'Response timeout - request timed out';
          if (!started) {
            sendJSON(res, 429, { error: { message: timeoutMsg, type: 'rate_limit_error', input_tokens: 0 }, retry_after: 5 });
            return;
          }
          if (!res.writableEnded) {
            try { res.write(`data: ${JSON.stringify({ error: { message: timeoutMsg, type: 'rate_limit_error' }, retry_after: 5 })}\n\n`); } catch {}
            try { res.destroy(); } catch {}
          }
        } else {
          log('error', 'Stream error', { message: e.message });
          try { abortController.abort(); } catch {} // 打断 CC 上游
          if (!started) {
            sendJSON(res, 502, { error: { message: `Upstream error: ${e.message}`, type: 'proxy_error', input_tokens: 0 }, retry_after: 10 });
            return;
          }
          if (!res.writableEnded) {
            try { res.write(`data: ${JSON.stringify({ error: { message: e.message, type: 'proxy_error' } })}\n\n`); } catch {}
          }
        }
      }

      if (!res.writableEnded) res.end();
    } else {
      // ── 非流式响应（缓冲完整 NDJSON）──
      let reasoningContent = '';
      let finishReason = 'stop';
      let usage = null;
      let toolCalls = null;
      let upstreamError = null;

      reader = ccResponse.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      const processLines = () => {
        const lines = buf.split('\n');
        buf = lines.pop() || '';
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed === '[DONE]' || trimmed.startsWith(':')) continue;
          try {
            const event = JSON.parse(trimmed);
            switch (event.type) {
              case 'text-delta': lastCcEvent = event.type; fullText += event.text || ''; break;
              case 'reasoning-delta': lastCcEvent = event.type; reasoningContent += event.text || ''; break;
              case 'tool-call':
                lastCcEvent = event.type;
                toolCalls = toolCalls || [];
                toolCalls.push({
                  id: event.toolCallId || ('call_' + randomUUID().slice(0, 8)),
                  type: 'function',
                  function: {
                    name: event.toolName || '',
                    arguments: typeof event.input === 'string' ? event.input : JSON.stringify(event.input || {}),
                  },
                });
                break;
              case 'finish':
                lastCcEvent = event.type;
                finishReason = mapFinishReason(event.finishReason || 'stop');
                if (event.totalUsage) usage = event.totalUsage;
                break;
              case 'error':
                lastCcEvent = event.type;
                log('warn', 'CC stream error (non-stream)', { message: event.error?.message || event.message });
                upstreamError = mapCcEventError(event);
                break;
              case 'reasoning-end': case 'provider-metadata': case 'tool-input-start': case 'tool-input-delta': case 'tool-input-end': case 'tool-error': case 'text-end':
                // Silent - no user-visible content
                break;
              default:
                log('warn', 'Unknown CC event type', { type: event.type });
                break;
            }
          } catch {}
        }
      };

      while (true) {
        const result = await Promise.race([
          reader.read(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('STREAM_IDLE_TIMEOUT')), NONSTREAM_IDLE_TIMEOUT_MS)
          ),
        ]);
        const { done, value } = result;
        if (done) break;
        bytesReceived += value.length;
        buf += decoder.decode(value, { stream: true });
        processLines();
      }
      processLines();

      if (upstreamError) {
        sendJSON(res, upstreamError.status, upstreamError.body);
        return;
      }

      // 输出 token 为 0 时记为错误，避免下游异常计费
      if ((usage?.outputTokens ?? 0) === 0) {
        try { if (!abortController.signal.aborted) abortController.abort(); } catch {}
        sendJSON(res, 429, { error: { message: 'Empty response from upstream (zero output tokens)', type: 'rate_limit_error' }, retry_after: 10 });
        return;
      }

      consecutiveTimeouts = 0;
      sendJSON(res, 200, {
        id: completionId,
        object: 'chat.completion',
        created,
        model,
        choices: [{
          index: 0,
          message: Object.assign(
            { role: 'assistant', content: fullText || null },
            toolCalls ? { tool_calls: toolCalls } : {},
            reasoningContent ? { reasoning_content: reasoningContent } : {},
          ),
          finish_reason: finishReason,
        }],
    usage: (() => {
      if (!usage) usage = {};
      normalizeUsage(usage);
      return {
        prompt_tokens: usage.inputTokens ?? 0,
        completion_tokens: usage.outputTokens ?? 0,
        total_tokens: (usage.inputTokens ?? 0) + (usage.outputTokens ?? 0),
        prompt_tokens_details: { cached_tokens: usage.cachedInputTokens ?? 0 },
      };
    })(),
      });
    }
  } catch (e) {
    if (abortController.signal.aborted) {
      log('warn', 'Request cancelled (client disconnected before CC response)', {
        path: '/v1/chat/completions',
        model,
        completionId,
      });
    } else if (e.message === 'STREAM_IDLE_TIMEOUT') {
      log('warn', 'Stream idle timeout', {
        path: '/v1/chat/completions',
        model,
        streaming: false,
        timeoutMs: NONSTREAM_IDLE_TIMEOUT_MS,
        elapsedMs: Date.now() - startTime,
        id: completionId,
        bytesReceived,
        lastCcEvent: lastCcEvent || '(none)',
        partialLen: fullText ? fullText.length : 0,
      });
      try { reader?.cancel(); } catch {}
      try { abortController.abort(); } catch {} // 打断 CC 上游
      consecutiveTimeouts++;
      const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
        ? 'Response timeout - try reducing context length (summarize earlier messages)'
        : 'Response timeout - request timed out';
      res.setHeader('Retry-After', '5');
      sendJSON(res, 429, { error: { message: timeoutMsg, type: 'rate_limit_error', input_tokens: 0 }, retry_after: 5 });
    } else {
      log('error', 'Upstream error', { message: e.message });
      try { abortController.abort(); } catch {} // 打断 CC 上游
      sendJSON(res, 502, { error: { message: `Upstream error: ${e.message}`, type: 'proxy_error', input_tokens: 0 }, retry_after: 10 });
    }
  }
}

// ── Anthropic /v1/messages 协议转换 ─────────────────

function mapAnthropicStopReason(finishReason) {
  switch (finishReason) {
    case 'tool_calls': return 'tool_use';
    case 'length': return 'max_tokens';
    case 'stop': return 'end_turn';
    default: return 'end_turn';
  }
}

// Generate a Claude-format fake signature for thinking blocks.
// Anthropic validates thinking signatures cryptographically; third-party
// proxies cannot mint valid ones. Claude Code's shallow check only requires
// base64 starting with 'E' (single-layer) / 'R' (double-layer) with payload
// first byte 0x12 — this satisfies that, letting CC display thinking.
// The payload is derived from the thinking text so each block's signature
// differs (closer to spec, avoids identical-signature quirks).
function fakeThinkingSignature(thinkingText) {
  const seed = crypto.createHash('sha256').update(thinkingText || 'dsh-proxy-thinking').digest().subarray(0, 64);
  const raw = Buffer.concat([Buffer.from([0x12, seed.length]), seed]);
  return raw.toString('base64');
}

function buildAnthropicResponse(model, fullText, toolCalls, finishReason, usage, thinkingText) {
  const content = [];
  if (thinkingText) content.push({ type: 'thinking', thinking: thinkingText, signature: fakeThinkingSignature(thinkingText) });
  if (fullText) content.push({ type: 'text', text: fullText });
  if (toolCalls) {
    for (const tc of toolCalls) {
      let input = {};
      try { input = JSON.parse(tc.function.arguments); } catch { input = {}; }
      content.push({ type: 'tool_use', id: tc.id, name: tc.function.name, input });
    }
  }
  return {
    id: `msg_${randomUUID().slice(0, 12)}`,
    type: 'message',
    role: 'assistant',
    model,
    content,
    stop_reason: mapAnthropicStopReason(finishReason || 'stop'),
    stop_sequence: null,
    usage: (() => {
      normalizeUsage(usage || {});
      return {
        input_tokens: usage?.inputTokens ?? 0,
        output_tokens: usage?.outputTokens ?? 0,
        cache_creation_input_tokens: usage?.inputTokenDetails?.cacheWriteTokens ?? null,
        cache_read_input_tokens: usage?.cachedInputTokens ?? 0,
      };
    })(),
  };
}

function convertAnthropicToOpenAI(anthropicReq) {
  // 1. Extract system prompt (top-level, not in messages array)
  let systemPrompt = '';
  if (anthropicReq.system) {
    if (typeof anthropicReq.system === 'string') {
      systemPrompt = anthropicReq.system;
    } else if (Array.isArray(anthropicReq.system)) {
      systemPrompt = anthropicReq.system
        .filter(b => b.type === 'text')
        .map(b => b.text)
        .join('\n');
    }
  }

  // 2. Build tool name map + convert messages
  const toolNameFromId = {};
  const openaiMessages = [];

  if (systemPrompt) {
    openaiMessages.push({ role: 'system', content: systemPrompt });
  }

  const messages = anthropicReq.messages || [];
  for (const msg of messages) {
    if (msg.role === 'assistant') {
      let textContent = '';
      const toolCalls = [];
      const blocks = Array.isArray(msg.content) ? msg.content : [{ type: 'text', text: msg.content || '' }];
      for (const block of blocks) {
        if (block.type === 'text') {
          textContent += block.text || '';
        } else if (block.type === 'tool_use') {
          toolNameFromId[block.id] = block.name;
          toolCalls.push({
            id: block.id,
            type: 'function',
            function: {
              name: block.name,
              arguments: JSON.stringify(block.input || {}),
            },
          });
        }
      }
      const assistantMsg = { role: 'assistant', content: textContent || null };
      if (toolCalls.length > 0) assistantMsg.tool_calls = toolCalls;
      openaiMessages.push(assistantMsg);
    } else if (msg.role === 'user') {
      let textContent = '';
      const toolResults = [];
      if (typeof msg.content === 'string') {
        textContent = msg.content;
      } else if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (block.type === 'text') {
            textContent += block.text || '';
          } else if (block.type === 'tool_result') {
            toolResults.push(block);
          }
        }
      }
      if (textContent) {
        openaiMessages.push({ role: 'user', content: textContent });
      }
      for (const tr of toolResults) {
        const toolContent = typeof tr.content === 'string' ? tr.content
          : Array.isArray(tr.content) ? tr.content.map(c => c.text || '').join('')
          : String(tr.content || '');
        openaiMessages.push({
          role: 'tool',
          tool_call_id: tr.tool_use_id,
          name: toolNameFromId[tr.tool_use_id] || '',
          content: toolContent,
        });
      }
    }
  }

  // 3. Build OpenAI request
  const openaiReq = {
    model: anthropicReq.model || 'deepseek/deepseek-v4-flash',
    messages: openaiMessages,
    max_tokens: anthropicReq.max_tokens || 64000,
    stream: anthropicReq.stream === true,
  };

  // 4. Map tools
  if (anthropicReq.tools && anthropicReq.tools.length > 0) {
    openaiReq.tools = anthropicReq.tools.map(t => ({
      type: 'function',
      function: {
        name: t.name,
        description: t.description || '',
        parameters: t.input_schema || { type: 'object', properties: {} },
      },
    }));
  }

  // 5. Map tool_choice
  if (anthropicReq.tool_choice) {
    const tc = anthropicReq.tool_choice;
    if (tc.type === 'auto' || tc.type === undefined) {
      openaiReq.tool_choice = 'auto';
    } else if (tc.type === 'any') {
      openaiReq.tool_choice = 'required';
    } else if (tc.type === 'tool') {
      openaiReq.tool_choice = { type: 'function', function: { name: tc.name } };
    } else if (tc.type === 'none') {
      openaiReq.tool_choice = 'none';
    }
  }

  // 6. Optional params
  if (anthropicReq.temperature !== undefined) openaiReq.temperature = anthropicReq.temperature;
  if (anthropicReq.top_p !== undefined) openaiReq.top_p = anthropicReq.top_p;
  if (anthropicReq.stop_sequences) openaiReq.stop = anthropicReq.stop_sequences;
  if (anthropicReq.metadata?.user_id) openaiReq.user = anthropicReq.metadata.user_id;

  // 7. Anthropic thinking → reasoning_effort（LiteLLM 标准映射）
  if (anthropicReq.thinking) {
    const t = anthropicReq.thinking;
    if (t.type === 'disabled' || t.type === 'none') {
      // 不发送 reasoning_effort
    } else if (t.type === 'adaptive') {
      openaiReq.reasoning_effort = t.effort ?? 'medium';
    } else if (t.budget_tokens !== undefined) {
      if (t.budget_tokens >= 10000) openaiReq.reasoning_effort = 'high';
      else if (t.budget_tokens >= 5000) openaiReq.reasoning_effort = 'medium';
      else if (t.budget_tokens >= 2000) openaiReq.reasoning_effort = 'low';
      else openaiReq.reasoning_effort = 'low'; // <2000 → low
    }
  }

  return openaiReq;
}

/**
 * Async generator that reads CC NDJSON response body and yields
 * Anthropic SSE events for streaming.
 */
async function* createAnthropicSseTranslator(response, model, messageId, ctx) {
  let nextBlockIndex = 0;
  let currentBlockIndex = -1;
  let currentBlockType = null;
  let blockStarted = false;
  let inputTokens = 0;
  let outputTokens = 0;
  let cachedInputTokens = 0;
  let cacheWriteTokens = 0;
  let stopReason = null;
  let hasError = false;
  let currentThinkingText = ''; // accumulated thinking text for the open block

  // Close the current block (text or thinking) if one is active.
  // For thinking blocks, emit a signature_delta (Anthropic standard) before stop.
  function closeBlock() {
    if (blockStarted) {
      const idx = currentBlockIndex;
      const type = currentBlockType;
      let out = '';
      if (type === 'thinking') {
        out += `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: idx, delta: { type: 'signature_delta', signature: fakeThinkingSignature(currentThinkingText) } })}\n\n`;
        currentThinkingText = '';
      }
      blockStarted = false;
      currentBlockType = null;
      return out + `event: content_block_stop\ndata: ${JSON.stringify({ type: 'content_block_stop', index: idx })}\n\n`;
    }
    return '';
  }
  const closeTextBlock = closeBlock;

  // Open a new block of the given type (closing any previous block first)
  function startBlock(type, contentBlock) {
    if (!blockStarted || currentBlockType !== type) {
      const close = closeBlock();
      currentBlockIndex = nextBlockIndex++;
      currentBlockType = type;
      blockStarted = true;
      return close + `event: content_block_start\ndata: ${JSON.stringify({ type: 'content_block_start', index: currentBlockIndex, content_block: contentBlock })}\n\n`;
    }
    return '';
  }

  // Open a new text block (closing any previous block first)
  function startTextBlock() {
    return startBlock('text', { type: 'text', text: '' });
  }

  // Open a new thinking block (closing any previous block first)
  function startThinkingBlock() {
    return startBlock('thinking', { type: 'thinking', thinking: '' });
  }

  // Emit message_start (always the first event)
  yield `event: message_start\ndata: ${JSON.stringify({
    type: 'message_start',
    message: {
      id: messageId,
      type: 'message',
      role: 'assistant',
      content: [],
      model,
      usage: { input_tokens: 0, output_tokens: 0 },
    }
  })}\n\n`;

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const result = await Promise.race([
        reader.read(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('STREAM_IDLE_TIMEOUT')), STREAM_IDLE_TIMEOUT_MS)
        ),
      ]);
      const { done, value } = result;
      if (done) break;
      ctx.bytesReceived += value.length;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      let hadOutput = false;
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed === '[DONE]') continue;
        let event;
        try { event = JSON.parse(trimmed); } catch { continue; }
        if (!event.type) continue;
        ctx.lastCcEvent = event.type;

        switch (event.type) {
          case 'start': case 'start-step': case 'text-start': case 'reasoning-start':
            // Signal events, no user-visible data
            break;

          case 'reasoning-delta': {
            // CC reasoning → Anthropic thinking block (Claude Code shows this as thinking)
            const text = event.text || '';
            if (!text) break;
            const startBlock = startThinkingBlock();
            currentThinkingText += text;
            yield startBlock + `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: currentBlockIndex, delta: { type: 'thinking_delta', thinking: text } })}\n\n`;
            hadOutput = true;
            break;
          }

          case 'text-delta': {
            const text = event.text || '';
            const startBlock = startTextBlock();
            yield startBlock + `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: currentBlockIndex, delta: { type: 'text_delta', text } })}\n\n`;
            outputTokens += 1;
            hadOutput = true;
            break;
          }

          case 'tool-call': {
            // Close any pending text block
            const closeBlock = closeTextBlock();
            if (closeBlock) yield closeBlock;

            const id = event.toolCallId || `toolu_${randomUUID().slice(0, 12)}`;
            const name = event.toolName || '';
            const input = typeof event.input === 'string' ? event.input : JSON.stringify(event.input || {});

            const tcIndex = nextBlockIndex++;
            yield `event: content_block_start\ndata: ${JSON.stringify({ type: 'content_block_start', index: tcIndex, content_block: { type: 'tool_use', id, name, input: {} } })}\n\n`;
            yield `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: tcIndex, delta: { type: 'input_json_delta', partial_json: input } })}\n\n`;
            yield `event: content_block_stop\ndata: ${JSON.stringify({ type: 'content_block_stop', index: tcIndex })}\n\n`;
            outputTokens += 20;
            break;
          }

          case 'finish-step':
          case 'finish': {
            if (event.finishReason) stopReason = mapAnthropicStopReason(event.finishReason);
            const u = event.totalUsage || event.usage;
            if (u) {
              normalizeUsage(u);
              inputTokens = u.inputTokens ?? inputTokens;
              outputTokens = u.outputTokens ?? outputTokens;
              cachedInputTokens = u.cachedInputTokens ?? cachedInputTokens;
              cacheWriteTokens = u.inputTokenDetails?.cacheWriteTokens ?? cacheWriteTokens;
              ctx.inputTokens = inputTokens;
              ctx.outputTokens = outputTokens;
              ctx.cachedInputTokens = cachedInputTokens;
            } else {
              inputTokens = 0;
              outputTokens = 0;
              cachedInputTokens = 0;
              cacheWriteTokens = 0;
              ctx.inputTokens = 0;
              ctx.outputTokens = 0;
              ctx.cachedInputTokens = 0;
            }
            break;
          }

          case 'error': {
            hasError = true;
            const upstreamError = mapCcEventError(event);
            ctx.upstreamError = upstreamError;
            yield `event: error\ndata: ${JSON.stringify({ type: 'error', error: upstreamError.body.error })}\n\n`;
            break;
          }

          case 'reasoning-end': case 'provider-metadata': case 'tool-input-start': case 'tool-input-delta': case 'tool-input-end': case 'tool-error': case 'text-end':
            // Silent - no user-visible content
            break;
          default:
            log('warn', 'Unknown CC event type', { type: event.type });
            break;
        }
      }
    }

    // Finalize — close pending text block, emit message_delta + message_stop
    if (!hasError) {
      const closeBlock = closeTextBlock();
      if (closeBlock) yield closeBlock;

      // 输出 token 为 0 时记为错误，避免下游异常计费
      if (outputTokens === 0) {
        yield `event: error\ndata: ${JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'Empty response from upstream (zero output tokens)' }, retry_after: 10 })}\n\n`;
      } else {
        yield `event: message_delta\ndata: ${JSON.stringify({
          type: 'message_delta',
          delta: { stop_reason: stopReason || 'end_turn' },
          usage: { output_tokens: outputTokens, cache_read_input_tokens: cachedInputTokens, cache_creation_input_tokens: cacheWriteTokens || null, input_tokens: inputTokens },
        })}\n\n`;

        yield `event: message_stop\ndata: ${JSON.stringify({ type: 'message_stop' })}\n\n`;
      }
    }
  } finally {
    // 确保流中断时通知上游
    try { reader.cancel(); } catch {}
  }
}

function sendAnthropicError(res, status, type, message, retryAfter) {
  const body = { type: 'error', error: { type, message } };
  const headers = { 'Content-Type': 'application/json' };
  if (retryAfter !== undefined) {
    body.retry_after = retryAfter;
    headers['Retry-After'] = String(retryAfter);
  }
  res.writeHead(status, headers);
  res.end(JSON.stringify(body));
}

async function handleMessages(req, res) {
  let anthropicReq;
  try {
    anthropicReq = await readBody(req);
  } catch (e) {
    if (e.statusCode === 413) {
      sendAnthropicError(res, 413, 'invalid_request_error', e.message);
      return;
    }
    sendAnthropicError(res, 400, 'invalid_request_error', 'Invalid JSON body');
    return;
  }

  const apiKey = getApiKey(req.headers);
  if (!apiKey) {
    sendJSON(res, 401, { type: 'error', error: { type: 'authentication_error', message: 'Missing API key. Send in Authorization: Bearer <key> or x-api-key header' } });
    return;
  }

  const stream = anthropicReq.stream === true;
  const model = anthropicReq.model || 'claude-sonnet-4-6';

  // Convert Anthropic → OpenAI → CC
  const openaiReq = convertAnthropicToOpenAI(anthropicReq);
  const ccBody = buildCcRequest(openaiReq);

  const abortController = new AbortController();
  let aborted = false;
  // 提前初始化，断连回调/超时 catch 安全引用（避免块级作用域 ReferenceError）
  const startTime = Date.now();
  let messageId = '';
  let reader = null;
  let bytesReceived = 0; let lastCcEvent = ''; let fullText = '';

  try {
    // 首次初始化（fingerprint + lifecycle）
    await ensureInitialized(apiKey, abortController.signal);
    const ccResponse = await forwardToCC(ccBody, apiKey, req.headers, abortController.signal);

    if (!ccResponse.ok) {
      const errorText = await ccResponse.text().catch(() => '');
      log('error', 'CC API error (Anthropic)', { status: ccResponse.status });
      const mapped = mapCcError(ccResponse.status, errorText);
      sendAnthropicError(res, mapped.status, mapped.body.error.type, mapped.body.error.message);
      return;
    }

    // 下游断连检测：打断 CC 上游 + 记录日志
    res.on('close', () => {
      if (res.writableEnded) return; // Normal completion, not a disconnect
      aborted = true;
      if (!abortController.signal.aborted) {
        // 断连前抢发 usage=0 终止事件，避免下游自行估算 token
        try {
          res.write(`event: message_delta\ndata: ${JSON.stringify({
            type: 'message_delta',
            delta: { stop_reason: 'end_turn' },
            usage: { output_tokens: 0, input_tokens: 0, cache_read_input_tokens: 0 },
          })}\n\n`);
          res.write(`event: message_stop\ndata: ${JSON.stringify({ type: 'message_stop' })}\n\n`);
        } catch {}
        try { abortController.abort(); } catch {}
      }
      log('warn', 'Client disconnected', {
        path: '/v1/messages',
        model,
        messageId,
        streaming: stream,
        elapsedMs: Date.now() - startTime,
      });
    });

    if (stream) {
      // ── 流式 Anthropic SSE ──
      let started = false; // 延迟写 200 header，超时/output=0 时返回 JSON 429/502 让 SDK 自动重试
      const buf = [];

      let ctx;
      try {
        messageId = 'msg_' + randomUUID().slice(0, 12);
        ctx = { bytesReceived: 0, lastCcEvent: '', inputTokens: 0, outputTokens: 0, cachedInputTokens: 0, upstreamError: null };
        const generator = createAnthropicSseTranslator(ccResponse, model, messageId, ctx);
        for await (const event of generator) {
          if (aborted) break;
          if (!started) {
            buf.push(event);
            // 确认有真实内容后才发 200 header
            if (event.includes('"text_delta"') || event.includes('"tool_use"')) {
              res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no',
              });
              started = true;
              for (const ev of buf) res.write(ev);
              buf.length = 0;
            }
          } else {
            res.write(event);
          }
        }

        if (!aborted) {
          consecutiveTimeouts = 0;
          if (ctx.upstreamError) {
            if (!started) {
              sendAnthropicError(
                res,
                ctx.upstreamError.status,
                ctx.upstreamError.body.error.type,
                ctx.upstreamError.body.error.message,
              );
            }
          } else if (ctx.outputTokens === 0) {
            try { abortController.abort(); } catch {}
            if (!started) {
              sendAnthropicError(res, 429, 'rate_limit_error', 'Empty response from upstream (zero output tokens)', 10);
              return;
            }
            for (const ev of buf) { try { res.write(ev); } catch {} }
            buf.length = 0;
          } else {
            if (!started) {
              res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no',
              });
              started = true;
            }
            for (const ev of buf) res.write(ev);
            buf.length = 0;
          }
        }
      } catch (e) {
        if (aborted) {
          // 客户端已断连，只清理（close handler 已调用 abortController.abort()）
        } else if (e.message === 'STREAM_IDLE_TIMEOUT') {
          log('warn', 'Stream idle timeout', {
            path: '/v1/messages',
            model,
            streaming: true,
            timeoutMs: STREAM_IDLE_TIMEOUT_MS,
            elapsedMs: Date.now() - startTime,
            id: messageId,
            bytesReceived: ctx.bytesReceived,
            lastCcEvent: ctx.lastCcEvent || '(none)',
            inputTokens: ctx.inputTokens,
            outputTokens: ctx.outputTokens,
            cachedInputTokens: ctx.cachedInputTokens,
          });
          try { abortController.abort(); } catch {} // 打断 CC 上游
          if (!started) {
            consecutiveTimeouts++;
            const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
              ? 'Response timeout - try reducing context length (summarize earlier messages)'
              : 'Response timeout - request timed out';
            sendAnthropicError(res, 429, 'rate_limit_error', timeoutMsg);
            return;
          }
          if (!res.writableEnded) {
            consecutiveTimeouts++;
            const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
              ? 'Response timeout - try reducing context length (summarize earlier messages)'
              : 'Response timeout - request timed out';
            try { res.write(`event: error\ndata: ${JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: timeoutMsg }, retry_after: 5 })}\n\n`); } catch {}
            try { res.destroy(); } catch {}
          }
        } else {
          log('error', 'Anthropic stream error', { message: e.message });
          try { abortController.abort(); } catch {} // 打断 CC 上游
          if (!started) {
            sendAnthropicError(res, 502, 'proxy_error', `Upstream error: ${e.message}`, 10);
            return;
          }
          if (!res.writableEnded) {
            try {
              res.write(`event: error\ndata: ${JSON.stringify({ type: 'error', error: { type: 'internal_error', message: e.message } })}\n\n`);
            } catch {}
          }
        }
      }

      if (!res.writableEnded) res.end();
    } else {
      // ── 非流式 Anthropic JSON ──
      const messageId = 'msg_' + randomUUID().slice(0, 12);
      let finishReason = 'stop';
      let usage = null;
      let toolCalls = null;
      let thinkingText = ''; // CC reasoning → Anthropic thinking block
      let upstreamError = null;

      reader = ccResponse.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      const processLines = () => {
        const lines = buf.split('\n');
        buf = lines.pop() || '';
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed === '[DONE]') continue;
          try {
            const event = JSON.parse(trimmed);
            switch (event.type) {
              case 'text-delta': lastCcEvent = event.type; fullText += event.text || ''; break;
              case 'reasoning-delta': lastCcEvent = event.type; thinkingText += event.text || ''; break;
              case 'tool-call':
                lastCcEvent = event.type;
                (toolCalls = toolCalls || []).push({
                  id: event.toolCallId || ('call_' + randomUUID().slice(0, 8)),
                  type: 'function',
                  function: {
                    name: event.toolName || '',
                    arguments: typeof event.input === 'string' ? event.input : JSON.stringify(event.input || {}),
                  },
                });
                break;
              case 'finish':
                lastCcEvent = event.type;
                finishReason = mapFinishReason(event.finishReason || 'stop');
                if (event.totalUsage) usage = event.totalUsage;
                break;
              case 'error':
                lastCcEvent = event.type;
                log('warn', 'CC error (Anthropic non-stream)', { message: event.error?.message || event.message });
                upstreamError = mapCcEventError(event);
                break;
              case 'reasoning-end': case 'provider-metadata': case 'tool-input-start': case 'tool-input-delta': case 'tool-input-end': case 'tool-error': case 'text-end':
                // Silent - no user-visible content
                break;
              default:
                log('warn', 'Unknown CC event type', { type: event.type });
                break;
            }
          } catch {}
        }
      };

      while (true) {
        const result = await Promise.race([
          reader.read(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('STREAM_IDLE_TIMEOUT')), NONSTREAM_IDLE_TIMEOUT_MS)
          ),
        ]);
        const { done, value } = result;
        if (done) break;
        bytesReceived += value.length;
        buf += decoder.decode(value, { stream: true });
        processLines();
      }
      processLines();

      if (upstreamError) {
        sendAnthropicError(res, upstreamError.status, upstreamError.body.error.type, upstreamError.body.error.message);
        return;
      }

      // 输出 token 为 0 时记为错误，避免下游异常计费
      if ((usage?.outputTokens ?? 0) === 0) {
        try { if (!abortController.signal.aborted) abortController.abort(); } catch {}
        sendAnthropicError(res, 429, 'rate_limit_error', 'Empty response from upstream (zero output tokens)', 10);
        return;
      }

      consecutiveTimeouts = 0;
      sendJSON(res, 200, buildAnthropicResponse(model, fullText, toolCalls, finishReason, usage, thinkingText));
    }
  } catch (e) {
    if (abortController.signal.aborted) {
      log('warn', 'Request cancelled (client disconnected before CC response)', {
        path: '/v1/messages',
        model,
        messageId,
      });
    } else if (e.message === 'STREAM_IDLE_TIMEOUT') {
      log('warn', 'Stream idle timeout', {
        path: '/v1/messages',
        model,
        streaming: false,
        timeoutMs: NONSTREAM_IDLE_TIMEOUT_MS,
        elapsedMs: Date.now() - startTime,
        id: messageId,
        bytesReceived,
        lastCcEvent: lastCcEvent || '(none)',
        partialLen: fullText ? fullText.length : 0,
      });
      try { reader?.cancel(); } catch {}
      try { abortController.abort(); } catch {} // 打断 CC 上游
      consecutiveTimeouts++;
      const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
        ? 'Response timeout - try reducing context length (summarize earlier messages)'
        : 'Response timeout - request timed out';
      res.setHeader('Retry-After', '5');
      sendAnthropicError(res, 429, 'rate_limit_error', timeoutMsg);
    } else {
      log('error', 'Upstream error', { message: e.message });
      try { abortController.abort(); } catch {} // 打断 CC 上游
      sendAnthropicError(res, 502, 'proxy_error', `Upstream error: ${e.message}`, 10);
    }
  }
}

// ── 动态模型列表 ────────────────────────────────────

let dynamicModels = null;
let modelsLastFetch = 0;

async function fetchModels(apiKey) {
  const now = Date.now();
  if (dynamicModels && (now - modelsLastFetch) < CFG.modelRefreshIntervalMs) {
    return dynamicModels;
  }

  try {
    if (!apiKey || !CFG.useProviderModels) throw new Error('Provider models disabled');

    const response = await fetch(`${CFG.apiBase}/provider/v1/models`, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'x-cli-environment': 'production',
        'x-command-code-version': CC_VERSION,
      },
      signal: AbortSignal.timeout(10000),
    });

    if (response.ok) {
      const data = await response.json();
      if (Array.isArray(data.data)) {
        dynamicModels = data.data.map(m => ({
          id: m.id,
          name: m.id,
        }));
        modelsLastFetch = now;
        log('info', 'Fetched models from Provider API', { count: dynamicModels.length });
        return dynamicModels;
      }
    }
    log('warn', 'Provider models fetch failed, using hardcoded list', { status: response.status });
  } catch (e) {
    log('warn', 'Provider models fetch error, using hardcoded list', { error: e.message });
  }

  // Fallback to hardcoded MODELS
  return MODELS;
}

async function handleModels(req, res) {
  const apiKey = getApiKey(req.headers);
  const models = await fetchModels(apiKey);
  const now = nowUnix();
  sendJSON(res, 200, {
    object: 'list',
    data: models.map(m => ({
      id: m.id,
      object: 'model',
      created: now,
      owned_by: 'command-code',
    })),
  });
}

// ── /alpha/billing/credits 透传 ─────────────────────
// 客户端可用真实 user_ key 查询账号 credits 与 usage window 余量。
// 完全透传：认证/orgId 归属均由上游按 Authorization 决定，代理不缓存、不聚合。
async function handleBillingCredits(req, res) {
  const apiKey = getApiKey(req.headers);
  if (!apiKey) {
    sendJSON(res, 401, { error: { message: 'Missing API key. Send in Authorization: Bearer <key> or x-api-key header', type: 'auth_error' } });
    return;
  }

  const url = new URL(`${CFG.apiBase}/alpha/billing/credits`);
  for (const [k, v] of req.url.includes('?') ? new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams : []) {
    url.searchParams.append(k, v);
  }

  const headers = {
    'Authorization': `Bearer ${apiKey}`,
    'x-cli-environment': 'production',
    'x-command-code-version': CC_VERSION,
    'Content-Type': 'application/json',
    ...(CFG.zdr ? { 'x-cmd-zdr': '1' } : {}),
  };

  try {
    const upstream = await fetch(url, { headers, signal: AbortSignal.timeout(15000) });
    const text = await upstream.text().catch(() => '');
    let body;
    try { body = text ? JSON.parse(text) : {}; } catch { body = { error: { message: text.slice(0, 300) || `Upstream returned ${upstream.status}`, type: 'upstream_error' } }; }
    log('info', 'Billing credits proxied', { status: upstream.status, query: url.search });
    sendJSON(res, upstream.status, body);
  } catch (e) {
    log('warn', 'Billing credits upstream error', { error: e.name === 'TimeoutError' ? 'timeout' : e.message });
    sendJSON(res, 502, { error: { message: `Upstream error: ${e.name === 'TimeoutError' ? 'timeout' : e.message}`, type: 'proxy_error' } });
  }
}

function handleHealth(req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('OK');
}

// ── 管理页后端：多 Key 用量查询 ─────────────────────

const ADMIN_CACHE_MS = 45 * 1000;          // 单 key 上游结果缓存 45s
const ADMIN_CACHE_FAIL_MS = 8 * 1000;      // 失败结果短缓存，防风暴
const adminCache = new Map();              // apiKey -> { at, data }

function maskKey(key) {
  if (key.length <= 13) return key;
  return `${key.slice(0, 9)}…${key.slice(-4)}`;
}
function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
}

// 套餐计划元数据（与官方 CLI 内置表一致）
// planId 前缀 → 显示名 / 月含额度(USD)
const ADMIN_PLANS = [
  { prefix: 'individual-goat', name: 'GOAT', monthlyCredits: 70 },
  { prefix: 'individual-go', name: 'Go', monthlyCredits: 10 },
  { prefix: 'individual-pro-v1', name: 'Pro', monthlyCredits: 80 },
  { prefix: 'individual-pro', name: 'Pro', monthlyCredits: 30 },
  { prefix: 'individual-provider', name: 'Provider', monthlyCredits: 15 },
  { prefix: 'individual-max', name: 'Max', monthlyCredits: 150 },
  { prefix: 'individual-ultra', name: 'Ultra', monthlyCredits: 300 },
  { prefix: 'teams-pro', name: 'Teams Pro', monthlyCredits: 40 },
];

function lookupPlan(planId) {
  if (!planId) return null;
  const id = String(planId).toLowerCase().replace(/_/g, '-');
  for (const p of ADMIN_PLANS) {
    if (id.startsWith(p.prefix)) return { planId, ...p };
  }
  return { planId, prefix: '', name: id, monthlyCredits: null };
}

async function fetchCcJson(keyInfo, path, signal) {
  const url = new URL(`${CFG.apiBase}${path}`);
  const res = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${keyInfo.key}`,
      'x-cli-environment': 'production',
      'x-command-code-version': CC_VERSION,
      'Content-Type': 'application/json',
      ...(CFG.zdr ? { 'x-cmd-zdr': '1' } : {}),
    },
    signal,
  });
  const text = await res.text().catch(() => '');
  let body = {};
  try { body = text ? JSON.parse(text) : {}; } catch {}
  return { ok: res.ok, status: res.status, body, error: res.ok ? null : (body?.error?.message || body?.error || `HTTP ${res.status}`) };
}

async function fetchKeyCredits(keyInfo, force) {
  const cached = adminCache.get(keyInfo.key);
  if (!force && cached) {
    const ttl = cached.data.ok ? ADMIN_CACHE_MS : ADMIN_CACHE_FAIL_MS;
    if (Date.now() - cached.at < ttl) return cached.data;
  }
  const signal = AbortSignal.timeout(15000);
  try {
    // 与官方 usage 面板一致：三接口并发
    const [credits, subscription, summary] = await Promise.all([
      fetchCcJson(keyInfo, '/alpha/billing/credits', signal),
      fetchCcJson(keyInfo, '/alpha/billing/subscriptions', signal),
      fetchCcJson(keyInfo, '/alpha/usage/summary', signal),
    ]);

    // 主请求（credits）失败视为整体失败；subscription/summary 失败只降级对应块
    const primary = credits;
    const data = {
      ok: primary.ok,
      status: primary.status,
      error: primary.error,
      at: Date.now(),
      credits: primary.body?.credits ?? null,
      windowLimits: primary.body?.windowLimits ?? null,
      subscription: subscription.ok ? (subscription.body?.data ?? subscription.body ?? null) : null,
      subscriptionError: subscription.ok ? null : (subscription.error || `HTTP ${subscription.status}`),
      summary: summary.ok ? summary.body : null,
      summaryError: summary.ok ? null : (summary.error || `HTTP ${summary.status}`),
    };
    adminCache.set(keyInfo.key, { at: Date.now(), data });
    if (!primary.ok) log('warn', 'Admin key query failed', { name: keyInfo.name, status: primary.status });
    else if (!subscription.ok || !summary.ok) log('warn', 'Admin key partial query', { name: keyInfo.name, sub: subscription.status, sum: summary.status });
    return data;
  } catch (e) {
    const data = { ok: false, status: 0, error: e.message || 'network error', at: Date.now(), credits: null, windowLimits: null, subscription: null, summary: null };
    adminCache.set(keyInfo.key, { at: Date.now(), data });
    log('warn', 'Admin key query error', { name: keyInfo.name, error: e.message });
    return data;
  }
}

async function handleAdminApi(req, res) {
  if (!adminEnabled()) {
    sendJSON(res, 403, { error: 'Admin panel disabled. Set adminPassword in config.json or ADMIN_PASSWORD env.' });
    return;
  }
  if (!adminPasswordOk(req) && !adminSessionOk(req)) {
    sendJSON(res, 401, { error: 'Unauthorized' });
    return;
  }

  if (req.method === 'GET') {
    const force = (new URL(req.url, 'http://localhost')).searchParams.get('force') === '1';
    const keys = loadAdminKeys();
    const settled = await Promise.allSettled(keys.map(async k => {
      const r = await fetchKeyCredits(k, force);
      const c = r.credits || {};
      const monthlyRemaining = Math.max(0, Number(c.monthlyCredits) || 0);
      const purchased = Math.max(0, Number(c.purchasedCredits) || 0);
      const free = Math.max(0, Number(c.freeCredits) || 0);
      const totalCost = Math.max(0, Number(r.summary?.totalCost) || 0);
      const sub = r.subscription || null;
      const plan = sub ? lookupPlan(sub.planId) : null;
      const isActive = sub?.status === 'active';
      const planMonthly = isActive && plan?.monthlyCredits != null ? Number(plan.monthlyCredits) : null;
      // 官方口径：月度窗口总额 = max(套餐月额度, 剩余月额度) + 已购 + 免费
      const totalPool = planMonthly != null
        ? Math.max(planMonthly, monthlyRemaining) + purchased + free
        : totalCost + monthlyRemaining + purchased + free;
      const monthlyUsed = Math.max(0, totalPool - (monthlyRemaining + purchased + free));
      const monthlyPct = totalPool > 0 ? Math.min(100, (monthlyUsed / totalPool) * 100) : 0;
      return {
        name: k.name,
        note: k.note,
        keyHash: hashKey(k.key),
        keyMasked: maskKey(k.key),
        ok: r.ok,
        status: r.status,
        error: r.error,
        credits: r.credits,
        windowLimits: r.windowLimits,
        // 套餐与月度窗口（官方 projectUsageView 口径）
        plan: plan ? { id: plan.planId, name: plan.name, monthlyCredits: plan.monthlyCredits } : null,
        subscriptionStatus: sub?.status ?? null,
        periodStart: sub?.currentPeriodStart ?? null,
        periodEnd: sub?.currentPeriodEnd ?? null,
        daysLeft: sub?.currentPeriodEnd ? Math.max(0, Math.ceil((new Date(sub.currentPeriodEnd).getTime() - Date.now()) / 86400000)) : null,
        monthly: {
          used: monthlyUsed,
          remaining: monthlyRemaining,
          purchased,
          free,
          totalSpent: totalCost,
          pool: totalPool,
          pct: monthlyPct,
        },
        summaryError: r.summaryError,
        subscriptionError: r.subscriptionError,
        at: r.at,
      };
    }));
    const results = settled.map(s => (s.status === 'fulfilled' ? s.value : {
      name: '(unknown)', keyHash: '', keyMasked: '', ok: false, status: 0,
      error: s.reason?.message || 'internal error', credits: null, windowLimits: null,
      plan: null, subscriptionStatus: null, monthly: null, at: Date.now(),
    }));
    sendJSON(res, 200, { keys: results, serverTime: Date.now() });
    return;
  }

  if (req.method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { sendJSON(res, 400, { error: 'Invalid JSON body' }); return; }
    const action = body?.action;
    const keys = loadAdminKeys();

    if (action === 'add') {
      const key = String(body?.key || '').trim();
      const name = String(body?.name || '').trim();
      if (!/^user_[A-Za-z0-9_-]+/.test(key)) {
        sendJSON(res, 400, { error: 'Key must start with user_ and contain only letters, digits, _ or -' });
        return;
      }
      if (keys.some(k => k.key === key)) { sendJSON(res, 400, { error: 'Key already exists' }); return; }
      keys.push({ name: name || maskKey(key), key, note: String(body?.note || '') });
      if (!saveAdminKeys(keys)) { sendJSON(res, 500, { error: 'Failed to write keys.json' }); return; }
      adminCache.delete(key);
      sendJSON(res, 200, { ok: true });
      return;
    }

    if (action === 'delete') {
      const hash = String(body?.keyHash || '');
      const idx = keys.findIndex(k => hashKey(k.key) === hash);
      if (idx < 0) { sendJSON(res, 404, { error: 'Key not found' }); return; }
      const [removed] = keys.splice(idx, 1);
      saveAdminKeys(keys);
      adminCache.delete(removed.key);
      sendJSON(res, 200, { ok: true });
      return;
    }

    sendJSON(res, 400, { error: 'Unknown action. Use add or delete.' });
    return;
  }

  sendJSON(res, 405, { error: 'Method not allowed' });
}

async function handleAdminLogin(req, res) {
  if (!adminEnabled()) {
    sendJSON(res, 403, { error: 'Admin panel disabled. Set adminPassword in config.json or ADMIN_PASSWORD env.' });
    return;
  }
  let body;
  try { body = await readBody(req); } catch { sendJSON(res, 400, { error: 'Invalid JSON body' }); return; }
  const pw = String(body?.password || '');
  if (pw.length === 0 || pw !== CFG.adminPassword) {
    sendJSON(res, 401, { error: 'Wrong password' });
    return;
  }
  issueAdminSession(res);
  sendJSON(res, 200, { ok: true });
}

function handleAdminLogout(req, res) {
  const token = parseCookies(req).admin_session;
  if (token) adminSessions.delete(token);
  res.setHeader('Set-Cookie', 'admin_session=; HttpOnly; Path=/admin; SameSite=Lax; Max-Age=0');
  sendJSON(res, 200, { ok: true });
}

const ADMIN_PAGE_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CommandCode Key 用量控制台</title>
<style>
  :root {
    --bg: #0a0e0a;
    --panel: #101710;
    --panel2: #0d130d;
    --line: #22301f;
    --text: #d9e5d1;
    --muted: #7e8f74;
    --accent: #bdf26a;
    --accent-dim: #6f9e3c;
    --cyan: #7fd8f0;
    --warn: #ffb454;
    --danger: #ff6b6b;
    --ok: #bdf26a;
    --mono: "Cascadia Mono", "SF Mono", "JetBrains Mono", ui-monospace, "IBM Plex Mono", Consolas, monospace;
    --sans: "PingFang SC", "Microsoft YaHei", "Noto Sans SC", system-ui, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { min-height: 100%; }
  body {
    background:
      radial-gradient(900px 500px at 85% -10%, rgba(189,242,106,0.08), transparent 60%),
      radial-gradient(700px 420px at -10% 110%, rgba(127,216,240,0.06), transparent 60%),
      repeating-linear-gradient(0deg, rgba(255,255,255,0.012) 0 1px, transparent 1px 4px),
      var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.5;
  }
  .wrap { max-width: 1180px; margin: 0 auto; padding: 28px 20px 60px; }
  header { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; margin-bottom: 26px; }
  .logo { width: 12px; height: 12px; background: var(--accent); box-shadow: 0 0 14px rgba(189,242,106,0.7); transform: rotate(45deg); margin-right: 4px; align-self: center; }
  h1 { font-size: 20px; font-weight: 600; letter-spacing: 0.5px; font-family: var(--mono); }
  h1 small { color: var(--muted); font-weight: 400; margin-left: 8px; font-size: 12px; }
  .sub { color: var(--muted); font-size: 12px; font-family: var(--mono); }
  .pill { font-size: 11px; padding: 3px 10px; border: 1px solid var(--line); border-radius: 99px; color: var(--muted); font-family: var(--mono); background: rgba(255,255,255,0.02); }
  .pill.ok { color: var(--ok); border-color: rgba(189,242,106,0.35); }
  .pill.err { color: var(--danger); border-color: rgba(255,107,107,0.4); }
  .gate {
    max-width: 400px; margin: 12vh auto 0; background: var(--panel);
    border: 1px solid var(--line); border-radius: 14px; padding: 32px 30px;
    box-shadow: 0 24px 60px rgba(0,0,0,0.5);
  }
  .gate h2 { font-size: 16px; margin-bottom: 6px; font-family: var(--mono); }
  .gate p { color: var(--muted); font-size: 12px; margin-bottom: 20px; }
  .gate input, .addrow input {
    width: 100%; background: var(--panel2); border: 1px solid var(--line); color: var(--text);
    padding: 10px 12px; border-radius: 8px; font-size: 13px; font-family: var(--mono); outline: none;
  }
  .gate input:focus, .addrow input:focus { border-color: var(--accent-dim); }
  .gate .err { color: var(--danger); font-size: 12px; margin-top: 10px; min-height: 18px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .stat { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; }
  .stat .k { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; font-family: var(--mono); }
  .stat .v { font-size: 22px; font-weight: 600; font-family: var(--mono); margin-top: 4px; }
  .stat .v.good { color: var(--ok); } .stat .v.bad { color: var(--danger); }
  .toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 14px; flex-wrap: wrap; }
  .btn {
    background: rgba(189,242,106,0.1); color: var(--accent); border: 1px solid rgba(189,242,106,0.35);
    padding: 8px 16px; border-radius: 8px; font-size: 13px; cursor: pointer; font-family: var(--mono);
    transition: background 0.15s;
  }
  .btn:hover { background: rgba(189,242,106,0.2); }
  .btn.ghost { background: transparent; color: var(--muted); border-color: var(--line); }
  .btn.ghost:hover { color: var(--text); border-color: var(--muted); }
  .btn.danger { background: transparent; color: var(--danger); border-color: rgba(255,107,107,0.4); }
  .btn.danger:hover { background: rgba(255,107,107,0.12); }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .statusline { margin-left: auto; color: var(--muted); font-size: 12px; font-family: var(--mono); }
  .statusline .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--accent); margin-right: 6px; animation: pulse 1.6s infinite; }
  .statusline .dot.err { background: var(--danger); }
  .statusline .dot.idle { background: var(--muted); animation: none; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.25; } }
  .addrow { display: grid; grid-template-columns: 1fr 2fr 1.2fr auto; gap: 10px; background: var(--panel); border: 1px dashed var(--line); border-radius: 12px; padding: 12px; margin-bottom: 20px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 14px; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; position: relative; transition: border-color 0.2s; }
  .card:hover { border-color: #33452f; }
  .card.err { border-color: rgba(255,107,107,0.45); }
  .card-head { display: flex; align-items: center; gap: 10px; padding: 14px 16px 10px; }
  .led { width: 9px; height: 9px; border-radius: 50%; flex: none; background: var(--accent); box-shadow: 0 0 8px rgba(189,242,106,0.8); }
  .led.err { background: var(--danger); box-shadow: 0 0 8px rgba(255,107,107,0.8); }
  .card-head .nm { font-weight: 600; font-size: 15px; }
  .card-head .nm .note { color: var(--muted); font-weight: 400; font-size: 12px; margin-left: 8px; }
  .card-head .keyid { margin-left: auto; color: var(--muted); font-family: var(--mono); font-size: 11px; background: rgba(255,255,255,0.04); padding: 3px 8px; border-radius: 6px; }
  .plan-badge { font-family: var(--mono); font-size: 11px; color: var(--accent); background: rgba(189,242,106,0.1); border: 1px solid rgba(189,242,106,0.3); padding: 3px 9px; border-radius: 99px; white-space: nowrap; }
  .plan-badge.muted { color: var(--warn); background: rgba(255,180,84,0.08); border-color: rgba(255,180,84,0.3); }
  .card-head .plan-badge + .keyid { margin-left: auto; }
  .card-body { padding: 4px 16px 14px; }
  .credits { display: flex; gap: 22px; padding: 8px 0 12px; border-bottom: 1px solid rgba(255,255,255,0.05); }
  .cr .lb { color: var(--muted); font-size: 10px; font-family: var(--mono); text-transform: uppercase; letter-spacing: 0.8px; }
  .cr .num { font-family: var(--mono); font-size: 16px; margin-top: 2px; font-weight: 600; }
  .cr.main .num { font-size: 22px; color: var(--accent); }
  .meter { margin-top: 12px; }
  .meter .mrow { display: flex; justify-content: space-between; font-size: 11px; font-family: var(--mono); margin-bottom: 5px; color: var(--muted); }
  .meter .mrow b { color: var(--text); font-weight: 500; }
  .bar { height: 6px; background: rgba(255,255,255,0.06); border-radius: 99px; overflow: hidden; }
  .bar i { display: block; height: 100%; border-radius: 99px; background: var(--accent-dim); transition: width 0.4s; }
  .bar.hot i { background: var(--warn); }
  .bar.over i { background: var(--danger); }
  .meta { display: flex; justify-content: space-between; margin-top: 10px; color: var(--muted); font-size: 10.5px; font-family: var(--mono); }
  .meta .warn { color: var(--warn); }
  .card-foot { display: flex; gap: 8px; padding: 10px 16px; border-top: 1px solid rgba(255,255,255,0.05); align-items: center; }
  .errbox { color: var(--danger); font-size: 12px; padding: 4px 0 10px; font-family: var(--mono); word-break: break-all; }
  .empty { text-align: center; color: var(--muted); padding: 60px 20px; border: 1px dashed var(--line); border-radius: 14px; font-family: var(--mono); }
  .foot { margin-top: 30px; color: var(--muted); font-size: 11px; font-family: var(--mono); text-align: center; opacity: 0.7; }
  [hidden] { display: none !important; }
  @media (max-width: 640px) {
    .cards { grid-template-columns: 1fr; }
    .addrow { grid-template-columns: 1fr; }
    .statusline { margin-left: 0; width: 100%; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <span class="logo"></span>
    <h1>KEY USAGE<small>CommandCode 多 Key 用量控制台</small></h1>
    <span class="sub" id="ver"></span>
    <span class="pill" id="envpill">prod</span>
  </header>

  <div class="gate" id="gate">
    <h2>访问受限</h2>
    <p>输入管理员密码以查看 Key 用量</p>
    <input type="password" id="pw" placeholder="Password" autocomplete="current-password">
    <div class="err" id="gateerr"></div>
    <br>
    <button class="btn" id="loginbtn" style="width:100%">进入控制台</button>
  </div>

  <div id="dash" hidden>
    <div class="stats">
      <div class="stat"><div class="k">Keys</div><div class="v" id="st-keys">–</div></div>
      <div class="stat"><div class="k">正常</div><div class="v good" id="st-ok">–</div></div>
      <div class="stat"><div class="k">异常</div><div class="v bad" id="st-err">–</div></div>
      <div class="stat"><div class="k">月度额度累计</div><div class="v" id="st-monthly">–</div></div>
      <div class="stat"><div class="k">免费额度累计</div><div class="v" id="st-free">–</div></div>
    </div>

    <div class="toolbar">
      <button class="btn" id="refresh">⟳ 刷新</button>
      <button class="btn ghost" id="logout">退出</button>
      <span class="statusline"><span class="dot idle" id="sdot"></span><span id="slabel">就绪</span></span>
    </div>

    <div class="addrow">
      <input type="text" id="add-name" placeholder="备注名（可选）">
      <input type="text" id="add-key" placeholder="user_ 开头的新 Key">
      <input type="text" id="add-note" placeholder="说明（可选）">
      <button class="btn" id="addbtn">添加</button>
    </div>

    <div class="cards" id="cards"></div>
    <div class="empty" id="empty" hidden>还没有 Key。在上方输入 user_ Key 开始监控。</div>
    <div class="foot" id="foot"></div>
  </div>
</div>

<script>
(function () {
  'use strict';
  var gate = document.getElementById('gate');
  var dash = document.getElementById('dash');
  var timer = null;
  var loading = false;

  function fmt(n, d) {
    if (n === null || n === undefined || isNaN(Number(n))) return '–';
    return Number(n).toFixed(d === undefined ? 3 : d);
  }
  function fmtTime(ms) {
    if (!ms) return '–';
    var d = new Date(Number(ms));
    if (isNaN(d)) return '–';
    var p = function (x) { return String(x).padStart(2, '0'); };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }
  function fmtAgo(ms) {
    if (!ms) return '–';
    var s = Math.max(0, Math.round((Date.now() - Number(ms)) / 1000));
    if (s < 60) return s + 's 前';
    if (s < 3600) return Math.round(s / 60) + 'm 前';
    return Math.round(s / 3600) + 'h 前';
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function setStatus(txt, cls) {
    var d = document.getElementById('sdot');
    d.className = 'dot ' + (cls || 'idle');
    document.getElementById('slabel').textContent = txt;
  }

  function meter(label, used, cap, resetAt) {
    var pct = cap > 0 ? Math.min(100, used / cap * 100) : 0;
    var cls = cap > 0 && used >= cap ? 'over' : (pct >= 80 ? 'hot' : '');
    var resetTxt = resetAt ? '重置 ' + fmtTime(resetAt) : '无重置时间';
    return '<div class="meter"><div class="mrow"><span>' + esc(label) + '</span><span>已用 <b>' + fmt(used, 2) + '</b> / ' + fmt(cap, 2) + '</span></div>' +
      '<div class="bar ' + cls + '"><i style="width:' + pct + '%"></i></div>' +
      '<div class="meta"><span>' + resetTxt + '</span><span class="' + (used >= cap ? 'warn' : '') + '">' + pct.toFixed(0) + '%</span></div></div>';
  }

  function render(data) {
    var keys = data.keys || [];
    var okN = keys.filter(function (k) { return k.ok; }).length;
    var errN = keys.length - okN;
    var monthly = 0, free = 0;
    keys.forEach(function (k) {
      if (k.ok) {
        monthly += Number(k.credits?.monthlyCredits) || 0;
        free += Number(k.credits?.freeCredits) || 0;
      }
    });
    document.getElementById('st-keys').textContent = keys.length;
    document.getElementById('st-ok').textContent = okN;
    document.getElementById('st-err').textContent = errN;
    document.getElementById('st-monthly').textContent = monthly.toFixed(3);
    document.getElementById('st-free').textContent = free.toFixed(3);

    var cards = document.getElementById('cards');
    cards.innerHTML = '';
    document.getElementById('empty').hidden = keys.length > 0;

    keys.forEach(function (k) {
      var card = document.createElement('div');
      card.className = 'card' + (k.ok ? '' : ' err');

      var head = document.createElement('div');
      head.className = 'card-head';
      var led = document.createElement('span');
      led.className = 'led' + (k.ok ? '' : ' err');
      head.appendChild(led);
      var nm = document.createElement('span');
      nm.className = 'nm';
      nm.textContent = k.name || '(未命名)';
      if (k.note) {
        var note = document.createElement('span');
        note.className = 'note';
        note.textContent = k.note;
        nm.appendChild(note);
      }
      head.appendChild(nm);
      // 套餐计划徽章
      if (k.plan) {
        var pbadge = document.createElement('span');
        pbadge.className = 'plan-badge';
        pbadge.textContent = k.plan.name;
        if (k.subscriptionStatus && k.subscriptionStatus !== 'active') {
          pbadge.className += ' muted';
          pbadge.textContent += ' · ' + k.subscriptionStatus;
        }
        if (k.plan.monthlyCredits != null) pbadge.title = '月含 $' + k.plan.monthlyCredits;
        head.appendChild(pbadge);
      } else if (k.subscriptionError) {
        var pbadge = document.createElement('span');
        pbadge.className = 'plan-badge muted';
        pbadge.textContent = '套餐获取失败';
        pbadge.title = k.subscriptionError;
        head.appendChild(pbadge);
      }
      var keyid = document.createElement('span');
      keyid.className = 'keyid';
      keyid.textContent = k.keyMasked || k.keyHash;
      keyid.title = 'Key Hash: ' + k.keyHash;
      head.appendChild(keyid);
      card.appendChild(head);

      var body = document.createElement('div');
      body.className = 'card-body';

      if (!k.ok) {
        var eb = document.createElement('div');
        eb.className = 'errbox';
        eb.textContent = '查询失败 [' + (k.status || 'ERR') + '] ' + (k.error || '');
        body.appendChild(eb);
      } else {
        var c = k.credits || {};
        var w = k.windowLimits || {};
        var cr = document.createElement('div');
        cr.className = 'credits';
        var mk = function (cls, lb, num) {
          var d = document.createElement('div');
          d.className = 'cr' + (cls ? ' ' + cls : '');
          var l = document.createElement('div'); l.className = 'lb'; l.textContent = lb;
          var n = document.createElement('div'); n.className = 'num'; n.textContent = num;
          d.appendChild(l); d.appendChild(n);
          return d;
        };
        cr.appendChild(mk('main', 'Monthly', fmt(c.monthlyCredits)));
        cr.appendChild(mk('', 'Purchased', fmt(c.purchasedCredits)));
        cr.appendChild(mk('', 'Free', fmt(c.freeCredits)));
        body.appendChild(cr);
        // 月度窗口（套餐周期用量）——官方口径：已用/(max(套餐月额,剩余)+已购+免费)
        if (k.monthly) {
          var m = k.monthly;
          var mCap = m.pool > 0 ? m.pool : null;
          var mReset = k.periodEnd ? fmtTime(k.periodEnd) : null;
          var mPct = mCap ? Math.min(100, m.pct) : 0;
          var mCls = mCap && m.used >= mCap ? 'over' : (mPct >= 80 ? 'hot' : '');
          var mUsedTxt = mCap != null ? fmt(m.used, 2) + ' / ' + fmt(mCap, 2) : fmt(m.used, 2);
          var mm = document.createElement('div');
          mm.className = 'meter';
          mm.innerHTML = '<div class="mrow"><span>' + esc('月度窗口' + (k.plan ? ' · ' + esc(k.plan.name) : '')) + '</span>' +
            '<span>已用 <b>' + mUsedTxt + '</b></span></div>' +
            '<div class="bar ' + mCls + '"><i style="width:' + mPct + '%"></i></div>' +
            '<div class="meta"><span>' + (mReset ? '周期至 ' + mReset + (k.daysLeft != null ? '（剩 ' + k.daysLeft + ' 天）' : '') : '周期信息不可用') +
            '</span><span>' + (mCap ? mPct.toFixed(0) + '%' : '') + '</span></div>';
          body.appendChild(mm);
        } else if (k.summaryError) {
          var me = document.createElement('div');
          me.className = 'meta';
          me.style.cssText = 'padding:8px 0 2px;color:var(--warn)';
          me.textContent = '月度窗口获取失败（summary 接口 ' + k.summaryError + '）';
          body.appendChild(me);
        }
        if (w.fiveHour) body.insertAdjacentHTML('beforeend', meter('5H 窗口', w.fiveHour.used, w.fiveHour.cap, w.fiveHour.resetAt));
        if (w.weekly) body.insertAdjacentHTML('beforeend', meter('Weekly 窗口', w.weekly.used, w.weekly.cap, w.weekly.resetAt));
      }
      card.appendChild(body);

      var foot = document.createElement('div');
      foot.className = 'card-foot';
      var when = document.createElement('span');
      when.style.cssText = 'color:var(--muted);font-family:var(--mono);font-size:10.5px';
      when.textContent = '更新 ' + fmtAgo(k.at);
      foot.appendChild(when);
      var del = document.createElement('button');
      del.className = 'btn danger';
      del.style.cssText = 'margin-left:auto;padding:5px 12px;font-size:12px';
      del.textContent = '删除';
      del.addEventListener('click', function () {
        if (!confirm('删除 Key ' + (k.name || '') + ' ？此操作只移除本地监控，不影响账号。')) return;
        post({ action: 'delete', keyHash: k.keyHash }, function (r) {
          if (r && r.ok) { setStatus('已删除', 'ok'); load(true); }
        });
      });
      foot.appendChild(del);
      card.appendChild(foot);
      cards.appendChild(card);
    });
  }

  function post(body, cb) {
    fetch('/admin/api/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'same-origin',
    }).then(function (r) {
      return r.json().then(function (d) {
        if (r.status === 401) { showGate(); return null; }
        if (r.status === 403) { alert('管理页未启用：请在 config.json 配置 adminPassword'); return null; }
        return d;
      });
    }).then(function (d) {
      if (!d) return;
      if (d.error) { alert('操作失败：' + d.error); cb(null); return; }
      cb(d);
    }).catch(function () { alert('网络错误'); cb(null); });
  }

  function load(force) {
    // 强制刷新时忽略进行中的请求，避免 loading 门闩吞掉关键刷新
    if (loading && !force) return;
    if (force) loading = false;
    loading = true;
    setStatus('查询中…', '');
    fetch('/admin/api/keys' + (force ? '?force=1' : ''), { credentials: 'same-origin' })
      .then(function (r) {
        if (r.status === 401) { showGate(); throw new Error('auth'); }
        if (r.status === 403) { alert('管理页未启用：请在 config.json 配置 adminPassword'); throw new Error('disabled'); }
        return r.json();
      })
      .then(function (d) {
        if (d && d.keys) { render(d); setStatus('更新于 ' + fmtAgo(d.serverTime), 'ok'); }
        else { setStatus('无数据', 'err'); }
      })
      .catch(function (e) {
        if (e && e.message !== 'auth' && e.message !== 'disabled') setStatus('加载失败', 'err');
      })
      .then(function () { loading = false; });
  }

  function showGate() {
    clearInterval(timer);
    dash.hidden = true;
    gate.hidden = false;
    setStatus('就绪', 'idle');
  }
  function enter() {
    gate.hidden = true;
    dash.hidden = false;
    load(true);
    clearInterval(timer);
    timer = setInterval(function () { load(false); }, 45000);
  }

  document.getElementById('loginbtn').addEventListener('click', function () {
    var pw = document.getElementById('pw').value;
    document.getElementById('gateerr').textContent = '';
    if (!pw) { document.getElementById('gateerr').textContent = '请输入密码'; return; }
    fetch('/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
      credentials: 'same-origin',
    }).then(function (r) {
      if (r.ok) { document.getElementById('pw').value = ''; enter(); return null; }
      return r.json().then(function (d) { throw new Error(d.error || '密码错误'); });
    }).catch(function (e) {
      document.getElementById('gateerr').textContent = e.message || '密码错误';
    });
  });
  document.getElementById('pw').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') document.getElementById('loginbtn').click();
  });
  document.getElementById('refresh').addEventListener('click', function () { load(true); });
  document.getElementById('logout').addEventListener('click', function () {
    fetch('/admin/logout', { method: 'POST', credentials: 'same-origin' }).then(function () { showGate(); });
  });
  document.getElementById('addbtn').addEventListener('click', function () {
    var btn = document.getElementById('addbtn');
    var key = document.getElementById('add-key').value.trim();
    if (!key) { alert('请输入 Key'); return; }
    if (key.indexOf('user_') !== 0) { alert('Key 必须以 user_ 开头'); return; }
    var payload = {
      action: 'add',
      name: document.getElementById('add-name').value.trim(),
      key: key,
      note: document.getElementById('add-note').value.trim(),
    };
    btn.disabled = true;
    btn.textContent = '添加中…';
    post(payload, function (r) {
      btn.disabled = false;
      btn.textContent = '添加';
      if (r && r.ok) {
        document.getElementById('add-key').value = '';
        document.getElementById('add-name').value = '';
        document.getElementById('add-note').value = '';
        setStatus('已添加 ' + (payload.name || key.slice(0, 9) + '…') + '，查询中…', 'ok');
        load(true);
      }
    });
  });
  document.getElementById('ver').textContent = 'cli ' + navigator.userAgent.indexOf('admin') > -1 ? '' : '';
  document.getElementById('envpill').textContent = 'local proxy';

  // 首次加载即探活：未登录显示密码门，已登录直接进
  fetch('/admin/api/keys', { credentials: 'same-origin' }).then(function (r) {
    if (r.status === 200) { enter(); }
    else { gate.hidden = false; }
  }).catch(function () { gate.hidden = false; });
})();
</script>
</body>
</html>
`;

function handleAdminPage(req, res) {
  if (!adminEnabled()) {
    sendJSON(res, 403, { error: 'Admin panel disabled. Set adminPassword in config.json or ADMIN_PASSWORD env.' });
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(ADMIN_PAGE_HTML);
}

// ── 服务器 ──────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const host = req.headers.host || 'localhost';
  const url = new URL(req.url, `http://${host}`);

  try {
    if (url.pathname === '/v1/chat/completions' && req.method === 'POST') {
      await handleChatCompletions(req, res);
    } else if (url.pathname === '/v1/messages' && req.method === 'POST') {
      await handleMessages(req, res);
    } else if (url.pathname === '/v1/models' && req.method === 'GET') {
      await handleModels(req, res);
    } else if (url.pathname === '/alpha/billing/credits' && req.method === 'GET') {
      await handleBillingCredits(req, res);
    } else if (url.pathname === '/admin' || url.pathname === '/admin/') {
      handleAdminPage(req, res);
    } else if (url.pathname === '/admin/api/keys' && (req.method === 'GET' || req.method === 'POST')) {
      await handleAdminApi(req, res);
    } else if (url.pathname === '/admin/login' && req.method === 'POST') {
      await handleAdminLogin(req, res);
    } else if (url.pathname === '/admin/logout' && req.method === 'POST') {
      handleAdminLogout(req, res);
    } else if (url.pathname === '/health' || url.pathname === '/') {
      handleHealth(req, res);
    } else {
      sendJSON(res, 404, { error: { message: 'Not found', type: 'not_found' } });
    }
  } catch (e) {
    sendJSON(res, 500, { error: { message: e.message, type: 'internal_error' } });
  }
});

// 全局兜底：abort 触发的异步 rejection 不会让进程崩溃
process.on('unhandledRejection', (reason) => {
  if (reason?.name === 'AbortError' || reason?.code === 'ABORT_ERR') {
    // 客户端断连触发的 abort — 预期行为，静默处理
    log('info', 'Aborted request cleaned up');
  } else {
    log('error', 'Unhandled rejection', { message: reason?.message || String(reason), stack: reason?.stack?.split('\n')[0] });
  }
});

server.listen(CFG.port, CFG.host, () => {
  log('info', 'CC Proxy started', {
    url: `http://${CFG.host}:${CFG.port}`,
    api: CFG.apiBase,
    models: MODELS.length,
    session: '12h + 1h jitter, per API key',
    zdr: CFG.zdr ? 'enabled (x-cmd-zdr: 1 on generation/init requests)' : 'off (CMD_ZDR=1 or per-request x-cmd-zdr: 1 to enable)',
    logFile: CFG.logFile || '(console only)',
  });
  if (!CFG.apiKey) {
    log('info', 'No API key in config. API key must be sent in Authorization: Bearer <key> header per request.');
  }
});
