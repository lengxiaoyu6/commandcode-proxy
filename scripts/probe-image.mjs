#!/usr/bin/env node
// 探针 B：带图片实验组 —— 内容与探针 A 完全相同，只多挂一张真实 PNG。
// 图片在脚本内现场生成（随机像素 → 不可压缩 → 大小贴近真实工具截图），无需外部素材。
//
// 用法：
//   API_KEY=user_xxx node probe-image.mjs
// 可调环境变量：
//   BASE_URL  默认 http://127.0.0.1:3050
//   MODEL     默认 deepseek/deepseek-v4.1-flash
//   COUNT     默认 10
//   IMG_KB    默认 1024（即 base64 后约 1MB，对齐线上那条 bytes=1049242）
//   REQ_TIMEOUT_MS 默认 150000
//   OUT       默认 probe-image.jsonl
import { appendFileSync, writeFileSync } from 'fs';
import crypto from 'crypto';
import zlib from 'zlib';

const BASE = process.env.BASE_URL || 'http://127.0.0.1:3050';
const KEY = process.env.API_KEY || '';
const MODEL = process.env.MODEL || 'deepseek/deepseek-v4.1-flash';
const COUNT = Number(process.env.COUNT || 10);
const IMG_KB = Number(process.env.IMG_KB || 1024);
const TIMEOUT_MS = Number(process.env.REQ_TIMEOUT_MS || 150000);
const OUT = process.env.OUT || 'probe-image.jsonl';
const PROMPT = process.env.PROMPT || 'Reply with exactly: ok';

if (!KEY) {
  console.error('缺少 API_KEY。示例：API_KEY=user_xxx node probe-image.mjs');
  process.exit(1);
}

// ── 生成一张合法的、体积可控的 PNG ──────────────────────────
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const t = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
  return Buffer.concat([len, t, data, crc]);
}

function makePng(width, height) {
  const stride = width * 4 + 1;
  const raw = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    raw[y * stride] = 0;                                    // filter: None
    crypto.randomFillSync(raw, y * stride + 1, width * 4);   // 随机像素 → 不可压缩
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 6;   // color type: RGBA
  const idat = zlib.deflateSync(raw, { level: 0 });          // 存储模式，体积≈原始
  return {
    buf: Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      pngChunk('IHDR', ihdr),
      pngChunk('IDAT', idat),
      pngChunk('IEND', Buffer.alloc(0)),
    ]),
    width, height,
  };
}

function makePngByBase64Size(targetB64Bytes) {
  const rawTarget = Math.round((targetB64Bytes * 3) / 4);
  const w = Math.max(16, Math.floor(Math.sqrt(rawTarget / 4)));
  const h = Math.max(16, Math.floor(rawTarget / (w * 4 + 1)));
  return makePng(w, h);
}

const png = makePngByBase64Size(IMG_KB * 1024);
const DATA_URL = `data:image/png;base64,${png.buf.toString('base64')}`;

const fmt = (ms) => (ms == null ? '   —  ' : ms >= 1000 ? (ms / 1000).toFixed(2) + 's' : ms + 'ms');

async function once(n) {
  const t0 = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  const rec = {
    n, kind: 'image', startedAt: new Date().toISOString(),
    ttfbMs: null, totalMs: null, status: 0, events: 0, done: false, error: null, lastEvent: null,
  };
  try {
    const res = await fetch(`${BASE}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${KEY}` },
      body: JSON.stringify({
        model: MODEL,
        stream: true,
        messages: [{
          role: 'user',
          content: [
            { type: 'text', text: PROMPT },
            { type: 'image_url', image_url: { url: DATA_URL } },
          ],
        }],
      }),
      signal: ctrl.signal,
    });
    rec.status = res.status;
    if (!res.ok) {
      rec.error = `HTTP ${res.status}: ${(await res.text().catch(() => '')).slice(0, 300)}`;
      return rec;
    }
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (rec.ttfbMs === null) rec.ttfbMs = Date.now() - t0;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop() || '';
      for (const line of lines) {
        const s = line.trim();
        if (!s.startsWith('data:')) continue;
        const payload = s.slice(5).trim();
        if (payload === '[DONE]') { rec.done = true; continue; }
        try {
          const ev = JSON.parse(payload);
          rec.events++;
          rec.lastEvent = ev.type || (ev.choices ? 'chunk' : '(other)');
          if (ev.error) rec.error = JSON.stringify(ev.error).slice(0, 300);
        } catch { /* 非法 JSON 行忽略 */ }
      }
    }
    try { await reader.cancel(); } catch {}
  } catch (e) {
    rec.error = e.name === 'AbortError'
      ? `无响应超过 ${TIMEOUT_MS}ms（客户端主动断开）`
      : `网络错误: ${e.message}`;
  } finally {
    clearTimeout(timer);
    rec.totalMs = Date.now() - t0;
  }
  return rec;
}

writeFileSync(OUT, '');
console.log(`探针 B（带图片）→ ${BASE}  model=${MODEL}  次数=${COUNT}`);
console.log(`图片：${png.width}x${png.height} PNG，base64 ${(DATA_URL.length / 1024 / 1024).toFixed(2)} MB（含 data URL 前缀）\n`);

const recs = [];
for (let i = 1; i <= COUNT; i++) {
  const r = await once(i);
  recs.push(r);
  appendFileSync(OUT, JSON.stringify(r) + '\n');
  console.log(
    `[${String(i).padStart(2)}/${COUNT}] status=${String(r.status).padEnd(3)}` +
    ` ttfb=${fmt(r.ttfbMs).padStart(8)} total=${fmt(r.totalMs).padStart(8)}` +
    ` events=${String(r.events).padStart(4)} done=${r.done ? 'yes' : ' NO'}` +
    (r.error ? `  err=${r.error.slice(0, 90)}` : '')
  );
}

const med = (a) => (a.length ? [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)] : null);
const okN = recs.filter((r) => r.done).length;
const tt = recs.map((r) => r.ttfbMs).filter((v) => v != null);
const tot = recs.map((r) => r.totalMs).filter((v) => v != null);

console.log(`\n================ 汇总（带图片）================`);
console.log(`样本 ${recs.length}｜正常收尾 ${okN}｜异常 ${recs.length - okN}`);
console.log(`TTFB   中位 ${fmt(med(tt))}  最小 ${fmt(tt.length ? Math.min(...tt) : null)}  最大 ${fmt(tt.length ? Math.max(...tt) : null)}`);
console.log(`总耗时 中位 ${fmt(med(tot))}  最小 ${fmt(tot.length ? Math.min(...tot) : null)}  最大 ${fmt(tot.length ? Math.max(...tot) : null)}`);
console.log(`日志：${OUT}`);
