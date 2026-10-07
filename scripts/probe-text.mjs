#!/usr/bin/env node
// 探针 A：纯文本对照组 —— 连续发 COUNT 次流式请求，记录 TTFB / 总耗时 / 事件数 / 是否正常收尾
//
// 用法：
//   API_KEY=user_xxx node probe-text.mjs
// 可调环境变量：
//   BASE_URL  默认 http://127.0.0.1:3050
//   MODEL     默认 deepseek/deepseek-v4.1-flash
//   COUNT     默认 10
//   REQ_TIMEOUT_MS 默认 150000（比代理的 CC_STREAM_IDLE_MS 略长，便于观察代理先超时）
//   OUT       默认 probe-text.jsonl
import { appendFileSync, writeFileSync } from 'fs';

const BASE = process.env.BASE_URL || 'http://127.0.0.1:3050';
const KEY = process.env.API_KEY || '';
const MODEL = process.env.MODEL || 'deepseek/deepseek-v4.1-flash';
const COUNT = Number(process.env.COUNT || 10);
const TIMEOUT_MS = Number(process.env.REQ_TIMEOUT_MS || 150000);
const OUT = process.env.OUT || 'probe-text.jsonl';
const PROMPT = process.env.PROMPT || 'Reply with exactly: ok';

if (!KEY) {
  console.error('缺少 API_KEY。示例：API_KEY=user_xxx node probe-text.mjs');
  process.exit(1);
}

const fmt = (ms) => (ms == null ? '   —  ' : ms >= 1000 ? (ms / 1000).toFixed(2) + 's' : ms + 'ms');

async function once(n) {
  const t0 = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  const rec = {
    n, kind: 'text', startedAt: new Date().toISOString(),
    ttfbMs: null, totalMs: null, status: 0, events: 0, done: false, error: null, lastEvent: null,
  };
  try {
    const res = await fetch(`${BASE}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${KEY}` },
      body: JSON.stringify({
        model: MODEL,
        stream: true,
        messages: [{ role: 'user', content: PROMPT }],
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
console.log(`探针 A（纯文本）→ ${BASE}  model=${MODEL}  次数=${COUNT}\n`);

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

console.log(`\n================ 汇总（纯文本）================`);
console.log(`样本 ${recs.length}｜正常收尾 ${okN}｜异常 ${recs.length - okN}`);
console.log(`TTFB   中位 ${fmt(med(tt))}  最小 ${fmt(tt.length ? Math.min(...tt) : null)}  最大 ${fmt(tt.length ? Math.max(...tt) : null)}`);
console.log(`总耗时 中位 ${fmt(med(tot))}  最小 ${fmt(tot.length ? Math.min(...tot) : null)}  最大 ${fmt(tot.length ? Math.max(...tot) : null)}`);
console.log(`日志：${OUT}`);
