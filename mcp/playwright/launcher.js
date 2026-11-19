const { spawn } = require('child_process');
const { spawnSync } = require('child_process');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');
const stateRoot = path.resolve(process.env.CTF_AGENT_ROOT || root);
const defaultPython = process.platform === 'win32'
  ? path.join(root, '.venv', 'Scripts', 'python.exe')
  : path.join(root, '.venv', 'bin', 'python');
const python = process.env.CTF_PYTHON || defaultPython;
const proxyPort = String(process.env.CTF_PLAYWRIGHT_PROXY_PORT || '18080');
const proxy = spawn(
  python,
  [
    path.join(__dirname, 'scope_proxy.py'),
    '--port',
    proxyPort,
    '--scope-file',
    path.join(stateRoot, 'challenges', 'current', 'active-scope.json'),
    '--log-file',
    path.join(root, 'logs', 'playwright-scope-proxy.jsonl'),
  ],
  { stdio: ['ignore', 'ignore', 'inherit'] },
);

let child;
let shuttingDown = false;
const pendingCalls = new Map();
const pythonPath = path.join(root, 'tools');

function budget(action, id, name, args, ok, summary, startedAtMs = 0) {
  const result = spawnSync(
    python,
    ['-m', 'ctf_core.browser_budget'],
    {
      input: JSON.stringify({
        action,
        tool_name: name,
        arguments: args || {},
        ok,
        result_summary: summary || '',
        started_at_ms: startedAtMs,
      }),
      encoding: 'utf8',
      timeout: 5000,
      env: {
        ...process.env,
        PYTHONPATH: pythonPath,
        CTF_AGENT_ROOT: stateRoot,
      },
    },
  );
  if (result.error || result.status !== 0 || !result.stdout.trim()) {
    return {
      allowed: false,
      code: 'BROWSER_BUDGET_FAILED',
      message: result.stderr || result.error?.message || 'browser budget bridge failed',
    };
  }
  try {
    return JSON.parse(result.stdout.trim().split(/\r?\n/).pop());
  } catch (error) {
    return {
      allowed: false,
      code: 'BROWSER_BUDGET_FAILED',
      message: `invalid browser budget response: ${error.message}`,
    };
  }
}

function blockedToolResponse(id, decision) {
  const text = JSON.stringify({
    ok: false,
    code: decision.code || 'BROWSER_TOOL_BLOCKED',
    message: decision.message || 'browser tool blocked',
  });
  return JSON.stringify({
    jsonrpc: '2.0',
    id,
    result: {
      content: [{ type: 'text', text }],
      isError: true,
    },
  }) + '\n';
}

function relayByLine(stream, output, onLine) {
  let buffer = Buffer.alloc(0);
  stream.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    let newline = buffer.indexOf(0x0a);
    while (newline >= 0) {
      const line = buffer.subarray(0, newline + 1);
      buffer = buffer.subarray(newline + 1);
      if (!onLine(line)) output.write(line);
      newline = buffer.indexOf(0x0a);
    }
  });
  stream.on('end', () => {
    if (buffer.length) {
      if (!onLine(buffer)) output.write(buffer);
    }
  });
}

function summarizeResult(message) {
  const result = message?.result || {};
  if (result.isError) return 'error';
  const content = Array.isArray(result.content) ? result.content : [];
  const text = content
    .filter((item) => item && item.type === 'text')
    .map((item) => item.text || '')
    .join('\n')
    .slice(0, 4000);
  return text || 'ok';
}

function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  if (child && !child.killed) child.kill();
  if (proxy && !proxy.killed) proxy.kill();
  setTimeout(() => process.exit(code), 100);
}

proxy.on('exit', (code) => {
  if (!shuttingDown) shutdown(code || 1);
});

setTimeout(() => {
  const cli = path.join(__dirname, 'node_modules', '@playwright', 'mcp', 'cli.js');
  const browserArgs = process.env.CTF_PLAYWRIGHT_BROWSER_EXECUTABLE
    ? ['--executable-path', process.env.CTF_PLAYWRIGHT_BROWSER_EXECUTABLE]
    : [];
  child = spawn(
    process.execPath,
    [
      cli,
      `--proxy-server=http://127.0.0.1:${proxyPort}`,
      ...browserArgs,
      ...process.argv.slice(2),
    ],
    { stdio: ['pipe', 'pipe', 'inherit'], env: process.env },
  );
  relayByLine(child.stdout, process.stdout, (line) => {
    let message;
    try {
      message = JSON.parse(line.toString('utf8').trim());
    } catch {
      return false;
    }
    const key = String(message.id);
    const pending = pendingCalls.get(key);
    if (!pending) return false;
    pendingCalls.delete(key);
    budget(
      'finish',
      message.id,
      pending.name,
      pending.arguments,
      !(message.result && message.result.isError),
      summarizeResult(message),
      pending.startedAtMs,
    );
    return false;
  });
  relayByLine(process.stdin, child.stdin, (line) => {
    let message;
    try {
      message = JSON.parse(line.toString('utf8').trim());
    } catch {
      return false;
    }
    if (message.method !== 'tools/call') return false;
    const name = message.params?.name || '';
    const args = message.params?.arguments || {};
    const decision = budget('begin', message.id, name, args, false, '');
    if (!decision.allowed) {
      process.stdout.write(blockedToolResponse(message.id, decision));
      return true;
    }
    pendingCalls.set(String(message.id), {
      name,
      arguments: args,
      startedAtMs: Date.now(),
    });
    return false;
  });
  child.on('exit', (code) => shutdown(code || 0));
}, 350);

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
