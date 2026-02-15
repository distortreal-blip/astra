const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

let mainWindow = null;
let tunProcess = null;
let pingInterval = null;
let logStream = null;

const isDev = !app.isPackaged;
const rootDir = app.isPackaged
  ? path.dirname(app.getPath('exe'))
  : path.join(__dirname, '..', '..');
const clientExe = path.join(rootDir, 'astra-tun-client.exe');
const configPath = path.join(rootDir, 'configs', 'astra-tun-client.json');
const logDir = path.join(rootDir, 'logs');
const currentLogPath = path.join(logDir, 'current.log');

function ensureLogDir() {
  try {
    fs.mkdirSync(logDir, { recursive: true });
  } catch (_) {}
}

function closeLogStream() {
  if (logStream) {
    try { logStream.end(); } catch (_) {}
    logStream = null;
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 300,
    height: 600,
    minWidth: 300,
    minHeight: 600,
    maxWidth: 300,
    maxHeight: 600,
    resizable: false,
    frame: true,
    transparent: false,
    backgroundColor: '#080D16',
    title: 'Astra VPN ver 0.1',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  }
  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(() => {
  ensureLogDir();
  createWindow();
});

app.on('window-all-closed', () => {
  if (tunProcess) {
    tunProcess.kill();
    tunProcess = null;
  }
  if (pingInterval) clearInterval(pingInterval);
  closeLogStream();
  app.quit();
});

ipcMain.handle('connect', async () => {
  if (tunProcess) return { ok: false, error: 'Already connected' };
  if (!fs.existsSync(clientExe)) {
    return { ok: false, error: 'astra-tun-client.exe not found. Build it and place next to Astra GUI.' };
  }
  ensureLogDir();
  closeLogStream();
  try {
    logStream = fs.createWriteStream(currentLogPath, { flags: 'w' });
    const ts = new Date().toISOString();
    logStream.write(`[${ts}] Astra TUN client started\n`);
  } catch (e) {
    logStream = null;
  }

  return new Promise((resolve) => {
    tunProcess = spawn(clientExe, ['-config', configPath], {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stderr = '';
    let allOut = '';
    let resolved = false;
    const MAX_WAIT_MS = 15000;
    const connectedMarker = 'connected to entry';

    function writeLog(prefix, data) {
      const s = data.toString();
      if (prefix === 'stderr') stderr += s;
      allOut += s;
      if (logStream) {
        try {
          logStream.write(s);
          if (!s.endsWith('\n')) logStream.write('\n');
        } catch (_) {}
      }
    }

    function checkConnected() {
      if (allOut.includes(connectedMarker)) done(true);
    }

    function done(ok, err) {
      if (resolved) return;
      resolved = true;
      if (tunProcess && !ok) {
        tunProcess.kill();
        tunProcess = null;
      }
      if (pingInterval && !ok) { clearInterval(pingInterval); pingInterval = null; }
      resolve({ ok: !!ok, error: err || undefined });
    }

    tunProcess.stderr.on('data', (d) => { writeLog('stderr', d); checkConnected(); });
    tunProcess.stdout.on('data', (d) => { writeLog('stdout', d); checkConnected(); });
    tunProcess.on('error', (err) => {
      tunProcess = null;
      done(false, err.message);
    });
    tunProcess.on('exit', (code, signal) => {
      const proc = tunProcess;
      tunProcess = null;
      if (pingInterval) { clearInterval(pingInterval); pingInterval = null; }
      closeLogStream();
      if (resolved) return;
      const msg = stderr.trim().slice(-800) || (code != null ? `Exit code ${code}` : 'Process exited');
      done(false, msg);
    });

    setTimeout(() => {
      if (!resolved && tunProcess) {
        if (allOut.includes(connectedMarker)) {
          done(true);
        } else {
          done(false, 'Timeout: no "connected to entry" in 15s. Check logs.');
        }
      }
    }, MAX_WAIT_MS);
  });
});

ipcMain.handle('disconnect', async () => {
  if (!tunProcess) return { ok: true };
  tunProcess.kill();
  tunProcess = null;
  if (pingInterval) {
    clearInterval(pingInterval);
    pingInterval = null;
  }
  closeLogStream();
  return { ok: true };
});

ipcMain.handle('get-status', () => {
  const connected = tunProcess != null;
  return { connected };
});

function runPing() {
  return new Promise((resolve) => {
    const isWin = process.platform === 'win32';
    const cmd = isWin ? 'ping' : 'ping';
    const args = isWin ? ['-n', '1', '10.10.0.1'] : ['-c', '1', '10.10.0.1'];
    const p = spawn(cmd, args, { windowsHide: true });
    let out = '';
    p.stdout.on('data', (d) => { out += d.toString(); });
    p.stderr.on('data', (d) => { out += d.toString(); });
    p.on('close', () => {
      const ms = parsePingMs(out, isWin);
      resolve(ms);
    });
    setTimeout(() => {
      p.kill();
      resolve(null);
    }, 3000);
  });
}

function parsePingMs(text, isWin) {
  const str = (text || '').replace(/\r\n/g, '\n');
  if (isWin) {
    const m = str.match(/Average\s*=\s*(\d+)\s*ms/i)
      || str.match(/Среднее\s*=\s*(\d+)/i)
      || str.match(/time[=<>]\s*(\d+)\s*ms/i)
      || str.match(/time\s*=\s*(\d+)ms/i)
      || str.match(/(\d+)\s*ms/i);
    return m ? parseInt(m[1], 10) : null;
  }
  const m = str.match(/time[=<>]\s*[\d.]+\s*ms/) || str.match(/(\d+\.?\d*)\s*ms/);
  return m ? Math.round(parseFloat(m[1])) : null;
}

ipcMain.handle('start-ping', () => {
  if (pingInterval) return;
  const run = async () => {
    if (!tunProcess || !mainWindow) return;
    const ms = await runPing();
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('ping', ms);
    }
  };
  setTimeout(run, 1500);
  pingInterval = setInterval(run, 2500);
});

ipcMain.handle('open-logs', () => {
  const { shell } = require('electron');
  shell.openPath(logDir);
});
ipcMain.handle('get-log-dir', () => logDir);
