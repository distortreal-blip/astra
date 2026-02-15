const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

let mainWindow = null;
let tunProcess = null;
let pingInterval = null;

const isDev = !app.isPackaged;
const rootDir = app.isPackaged
  ? path.dirname(app.getPath('exe'))
  : path.join(__dirname, '..', '..');
const clientExe = path.join(rootDir, 'astra-tun-client.exe');
const configPath = path.join(rootDir, 'configs', 'astra-tun-client.json');
const logDir = path.join(rootDir, 'logs');

function ensureLogDir() {
  try {
    fs.mkdirSync(logDir, { recursive: true });
  } catch (_) {}
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
  app.quit();
});

ipcMain.handle('connect', async () => {
  if (tunProcess) return { ok: false, error: 'Already connected' };
  if (!fs.existsSync(clientExe)) {
    return { ok: false, error: 'astra-tun-client.exe not found. Build it and place next to Astra GUI.' };
  }
  ensureLogDir();
  return new Promise((resolve) => {
    tunProcess = spawn(clientExe, ['-config', configPath], {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stderr = '';
    let resolved = false;
    tunProcess.stderr.on('data', (d) => { stderr += d.toString(); });
    tunProcess.on('error', (err) => {
      tunProcess = null;
      if (!resolved) { resolved = true; resolve({ ok: false, error: err.message }); }
    });
    tunProcess.on('exit', (code, signal) => {
      tunProcess = null;
      if (pingInterval) { clearInterval(pingInterval); pingInterval = null; }
      if (!resolved && (code !== 0 && code !== null && !signal)) {
        resolved = true;
        resolve({ ok: false, error: stderr.slice(-500) || `Exit code ${code}` });
      }
    });
    tunProcess.stdout.on('data', () => {});
    setTimeout(() => {
      if (!resolved && tunProcess) {
        resolved = true;
        resolve({ ok: true });
      }
    }, 2000);
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
