const { app, BrowserWindow, ipcMain, shell } = require('electron');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

let win;

app.whenReady().then(() => {
  win = new BrowserWindow({
    width: 900,
    height: 600,
    webPreferences: { preload: path.join(__dirname, 'preload.js') },
  });
  win.loadFile('index.html');
});

const ALLOWED_LINKS = ['https://example.com/help', 'https://example.com/terms'];
const ALLOWED_TOOLS = ['ffmpeg', 'convert'];
const ALLOWED_PAGES = ['index.html', 'settings.html'];

ipcMain.on('open-link', (event, url) => {
  if (ALLOWED_LINKS.includes(url)) {
    shell.openExternal(url);
  }
});

ipcMain.handle('read-note', async (event, name) => {
  return fs.readFileSync(path.join(app.getPath('documents'), path.basename(name)), 'utf8');
});

ipcMain.handle('run-tool', (event, tool) => {
  return new Promise((resolve) => {
    if (!ALLOWED_TOOLS.includes(tool)) {
      return resolve('unknown tool');
    }
    execFile('tools/' + tool, ['--version'], (err, out) => resolve(out));
  });
});

ipcMain.on('navigate', (event, target) => {
  if (ALLOWED_PAGES.includes(target)) {
    win.loadFile(target);
  }
});
