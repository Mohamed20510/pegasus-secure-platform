const { app, BrowserWindow, shell } = require('electron');
const path = require('path');
const fs = require('fs');

function createWindow() {
  // Use PNG or ICO if present; otherwise keep undefined to prevent Windows icon crash
  let iconPath = path.join(__dirname, 'public', 'logo.png');
  if (!fs.existsSync(iconPath)) {
    iconPath = undefined;
  }

  const win = new BrowserWindow({
    width: 1300,
    height: 880,
    minWidth: 1050,
    minHeight: 700,
    title: "PEGASUS - Secure Software Intelligence Platform",
    icon: iconPath,
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  const appUrl = 'http://localhost:3000';
  console.log('[PEGASUS Desktop] Connecting to:', appUrl);
  win.loadURL(appUrl);

  // Keep all internal application navigation INSIDE the desktop window
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http://localhost:3000') || url.startsWith('/')) {
      win.loadURL(url);
      return { action: 'deny' };
    }
    // Only open external documentation (e.g. MITRE CWE / OWASP links) in an external browser
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // If Next.js is still compiling or booting, automatically retry until connected
  win.webContents.on('did-fail-load', () => {
    console.log('[PEGASUS Desktop] Waiting for server to finish starting...');
    setTimeout(() => {
      win.loadURL(appUrl);
    }, 1500);
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});