const { app, BrowserWindow } = require('electron')
let win
function createWindow () {
  win = new BrowserWindow({
    width: 450,
    height: 650,
    webPreferences: {
      devTools: true,
      enableRemoteModule: true,
      contextIsolation: false,
      nodeIntegration: true,
      nodeIntegrationInSubFrames: true,
      nodeIntegrationInWorker: true
    },    
    frame: false,
    autoHideMenuBar: true
  })
  win.loadFile('index.html');
  //win.maximize();
  //win.webContents.openDevTools();
}

app.whenReady().then(createWindow)

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow()
  }
})