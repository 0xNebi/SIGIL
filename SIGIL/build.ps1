$ErrorActionPreference = "Stop"

$SCRIPT_DIR  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ENTRY_POINT = Join-Path $SCRIPT_DIR "sigil.py"
$ICON_PATH   = Join-Path $SCRIPT_DIR "src\assets\sigil_logo.ico"

Write-Host "=== SIGIL Build ===" -ForegroundColor Cyan
Write-Host "Script   : $ENTRY_POINT"

if (-not (Test-Path $ICON_PATH)) {
    $PNG_PATH = Join-Path $SCRIPT_DIR "src\assets\sigil_logo.png"
    if (Test-Path $PNG_PATH) {
        Write-Host "Converting PNG to ICO via pillow..." -ForegroundColor Yellow
        python -c "
from PIL import Image
img = Image.open(r'$PNG_PATH')
img.save(r'$ICON_PATH', sizes=[(16,16),(32,32),(48,48),(256,256)])
print('ICO created.')
"
    } else {
        Write-Host "Warning: sigil_logo.png not found, building without icon." -ForegroundColor Yellow
        $ICON_PATH = $null
    }
}

$HOOKS_DIR = "G:\Visual Studio Projects\GUI\.venv\Lib\site-packages\pygame_gui\__pyinstaller"
$ICON_ARG = if ($ICON_PATH -and (Test-Path $ICON_PATH)) { "--icon `"$ICON_PATH`"" } else { "" }

$CMD = "& `"G:\Visual Studio Projects\GUI\.venv\Scripts\pyinstaller.exe`" " +
       "--onefile " +
       "--noconsole " +
       "--name SIGIL " +
       "--add-data `"src;src`" " +
       "--add-data `"plugins;plugins`" " +
       "--collect-all pygame_gui " +
       "--collect-all pygame " +
       "--collect-binaries cryptography " +
       "--hidden-import=bcrypt " +
       "--hidden-import=pyperclip " +
       "--hidden-import=tkinter " +
       "--hidden-import=tkinter.ttk " +
       "--hidden-import=tkinter.messagebox " +
       "--hidden-import=_tkinter " +
       "--additional-hooks-dir=`"$HOOKS_DIR`" " +
       $ICON_ARG + " " +
       "`"$ENTRY_POINT`""

Write-Host "Running: $CMD" -ForegroundColor Green
Invoke-Expression $CMD

$EXE = Join-Path $SCRIPT_DIR "dist\SIGIL.exe"
if (Test-Path $EXE) {
    $SIZE_MB = [math]::Round((Get-Item $EXE).Length / 1MB, 1)
    Write-Host ""
    Write-Host "Build successful: $EXE  ($SIZE_MB MB)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Distribute to user:"
    Write-Host "  SIGIL.exe"
    Write-Host "  src/"
    Write-Host "    assets/"
    Write-Host "      sigil_logo.png"
    Write-Host "    config/"
    Write-Host "      public_key.pem"
    Write-Host "  plugins/   (empty folder)"
    Write-Host ""
    Write-Host "DO NOT include: app.salt, users.enc, encrypted_secret.key"
} else {
    Write-Host "Build FAILED - EXE not found at $EXE" -ForegroundColor Red
    exit 1
}
