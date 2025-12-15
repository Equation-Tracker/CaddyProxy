# Caddy Proxy - Service Installer
# Run as Administrator in PowerShell
# This script installs/reinstalls CaddyProxy as a Windows Service

# ============================================================================
# CONFIGURATION
# ============================================================================

$SERVICE_NAME = "CaddyProxy"
$CADDY_DIR = "C:\CaddyProxy"
$CADDY_EXE = "$CADDY_DIR\caddy.exe"
$CADDYFILE = "$CADDY_DIR\Caddyfile"
$LOG_DIR = "$CADDY_DIR\logs"

# ============================================================================
# VERIFY PREREQUISITES
# ============================================================================

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Caddy Proxy - Service Installer" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "[1/5] Checking prerequisites..." -ForegroundColor Cyan

# Check if Caddy executable exists
if (-not (Test-Path $CADDY_EXE)) {
    Write-Host "ERROR: Caddy executable not found at: $CADDY_EXE" -ForegroundColor Red
    Write-Host "Please run the setup script first to build Caddy." -ForegroundColor Yellow
    pause
    exit 1
}
Write-Host "  ✓ Found Caddy executable" -ForegroundColor Green

# Check if Caddyfile exists
if (-not (Test-Path $CADDYFILE)) {
    Write-Host "ERROR: Caddyfile not found at: $CADDYFILE" -ForegroundColor Red
    Write-Host "Please run the setup script first." -ForegroundColor Yellow
    pause
    exit 1
}
Write-Host "  ✓ Found Caddyfile" -ForegroundColor Green

# Create logs directory if it doesn't exist
if (-not (Test-Path $LOG_DIR)) {
    New-Item -ItemType Directory -Force -Path $LOG_DIR | Out-Null
    Write-Host "  ✓ Created logs directory" -ForegroundColor Green
} else {
    Write-Host "  ✓ Logs directory exists" -ForegroundColor Green
}

# ============================================================================
# CHECK AND REMOVE EXISTING SERVICE
# ============================================================================

Write-Host ""
Write-Host "[2/5] Checking for existing service..." -ForegroundColor Cyan

$existingService = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Host "  ⚠ Service '$SERVICE_NAME' already exists" -ForegroundColor Yellow
    Write-Host "  Status: $($existingService.Status)" -ForegroundColor Yellow
    Write-Host ""
    
    $confirm = Read-Host "  Do you want to remove and reinstall the service? (y/n)"
    
    if ($confirm -ne "y") {
        Write-Host "  Installation cancelled." -ForegroundColor Yellow
        pause
        exit 0
    }
    
    Write-Host ""
    Write-Host "  Removing existing service..." -ForegroundColor Yellow
    
    # Stop the service if it's running
    if ($existingService.Status -eq "Running") {
        Write-Host "    - Stopping service..." -ForegroundColor Yellow
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Host "    ✓ Service stopped" -ForegroundColor Green
    }
    
    # Try to delete using sc.exe first (works for NSSM services)
    Write-Host "    - Deleting service..." -ForegroundColor Yellow
    $result = sc.exe delete $SERVICE_NAME
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    ✓ Service deletion initiated" -ForegroundColor Green
    } else {
        Write-Host "    ⚠ Warning: Could not delete service using sc.exe" -ForegroundColor Yellow
        Write-Host "    Attempting alternative method..." -ForegroundColor Yellow
        
        # Try using WMI as fallback
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='$SERVICE_NAME'"
        if ($service) {
            $service.Delete() | Out-Null
            Write-Host "    ✓ Service deletion initiated using WMI" -ForegroundColor Green
        }
    }
    
    # Wait for Windows to fully remove the service
    Write-Host "    - Waiting for service deletion to complete..." -ForegroundColor Yellow
    $maxWait = 30 # Maximum wait time in seconds
    $waited = 0
    
    while ($waited -lt $maxWait) {
        Start-Sleep -Seconds 1
        $waited++
        
        # Check if service still exists
        $stillExists = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
        
        if (-not $stillExists) {
            Write-Host "    ✓ Service fully removed after $waited seconds" -ForegroundColor Green
            break
        }
        
        # Show progress every 5 seconds
        if ($waited % 5 -eq 0) {
            Write-Host "      Still waiting... ($waited/$maxWait seconds)" -ForegroundColor DarkGray
        }
    }
    
    # Final check
    $stillExists = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($stillExists) {
        Write-Host "    ⚠ WARNING: Service still exists after $maxWait seconds" -ForegroundColor Yellow
        Write-Host "    Please close Services.msc if open and try again" -ForegroundColor Yellow
        Write-Host ""
        pause
        exit 1
    }
    
    # Extra safety wait
    Start-Sleep -Seconds 2
} else {
    Write-Host "  ✓ No existing service found" -ForegroundColor Green
}

# ============================================================================
# DOWNLOAD NSSM
# ============================================================================

Write-Host ""
Write-Host "[3/5] Setting up NSSM (Non-Sucking Service Manager)..." -ForegroundColor Cyan

$nssmDir = "$CADDY_DIR\nssm"
$nssmExePath = $null

# Check if NSSM already exists
$existingNssm = Get-ChildItem -Path $CADDY_DIR -Recurse -Filter "nssm.exe" -ErrorAction SilentlyContinue | 
                Where-Object { $_.FullName -match 'win64' } | 
                Select-Object -First 1

if (-not $existingNssm) {
    $existingNssm = Get-ChildItem -Path $CADDY_DIR -Recurse -Filter "nssm.exe" -ErrorAction SilentlyContinue | 
                    Select-Object -First 1
}

if ($existingNssm) {
    $nssmExePath = $existingNssm.FullName
    Write-Host "  ✓ Found existing NSSM at: $nssmExePath" -ForegroundColor Green
} else {
    Write-Host "  Downloading NSSM..." -ForegroundColor Yellow
    
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $nssmZip = "$env:TEMP\nssm.zip"
    
    try {
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing
        Expand-Archive -Path $nssmZip -DestinationPath $nssmDir -Force
        
        # Find nssm.exe
        $nssmExe = Get-ChildItem -Path $nssmDir -Recurse -Filter "nssm.exe" | 
                   Where-Object { $_.FullName -match 'win64' } | 
                   Select-Object -First 1
        
        if (-not $nssmExe) {
            $nssmExe = Get-ChildItem -Path $nssmDir -Recurse -Filter "nssm.exe" | 
                       Select-Object -First 1
        }
        
        if ($nssmExe) {
            $nssmExePath = $nssmExe.FullName
            Write-Host "  ✓ Downloaded and extracted NSSM" -ForegroundColor Green
        } else {
            Write-Host "  ERROR: Could not find nssm.exe in downloaded archive" -ForegroundColor Red
            pause
            exit 1
        }
        
        # Clean up zip file
        Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Host "  ERROR: Failed to download NSSM: $($_.Exception.Message)" -ForegroundColor Red
        pause
        exit 1
    }
}

# ============================================================================
# INSTALL SERVICE
# ============================================================================

Write-Host ""
Write-Host "[4/5] Installing service..." -ForegroundColor Cyan

try {
    # Install service
    & $nssmExePath install $SERVICE_NAME $CADDY_EXE "run" "--config" $CADDYFILE
    if ($LASTEXITCODE -ne 0) {
        throw "NSSM install command failed with exit code $LASTEXITCODE"
    }
    Write-Host "  ✓ Service installed" -ForegroundColor Green
    
    # Configure service settings
    & $nssmExePath set $SERVICE_NAME AppDirectory $CADDY_DIR
    & $nssmExePath set $SERVICE_NAME AppStdout "$LOG_DIR\caddy-out.log"
    & $nssmExePath set $SERVICE_NAME AppStderr "$LOG_DIR\caddy-err.log"
    & $nssmExePath set $SERVICE_NAME DisplayName "Caddy Filter Proxy"
    & $nssmExePath set $SERVICE_NAME Description "O(1) filtering proxy with domain blocking and logging"
    & $nssmExePath set $SERVICE_NAME Start SERVICE_AUTO_START
    
    Write-Host "  ✓ Service configured" -ForegroundColor Green
    
} catch {
    Write-Host "  ERROR: Failed to install service: $($_.Exception.Message)" -ForegroundColor Red
    pause
    exit 1
}

# ============================================================================
# START SERVICE
# ============================================================================

Write-Host ""
Write-Host "[5/5] Starting service..." -ForegroundColor Cyan

try {
    Start-Service -Name $SERVICE_NAME
    Start-Sleep -Seconds 2
    
    $service = Get-Service -Name $SERVICE_NAME
    if ($service.Status -eq "Running") {
        Write-Host "  ✓ Service started successfully" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Warning: Service state is $($service.Status)" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "  ERROR: Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  You can start it manually: Start-Service $SERVICE_NAME" -ForegroundColor Yellow
}

# ============================================================================
# COMPLETION
# ============================================================================

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  ✅ SERVICE INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Service Name:     $SERVICE_NAME" -ForegroundColor Cyan
Write-Host "Service Status:   $($(Get-Service -Name $SERVICE_NAME).Status)" -ForegroundColor Cyan
Write-Host "Caddy Path:       $CADDY_EXE" -ForegroundColor Cyan
Write-Host "Config Path:      $CADDYFILE" -ForegroundColor Cyan
Write-Host "Logs Directory:   $LOG_DIR" -ForegroundColor Cyan
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Service Management Commands:" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Start Service:    Start-Service $SERVICE_NAME" -ForegroundColor White
Write-Host "Stop Service:     Stop-Service $SERVICE_NAME" -ForegroundColor White
Write-Host "Restart Service:  Restart-Service $SERVICE_NAME" -ForegroundColor White
Write-Host "Service Status:   Get-Service $SERVICE_NAME" -ForegroundColor White
Write-Host ""
Write-Host "View Logs:" -ForegroundColor Yellow
Write-Host "  Blocked URLs:   Get-Content $LOG_DIR\blocked.log -Tail 20 -Wait" -ForegroundColor White
Write-Host "  Caddy Output:   Get-Content $LOG_DIR\caddy-out.log -Tail 20 -Wait" -ForegroundColor White
Write-Host "  Caddy Errors:   Get-Content $LOG_DIR\caddy-err.log -Tail 20 -Wait" -ForegroundColor White
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

pause
