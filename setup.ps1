# Caddy Filter Proxy - Complete Setup Script with LOGGING
# Run in PowerShell as Administrator
# Prerequisites: Go installed, hosts file with blocked domains

# ============================================================================
# CONFIGURATION - CHANGE THESE IF NEEDED
# ============================================================================

$REMOTE_HOSTS_FILE = "https://raw.githubusercontent.com/Equation-Tracker/CaddyProxy/refs/heads/main/hosts.txt"
$HOSTS_FILE = "C:\\CaddyProxy\\hosts.txt"  # ← CHANGE THIS to your hosts file location
$CADDY_DIR  = "C:\\CaddyProxy"             # Where to install everything
$PROXY_PORT = 8080                         # Proxy port (change if needed)

# ============================================================================
# HELPERS
# ============================================================================

function New-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

# ============================================================================
# STEP 1: Verify Go is installed
# ============================================================================

Write-Host "[1/9] Checking Go installation..." -ForegroundColor Cyan

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Go is not installed or not in PATH!" -ForegroundColor Red
    Write-Host "Install from: https://go.dev/dl/" -ForegroundColor Yellow
    exit 1
}

$goVersion = go version
Write-Host "✓ Found: $goVersion" -ForegroundColor Green

# ============================================================================
# STEP 2: Choose / download hosts file and verify it exists
# ============================================================================

Write-Host "[2/9] Hosts file selection..." -ForegroundColor Cyan

# Prompt the user: empty = download default remote, URL = download that URL, otherwise treat as local path
$prompt = "Enter hosts source — press Enter to download default remote ($REMOTE_HOSTS_FILE), or enter a URL (http(s)://...), or enter a local file path:"
$userInput = Read-Host $prompt

if ([string]::IsNullOrWhiteSpace($userInput)) {
	Write-Host "Downloading default remote hosts from $REMOTE_HOSTS_FILE..." -ForegroundColor Cyan
	try {
		Invoke-WebRequest -Uri $REMOTE_HOSTS_FILE -OutFile $HOSTS_FILE -UseBasicParsing -ErrorAction Stop
		Write-Host "✓ Downloaded remote hosts to $HOSTS_FILE" -ForegroundColor Green
	} catch {
		Write-Host "ERROR: Failed to download remote hosts: $($_.Exception.Message)" -ForegroundColor Red
		exit 1
	}
} elseif ($userInput -match '^\s*https?://') {
	Write-Host "Downloading hosts from $userInput..." -ForegroundColor Cyan
	try {
		Invoke-WebRequest -Uri $userInput -OutFile $HOSTS_FILE -UseBasicParsing -ErrorAction Stop
		Write-Host "✓ Downloaded remote hosts to $HOSTS_FILE" -ForegroundColor Green
	} catch {
		Write-Host "ERROR: Failed to download hosts from ${userInput}: $($_.Exception.Message)" -ForegroundColor Red
		exit 1
	}
} else {
	$path = $userInput.Trim()
	if (-not (Test-Path $path)) {
		Write-Host "ERROR: File not found at: $path" -ForegroundColor Red
		exit 1
	}
	$HOSTS_FILE = $path
	Write-Host "Using local hosts file: $HOSTS_FILE" -ForegroundColor Green
}

# Count domain entries from hosts file (robust token parsing)
$domainCount = (Get-Content $HOSTS_FILE | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq '' -or $line -match '^\s*#') { return }

        # Strip inline comments
        $line = $line -replace '\s+#.*$',''

        # Split tokens: first token is usually the IP, rest are hostnames
        $tokens = -split $line
        if ($tokens.Count -lt 2) { return }

		$ip = $tokens[0]
		# Only count domains that are explicitly mapped to 0.0.0.0
		if ($ip -eq '0.0.0.0') {
			for ($i = 1; $i -lt $tokens.Count; $i++) { $tokens[$i].Trim() }
		}
} | Where-Object { $_ -and $_ -notmatch '^\s*$' } | Measure-Object).Count

Write-Host "✓ Found hosts file with $domainCount entries" -ForegroundColor Green

# ============================================================================
# STEP 3: Create directory structure
# ============================================================================

Write-Host "[3/9] Creating directories..." -ForegroundColor Cyan

New-Directory $CADDY_DIR
New-Directory "$CADDY_DIR\\blockfilter"
New-Directory "$CADDY_DIR\\logs"

Write-Host "✓ Created/verified $CADDY_DIR" -ForegroundColor Green

# ============================================================================
# STEP 4: Extract domains from hosts file and create blocklist
# ============================================================================

Write-Host "[4/9] Converting hosts file to blocklist..." -ForegroundColor Cyan

$blocklist = Join-Path $CADDY_DIR 'blocklist.txt'

# Build blocklist: extract hostnames from standard hosts entries
Get-Content $HOSTS_FILE | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq '' -or $line -match '^\s*#') { return }

        $line = $line -replace '\s+#.*$',''
        $tokens = -split $line
        if ($tokens.Count -lt 2) { return }

		$ip = $tokens[0]
		# Only include domains explicitly mapped to 0.0.0.0
		if ($ip -eq '0.0.0.0') {
			for ($i = 1; $i -lt $tokens.Count; $i++) { $tokens[$i].Trim() }
		}
} | Where-Object { $_ -and $_ -notmatch '^\s*$' } | Sort-Object -Unique | Out-File -FilePath $blocklist -Encoding UTF8

$blockCount = (Get-Content $blocklist).Count
Write-Host "✓ Created blocklist with $blockCount domains" -ForegroundColor Green

# ============================================================================
# STEP 5: Create the filter plugin (Go code) WITH LOGGING
# ============================================================================

Write-Host "[5/9] Creating filter plugin with logging..." -ForegroundColor Cyan

$pluginCode = @'
package blockfilter

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/publicsuffix"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(BlockFilter{})
	httpcaddyfile.RegisterHandlerDirective("block_filter", parseCaddyfile)
}

type BlockFilter struct {
	BlocklistPath string `json:"blocklist_path,omitempty"`
	LogPath       string `json:"log_path,omitempty"`

	blocked map[string]struct{}
	mu      sync.RWMutex
	logFile *os.File
	logMu   sync.Mutex
}

func (BlockFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.block_filter",
		New: func() caddy.Module { return new(BlockFilter) },
	}
}

func (b *BlockFilter) Provision(ctx caddy.Context) error {
	b.blocked = make(map[string]struct{}, 100000)

	if b.BlocklistPath == "" {
		b.BlocklistPath = "C:\\CaddyProxy\\blocklist.txt"
	}

	if b.LogPath == "" {
		b.LogPath = "C:\\CaddyProxy\\logs\\blocked.log"
	}

	// Open log file for appending
	var err error
	b.logFile, err = os.OpenFile(b.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	log.Printf("Block filter logging to: %s", b.LogPath)

	return b.loadBlocklist()
}

func hasLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		switch {
		case ipv4[0] == 10:
			return true
		case ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31:
			return true
		case ipv4[0] == 192 && ipv4[1] == 168:
			return true
		}
	}
	// IPv6 link-local/loopback
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}

func (b *BlockFilter) loadBlocklist() error {
	file, err := os.Open(b.BlocklistPath)
	if err != nil {
		return err
	}
	defer file.Close()

	b.mu.Lock()
	defer b.mu.Unlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// skip entries that contain no letters (likely numeric fragments or malformed)
		if !hasLetter(line) {
			continue
		}
		b.blocked[line] = struct{}{}
	}

	log.Printf("Loaded %d blocked domains", len(b.blocked))
	return scanner.Err()
}

func (b *BlockFilter) isBlocked(host string) bool {
	// Normalize host: strip port, trim, lowercase
	if i := strings.Index(host, ":"); i != -1 {
		host = host[:i]
	}
	host = strings.ToLower(strings.TrimSpace(host))

	b.mu.RLock()
	defer b.mu.RUnlock()

	// If host is an IP, parse it and handle accordingly
	if ip := net.ParseIP(host); ip != nil {
		// Allow private / loopback addresses (do not block router/local UI)
		if isPrivateIP(ip) {
			return false
		}
		// For IPs, only check exact match in blocklist
		if _, exists := b.blocked[host]; exists {
			return true
		}
		return false
	}

	// Host is a domain name: check exact match first
	if _, exists := b.blocked[host]; exists {
		return true
	}

	// Try to determine the effective TLD+1 (publicsuffix). If successful,
	// only check parent domains down to that boundary. This prevents
	// crossing public suffix boundaries like "com.bd".
	if etld1, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		h := host
		for {
			if _, exists := b.blocked[h]; exists {
				return true
			}
			if h == etld1 {
				break
			}
			idx := strings.Index(h, ".")
			if idx == -1 {
				break
			}
			h = h[idx+1:]
		}
		return false
	}

	// Fallback: if we can't determine eTLD+1, do a safer parent-domain check:
	// only consider suffixes that contain at least one letter and are not very short.
	h := host
	for {
		idx := strings.Index(h, ".")
		if idx == -1 {
			break
		}
		h = h[idx+1:]
		if len(h) < 3 {
			continue
		}
		if !hasLetter(h) {
			continue
		}
		if _, exists := b.blocked[h]; exists {
			return true
		}
	}
	return false
}

func (b *BlockFilter) logBlocked(host, url, clientIP string) {
	b.logMu.Lock()
	defer b.logMu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] BLOCKED | Host: %s | URL: %s | Client: %s\n",
		timestamp, host, url, clientIP)

	if b.logFile != nil {
		b.logFile.WriteString(logLine)
		b.logFile.Sync() // Flush to disk immediately
	}
}

func (b *BlockFilter) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if b.isBlocked(r.Host) {
		// Extract client IP
		clientIP := r.RemoteAddr
		if i := strings.LastIndex(clientIP, ":"); i != -1 {
			clientIP = clientIP[:i]
		}

		// Construct full URL
		fullURL := r.URL.String()
		if r.URL.Scheme == "" {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			fullURL = scheme + "://" + r.Host + fullURL
		}

		// Log the blocked request
		b.logBlocked(r.Host, fullURL, clientIP)

		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access blocked by filter"))
		return nil
	}
	return next.ServeHTTP(w, r)
}

func (b *BlockFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "blocklist":
				if !d.NextArg() {
					return d.Err("blocklist requires a path argument")
				}
				b.BlocklistPath = d.Val()
			case "log":
				if !d.NextArg() {
					return d.Err("log requires a path argument")
				}
				b.LogPath = d.Val()
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var b BlockFilter
	err := b.UnmarshalCaddyfile(h.Dispenser)
	return &b, err
}

var (
	_ caddy.Provisioner           = (*BlockFilter)(nil)
	_ caddyhttp.MiddlewareHandler = (*BlockFilter)(nil)
	_ caddyfile.Unmarshaler       = (*BlockFilter)(nil)
)
'@

Set-Content -Path "$CADDY_DIR\\blockfilter\\blockfilter.go" -Value $pluginCode -Encoding UTF8

# Create go.mod file for the plugin
$goModContent = @'
module blockfilter

go 1.21

require (
	github.com/caddyserver/caddy/v2 v2.7.6
	golang.org/x/net v0.17.0
)
'@

Set-Content -Path "$CADDY_DIR\\blockfilter\\go.mod" -Value $goModContent -Encoding UTF8

Write-Host "✓ Created plugin files with logging support" -ForegroundColor Green

# ============================================================================
# STEP 6: Download dependencies for the plugin
# ============================================================================

Write-Host "[6/9] Downloading Go dependencies..." -ForegroundColor Cyan

Push-Location "$CADDY_DIR\\blockfilter"
go mod tidy
Pop-Location

Write-Host "✓ Dependencies ready" -ForegroundColor Green

# ============================================================================
# STEP 7: Install xcaddy and build Caddy with the plugin
# ============================================================================

Write-Host "[7/9] Building Caddy (this takes a few minutes)..." -ForegroundColor Cyan

# Install xcaddy if not already installed
if (-not (Get-Command xcaddy -ErrorAction SilentlyContinue)) {
    Write-Host "Installing xcaddy..." -ForegroundColor Yellow
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

    # Add Go bin to PATH for this session
    $env:PATH += ";$env:USERPROFILE\\go\\bin"
}

# Build Caddy with our plugin and forwardproxy
Push-Location $CADDY_DIR
& "$env:USERPROFILE\\go\\bin\\xcaddy.exe" build --with blockfilter=./blockfilter --with github.com/caddyserver/forwardproxy --output caddy.exe
Pop-Location

if (-not (Test-Path "$CADDY_DIR\\caddy.exe")) {
    Write-Host "ERROR: Failed to build Caddy!" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Caddy built successfully with logging support" -ForegroundColor Green

# ============================================================================
# STEP 8: Create Caddyfile configuration with logging
# ============================================================================

Write-Host "[8/9] Creating configuration..." -ForegroundColor Cyan

$caddyfileContent = @"
{
    admin off
    auto_https off
}

:8080 {
    route {
        block_filter {
            blocklist $CADDY_DIR\\blocklist.txt
            log $CADDY_DIR\\logs\\blocked.log
        }

        forward_proxy {
            hide_ip
            hide_via
        }

        header -Server
    }
}
"@

Set-Content -Path "$CADDY_DIR\\Caddyfile" -Value $caddyfileContent -Encoding UTF8

Write-Host "✓ Configuration created with logging enabled" -ForegroundColor Green

# ============================================================================
# STEP 9: Create Windows Service (optional)
# ============================================================================

Write-Host ""
Write-Host "Creating Windows Service..." -ForegroundColor Cyan

$createService = Read-Host "Do you want to install as Windows Service? (y/n)"

if ($createService -eq "y") {
    # Download NSSM
    Write-Host "Downloading NSSM..." -ForegroundColor Yellow
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $nssmZip = "$env:TEMP\\nssm.zip"
    Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip
    Expand-Archive -Path $nssmZip -DestinationPath "$CADDY_DIR\\nssm" -Force

    # adjust path if the zip layout differs; this assumes nssm-2.24\win64\nssm.exe
    $nssmExe = Get-ChildItem -Path "$CADDY_DIR\\nssm" -Recurse -Filter "nssm.exe" | Where-Object { $_.FullName -match 'win64' } | Select-Object -First 1
    if (-not $nssmExe) {
        $nssmExe = Get-ChildItem -Path "$CADDY_DIR\\nssm" -Recurse -Filter "nssm.exe" | Select-Object -First 1
    }
    if ($nssmExe) {
        $nssmPath = $nssmExe.FullName
        & $nssmPath install CaddyProxy "$CADDY_DIR\\caddy.exe" "run" "--config" "$CADDY_DIR\\Caddyfile"
        & $nssmPath set CaddyProxy AppDirectory $CADDY_DIR
        & $nssmPath set CaddyProxy AppStdout $CADDY_DIR\logs\caddy-out.log
        & $nssmPath set CaddyProxy AppStderr $CADDY_DIR\logs\caddy-err.log
        & $nssmPath set CaddyProxy DisplayName "Caddy Filter Proxy"
        & $nssmPath set CaddyProxy Description "O(1) filtering proxy with logging"
        & $nssmPath set CaddyProxy Start SERVICE_AUTO_START

        Start-Service CaddyProxy
        Write-Host "✓ Service installed and started" -ForegroundColor Green
    } else {
        Write-Host "ERROR: NSSM executable not found in archive" -ForegroundColor Red
    }
}

# ============================================================================
# COMPLETE!
# ============================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "✅ SETUP COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "📁 Installation directory: $CADDY_DIR" -ForegroundColor Cyan
Write-Host "📝 Blocklist: $CADDY_DIR\\blocklist.txt ($blockCount domains)" -ForegroundColor Cyan
Write-Host "📊 Blocked requests log: $CADDY_DIR\\logs\\blocked.log" -ForegroundColor Cyan
Write-Host "🌐 Proxy address: 127.0.0.1:$PROXY_PORT" -ForegroundColor Cyan
Write-Host ""

if ($createService -eq "y") {
    Write-Host "🔧 Service Management:" -ForegroundColor Yellow
    Write-Host "   Start:   Start-Service CaddyProxy" -ForegroundColor White
    Write-Host "   Stop:    Stop-Service CaddyProxy" -ForegroundColor White
    Write-Host "   Restart: Restart-Service CaddyProxy" -ForegroundColor White
} else {
    Write-Host "🔧 To run manually:" -ForegroundColor Yellow
    Write-Host "   cd $CADDY_DIR" -ForegroundColor White
    Write-Host "   .\\caddy.exe run --config Caddyfile" -ForegroundColor White
}

Write-Host ""
Write-Host "📊 View blocked requests log:" -ForegroundColor Yellow
Write-Host "   Get-Content $CADDY_DIR\\logs\\blocked.log -Tail 20 -Wait" -ForegroundColor White
Write-Host ""
Write-Host "🌐 Configure Windows Proxy:" -ForegroundColor Yellow
Write-Host "   Settings → Network → Proxy → Manual" -ForegroundColor White
Write-Host "   Address: 127.0.0.1  Port: $PROXY_PORT" -ForegroundColor White
Write-Host ""
