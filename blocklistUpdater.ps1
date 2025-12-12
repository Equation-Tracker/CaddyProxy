# ============================================================================
# CONFIGURATION - CHANGE THESE IF NEEDED
# ============================================================================

$REMOTE_HOSTS_FILE = "https://raw.githubusercontent.com/Equation-Tracker/CaddyProxy/refs/heads/main/hosts.txt"
$HOSTS_FILE = "C:\\CaddyProxy\\hosts.txt"  # ← CHANGE THIS to your hosts file location
$CADDY_DIR  = "C:\\CaddyProxy"             # Where to install everything

# ============================================================================
# STEP 1: Choose / download hosts file and verify it exists
# ============================================================================

Write-Host "[1/2] Hosts file selection..." -ForegroundColor Cyan

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
        if ($ip -match '^(?:\d{1,3}\.){3}\d{1,3}$' -or $ip -match '^[0-9a-fA-F:]+$') {
                for ($i = 1; $i -lt $tokens.Count; $i++) { $tokens[$i].Trim() }
        }
} | Where-Object { $_ -and $_ -notmatch '^\s*$' } | Measure-Object).Count

Write-Host "✓ Found hosts file with $domainCount entries" -ForegroundColor Green

# ============================================================================
# STEP 2: Extract domains from hosts file and create blocklist
# ============================================================================

Write-Host "[2/2] Converting hosts file to blocklist..." -ForegroundColor Cyan

$blocklist = Join-Path $CADDY_DIR 'blocklist.txt'

# Build blocklist: extract hostnames from standard hosts entries
Get-Content $HOSTS_FILE | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq '' -or $line -match '^\s*#') { return }

        $line = $line -replace '\s+#.*$',''
        $tokens = -split $line
        if ($tokens.Count -lt 2) { return }

        $ip = $tokens[0]
        if ($ip -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1|0:0:0:0:0:0:0:1|::)$' -or $ip -match '^(?:\d{1,3}\.){3}\d{1,3}$' -or $ip -match '^[0-9a-fA-F:]+$') {
                for ($i = 1; $i -lt $tokens.Count; $i++) { $tokens[$i].Trim() }
        }
} | Where-Object { $_ -and $_ -notmatch '^\s*$' } | Sort-Object -Unique | Out-File -FilePath $blocklist -Encoding UTF8

$blockCount = (Get-Content $blocklist).Count
Write-Host "✓ Created blocklist with $blockCount domains" -ForegroundColor Green
