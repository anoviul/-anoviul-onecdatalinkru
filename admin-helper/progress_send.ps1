$ErrorActionPreference = 'SilentlyContinue'
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch { }
$base    = ($env:ODL_BASE).TrimEnd('/')
$token   = $env:ODL_TOKEN
$secret  = $env:ODL_SECRET
$iid     = $env:ODL_IID
$cid     = [int]('0' + $env:ODL_CID)
$opuid   = $env:ODL_OPUID
$payload = $env:ODL_PAYLOAD
$pfile   = $env:ODL_PROGRESS
$stop    = $env:ODL_STOP
$ppid    = [int]('0' + $env:ODL_PPID)
$pstart  = [long]('0' + $env:ODL_PSTART)
$every   = [int]('0' + $env:ODL_EVERY); if ($every -lt 5) { $every = 20 }
$tail    = [int]('0' + $env:ODL_TAIL);  if ($tail -lt 500) { $tail = 3500 }
$deadln  = [int]('0' + $env:ODL_DEADLINE); if ($deadln -lt 10) { $deadln = 3600 }
if (-not $base -or -not $token -or -not $iid -or $cid -le 0 -or -not $pfile -or -not $opuid -or -not $payload) { exit 0 }

try { $u = [System.Uri]$base } catch { exit 0 }
if ($u.Scheme -ne 'https') { exit 0 }
$origin = $u

function Родитель-Жив {
    if ($ppid -le 0) { return $true }
    try {
        $p = Get-Process -Id $ppid -ErrorAction Stop
        if ($pstart -gt 0) { return ($p.StartTime.ToFileTimeUtc() -eq $pstart) }
        return $true
    } catch { return $false }
}

function Хвост([string]$путь, [int]$лимит) {
    try {
        $fi = Get-Item -LiteralPath $путь -ErrorAction Stop
        $len = $fi.Length
        $fs = [System.IO.File]::Open($путь, 'Open', 'Read', 'ReadWrite')
        try {
            if ($len -gt $лимит) { [void]$fs.Seek($len - $лимит, 'Begin') }
            $buf = New-Object byte[] ([int][Math]::Min($len, $лимит))
            [void]$fs.Read($buf, 0, $buf.Length)
        } finally { $fs.Close() }
    } catch { return '' }
    $txt = [System.Text.Encoding]::UTF8.GetString($buf)
    if ($len -gt $лимит) { $nl = $txt.IndexOf("`n"); if ($nl -ge 0) { $txt = $txt.Substring($nl + 1) } }
    return $txt.Trim()
}

function JsonStr([string]$s) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $s.ToCharArray()) {
        switch ($ch) {
            '"'  { [void]$sb.Append('\"') }
            '\'  { [void]$sb.Append('\\') }
            "`n" { [void]$sb.Append('\n') }
            "`r" { [void]$sb.Append('\r') }
            "`t" { [void]$sb.Append('\t') }
            default { if ([int][char]$ch -lt 32) { [void]$sb.Append(('\u{0:x4}' -f [int][char]$ch)) } else { [void]$sb.Append($ch) } }
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Послать([string]$текст) {
    try {
        $json = '{"install_id":' + (JsonStr $iid) + ',"command_id":' + $cid +
                ',"progress_text":' + (JsonStr $текст) +
                ',"op_uid":' + (JsonStr $opuid) + ',"payload_sha256":' + (JsonStr $payload) + '}'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $req = [System.Net.HttpWebRequest]::Create($origin.ToString().TrimEnd('/') + '/api/v1/desktop/progress')
        $req.Method = 'POST'; $req.ContentType = 'application/json; charset=utf-8'
        $req.Headers['X-Bridge-Token'] = $token
        if ($secret) { $req.Headers['X-Agent-Secret'] = $secret }
        $req.AllowAutoRedirect = $false
        $req.Timeout = 15000; $req.ContentLength = $bytes.Length
        $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode; $resp.Close()
        if ($code -ge 300) { return 1 }
        return 0
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) { $c = [int]$r.StatusCode; if ($c -eq 401 -or $c -eq 403 -or $c -eq 404 -or $c -eq 409) { return 1 } }
        return 0
    } catch { return 0 }
}

$прежнее = ''
$живём = 0
while ($true) {
    Start-Sleep -Seconds $every
    if ($stop -and (Test-Path -LiteralPath $stop)) { break }
    if (-not (Родитель-Жив)) { break }
    $живём += $every
    if ($живём -gt $deadln) { break }
    $t = Хвост $pfile $tail
    if ($t -and $t -ne $прежнее) {
        $r = Послать $t
        if ($r -eq 1) { break }
        $прежнее = $t
    }
}
