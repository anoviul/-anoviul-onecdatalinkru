
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Script:ЗДЕСЬ = $null
try {
    $psr = Get-Variable -Name PSScriptRoot -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not $psr) { $psr = Get-Variable -Name PSScriptRoot -ValueOnly -ErrorAction SilentlyContinue }
    if ($psr) { $Script:ЗДЕСЬ = $psr }
} catch { }
if (-not $ЗДЕСЬ) {
    if ($MyInvocation.MyCommand.Path) { $Script:ЗДЕСЬ = Split-Path -Parent $MyInvocation.MyCommand.Path }
}
if (-not $ЗДЕСЬ) {
    $Script:ЗДЕСЬ = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}
$Script:CONFIG_DIR  = Join-Path $ЗДЕСЬ 'config'
$Script:LOGS_DIR    = Join-Path $ЗДЕСЬ 'logs'
$Script:RUNTIME_DIR = Join-Path $ЗДЕСЬ 'runtime'
foreach ($d in @($CONFIG_DIR, $LOGS_DIR, $RUNTIME_DIR)) {
    try { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } } catch { }
}
$Script:CONFIG  = Join-Path $CONFIG_DIR 'config.json'
$Script:HISTORY = Join-Path $RUNTIME_DIR 'history.json'
$Script:HISTORY_LEGACY = Join-Path $RUNTIME_DIR 'history.legacy.json'
$Script:LOCK    = Join-Path $RUNTIME_DIR 'helper.lock'
$Script:PIDFILE = Join-Path $RUNTIME_DIR 'helper.pid'
$Script:LOG     = Join-Path $LOGS_DIR 'helper.log'
$Script:HISTORY_FMT = 2
$Script:LOG_MAX = 10MB
$Script:OUTPUT_MAX = 256KB
$Script:SCRIPT_MAX = 64KB
$Script:CONFIRM_TIMEOUT = 120
$Script:POLL_IDLE_SEC = 3
$Script:RESEND_EVERY_SEC = 60
$Script:TIMEOUT_MIN = 5
$Script:TIMEOUT_MAX = 300
$Script:HELPER_VERSION = '0.3-ps'
$Script:УборкаНеПодтверждена = $false
$Script:ДовериеНаСеанс = $false

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Журнал([string]$текст) {
    try {
        if ((Test-Path $LOG) -and (Get-Item $LOG).Length -gt $LOG_MAX) {
            Move-Item -Force $LOG ($LOG + '.1')
        }
        $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
        Add-Content -Path $LOG -Value ("{0}  {1}" -f $ts, $текст) -Encoding UTF8
    } catch { }
}

function Защитить-Файл([string]$путь, [bool]$каталог = $false) {
    try {
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        if (-not $sid) { Журнал "ACL: нет SID - защита не применена"; return $false }
        if ($каталог) {
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $inh = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
                   [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        } else {
            $acl = New-Object System.Security.AccessControl.FileSecurity
            $inh = [System.Security.AccessControl.InheritanceFlags]::None
        }
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inh, [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.SetAccessRule($rule)
        if ($каталог) { [System.IO.Directory]::SetAccessControl($путь, $acl) }
        else          { [System.IO.File]::SetAccessControl($путь, $acl) }
        $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor `
                    [System.Security.AccessControl.AccessControlSections]::Owner
        if ($каталог) { $chk = [System.IO.Directory]::GetAccessControl($путь, $sections) }
        else          { $chk = [System.IO.File]::GetAccessControl($путь, $sections) }
        $rules = @($chk.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        if ((-not $chk.AreAccessRulesProtected) -or $rules.Count -ne 1 -or
            $chk.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) {
            Журнал "ACL: неверный владелец или приватная DACL не подтверждена"; return $false
        }
        $r = $rules[0]
        if ($r.IdentityReference.Value -ne $sid.Value -or $r.IsInherited -or
            $r.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $r.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $r.InheritanceFlags -ne $inh -or
            $r.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
            Журнал "ACL: правило доступа не соответствует текущей учетной записи"; return $false
        }
        return $true
    } catch {
        Журнал ("ACL: не удалось защитить {0} ({1})" -f (Split-Path -Leaf $путь), $_.Exception.Message)
        return $false
    }
}

function Защитить-Окружение() {
    foreach ($d in @($ЗДЕСЬ, $CONFIG_DIR, $LOGS_DIR, $RUNTIME_DIR)) {
        if (-not (Защитить-Файл $d $true)) { return $false }
    }
    foreach ($p in @($CONFIG, $LOG, ($LOG + '.1'), $HISTORY, $HISTORY_LEGACY, $LOCK, $PIDFILE)) {
        if ((Test-Path $p) -and (-not (Защитить-Файл $p))) { return $false }
    }
    return $true
}

function _JsonEsc([string]$s) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $code = [int][char]$ch
        if ($ch -eq '"') { [void]$sb.Append('\"') }
        elseif ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ($code -eq 8) { [void]$sb.Append('\b') }
        elseif ($code -eq 12) { [void]$sb.Append('\f') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
        elseif ($code -eq 9) { [void]$sb.Append('\t') }
        elseif ($code -lt 32) { [void]$sb.Append('\u'); [void]$sb.Append($code.ToString('x4')) }
        else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

function _ВJson($obj) {
    if ($null -eq $obj) { return 'null' }
    if ($obj -is [bool]) { if ($obj) { return 'true' } else { return 'false' } }
    if ($obj -is [int] -or $obj -is [long] -or $obj -is [int16] -or $obj -is [byte] -or $obj -is [int64] -or $obj -is [int32]) {
        return ([string]([long]$obj))
    }
    if ($obj -is [double] -or $obj -is [single] -or $obj -is [decimal]) {
        return ([System.Convert]::ToString($obj, [System.Globalization.CultureInfo]::InvariantCulture))
    }
    if ($obj -is [System.Collections.IDictionary]) {
        $parts = @()
        foreach ($k in $obj.Keys) { $parts += ('"' + (_JsonEsc ([string]$k)) + '":' + (_ВJson $obj[$k])) }
        return '{' + ($parts -join ',') + '}'
    }
    if (($obj -is [System.Collections.IEnumerable]) -and (-not ($obj -is [string]))) {
        $parts = @()
        foreach ($e in $obj) { $parts += (_ВJson $e) }
        return '[' + ($parts -join ',') + ']'
    }
    return '"' + (_JsonEsc ([string]$obj)) + '"'
}

function _ПреобразоватьJson($o) {
    if ($o -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $o.Keys) { $h[[string]$k] = (_ПреобразоватьJson $o[$k]) }
        return $h
    }
    if ($o -is [object[]]) {
        $a = @()
        foreach ($e in $o) { $a += ,(_ПреобразоватьJson $e) }
        return ,$a
    }
    return $o
}

function _ИзJson([string]$text) {
    if (-not $text) { return $null }
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Web.Extensions')
    $js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $js.MaxJsonLength = [int]::MaxValue
    return (_ПреобразоватьJson ($js.DeserializeObject($text)))
}

function _ПрочитатьТекст([string]$путь) {
    return [System.IO.File]::ReadAllText($путь, [System.Text.Encoding]::UTF8)
}

function Прочит-Json([string]$путь) {
    if (-not (Test-Path $путь)) { return $null }
    try { return (_ИзJson (_ПрочитатьТекст $путь)) }
    catch { return $null }
}

function Записать-Защищенно([string]$путь, $данные) {
    $tmp = $путь + '.tmp'
    if (Test-Path $tmp) { Remove-Item -Force $tmp }
    New-Item -ItemType File -Path $tmp -Force | Out-Null
    try {
        if (-not (Защитить-Файл $tmp)) {
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            throw "не удалось защитить права временного файла"
        }
        [System.IO.File]::WriteAllText($tmp, (_ВJson $данные), (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        throw
    }
    Move-Item -Force $tmp $путь
    Защитить-Файл $путь | Out-Null
}

function Прочит-Историю() {
    if (-not (Test-Path $HISTORY)) { return @{} }
    $текст = $null
    try { $текст = _ПрочитатьТекст $HISTORY } catch { throw "ПОВРЕЖДЕНА-ИСТОРИЯ: не прочитать файл" }
    if ($null -eq $текст -or $текст.Trim() -eq '') { throw "ПОВРЕЖДЕНА-ИСТОРИЯ: пустой файл истории" }
    $o = $null
    try { $o = _ИзJson $текст } catch { throw "ПОВРЕЖДЕНА-ИСТОРИЯ: $($_.Exception.Message)" }
    if ($null -eq $o -or (-not ($o -is [hashtable]))) { throw "ПОВРЕЖДЕНА-ИСТОРИЯ: не словарь операций" }
    foreach ($k in @($o.Keys)) {
        if (-not ($o[$k] -is [hashtable])) { throw "ПОВРЕЖДЕНА-ИСТОРИЯ: запись $k не словарь" }
    }
    return $o
}

function Запись-Истории([string]$opUid) {
    $h = Прочит-Историю
    if ($h.ContainsKey($opUid)) { return $h[$opUid] } else { return $null }
}

function Обновить-Историю([string]$opUid, [hashtable]$поля) {
    $h = Прочит-Историю
    $зап = @{}
    if ($h.ContainsKey($opUid) -and $h[$opUid]) {
        $old = $h[$opUid]
        if ($old -is [hashtable]) { foreach ($k in @($old.Keys)) { $зап[$k] = $old[$k] } }
    }
    $зап['fmt'] = $HISTORY_FMT
    foreach ($k in $поля.Keys) { $зап[$k] = $поля[$k] }
    $h[$opUid] = $зап
    Записать-Защищенно $HISTORY $h
}

function _Sha256Hex([string]$s) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
        $hash = $sha.ComputeHash($bytes)
        return -join ($hash | ForEach-Object { $_.ToString('x2') })
    } finally { $sha.Dispose() }
}

function Канон-OpUid([string]$token, [string]$installId, [string]$requestId) {
    $s = "odl-desktop-op-v1`n$token`n$requestId"
    return (_Sha256Hex $s).Substring(0, 32)
}

function Канон-Отпечаток([string]$installId, [string]$opUid, [int]$timeout, [string]$script) {
    $s = "powershell`n$timeout`n$installId`n$opUid`n$script"
    return (_Sha256Hex $s)
}

function Канон-Содержимого([int]$timeout, [string]$script) {
    $s = "op-content-v1`n$timeout`npowershell`n$script"
    return (_Sha256Hex $s)
}

function Адрес-Допустим([string]$url) {
    try { $u = [System.Uri]$url } catch { return $false }
    return ($u.Scheme -eq 'https')
}

function Запрос($cfg, [string]$путь, $тело, [string]$секрет = '') {
    $url = ($cfg.base_url.TrimEnd('/')) + $путь
    if (-not (Адрес-Допустим $url)) { return @{ ok = $false; error = 'адрес сервиса должен быть https' } }
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch { }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes((_ВJson $тело))
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = 'POST'
        $req.ContentType = 'application/json; charset=utf-8'
        $req.Headers['X-Bridge-Token'] = [string]$cfg.token
        if ($секрет) { $req.Headers['X-Agent-Secret'] = $секрет }
        $req.AllowAutoRedirect = $false
        $req.Timeout = 120000
        $req.ReadWriteTimeout = 120000
        $req.ContentLength = $bytes.Length
        $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $content = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
        if ($content) { return (_ИзJson $content) } else { return @{} }
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($resp) {
            $код = [int]$resp.StatusCode
            $detail = ''
            try {
                $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $body = $sr.ReadToEnd(); $sr.Close()
                try { $detail = [string]((_ИзJson $body).detail) } catch { $detail = $body }
            } catch { }
            $detail = "" + $detail
            return @{ ok = $false; http = $код; detail = $detail.Substring(0, [Math]::Min(300, $detail.Length)) }
        }
        return @{ ok = $false; error = $_.Exception.Message }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}

function Проверить-Команду($cfg, $cmd) {
    if ((Поле $cmd 'shell') -ne 'powershell') { return 'неподдерживаемая оболочка' }
    if (Поле $cmd 'elevate' $false) { return 'повышение прав запрещено' }
    $rid = [string]$cmd.request_id
    if (-not $rid -or $rid.Length -lt 8) { return 'команда без стабильного request_id' }
    $op = [string]$cmd.op_uid
    if (-not $op -or $op.Length -ne 32 -or ($op -notmatch '^[0-9a-f]{32}$')) { return 'неверный формат op_uid' }
    if ($op -ne (Канон-OpUid $cfg.token $cfg.install_id $rid)) { return 'op_uid не совпал с ключом/машиной/request_id' }
    $s = [string]$cmd.script_text
    if (-not $s) { return 'пустой текст команды' }
    if ([System.Text.Encoding]::UTF8.GetByteCount($s) -gt $SCRIPT_MAX) { return 'текст команды слишком большой' }
    $t = [int]$cmd.timeout_sec
    if ($t -lt $TIMEOUT_MIN -or $t -gt $TIMEOUT_MAX) { return 'недопустимый предел времени' }
    $отп = [string]$cmd.payload_sha256
    if (-not $отп) { return 'нет отпечатка payload (обязателен)' }
    if ($отп -ne (Канон-Отпечаток $cfg.install_id $op $t $s)) { return 'отпечаток команды не совпал' }
    return $null
}

function Показать-Подтверждение($cmd) {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch {
        Write-Host 'Нет графической среды для подтверждения - команда ОТКЛОНЕНА (безопасный отказ).'
        Журнал 'нет GUI: безопасный отказ'
        return $false
    }
    $результат = @{ v = 'deny' }
    $форма = New-Object System.Windows.Forms.Form
    try {
        $форма.Text = 'Помощник администратора: подтверждение команды'
        $форма.Size = New-Object System.Drawing.Size(800, 600)
        $форма.StartPosition = 'CenterScreen'
        $форма.TopMost = $true

        $заг = New-Object System.Windows.Forms.Label
        $заг.Text = 'ИИ предлагает выполнить команду PowerShell на этом компьютере.'
        $заг.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
        $заг.AutoSize = $true; $заг.Location = New-Object System.Drawing.Point(12, 12)
        $форма.Controls.Add($заг)

        $под = New-Object System.Windows.Forms.Label
        $под.Text = ("Права: текущий пользователь. Предел: {0} с. Выполнится РОВНО этот текст." -f $cmd.timeout_sec)
        $под.AutoSize = $true; $под.ForeColor = [System.Drawing.Color]::FromArgb(150, 90, 0)
        $под.Location = New-Object System.Drawing.Point(12, 40); $форма.Controls.Add($под)

        $txt = New-Object System.Windows.Forms.TextBox
        $txt.Multiline = $true; $txt.ReadOnly = $true; $txt.ScrollBars = 'Both'; $txt.WordWrap = $false
        $txt.Font = New-Object System.Drawing.Font('Consolas', 10)
        $txt.Text = [string]$cmd.script_text
        $txt.Location = New-Object System.Drawing.Point(12, 70)
        $txt.Size = New-Object System.Drawing.Size(760, 360)
        $txt.Anchor = 'Top,Bottom,Left,Right'
        $форма.Controls.Add($txt)

        $отсчет = New-Object System.Windows.Forms.Label
        $отсчет.AutoSize = $true; $отсчет.Location = New-Object System.Drawing.Point(12, 452)
        $отсчет.Anchor = 'Bottom,Left'; $форма.Controls.Add($отсчет)

        $предупр = New-Object System.Windows.Forms.Label
        $предупр.Text = '«Разрешить все» отключает окно до остановки помощника: команды будут выполняться без показа. Включайте, только если доверяете источнику.'
        $предупр.ForeColor = [System.Drawing.Color]::FromArgb(176, 0, 0)
        $предупр.AutoSize = $false; $предупр.Size = New-Object System.Drawing.Size(744, 34)
        $предупр.Location = New-Object System.Drawing.Point(12, 476); $предупр.Anchor = 'Bottom,Left,Right'
        $форма.Controls.Add($предупр)

        $кнОтклонить = New-Object System.Windows.Forms.Button
        $кнОтклонить.Text = 'Отклонить'; $кнОтклонить.Size = New-Object System.Drawing.Size(120, 34)
        $кнОтклонить.Location = New-Object System.Drawing.Point(400, 516); $кнОтклонить.Anchor = 'Bottom,Right'
        $кнОтклонить.Add_Click({ $результат.v = 'deny'; $форма.Close() })
        $форма.Controls.Add($кнОтклонить)

        $кнРазрешить = New-Object System.Windows.Forms.Button
        $кнРазрешить.Text = 'Разрешить'; $кнРазрешить.Size = New-Object System.Drawing.Size(120, 34)
        $кнРазрешить.Location = New-Object System.Drawing.Point(530, 516); $кнРазрешить.Anchor = 'Bottom,Right'
        $кнРазрешить.Add_Click({ $результат.v = 'once'; $форма.Close() })
        $форма.Controls.Add($кнРазрешить)

        $кнДоверие = New-Object System.Windows.Forms.Button
        $кнДоверие.Text = 'Разрешить все до остановки'; $кнДоверие.Size = New-Object System.Drawing.Size(220, 34)
        $кнДоверие.Location = New-Object System.Drawing.Point(12, 516); $кнДоверие.Anchor = 'Bottom,Left'
        $кнДоверие.Add_Click({ $результат.v = 'session'; $форма.Close() })
        $форма.Controls.Add($кнДоверие)

        $осталось = @{ n = $CONFIRM_TIMEOUT }
        $таймер = New-Object System.Windows.Forms.Timer
        $таймер.Interval = 1000
        $таймер.Add_Tick({
            $осталось.n -= 1
            $отсчет.Text = ("Автоотклонение через {0} с" -f $осталось.n)
            if ($осталось.n -le 0) { $таймер.Stop(); $форма.Close() }
        }.GetNewClosure())
        $отсчет.Text = ("Автоотклонение через {0} с" -f $осталось.n)
        $таймер.Start()
        [void]$форма.ShowDialog()
        $таймер.Stop()
    } finally {
        $форма.Dispose()
    }
    return $результат.v
}

if (-not ('ODL.Job' -as [type])) {
Add-Type @"
using System;
using System.Runtime.InteropServices;
namespace ODL {
  public static class Job {
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
      public Int64 PerProcessUserTimeLimit; public Int64 PerJobUserTimeLimit;
      public UInt32 LimitFlags; public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize;
      public UInt32 ActiveProcessLimit; public UIntPtr Affinity; public UInt32 PriorityClass; public UInt32 SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS {
      public UInt64 ReadOperationCount; public UInt64 WriteOperationCount; public UInt64 OtherOperationCount;
      public UInt64 ReadTransferCount; public UInt64 WriteTransferCount; public UInt64 OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
      public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo;
      public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit;
      public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr CreateJobObject(IntPtr a, string n);
    [DllImport("kernel32.dll")] public static extern bool SetInformationJobObject(IntPtr job, int cls, IntPtr info, uint len);
    [DllImport("kernel32.dll")] public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
    [DllImport("kernel32.dll")] public static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    public const int ExtendedLimitInformation = 9;
    public const uint KILL_ON_JOB_CLOSE = 0x2000;
  }
}
"@
}

if (-not ('ODL.Proc' -as [type])) {
Add-Type @"
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
namespace ODL {
  public static class Proc {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFO {
      public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
      public int dwX; public int dwY; public int dwXSize; public int dwYSize;
      public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute;
      public int dwFlags; public short wShowWindow; public short cbReserved2;
      public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcess(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit,
      uint flags, IntPtr env, string curdir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFile(string name, uint access, uint share, ref SECURITY_ATTRIBUTES sa, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
    [DllImport("kernel32.dll")] static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr h, uint code);
    const uint RESUME_FAILED = 0xFFFFFFFF;

    const uint GENERIC_WRITE=0x40000000, GENERIC_READ=0x80000000;
    const uint FILE_SHARE_READ=1, FILE_SHARE_WRITE=2;
    const uint CREATE_ALWAYS=2, OPEN_EXISTING=3;
    const uint CREATE_SUSPENDED=0x4, CREATE_NO_WINDOW=0x08000000;
    const int STARTF_USESTDHANDLES=0x100;
    const uint STILL_ACTIVE=259, WAIT_OBJECT_0=0;

    static IntPtr OpenWrite(string path) {
      SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
      sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)); sa.bInheritHandle = 1; sa.lpSecurityDescriptor = IntPtr.Zero;
      return CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, ref sa, CREATE_ALWAYS, 0, IntPtr.Zero);
    }
    static IntPtr OpenNul() {
      SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
      sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)); sa.bInheritHandle = 1; sa.lpSecurityDescriptor = IntPtr.Zero;
      return CreateFile("NUL", GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, ref sa, OPEN_EXISTING, 0, IntPtr.Zero);
    }

    public static long[] Run(string exe, string cmdline, string curdir, string outPath, string errPath, int timeoutMs, long cap, IntPtr job) {
      long[] r = new long[] { 0, 0, 0, -1, 0, 0, 0 };
      IntPtr INV = (IntPtr)(-1);
      IntPtr hOut = OpenWrite(outPath), hErr = OpenWrite(errPath), hIn = OpenNul();
      try {
        if (hOut==INV || hErr==INV || hIn==INV) { return r; }
        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = hOut; si.hStdError = hErr; si.hStdInput = hIn;
        PROCESS_INFORMATION pi;
        StringBuilder cmd = new StringBuilder(cmdline);
        bool ok = CreateProcess(exe, cmd, IntPtr.Zero, IntPtr.Zero, true,
                                CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, curdir, ref si, out pi);
        if (!ok) { return r; }
        r[0] = 1;
        bool assigned = AssignProcessToJobObject(job, pi.hProcess);
        r[1] = assigned ? 1 : 0;
        if (!assigned) {
          bool killed = TerminateProcess(pi.hProcess, 1);
          bool gone = (WaitForSingleObject(pi.hProcess, 5000) == WAIT_OBJECT_0);
          r[6] = (killed && gone) ? 1 : 0;
          CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
          return r;
        }
        uint rt = ResumeThread(pi.hThread);
        if (rt == RESUME_FAILED) {
          r[2] = 0;
          bool t = TerminateJobObject(job, 1);
          bool gone = (WaitForSingleObject(pi.hProcess, 5000) == WAIT_OBJECT_0);
          r[6] = (t && gone) ? 1 : 0;
          CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
          return r;
        }
        r[2] = 1;
        int start = Environment.TickCount;
        bool timedOut = false, overflow = false;
        while (true) {
          if (WaitForSingleObject(pi.hProcess, 250) == WAIT_OBJECT_0) break;
          long sz = 0;
          try { sz += new FileInfo(outPath).Length; } catch { }
          try { sz += new FileInfo(errPath).Length; } catch { }
          if (cap > 0 && sz > cap) { overflow = true; break; }
          if (timeoutMs > 0 && (Environment.TickCount - start) >= timeoutMs) { timedOut = true; break; }
        }
        bool cleanupOk = true;
        if (timedOut || overflow) {
          bool t = TerminateJobObject(job, 1);
          bool gone = (WaitForSingleObject(pi.hProcess, 5000) == WAIT_OBJECT_0);
          cleanupOk = (t && gone);
        }
        uint code;
        if (GetExitCodeProcess(pi.hProcess, out code)) { r[3] = (code == STILL_ACTIVE) ? -1 : (long)(int)code; }
        r[4] = timedOut ? 1 : 0; r[5] = overflow ? 1 : 0; r[6] = cleanupOk ? 1 : 0;
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return r;
      } finally {
        if (hOut != IntPtr.Zero && hOut != INV) CloseHandle(hOut);
        if (hErr != IntPtr.Zero && hErr != INV) CloseHandle(hErr);
        if (hIn  != IntPtr.Zero && hIn  != INV) CloseHandle(hIn);
      }
    }
  }
}
"@
}

function _КодировкаВывода() {
    try {
        $cp = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage
        if ($cp -gt 0) { return [System.Text.Encoding]::GetEncoding($cp) }
    } catch { }
    return [System.Text.Encoding]::UTF8
}

function Прочит-С-Лимитом([string]$файл, [int]$уже = 0) {
    try {
        if (-not (Test-Path $файл)) { return '' }
        $доступно = $OUTPUT_MAX - $уже
        if ($доступно -le 0) { return '' }
        $байты = [System.IO.File]::ReadAllBytes($файл)
        if ($байты.Length -gt $доступно) { $байты = $байты[0..($доступно - 1)] }
        return (_КодировкаВывода).GetString($байты)
    } catch { return '' }
}

function Создать-Job() {
    try {
        $job = [ODL.Job]::CreateJobObject([IntPtr]::Zero, $null)
        if ($job -eq [IntPtr]::Zero) { return [IntPtr]::Zero }
        $info = New-Object 'ODL.Job+JOBOBJECT_EXTENDED_LIMIT_INFORMATION'
        $info.BasicLimitInformation.LimitFlags = [ODL.Job]::KILL_ON_JOB_CLOSE
        $len = [System.Runtime.InteropServices.Marshal]::SizeOf($info)
        $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($len)
        try {
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($info, $ptr, $false)
            if (-not [ODL.Job]::SetInformationJobObject($job, [ODL.Job]::ExtendedLimitInformation, $ptr, $len)) {
                [ODL.Job]::CloseHandle($job) | Out-Null
                return [IntPtr]::Zero
            }
        } finally { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr) }
        return $job
    } catch { Журнал ("Job Object не создан ({0})" -f $_.Exception.Message); return [IntPtr]::Zero }
}

function Выполнить-С-Ходом($cfg, [int]$cid, [string]$opUid, [string]$отп, [string]$скрипт, [int]$таймаут) {
    $pfile = Join-Path $RUNTIME_DIR ('progress-cmd-' + $cid + '.txt')
    $sfile = Join-Path $RUNTIME_DIR ('progress-cmd-' + $cid + '.stop')
    $sender = $null
    try {
        New-Item -ItemType File -Path $pfile -Force | Out-Null
        Защитить-Файл $pfile | Out-Null
        Remove-Item -Force $sfile -ErrorAction SilentlyContinue
        $env:ODL_PROGRESS = $pfile
        $отпр = Join-Path $ЗДЕСЬ 'progress_send.ps1'
        $exePS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if ((Test-Path $отпр) -and (Test-Path $exePS)) {
            $me = [System.Diagnostics.Process]::GetCurrentProcess()
            $myStart = 0; try { $myStart = $me.StartTime.ToFileTimeUtc() } catch { $myStart = 0 }
            $env:ODL_BASE = [string]$cfg.base_url; $env:ODL_TOKEN = [string]$cfg.token
            $env:ODL_SECRET = [string]$cfg.agent_secret; $env:ODL_IID = [string]$cfg.install_id
            $env:ODL_CID = [string]$cid; $env:ODL_STOP = $sfile
            $env:ODL_OPUID = [string]$opUid; $env:ODL_PAYLOAD = [string]$отп
            $env:ODL_PPID = [string]$me.Id; $env:ODL_PSTART = [string]$myStart
            $env:ODL_EVERY = '20'; $env:ODL_TAIL = '3500'
            $env:ODL_DEADLINE = [string]($таймаут + 120)
            try {
                $sender = Start-Process -FilePath $exePS `
                    -ArgumentList '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $отпр `
                    -WindowStyle Hidden -PassThru
            } catch { $sender = $null; Журнал ('ход: отправитель не запущен: ' + $_.Exception.Message) }
            Remove-Item Env:ODL_SECRET -ErrorAction SilentlyContinue
            Remove-Item Env:ODL_TOKEN -ErrorAction SilentlyContinue
            Remove-Item Env:ODL_PAYLOAD -ErrorAction SilentlyContinue
        }
        return (Выполнить-PowerShell $скрипт $таймаут)
    } finally {
        try { New-Item -ItemType File -Path $sfile -Force | Out-Null } catch { }
        if ($sender) { try { Stop-Process -Id $sender.Id -Force -ErrorAction SilentlyContinue } catch { } }
        try {
            $хвост = ''
            if (Test-Path $pfile) {
                $len = (Get-Item $pfile).Length
                if ($len -gt 0) {
                    $txt = [System.IO.File]::ReadAllText($pfile, [System.Text.Encoding]::UTF8)
                    if ($txt.Length -gt 3500) { $txt = $txt.Substring($txt.Length - 3500) }
                    $хвост = $txt.Trim()
                }
            }
            if ($хвост) {
                Запрос $cfg '/api/v1/desktop/progress' @{ install_id = $cfg.install_id; command_id = $cid; progress_text = $хвост; op_uid = $opUid; payload_sha256 = $отп } $cfg.agent_secret | Out-Null
            }
        } catch { }
        Remove-Item Env:ODL_PROGRESS -ErrorAction SilentlyContinue
        Remove-Item -Force $pfile -ErrorAction SilentlyContinue
        Remove-Item -Force $sfile -ErrorAction SilentlyContinue
    }
}

function Выполнить-PowerShell([string]$скрипт, [int]$таймаут) {
    if ($Script:УборкаНеПодтверждена) {
        return @{ error = 'предыдущее задание не подтверждено завершенным - выполнение остановлено до разбора' }
    }
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $exe)) { return @{ error = 'powershell не найден на этой машине' } }
    $tmp = Join-Path $ЗДЕСЬ ('odl_' + [System.IO.Path]::GetRandomFileName() + '.ps1')
    New-Item -ItemType File -Path $tmp -Force | Out-Null
    if (-not (Защитить-Файл $tmp)) {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        return @{ error = 'не удалось защитить права временного файла - команда не выполнена' }
    }
    [System.IO.File]::WriteAllText($tmp, $скрипт, (New-Object System.Text.UTF8Encoding($true)))
    $job = Создать-Job
    if ($job -eq [IntPtr]::Zero) {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        return @{ error = 'не удалось создать Job Object - команда не выполнена' }
    }
    $outFile = $tmp + '.out'; $errFile = $tmp + '.err'
    try {
        New-Item -ItemType File -Path $outFile -Force | Out-Null; Защитить-Файл $outFile | Out-Null
        New-Item -ItemType File -Path $errFile -Force | Out-Null; Защитить-Файл $errFile | Out-Null
        $cmdline = '"' + $exe + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $tmp + '"'
        $начало = Get-Date
        $r = [ODL.Proc]::Run($exe, $cmdline, $ЗДЕСЬ, $outFile, $errFile, ($таймаут * 1000), [long]($OUTPUT_MAX * 4), $job)
        if ($r[0] -ne 1) { Журнал 'CreateProcess не создал процесс'; return @{ error = 'не удалось запустить процесс (CreateProcess)' } }
        if ($r[1] -ne 1) {
            if ($r[6] -ne 1) { $Script:УборкаНеПодтверждена = $true; Журнал 'Job: процесс не назначен И завершение НЕ подтверждено - запуск запрещён' }
            else { Журнал 'Job Object: процесс не назначен (не запускался, завершён) - команда НЕ выполнена' }
            return @{ error = 'процесс не назначен в Job Object - команда не выполнена' }
        }
        if ($r[2] -ne 1) {
            if ($r[6] -ne 1) { $Script:УборкаНеПодтверждена = $true; Журнал 'Job: поток не возобновлён И завершение НЕ подтверждено - запуск запрещён' }
            else { Журнал 'Job: поток не возобновлён (процесс завершён) - команда НЕ выполнена' }
            return @{ error = 'не удалось возобновить процесс - команда не выполнена' }
        }
        $timed = ($r[4] -eq 1)
        $перелив = ($r[5] -eq 1)
        if ($r[6] -ne 1) {
            $Script:УборкаНеПодтверждена = $true
            Журнал 'Job: завершение дерева после таймаута/перелива НЕ подтверждено - следующий запуск запрещён'
        }
        $stdout = Прочит-С-Лимитом $outFile
        $stderr = Прочит-С-Лимитом $errFile ($stdout.Length)
        $res = @{
            exit_code   = $(if ($timed -or $перелив) { $null } else { [int]$r[3] })
            duration_ms = [int]((Get-Date) - $начало).TotalMilliseconds
            stdout      = $stdout; stderr = $stderr
        }
        if ($перелив -or ($stdout.Length + $stderr.Length) -ge $OUTPUT_MAX) { $res['truncated'] = $true }
        if ($timed) { $res['timed_out'] = $true }
        return $res
    } finally {
        $termOk = $false; $closeOk = $false
        try { $termOk = [ODL.Job]::TerminateJobObject($job, 1); $closeOk = [ODL.Job]::CloseHandle($job) } catch { }
        if (-not ($termOk -and $closeOk)) {
            $Script:УборкаНеПодтверждена = $true
            Журнал ("Job Object: уборка НЕ подтверждена (terminate={0}, close={1}) - следующий запуск запрещён" -f $termOk, $closeOk)
        }
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        Remove-Item -Force $outFile -ErrorAction SilentlyContinue
        Remove-Item -Force $errFile -ErrorAction SilentlyContinue
    }
}

. (Join-Path $ЗДЕСЬ 'helper_flow.ps1')

Main
