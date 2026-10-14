
function Поле($объект, [string]$имя, $умолч = $null) {
    if ($null -eq $объект) { return $умолч }
    if ($объект -is [hashtable]) { if ($объект.ContainsKey($имя)) { return $объект[$имя] } else { return $умолч } }
    $p = $объект.PSObject.Properties[$имя]
    if ($p) { return $p.Value } else { return $умолч }
}

function _Норм-Url([string]$u) {
    if (-not $u) { return '' }
    return $u.Trim().TrimEnd('/').ToLower()
}

function Ctx($cfg) {
    return (_Sha256Hex ((_Норм-Url ([string]$cfg.base_url)) + '|' + ([string]$cfg.token))).Substring(0, 16)
}

function Возможные-Ctx($cfg) {
    $token = [string]$cfg.token
    $base = ([string]$cfg.base_url).Trim()
    $варианты = @($base, $base.TrimEnd('/'), ($base.TrimEnd('/') + '/'), (_Норм-Url $base)) | Select-Object -Unique
    return @($варианты | ForEach-Object { (_Sha256Hex ($_ + '|' + $token)).Substring(0, 16) })
}

function _СтрогоПрочитатьАрхив([string]$путь) {
    if (-not (Test-Path $путь)) { return @{} }
    $текст = $null
    try { $текст = _ПрочитатьТекст $путь } catch { throw "АРХИВ-ПОВРЕЖДЁН: не прочитать" }
    if ($null -eq $текст -or $текст.Trim() -eq '') { throw "АРХИВ-ПОВРЕЖДЁН: пусто" }
    $o = $null
    try { $o = _ИзJson $текст } catch { throw "АРХИВ-ПОВРЕЖДЁН: не JSON" }
    if ($null -eq $o -or (-not ($o -is [hashtable]))) { throw "АРХИВ-ПОВРЕЖДЁН: не словарь" }
    return $o
}

function Миграция-Истории($cfg) {
    if (-not (Поле $cfg 'token')) { return $true }
    if (-not (Test-Path $HISTORY)) { return $true }
    $h = Прочит-Историю
    $legacy = @{}
    foreach ($k in @($h.Keys)) {
        $v = $h[$k]
        if ($v -and (-not (Поле $v 'fmt'))) { $legacy[$k] = $v }
    }
    if ($legacy.Count -eq 0) { return $true }
    foreach ($k in @($legacy.Keys)) {
        $v = $legacy[$k]
        if ((Поле $v 'executed') -or (Поле $v 'exec_status')) {
            Журнал 'история прежнего формата: есть выполненные операции - переходный запрет'
            return $false
        }
    }
    try {
        $кар = _СтрогоПрочитатьАрхив $HISTORY_LEGACY
    } catch {
        Журнал 'карантин истории повреждён - переход запрещён до разбора'; return $false
    }
    foreach ($k in @($legacy.Keys)) { $кар[$k] = $legacy[$k] }
    try {
        Записать-Защищенно $HISTORY_LEGACY $кар
        $пров = _СтрогоПрочитатьАрхив $HISTORY_LEGACY
        foreach ($k in @($legacy.Keys)) {
            if (-not $пров.ContainsKey($k)) { Журнал 'карантин истории не подтверждён записью - переход запрещён'; return $false }
        }
    } catch {
        Журнал 'ошибка записи/проверки карантина истории - исходную не трогаю, переход запрещён'; return $false
    }
    $новая = @{}
    foreach ($k in @($h.Keys)) { if (-not $legacy.ContainsKey($k)) { $новая[$k] = $h[$k] } }
    Записать-Защищенно $HISTORY $новая
    Журнал ("история: {0} записей прежнего формата перенесены в карантин" -f $legacy.Count)
    return $true
}

function _Занять-СтарыйЗамок([string]$путь) {
    try {
        return [System.IO.File]::Open($путь, [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    } catch { return $null }
}

function Миграция-Раскладки() {
    $корень = $ЗДЕСЬ
    $старыйLock = Join-Path $корень 'helper.lock'
    $старыйCfg = Join-Path $корень 'config.json'
    $пары = @(
        @{ old = (Join-Path $корень 'history.json');        new = $HISTORY },
        @{ old = (Join-Path $корень 'history.legacy.json'); new = $HISTORY_LEGACY }
    )
    $естьЧто = $false
    foreach ($p in $пары) { if ((Test-Path $p.old) -and ([System.IO.Path]::GetFullPath($p.old) -ne [System.IO.Path]::GetFullPath($p.new))) { $естьЧто = $true } }
    if ((Test-Path $старыйCfg) -and ([System.IO.Path]::GetFullPath($старыйCfg) -ne [System.IO.Path]::GetFullPath($CONFIG))) { $естьЧто = $true }
    if ((Test-Path $старыйLock) -and ([System.IO.Path]::GetFullPath($старыйLock) -ne [System.IO.Path]::GetFullPath($LOCK))) { $естьЧто = $true }
    if (-not $естьЧто) { return $true }
    $держатель = _Занять-СтарыйЗамок $старыйLock
    if ($null -eq $держатель) {
        Журнал 'переезд раскладки: старый помощник ещё работает (замок занят) - отказ'
        Write-Host 'ОТКАЗ: похоже, работает СТАРАЯ версия помощника из этой папки.'
        Write-Host 'Остановите её (закройте окно), затем запустите снова.'
        return $false
    }
    try {
        if ((Test-Path $старыйCfg) -and ([System.IO.Path]::GetFullPath($старыйCfg) -ne [System.IO.Path]::GetFullPath($CONFIG)) -and (Test-Path $CONFIG)) {
            $ст = Прочит-Json $старыйCfg; $нов = Прочит-Json $CONFIG
            if (([string](Поле $ст 'token')) -ne ([string](Поле $нов 'token')) -or
                ([string](Поле $ст 'base_url')) -ne ([string](Поле $нов 'base_url'))) {
                Журнал 'переезд раскладки: старый и новый config.json РАЗНЫЕ - отказ до изменений'
                Write-Host 'ОТКАЗ: в корне и в config\ РАЗНЫЕ настройки (ключ/адрес).'
                Write-Host 'Оставьте одну актуальную конфигурацию, вторую уберите, затем запустите снова.'
                return $false
            }
        }
        try {
            if ((Test-Path $старыйCfg) -and ([System.IO.Path]::GetFullPath($старыйCfg) -ne [System.IO.Path]::GetFullPath($CONFIG))) {
                if (-not (Test-Path $CONFIG)) {
                    Move-Item -Force $старыйCfg $CONFIG
                    Журнал 'переезд раскладки: config.json -> config\'
                } else {
                    Remove-Item -Force $старыйCfg
                    Журнал 'переезд раскладки: старый config.json удалён (ключ уже в config\)'
                }
            }
        } catch {
            Журнал 'переезд раскладки: не удалось вывести старый config.json - отказ, история НЕ тронута'
            Write-Host 'ОТКАЗ: не удалось убрать старый config.json из корня. История не тронута,'
            Write-Host 'повтора нет. Проверьте права на файл и запустите снова.'
            return $false
        }
        foreach ($p in $пары) {
            if (-not (Test-Path $p.old)) { continue }
            if ([System.IO.Path]::GetFullPath($p.old) -eq [System.IO.Path]::GetFullPath($p.new)) { continue }
            if (Test-Path $p.new) {
                Журнал ('переезд раскладки: есть и старая, и новая ' + (Split-Path -Leaf $p.new) + ' - отказ')
                Write-Host 'ОТКАЗ: найдены ДВЕ истории операций - старая (в корне) и новая (в runtime\).'
                Write-Host 'Оставьте одну актуальную, вторую удалите, затем запустите снова.'
                return $false
            }
            try { Move-Item -Force $p.old $p.new; Журнал ('переезд раскладки: ' + (Split-Path -Leaf $p.old) + ' -> runtime\') }
            catch { Журнал ('переезд раскладки: ошибка с ' + (Split-Path -Leaf $p.old) + ' - отказ'); return $false }
        }
    } finally {
        if ($null -ne $держатель) { try { $держатель.Close() } catch { } }
    }
    foreach ($имя in @('helper.lock', 'helper.pid')) {
        try {
            $pp = Join-Path $корень $имя
            if ((Test-Path $pp) -and ([System.IO.Path]::GetFullPath($pp) -ne [System.IO.Path]::GetFullPath((Join-Path $RUNTIME_DIR $имя)))) {
                Remove-Item -Force $pp -ErrorAction SilentlyContinue
            }
        } catch { }
    }
    return $true
}

function Взять-Замок() {
    try {
        $Script:LockStream = [System.IO.File]::Open(
            $LOCK, [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    } catch {
        return $false
    }
    if (-not (Защитить-Файл $LOCK)) {
        Журнал 'замок: не удалось защитить права helper.lock - запуск отклонен'
        try { $Script:LockStream.Close() } catch { }
        return $false
    }
    return $true
}

function _Послать-Результат($cfg, [int]$cid, [string]$opUid, [string]$отп, [string]$статус, $res, [string]$err) {
    $тело = @{
        install_id = $cfg.install_id; command_id = $cid; op_uid = $opUid;
        payload_sha256 = $отп; status = $статус; error = $err
        result = $(if ($статус -eq 'completed') { $res } else { $null })
    }
    return (Запрос $cfg '/api/v1/desktop/result' $тело $cfg.agent_secret)
}

function Задать-Доставку([string]$opUid, [string]$статус, [string]$ошибка, [int]$cid, [hashtable]$доп = @{}) {
    $поля = @{ deliver = @{ status = $статус; error = $ошибка; command_id = $cid }; delivered = $false; conflict = $null }
    foreach ($k in $доп.Keys) { $поля[$k] = $доп[$k] }
    Обновить-Историю $opUid $поля
}

function Доставить($cfg, [string]$opUid, [int]$попыток = 1) {
    $зап = Запись-Истории $opUid
    $d = Поле $зап 'deliver'
    if (-not $d) { return $false }
    if (Поле $зап 'delivered') { return $true }
    if (Поле $зап 'conflict') { return $false }
    $cid = [int](Поле $d 'command_id')
    $статус = [string](Поле $d 'status')
    $err = [string](Поле $d 'error')
    $отп = [string](Поле $зап 'payload_sha256')
    $res = $(if ($статус -eq 'completed') { Поле $зап 'exec_result' } else { $null })
    $задержка = 2
    for ($i = 0; $i -lt [Math]::Max(1, $попыток); $i++) {
        $итог = _Послать-Результат $cfg $cid $opUid $отп $статус $res $err
        if (Поле $итог 'ok') {
            Обновить-Историю $opUid @{ delivered = $true }
            Журнал ("операция {0} (команда {1}): исход {2} доставлен" -f $opUid, $cid, $статус)
            return $true
        }
        if ((Поле $итог 'http') -eq 409) {
            $detail = [string](Поле $итог 'detail')
            if ($detail -like '*недопустимый переход*' -and (@('failed', 'declined') -contains $статус) -and ($null -eq $res)) {
                $другой = $(if ($статус -eq 'failed') { 'declined' } else { 'failed' })
                $alt = _Послать-Результат $cfg $cid $opUid $отп $другой $null $err
                if (Поле $alt 'ok') {
                    Обновить-Историю $opUid @{ delivered = $true }
                    Журнал ("операция {0} (команда {1}): исход доставлен как {2}" -f $opUid, $cid, $другой)
                    return $true
                }
            }
            Журнал ("операция {0} (команда {1}): сервер отверг (409: {2}) - не повторяю" -f $opUid, $cid, $detail)
            Обновить-Историю $opUid @{ conflict = $detail }
            return $false
        }
        Журнал ("операция {0} (команда {1}): исход НЕ доставлен - повтор позже" -f $opUid, $cid)
        if ($i -lt $попыток - 1) { Start-Sleep -Seconds $задержка; $задержка = [Math]::Min($задержка * 2, 30) }
    }
    return $false
}

function Дослать-Незавершенные($cfg) {
    $ctx = Ctx $cfg
    $h = Прочит-Историю
    foreach ($opUid in @($h.Keys)) {
        $зап = $h[$opUid]
        if ((Поле $зап 'ctx') -ne $ctx) { continue }
        if ((Поле $зап 'delivered') -or (Поле $зап 'conflict')) { continue }
        if (Поле $зап 'deliver') { Доставить $cfg $opUid 3 | Out-Null }
    }
}

function Обработать($cfg, $cmd) {
    $cid = [int]$cmd.command_id
    $opUid = [string]$cmd.op_uid
    $отп = [string]$cmd.payload_sha256
    $сод = Канон-Содержимого ([int]$cmd.timeout_sec) ([string]$cmd.script_text)
    $ctx = Ctx $cfg

    $ошибка = Проверить-Команду $cfg $cmd
    if ($ошибка) {
        Журнал ("команда {0} отклонена проверкой: {1}" -f $cid, $ошибка)
        if ($opUid) {
            Задать-Доставку $opUid 'declined' ("проверка: " + $ошибка) $cid @{ ctx = $ctx; payload_sha256 = $отп; content_hash = $сод }
            Доставить $cfg $opUid 3 | Out-Null
        }
        return
    }

    $прежняя = Запись-Истории $opUid
    if ($прежняя) {
        $пctx = Поле $прежняя 'ctx'
        if ($пctx -and $пctx -ne $ctx) {
            Задать-Доставку $opUid 'declined' 'операция принадлежит другой установке' $cid @{ payload_sha256 = $отп; content_hash = $сод }
            Доставить $cfg $opUid 3 | Out-Null; return
        }
        $пСод = Поле $прежняя 'content_hash'
        if ($пСод -and $пСод -ne $сод) {
            Журнал ("операция {0}: request_id повторно использован с другим содержимым - отказ" -f $opUid)
            Задать-Доставку $opUid 'declined' 'request_id повторно использован с другим содержимым' $cid @{ payload_sha256 = $отп; content_hash = $сод }
            Доставить $cfg $opUid 3 | Out-Null; return
        }
        if ((Поле $прежняя 'executed') -or (Поле $прежняя 'exec_status')) {
            Журнал ("операция {0} уже выполнялась - повторно НЕ выполняю" -f $opUid)
            $прежний = [string](Поле $прежняя 'exec_status'); if (-not $прежний) { $прежний = 'неизвестен' }
            $dПрежн = Поле $прежняя 'deliver'
            $нетДоставки = ((Поле $dПрежн 'status') -ne 'completed')
            $поясн = ("операция уже выполнялась ранее (исход: {0})" -f $прежний)
            if ($нетДоставки) { $поясн += (", результат не был доставлен - требуется сведение по op_uid " + $opUid) }
            Задать-Доставку $opUid 'declined' $поясн $cid @{ payload_sha256 = $отп; content_hash = $сод }
            Доставить $cfg $opUid 5 | Out-Null
            return
        }
    }

    $задание = [string]$cmd.task
    if ($задание) {
        Write-Host ("`nЗадание ИИ (команда {0}): {1}" -f $cid, $задание)
        Журнал ("команда {0}: задание ИИ: {1}" -f $cid, $задание)
    }
    Журнал ("команда {0} (операция {1}) получена" -f $cid, $opUid)
    Журнал ("команда {0}: request_id={1}" -f $cid, [string]$cmd.request_id)
    Журнал ("команда {0} script_text:`n{1}" -f $cid, [string]$cmd.script_text)

    if ($Script:ДовериеНаСеанс) {
        Write-Host ("`n[РЕЖИМ ДОВЕРИЯ] выполняю без подтверждения, команда {0}:" -f $cid)
        Write-Host ("    " + (([string]$cmd.script_text) -replace "`n", "`n    "))
        Журнал ("команда {0}: режим доверия, выполнение без окна" -f $cid)
    } else {
        $решение = Показать-Подтверждение $cmd
        if ($решение -eq 'session') {
            $Script:ДовериеНаСеанс = $true
            Write-Host "`n[РЕЖИМ ДОВЕРИЯ ВКЛЮЧЕН] до остановки помощника команды выполняются без окна."
            Write-Host "Чтобы выключить - остановите помощника (Ctrl+C) и запустите снова."
            Журнал "ВКЛЮЧЕН режим доверия на сеанс (человек нажал «Разрешить все»)"
        } elseif ($решение -ne 'once') {
            Журнал ("команда {0} ОТКЛОНЕНА человеком/таймаутом" -f $cid)
            Задать-Доставку $opUid 'declined' 'declined_by_user' $cid @{ ctx = $ctx; payload_sha256 = $отп; content_hash = $сод }
            Доставить $cfg $opUid 5 | Out-Null
            return
        }
    }

    Задать-Доставку $opUid 'failed' 'unknown: прервано на этапе разрешения запуска, выполнение не подтверждено' $cid `
        @{ ctx = $ctx; payload_sha256 = $отп; content_hash = $сод; start_attempted = $true }
    $st = Запрос $cfg '/api/v1/desktop/start' `
        @{ install_id = $cfg.install_id; command_id = $cid; op_uid = $opUid; payload_sha256 = $отп } $cfg.agent_secret
    if (-not (Поле $st 'ok')) {
        $http = Поле $st 'http'
        if (@(400, 403, 404) -contains $http) {
            Журнал ("команда {0}: старт отклонен сервером (http {1}) - задание снято" -f $cid, $http)
            Обновить-Историю $opUid @{ deliver = $null }
        } else {
            Журнал ("команда {0}: исход старта не определен (http {1}) - закроет досыл" -f $cid, $http)
        }
        return
    }

    Задать-Доставку $opUid 'failed' 'unknown: выполнение прервано, исход неизвестен' $cid @{ executed = $true; payload_sha256 = $отп; content_hash = $сод }
    $res = Выполнить-С-Ходом $cfg ([int]$cid) ([string]$opUid) ([string]$отп) ([string]$cmd.script_text) ([int]$cmd.timeout_sec)
    $статус = $(if ($res.ContainsKey('error')) { 'failed' } else { 'completed' })
    $res['approved_by'] = [string]$env:USERNAME

    Обновить-Историю $opUid @{
        exec_status = $статус
        exec_result = $(if ($статус -eq 'completed') { $res } else { $null })
        exec_error  = [string]$res['error']
        content_hash = $сод
    }
    Задать-Доставку $opUid $статус ([string]$res['error']) $cid @{ payload_sha256 = $отп; content_hash = $сод }
    Доставить $cfg $opUid 5 | Out-Null
}

function Первичная-Настройка() {
    $cfg = Прочит-Json $CONFIG
    if (-not $cfg -or -not (Поле $cfg 'base_url') -or -not (Поле $cfg 'token')) {
        Write-Host 'Заполните config.json: base_url (https://api.onecdatalink.ru) и token (ключ помощника).'
        exit 2
    }
    $installId = 'inst-' + [guid]::NewGuid().ToString('N').Substring(0, 20)
    $cfg['install_id'] = $installId
    $cfg['agent_secret'] = ''
    $имяПк = $env:COMPUTERNAME
    $отв = Запрос $cfg '/api/v1/desktop/register' `
        @{ install_id = $installId; hostname = $имяПк; helper_version = $HELPER_VERSION } ''
    if (Поле $отв 'agent_secret') {
        $cfg['agent_secret'] = [string](Поле $отв 'agent_secret')
        Журнал ('регистрация сессии {0}: получен секрет, ожидает подтверждения' -f $installId)
    }
    $статус = Поле $отв 'status'
    if ($статус -eq 'pending') {
        Write-Host ('Сессия зарегистрирована. В кабинете (карточка ключа помощника) подтвердите этот компьютер: ' + $имяПк + '. Это окно не закрывайте.')
    } elseif ($статус -eq 'approved') { Write-Host 'Сессия подтверждена, помощник готов к работе.' }
    else { Write-Host ('Ответ регистрации: ' + (_ВJson $отв)) }
    return $cfg
}

function Ждать-Подтверждения($cfg) {
    Write-Host 'Ожидаю подтверждения в кабинете... (Ctrl+C - отмена)'
    $имяПк = $env:COMPUTERNAME
    while ($true) {
        $отв = Запрос $cfg '/api/v1/desktop/register' `
            @{ install_id = $cfg.install_id; hostname = $имяПк; helper_version = $HELPER_VERSION } $cfg.agent_secret
        if ((Поле $отв 'status') -eq 'approved') { Write-Host 'Подтверждено. Помощник работает.'; return $true }
        $http = Поле $отв 'http'
        if ((-not (Поле $отв 'ok')) -and ($http -ne 403) -and ($null -ne $http)) {
            Журнал ('ожидание подтверждения: ' + [string](Поле $отв 'detail'))
        }
        Start-Sleep -Seconds $POLL_IDLE_SEC
    }
}

function Отключиться($cfg) {
    try {
        if ((Поле $cfg 'install_id') -and (Поле $cfg 'agent_secret')) {
            Запрос $cfg '/api/v1/desktop/disconnect' @{ install_id = $cfg.install_id } $cfg.agent_secret | Out-Null
            Журнал ('сессия {0} завершена, запись удалена' -f $cfg.install_id)
        }
    } catch { }
}

$Script:Завершено = $false
function Финал($cfg) {
    if ($Script:Завершено) { return }
    $Script:Завершено = $true
    Отключиться $cfg
    try { if (Test-Path $PIDFILE) { Remove-Item -Force $PIDFILE -ErrorAction SilentlyContinue } } catch { }
}

if (-not ('ODL.CtrlClose' -as [type])) {
Add-Type @"
using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
namespace ODL {
  public static class CtrlClose {
    public delegate bool HandlerRoutine(uint ctrlType);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetConsoleCtrlHandler(HandlerRoutine h, bool add);
    private static string _url, _token, _secret, _install;
    private static int _done = 0;
    private static HandlerRoutine _ref;
    public static void Configure(string baseUrl, string token, string secret, string install) {
      _url = baseUrl.TrimEnd('/') + "/api/v1/desktop/disconnect";
      _token = token; _secret = secret; _install = install;
    }
    private static void Disconnect() {
      if (Interlocked.Exchange(ref _done, 1) != 0) return;
      if (string.IsNullOrEmpty(_install) || string.IsNullOrEmpty(_secret)) return;
      try {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        var req = (HttpWebRequest)WebRequest.Create(_url);
        req.Method = "POST"; req.ContentType = "application/json; charset=utf-8";
        req.Headers["X-Bridge-Token"] = _token;
        req.Headers["X-Agent-Secret"] = _secret;
        req.Timeout = 3000; req.AllowAutoRedirect = false;
        var body = Encoding.UTF8.GetBytes("{\"install_id\":\"" + _install + "\"}");
        req.ContentLength = body.Length;
        using (var s = req.GetRequestStream()) { s.Write(body, 0, body.Length); }
        using (var r = (HttpWebResponse)req.GetResponse()) { }
      } catch { }
    }
    private static bool Handler(uint t) {
      if (t==2 || t==5 || t==6) Disconnect();
      return false;
    }
    public static bool Install() { _ref = Handler; return SetConsoleCtrlHandler(_ref, true); }
  }
}
"@
}

function Установить-Обработчик-Закрытия($cfg) {
    try {
        [ODL.CtrlClose]::Configure([string]$cfg.base_url, [string]$cfg.token,
            [string]$cfg.agent_secret, [string]$cfg.install_id)
        [void][ODL.CtrlClose]::Install()
    } catch {
        Журнал ('обработчик закрытия окна не поставлен: ' + $_.Exception.Message)
    }
}

function Цикл($cfg) {
    try { Дослать-Незавершенные $cfg }
    catch { if ($_.Exception.Message -like 'ПОВРЕЖДЕНА-ИСТОРИЯ*') { Write-Host 'История повреждена - остановка до разбора'; exit 4 } else { throw } }
    Write-Host ('Помощник работает. Опрос каждые {0} с. Ctrl+C для остановки.' -f $POLL_IDLE_SEC)
    $последний = Get-Date
    while ($true) {
        if (((Get-Date) - $последний).TotalSeconds -gt $RESEND_EVERY_SEC) {
            try { Дослать-Незавершенные $cfg } catch { if ($_.Exception.Message -like 'ПОВРЕЖДЕНА-ИСТОРИЯ*') { exit 4 } }
            $последний = Get-Date
        }
        $отв = Запрос $cfg '/api/v1/desktop/pull' @{ install_id = $cfg.install_id } $cfg.agent_secret
        if (-not (Поле $отв 'ok')) { Start-Sleep -Seconds ($POLL_IDLE_SEC * 2); continue }
        $cmd = Поле $отв 'command'
        if (-not $cmd) { Start-Sleep -Seconds $POLL_IDLE_SEC; continue }
        try { Обработать $cfg $cmd }
        catch { if ($_.Exception.Message -like 'ПОВРЕЖДЕНА-ИСТОРИЯ*') { Write-Host 'История повреждена - остановка'; exit 4 } else { Журнал ("ошибка обработки: " + $_.Exception.Message) } }
    }
}

function Main() {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'ОТКАЗ: помощник запущен с правами администратора. Перезапустите под обычным пользователем.'
        Журнал 'запуск с высокими правами отклонен'
        exit 3
    }
    if (-not (Миграция-Раскладки)) { exit 8 }
    if (-not (Взять-Замок)) {
        Write-Host 'ОТКАЗ: помощник уже запущен (не удалось взять helper.lock).'
        exit 5
    }
    if (-not (Защитить-Окружение)) {
        Write-Host 'ОТКАЗ: не удалось закрыть доступ к файлам помощника только своей учёткой (см. helper.log).'
        Журнал 'защита окружения не удалась - старт отклонён'
        exit 6
    }
    $cfgПредв = Прочит-Json $CONFIG
    if (-not $cfgПредв -or -not (Поле $cfgПредв 'token')) { Write-Host 'Заполните config.json: base_url и token.'; exit 2 }
    try {
        $переходОк = Миграция-Истории $cfgПредв
    } catch {
        if ($_.Exception.Message -like 'ПОВРЕЖДЕНА-ИСТОРИЯ*') {
            Write-Host 'История операций повреждена - помощник остановлен до разбора.'; exit 4
        } else { throw }
    }
    if (-not $переходОк) {
        Write-Host 'ОТКАЗ: история прежнего формата содержит ВЫПОЛНЕННЫЕ операции.'
        Write-Host 'По истории нельзя доказать, что они относятся к другому ключу, поэтому нужно'
        Write-Host 'РУЧНОЕ сведение: убедиться, что их результаты доставлены, затем заархивировать'
        Write-Host 'старую историю (обратитесь к разработчику). Перевыпуск ключа сам по себе НЕ'
        Write-Host 'снимает запрет; history.json удалять нельзя - снимется защита от повтора.'
        Журнал 'переходный запрет истории прежнего формата - старт отклонён'
        exit 7
    }
    $cfg = Первичная-Настройка
    if (-not (Поле $cfg 'agent_secret')) { Write-Host 'Регистрация не удалась - смотрите helper.log.'; return }
    try {
        $метка = [string]$PID
        try { $метка = $метка + "`n" + ([string]((Get-Process -Id $PID).StartTime.ToFileTimeUtc())) } catch { }
        [System.IO.File]::WriteAllText($PIDFILE, $метка, (New-Object System.Text.UTF8Encoding($false)))
        Защитить-Файл $PIDFILE | Out-Null
    } catch { }
    Установить-Обработчик-Закрытия $cfg
    try {
        if (Ждать-Подтверждения $cfg) { Цикл $cfg }
    } finally {
        Финал $cfg
    }
}
