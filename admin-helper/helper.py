                       
import argparse
import base64
import ctypes
import datetime
import hashlib
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

if getattr(sys, "frozen", False):
    ЗДЕСЬ = os.path.dirname(os.path.abspath(sys.executable))
else:
    ЗДЕСЬ = os.path.dirname(os.path.abspath(__file__))
                                                                                     
CONFIG_DIR = os.path.join(ЗДЕСЬ, "config")
LOGS_DIR = os.path.join(ЗДЕСЬ, "logs")
RUNTIME_DIR = os.path.join(ЗДЕСЬ, "runtime")
for _d in (CONFIG_DIR, LOGS_DIR, RUNTIME_DIR):
    try:
        os.makedirs(_d, exist_ok=True)
    except OSError:
        pass
CONFIG = os.path.join(CONFIG_DIR, "config.json")
HISTORY = os.path.join(RUNTIME_DIR, "history.json")
HISTORY_LEGACY = os.path.join(RUNTIME_DIR, "history.legacy.json")                                           
LOCK = os.path.join(RUNTIME_DIR, "helper.lock")
PIDFILE = os.path.join(RUNTIME_DIR, "helper.pid")                                                           
LOG = os.path.join(LOGS_DIR, "helper.log")
LOG_MAX = 10 * 1024 * 1024
OUTPUT_MAX = 256 * 1024                                                             
SCRIPT_MAX = 64 * 1024                                       
CONFIRM_TIMEOUT = 120
POLL_IDLE_SEC = 3
RESEND_EVERY_SEC = 60
PROGRESS_SEND_SEC = 20                                                            
PROGRESS_TAIL = 3500                                                                   
TIMEOUT_MIN, TIMEOUT_MAX = 5, 300
HELPER_VERSION = "0.3"

def журнал(текст: str) -> None:
    try:
        if os.path.exists(LOG) and os.path.getsize(LOG) > LOG_MAX:
            os.replace(LOG, LOG + ".1")
        with open(LOG, "a", encoding="utf-8") as f:
            f.write("%s  %s\n" % (datetime.datetime.now().isoformat(timespec="seconds"), текст))
    except OSError:
        pass

def _чит(путь: str) -> dict:
    try:
        return json.load(open(путь, encoding="utf-8"))
    except (OSError, ValueError):
        return {}

_защита_файла = None

def _текущий_sid() -> str | None:
    if os.name != "nt":
        return None
    try:
        r = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, timeout=15, text=True)
        if r.returncode == 0 and r.stdout:
            части = [c.strip().strip('"') for c in r.stdout.strip().splitlines()[-1].split(",")]
            if len(части) >= 2 and части[-1].startswith("S-1-"):
                return части[-1]
    except Exception:                
        return None
    return None

def _ps_строка(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"

def _set_acl_только_себе(путь: str, каталог: bool) -> bool:
    наследование = "ContainerInherit,ObjectInherit" if каталог else "None"
    тип = "DirectorySecurity" if каталог else "FileSecurity"
    io_тип = "Directory" if каталог else "File"
    ps = (
        "[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);"
        "$ErrorActionPreference='Stop';try{"
        "$p=%s;"
        "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User;"
        "$acl=New-Object System.Security.AccessControl.%s;"
        "$acl.SetAccessRuleProtection($true,$false);"
        "$rule=New-Object System.Security.AccessControl.FileSystemAccessRule("
        "$sid,'FullControl','%s','None','Allow');"
        "$acl.SetAccessRule($rule);"
                                                                                 
        "[System.IO.%s]::SetAccessControl($p,$acl);"
        "$sections=[System.Security.AccessControl.AccessControlSections]::Access -bor "
        "[System.Security.AccessControl.AccessControlSections]::Owner;"
        "$chk=[System.IO.%s]::GetAccessControl($p,$sections);"
        "$rules=@($chk.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]));"
        "if(-not $chk.AreAccessRulesProtected -or $rules.Count -ne 1 -or "
        "$chk.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){"
        "throw 'ACL: неверный владелец или приватная DACL не подтверждена'};"
        "$r=$rules[0];"
        "if($r.IdentityReference.Value -ne $sid.Value -or $r.IsInherited -or "
        "$r.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or "
        "$r.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or "
        "$r.InheritanceFlags -ne ([System.Security.AccessControl.InheritanceFlags]::%s) -or "
        "$r.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None){"
        "throw 'ACL: правило доступа не соответствует текущей учетной записи'};"
        "Write-Output 'ODL_ACL_OK';exit 0"
        "}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}"
    ) % (_ps_строка(путь), тип, наследование, io_тип, io_тип,
         ("ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit"
          if каталог else "None"))
    try:
        exe = powershell_путь()
        if not exe:
            журнал("ACL: штатный PowerShell не найден - защита не применена")
            return False
        encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
        r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                           capture_output=True, timeout=30, text=True, encoding="utf-8", errors="replace")
        if r.returncode == 0 and (r.stdout or "").strip() == "ODL_ACL_OK":
            return True
        журнал("ACL: защита %s не удалась (rc=%s, %s)" % (
            os.path.basename(путь), r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()[:160]))
        return False
    except Exception as e:                
        журнал("ACL: Set-Acl не выполнен для %s (%s)" % (os.path.basename(путь), str(e)[:80]))
        return False

def защитить_окружение() -> bool:
    if _защита_файла is not None:
        return True                                    
    _файлы = (CONFIG, LOG, LOG + ".1", HISTORY, HISTORY_LEGACY, LOCK, PIDFILE)
    if os.name != "nt":
        for p in (ЗДЕСЬ, CONFIG_DIR, LOGS_DIR, RUNTIME_DIR) + _файлы:
            try:
                if os.path.exists(p):
                    os.chmod(p, 0o700 if os.path.isdir(p) else 0o600)
            except OSError:
                pass
        return True
    for d in (ЗДЕСЬ, CONFIG_DIR, LOGS_DIR, RUNTIME_DIR):                     
        if not защитить_файл(d):
            return False
    for p in _файлы:                                             
        if os.path.exists(p) and not защитить_файл(p):
            return False
    return True

def защитить_файл(путь: str) -> bool:
    if _защита_файла is not None:                       
        return _защита_файла(путь)
    if os.name == "nt":
        return _set_acl_только_себе(путь, os.path.isdir(путь))
    try:
        os.chmod(путь, 0o600)
        return True
    except OSError:
        return False

def _зап(путь: str, data: dict) -> None:
    tmp = путь + ".tmp"
    try:
        os.unlink(tmp)                                                                   
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    закрыт = False
    try:
        if not защитить_файл(tmp):                                              
            raise OSError("не удалось защитить права файла %s - запись отменена" % os.path.basename(путь))
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            закрыт = True                                
            json.dump(data, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        if not закрыт:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, путь)
    защитить_файл(путь)

class ПовреждённаяИстория(Exception):
    pass

_lock_fh = None
_причина_отказа_замка = ""
_уборка_не_подтверждена = False                                                   
                                                                                
_доверие_на_сеанс = False

def взять_замок() -> bool:
    global _lock_fh, _причина_отказа_замка
    _причина_отказа_замка = ""
    try:
        _lock_fh = open(LOCK, "a+")
        if not защитить_файл(LOCK):                                                    
            _причина_отказа_замка = "не удалось защитить права helper.lock - подробности в helper.log"
            журнал("замок: не удалось защитить права helper.lock - запуск отклонён")
            try:
                _lock_fh.close()
            except OSError:
                pass
            _lock_fh = None
            return False
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(_lock_fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(_lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as e:
        _причина_отказа_замка = "не удалось открыть или захватить helper.lock: %s" % str(e)
        журнал(_причина_отказа_замка)
        if _lock_fh is not None:
            try:
                _lock_fh.close()
            except OSError:
                pass
            _lock_fh = None
        return False

def _ctx(cfg: dict) -> str:
    сырьё = (_норм_url(cfg.get("base_url", "")) + "|" + cfg.get("token", "")).encode("utf-8")
    return hashlib.sha256(сырьё).hexdigest()[:16]

def _норм_url(u: str) -> str:
    return (u or "").strip().rstrip("/").lower()

def _возможные_ctx(cfg: dict) -> set:
    token = cfg.get("token", "")
    base = (cfg.get("base_url", "") or "").strip()
    варианты = {base, base.rstrip("/"), base.rstrip("/") + "/", _норм_url(base)}
    return {hashlib.sha256((v + "|" + token).encode("utf-8")).hexdigest()[:16] for v in варианты}

def история() -> dict:
    if not os.path.exists(HISTORY):
        return {}
    try:
        d = json.load(open(HISTORY, encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ПовреждённаяИстория(str(e))
    if not isinstance(d, dict):
        raise ПовреждённаяИстория("история не словарь")
    return d

HISTORY_FMT = 2                                                                                    

def история_записать(op_uid: str, поле: dict) -> None:
    d = история()
                                                                                     
    d[op_uid] = {**d.get(op_uid, {}), "fmt": HISTORY_FMT, **поле}
    _зап(HISTORY, d)

def история_запись(op_uid: str) -> dict:
    return история().get(op_uid, {})

def _строгий_чит_архива(путь: str) -> dict:
    if not os.path.exists(путь):
        return {}
    try:
        with open(путь, encoding="utf-8") as f:
            текст = f.read()
    except OSError as e:
        raise ПовреждённаяИстория("карантин не прочитать: %s" % e)
    if not текст.strip():
        raise ПовреждённаяИстория("карантин пуст")
    try:
        d = json.loads(текст)
    except ValueError as e:
        raise ПовреждённаяИстория("карантин не JSON: %s" % e)
    if not isinstance(d, dict):
        raise ПовреждённаяИстория("карантин не словарь")
    return d

def миграция_истории() -> bool:
    if _защита_файла is not None:
        return True         
    try:
        cfg = _чит(CONFIG)
        if not cfg.get("token"):
            return True
        h = история()
    except ПовреждённаяИстория:
        return True                                        
    legacy = {k: v for k, v in h.items() if isinstance(v, dict) and not v.get("fmt")}
    if not legacy:
        return True
    блок = [k for k, v in legacy.items() if (v.get("executed") or v.get("exec_status"))]
    if блок:
        журнал("история прежнего формата: %d выполненных операций - переходный запрет" % len(блок))
        return False
                                                                                        
    try:
        кар = _строгий_чит_архива(HISTORY_LEGACY)
    except ПовреждённаяИстория:
        журнал("карантин истории повреждён - переход запрещён до разбора")
        return False
    try:
        кар.update(legacy)
        _зап(HISTORY_LEGACY, кар)
        проверка = _строгий_чит_архива(HISTORY_LEGACY)
        if not all(k in проверка for k in legacy):
            журнал("карантин истории не подтверждён записью - переход запрещён")
            return False
    except ПовреждённаяИстория:
        журнал("карантин истории после записи повреждён - переход запрещён")
        return False
    except Exception as e:                
        журнал("ошибка записи карантина истории (%s) - исходную не трогаю, переход запрещён" % str(e)[:80])
        return False
    новая = {k: v for k, v in h.items() if not (isinstance(v, dict) and not v.get("fmt"))}
    _зап(HISTORY, новая)
    журнал("история: %d записей прежнего формата перенесены в карантин %s"
           % (len(legacy), os.path.basename(HISTORY_LEGACY)))
    return True

def запущен_админом() -> bool:
    if os.name != "nt":
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:                                                                      
        return True

def _кодировка_консоли() -> str:
    if os.name == "nt":
        try:
            import ctypes
            cp = ctypes.windll.kernel32.GetConsoleOutputCP()
            if cp:
                return "cp%d" % cp
        except Exception:                
            return "cp866"
    return "utf-8"

_CONSOLE_ENC = _кодировка_консоли()

def _декод_вывод(b: bytes) -> str:
    try:
        return b.decode(_CONSOLE_ENC, "replace")
    except (LookupError, ValueError):
        return b.decode("utf-8", "replace")

def powershell_путь() -> str | None:
    if os.name == "nt":
        p = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                         "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        return p if os.path.exists(p) else None
    import shutil
    return shutil.which("pwsh") or shutil.which("powershell")                         

class _НетРедиректаСекретов(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "редирект с секретными заголовками запрещён", headers, fp)

_ctx_tls = ssl.create_default_context()
_opener = urllib.request.build_opener(_НетРедиректаСекретов,
                                      urllib.request.HTTPSHandler(context=_ctx_tls))

def _адрес_допустим(url: str) -> bool:
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return u.scheme == "https"

def запрос(cfg: dict, путь: str, тело: dict, секрет: str = "") -> dict:
    url = cfg["base_url"].rstrip("/") + путь
    if not _адрес_допустим(url):
        return {"ok": False, "error": "адрес сервиса должен быть https"}
    data = json.dumps(тело, ensure_ascii=False).encode("utf-8")
    заголовки = {"Content-Type": "application/json", "X-Bridge-Token": cfg["token"]}
    if секрет:
        заголовки["X-Agent-Secret"] = секрет
    req = urllib.request.Request(url, data=data, headers=заголовки, method="POST")
    try:
        with _opener.open(req, timeout=120) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            detail = json.loads(body).get("detail", body)
        except ValueError:
            detail = body
        return {"ok": False, "http": e.code, "detail": str(detail)[:300]}
    except Exception as e:                
        return {"ok": False, "error": str(e)[:200]}

def первичная_настройка() -> dict:
    cfg = _чит(CONFIG)
    if not cfg.get("base_url") or not cfg.get("token"):
        print("Заполните config.json: base_url (https://api.onecdatalink.ru) и token (ключ помощника).")
        print("Пример: config.example.json рядом.")
        sys.exit(2)
    cfg["install_id"] = "inst-" + secrets.token_hex(10)                        
    cfg["agent_secret"] = ""
    host = os.environ.get("COMPUTERNAME") or (os.uname().nodename if hasattr(os, "uname") else "")
    отв = запрос(cfg, "/api/v1/desktop/register",
                 {"install_id": cfg["install_id"], "hostname": host[:120], "helper_version": HELPER_VERSION}, "")
    if отв.get("agent_secret"):
        cfg["agent_secret"] = отв["agent_secret"]
        журнал("регистрация сессии %s: получен секрет, ожидает подтверждения" % cfg["install_id"])
    if отв.get("status") == "pending":
        print("Сессия зарегистрирована. В кабинете (карточка ключа помощника) подтвердите")
        print("этот компьютер: %s. Это окно не закрывайте." % (host or cfg["install_id"]))
    elif отв.get("status") == "approved":
        print("Сессия подтверждена, помощник готов к работе.")
    else:
        print("Ответ регистрации:", отв)
    return cfg

def ждать_подтверждения(cfg: dict) -> bool:
    print("Ожидаю подтверждения в кабинете... (Ctrl+C - отмена)")
    host = os.environ.get("COMPUTERNAME") or (os.uname().nodename if hasattr(os, "uname") else "")
    while True:
        отв = запрос(cfg, "/api/v1/desktop/register",
                     {"install_id": cfg["install_id"], "hostname": host[:120], "helper_version": HELPER_VERSION},
                     cfg.get("agent_secret", ""))
        if отв.get("status") == "approved":
            print("Подтверждено. Помощник работает.")
            return True
        if not отв.get("ok") and отв.get("http") not in (403, None):
            журнал("ожидание подтверждения: %s" % (отв.get("detail") or отв.get("error")))
        time.sleep(POLL_IDLE_SEC)

def отключиться(cfg: dict) -> None:
    try:
        if cfg.get("install_id") and cfg.get("agent_secret"):
            запрос(cfg, "/api/v1/desktop/disconnect", {"install_id": cfg["install_id"]}, cfg.get("agent_secret", ""))
            журнал("сессия %s завершена, запись удалена" % cfg["install_id"])
    except Exception:                
        pass

_завершение_lock = threading.Lock()
_завершено = False
_ctrl_handler_ref = None                                                                

def _финал(cfg: dict) -> None:
    global _завершено
    with _завершение_lock:
        if _завершено:
            return
        _завершено = True
    отключиться(cfg)
    try:
        os.remove(PIDFILE)
    except OSError:
        pass

def установить_обработчик_закрытия(cfg: dict) -> None:
    global _ctrl_handler_ref
    if os.name != "nt":
        return
    try:
        from ctypes import wintypes as w
        HANDLER = ctypes.WINFUNCTYPE(w.BOOL, w.DWORD)
        ЗАКРЫТИЕ = {2, 5, 6}                                                

        def _на_сигнал(код):
            if int(код) in ЗАКРЫТИЕ:
                try:
                    _финал(cfg)
                except Exception:                
                    pass
            return False                                                         

        _ctrl_handler_ref = HANDLER(_на_сигнал)
        if not ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_handler_ref, True):
            журнал("обработчик закрытия окна не поставлен (SetConsoleCtrlHandler)")
    except Exception:                
        журнал("не удалось поставить обработчик закрытия окна")

def канон_op_uid(cfg: dict, request_id: str) -> str:
    сырьё = ("odl-desktop-op-v1\n%s\n%s" % (cfg["token"], request_id)).encode("utf-8")
    return hashlib.sha256(сырьё).hexdigest()[:32]

def канон_содержимого(cmd: dict) -> str:
    строка = "op-content-v1\n%d\npowershell\n%s" % (int(cmd.get("timeout_sec") or 0), cmd.get("script_text") or "")
    return hashlib.sha256(строка.encode("utf-8")).hexdigest()

def канон_отпечаток(cfg: dict, cmd: dict) -> str:
    строка = "powershell\n%d\n%s\n%s\n%s" % (int(cmd.get("timeout_sec") or 0), cfg["install_id"],
                                             cmd.get("op_uid") or "", cmd.get("script_text") or "")
    return hashlib.sha256(строка.encode("utf-8")).hexdigest()

def проверить_команду(cfg: dict, cmd: dict) -> str | None:
    if cmd.get("shell") != "powershell":
        return "неподдерживаемая оболочка"
    if cmd.get("elevate"):
        return "повышение прав в этой версии запрещено"
    rid = cmd.get("request_id")
    if not isinstance(rid, str) or len(rid) < 8:
        return "команда без стабильного request_id"
    op = cmd.get("op_uid")
    if not isinstance(op, str) or len(op) != 32 or any(c not in "0123456789abcdef" for c in op):
        return "неверный формат op_uid"
    if op != канон_op_uid(cfg, rid):
        return "op_uid не совпал с ключом/машиной/request_id"
    скрипт = cmd.get("script_text")
    if not isinstance(скрипт, str) or not скрипт:
        return "пустой текст команды"
    if len(скрипт.encode("utf-8")) > SCRIPT_MAX:
        return "текст команды слишком большой"
    t = cmd.get("timeout_sec")
    if not isinstance(t, int) or not (TIMEOUT_MIN <= t <= TIMEOUT_MAX):
        return "недопустимый предел времени"
    отп = cmd.get("payload_sha256")
    if not отп:
        return "нет отпечатка payload (обязателен)"
    if отп != канон_отпечаток(cfg, cmd):
        return "отпечаток команды не совпал"
    return None

def показать_подтверждение(cmd: dict) -> str:
    скрипт = cmd["script_text"]
    шапка = "Команда для этого компьютера. Права: текущий пользователь. Предел: %s с." % cmd.get("timeout_sec", "?")
    try:
        import tkinter as tk
        from tkinter import scrolledtext
        root = tk.Tk()                                                                        
    except Exception:                
        print("Нет графической среды для подтверждения - команда ОТКЛОНЕНА (безопасный отказ).")
        журнал("нет GUI: безопасный отказ")
        return "deny"

    результат = {"v": "deny"}
    try:
        root.title("Помощник администратора: подтверждение команды")
        root.geometry("780x580")
        tk.Label(root, text="ИИ предлагает выполнить команду PowerShell на этом компьютере.",
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=12, pady=(12, 2))
        tk.Label(root, text=шапка, fg="#555").pack(anchor="w", padx=12)
        tk.Label(root, text="Выполнится РОВНО этот текст. Вывод уйдёт обратно ИИ.",
                 fg="#b96a00").pack(anchor="w", padx=12, pady=(2, 6))
        txt = scrolledtext.ScrolledText(root, wrap="none", height=17, font=("Consolas", 10))
        txt.insert("1.0", скрипт)
        txt.configure(state="disabled")
        txt.pack(fill="both", expand=True, padx=12)
        отсчёт = {"n": CONFIRM_TIMEOUT}
        lbl = tk.Label(root, text="", fg="#555")
        lbl.pack(anchor="w", padx=12)
        tk.Label(root, text="«Разрешить все» отключает окно до остановки помощника: команды будут "
                            "выполняться без показа. Включайте, только если доверяете источнику.",
                 fg="#b00", wraplength=740, justify="left").pack(anchor="w", padx=12, pady=(4, 0))

        def решить(v):
            результат["v"] = v
            root.destroy()

        низ = tk.Frame(root)
        низ.pack(fill="x", padx=12, pady=10)
        tk.Button(низ, text="Отклонить", width=14, command=lambda: решить("deny")).pack(side="right")
        tk.Button(низ, text="Разрешить", width=14, command=lambda: решить("once")).pack(side="right", padx=8)
        tk.Button(низ, text="Разрешить все до остановки", width=24,
                  command=lambda: решить("session")).pack(side="right")

        after_id = {"v": None}

        def тик():
            отсчёт["n"] -= 1
            try:
                lbl.config(text="Автоотклонение через %d с" % отсчёт["n"])
            except Exception:                
                return
            if отсчёт["n"] <= 0:
                root.destroy()
            else:
                after_id["v"] = root.after(1000, тик)

        after_id["v"] = root.after(1000, тик)
        root.mainloop()
    finally:
                                                                                      
        try:
            if after_id.get("v") is not None:
                root.after_cancel(after_id["v"])
        except Exception:                
            pass
        try:
            root.destroy()
        except Exception:                
            pass
        try:
            root.quit()
        except Exception:                
            pass
        тик = lbl = txt = низ = root = None
        import gc
        gc.collect()
    return результат["v"]

def _поток_чтения(pipe, буфер: list, общий: dict) -> None:
    try:
        while True:
            chunk = pipe.read(65536)
            if not chunk:
                break
            with общий["lock"]:
                if общий["n"] < OUTPUT_MAX:
                    можно = OUTPUT_MAX - общий["n"]
                    буфер.append(chunk[:можно])
                    общий["n"] += min(len(chunk), можно)
                    if len(chunk) > можно:
                        общий["cut"] = True
                else:
                    общий["cut"] = True                                                  
    finally:
        try:
            pipe.close()
        except OSError:
            pass

def _job_запуск_разрешён(создан: bool, настроен: bool, назначен: bool, возобновлён: bool):
    if not создан:
        return (False, "не удалось создать Job Object")
    if not настроен:
        return (False, "не удалось настроить Job Object (kill-on-close)")
    if not назначен:
        return (False, "процесс не назначен в Job Object")
    if not возобновлён:
        return (False, "не удалось возобновить процесс после назначения в Job Object")
    return (True, "")

def _собрать_вывод(p, таймаут: int, начало: float, убить) -> dict:
    o_buf, e_buf = [], []
    общий = {"n": 0, "cut": False, "lock": threading.Lock()}
    to = threading.Thread(target=_поток_чтения, args=(p.stdout, o_buf, общий), daemon=True)
    te = threading.Thread(target=_поток_чтения, args=(p.stderr, e_buf, общий), daemon=True)
    to.start(); te.start()
    try:
        p.wait(timeout=таймаут)
        timed = False
    except subprocess.TimeoutExpired:
        убить()
        timed = True
    to.join(timeout=10); te.join(timeout=10)
    res = {"exit_code": None if timed else p.returncode,
           "duration_ms": int((time.time() - начало) * 1000),
           "stdout": _декод_вывод(b"".join(o_buf)),
           "stderr": _декод_вывод(b"".join(e_buf))}
    if общий["cut"]:
        res["truncated"] = True
    if timed:
        res["timed_out"] = True
    return res

def _запуск_обычный(аргументы: list, таймаут: int) -> dict:
    начало = time.time()
    p = subprocess.Popen(аргументы, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ЗДЕСЬ)
    return _собрать_вывод(p, таймаут, начало, lambda: _убить_дерево(p, None))

def _запуск_windows(аргументы: list, таймаут: int) -> dict:
    import ctypes
    from ctypes import wintypes as w
    k = ctypes.windll.kernel32
    k.CreateJobObjectW.restype = w.HANDLE
    k.CreateJobObjectW.argtypes = [w.LPVOID, w.LPCWSTR]
    k.SetInformationJobObject.restype = w.BOOL
    k.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD]
    k.OpenProcess.restype = w.HANDLE
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    k.AssignProcessToJobObject.restype = w.BOOL
    k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    k.TerminateJobObject.restype = w.BOOL
    k.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
    k.CloseHandle.restype = w.BOOL
    k.CloseHandle.argtypes = [w.HANDLE]
    k.OpenThread.restype = w.HANDLE
    k.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    k.ResumeThread.restype = w.DWORD
    k.ResumeThread.argtypes = [w.HANDLE]
    k.CreateToolhelp32Snapshot.restype = w.HANDLE
    k.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]

    class IO(ctypes.Structure):
        _fields_ = [("ReadOperationCount", ctypes.c_ulonglong), ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong), ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong), ("OtherTransferCount", ctypes.c_ulonglong)]

    class EXT(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    class TH32(ctypes.Structure):
        _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ThreadID", w.DWORD),
                    ("th32OwnerProcessID", w.DWORD), ("tpBasePri", ctypes.c_long),
                    ("tpDeltaPri", ctypes.c_long), ("dwFlags", w.DWORD)]

    k.Thread32First.restype = w.BOOL
    k.Thread32First.argtypes = [w.HANDLE, ctypes.POINTER(TH32)]
    k.Thread32Next.restype = w.BOOL
    k.Thread32Next.argtypes = [w.HANDLE, ctypes.POINTER(TH32)]

    def _возобновить_потоки(pid: int) -> bool:
        snap = k.CreateToolhelp32Snapshot(0x00000004, 0)                      
        if not snap or snap == w.HANDLE(-1).value:
            return False
        try:
            e = TH32(); e.dwSize = ctypes.sizeof(TH32)
            ok = k.Thread32First(snap, ctypes.byref(e))
            все_ок = True
            нашёл = False
            while ok:
                if e.th32OwnerProcessID == pid:
                    нашёл = True
                    th = k.OpenThread(0x0002, False, e.th32ThreadID)                          
                    if not th:
                        все_ок = False
                    else:
                        r = k.ResumeThread(th)                                                          
                        k.CloseHandle(th)
                        if r == 0xFFFFFFFF:
                            все_ок = False
                ok = k.Thread32Next(snap, ctypes.byref(e))
            return нашёл and все_ок                                                    
        finally:
            k.CloseHandle(snap)

    job = k.CreateJobObjectW(None, None)
    создан = bool(job)
    настроен = False
    if создан:
        info = EXT()
        info.BasicLimitInformation.LimitFlags = 0x2000                                       
        настроен = bool(k.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)))

    p = None
    назначен = False
    возобновлён = False
    try:
        if создан and настроен:
            p = subprocess.Popen(аргументы, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ЗДЕСЬ,
                                 creationflags=0x00000004 | 0x00000200)                                         
            h = k.OpenProcess(0x0100 | 0x0001, False, p.pid)                          
            if h:
                назначен = bool(k.AssignProcessToJobObject(job, h))
                k.CloseHandle(h)
            if назначен:
                возобновлён = _возобновить_потоки(p.pid)

        разрешить, ошибка = _job_запуск_разрешён(создан, настроен, назначен, возобновлён)
        if not разрешить:
            журнал("Job Object: %s - команда НЕ выполнена" % ошибка)
            if p is not None:
                _убить_дерево(p, job)                                                        
            return {"error": ошибка}

        начало = time.time()
        return _собрать_вывод(p, таймаут, начало, lambda: _убить_дерево(p, job))
    finally:
                                                                                     
        term_ok = False
        close_ok = False
        if job:
            try:
                term_ok = bool(k.TerminateJobObject(job, 1))
                                                                                                   
                close_ok = bool(k.CloseHandle(job))
            except Exception as e:                
                журнал("Job Object: ошибка завершения/закрытия (%s)" % str(e)[:80])
        if p is not None:
            try:
                p.wait(timeout=10)
                процесс_завершён = True
            except Exception:                
                процесс_завершён = False
            if not (term_ok and close_ok and процесс_завершён):
                global _уборка_не_подтверждена
                _уборка_не_подтверждена = True
                журнал("Job Object: уборка НЕ подтверждена (term=%s, close=%s, exited=%s) - "
                       "следующий запуск запрещён до разбора" % (term_ok, close_ok, процесс_завершён))

def _хвост_файла(путь: str, лимит: int) -> str:
    try:
        размер = os.path.getsize(путь)
        with open(путь, "rb") as f:
            if размер > лимит:
                f.seek(размер - лимит)
            data = f.read()
    except OSError:
        return ""
    текст = data.decode("utf-8", errors="replace")
    if размер > лимит:
        nl = текст.find("\n")                                                     
        if nl >= 0:
            текст = текст[nl + 1:]
    return текст.strip()

def _послать_ход(cfg: dict, cid: int, op_uid: str, отп: str, текст: str) -> dict:
    return запрос(cfg, "/api/v1/desktop/progress",
                  {"install_id": cfg["install_id"], "command_id": int(cid), "progress_text": текст,
                   "op_uid": op_uid, "payload_sha256": отп},
                  cfg.get("agent_secret", ""))

def _поток_прогресса(cfg: dict, cid: int, op_uid: str, отп: str, файл: str, стоп) -> None:
    прежнее = ""
    while not стоп.wait(PROGRESS_SEND_SEC):
        текст = _хвост_файла(файл, PROGRESS_TAIL)
        if not текст or текст == прежнее:
            continue
        try:
            отв = _послать_ход(cfg, cid, op_uid, отп, текст)
            if isinstance(отв, dict) and отв.get("http") in (401, 403, 404, 409):
                return
            прежнее = текст
        except Exception:                
            pass

def выполнить_с_ходом(cfg: dict, cid: int, op_uid: str, отп: str, скрипт: str, таймаут: int) -> dict:
    файл = os.path.join(RUNTIME_DIR, "progress-cmd-%d.txt" % cid)
    try:
        with open(файл, "w", encoding="utf-8"):
            pass
        защитить_файл(файл)                                                              
    except OSError:
        файл = ""
    стоп = threading.Event()
    поток = None
    прежний_env = os.environ.get("ODL_PROGRESS")
    if файл:
        os.environ["ODL_PROGRESS"] = файл
        поток = threading.Thread(target=_поток_прогресса, args=(cfg, cid, op_uid, отп, файл, стоп), daemon=True)
        поток.start()
    try:
        return выполнить_powershell(скрипт, таймаут)
    finally:
        стоп.set()
        if поток is not None:
            поток.join(timeout=5)
        if прежний_env is None:
            os.environ.pop("ODL_PROGRESS", None)
        else:
            os.environ["ODL_PROGRESS"] = прежний_env
        if файл:
                                                                                      
            хвост = _хвост_файла(файл, PROGRESS_TAIL)
            if хвост:
                try:
                    _послать_ход(cfg, cid, op_uid, отп, хвост)
                except Exception:                
                    pass
            try:
                os.remove(файл)
            except OSError:
                pass

def выполнить_powershell(скрипт: str, таймаут: int) -> dict:
                                                                              
    if _уборка_не_подтверждена:
        return {"error": "предыдущее задание не подтверждено завершённым - выполнение остановлено до разбора"}
    exe = powershell_путь()
    if not exe:
        return {"error": "powershell не найден на этой машине"}
    import tempfile
    fd, путь = tempfile.mkstemp(suffix=".ps1", prefix="odl_", dir=ЗДЕСЬ)
    os.close(fd)
    if not защитить_файл(путь):                                                
        try:
            os.remove(путь)
        except OSError:
            pass
        return {"error": "не удалось защитить права временного файла - команда не выполнена"}
    try:
        with open(путь, "w", encoding="utf-8-sig") as f:
            f.write(скрипт)
        аргументы = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", путь]
        if os.name == "nt":
            return _запуск_windows(аргументы, таймаут)
        return _запуск_обычный(аргументы, таймаут)
    finally:
        try:
            os.remove(путь)
        except OSError:
            pass

def _убить_дерево(p, job=None) -> None:
    try:
        if os.name == "nt":
            if job is not None:
                import ctypes
                ctypes.windll.kernel32.TerminateJobObject(job, 1)                     
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True, timeout=15)
        else:
            p.kill()
    except Exception:                
        pass

def _послать_результат(cfg: dict, cid: int, op_uid: str, payload_sha256: str, статус: str,
                       res: dict | None, err: str) -> dict:
    return запрос(cfg, "/api/v1/desktop/result",
                  {"install_id": cfg["install_id"], "command_id": cid, "op_uid": op_uid,
                   "payload_sha256": payload_sha256, "status": статус,
                   "result": res if статус == "completed" else None, "error": err},
                  cfg.get("agent_secret", ""))

def задать_доставку(op_uid: str, статус: str, ошибка: str, cid: int, отп: str = "", **поля) -> None:
    история_записать(op_uid, {"deliver": {"status": статус, "error": ошибка[:3800],
                                          "command_id": int(cid), "payload_sha256": отп},
                              "delivered": False, "conflict": None, **поля})

def доставить(cfg: dict, op_uid: str, попыток: int = 1) -> bool:
    зап = история_запись(op_uid)
    d = зап.get("deliver")
    if not d or not d.get("command_id") or not op_uid:
        return False
    if зап.get("delivered") or зап.get("conflict"):
        return bool(зап.get("delivered"))
    cid = int(d["command_id"]); статус = d["status"]; err = d.get("error", "")
                                                                                
    отп = d.get("payload_sha256") or зап.get("payload_sha256", "")
    res = зап.get("exec_result") if статус == "completed" else None
    задержка = 2
    for попытка in range(max(1, попыток)):
        итог = _послать_результат(cfg, cid, op_uid, отп, статус, res, err)
        if итог.get("ok"):
            история_записать(op_uid, {"delivered": True, "server_status": итог.get("status") or ""})
            журнал("операция %s (команда %d): исход %s доставлен" % (op_uid, cid, статус))
            return True
        if итог.get("http") == 409:
            detail = str(итог.get("detail") or "")
                                                                                        
            if "недопустимый переход" in detail and статус in ("failed", "declined") and res is None:
                другой = "declined" if статус == "failed" else "failed"
                alt = _послать_результат(cfg, cid, op_uid, отп, другой, None, err)
                if alt.get("ok"):
                    история_записать(op_uid, {"delivered": True, "server_status": alt.get("status") or ""})
                    журнал("операция %s (команда %d): исход доставлен как %s" % (op_uid, cid, другой))
                    return True
            журнал("операция %s (команда %d): сервер отверг (409: %s) - не повторяю" % (op_uid, cid, detail))
            история_записать(op_uid, {"conflict": detail or "409"})
            return False
        журнал("операция %s (команда %d): исход НЕ доставлен (%s), повтор позже"
               % (op_uid, cid, итог.get("detail") or итог.get("error")))
        if попытка < попыток - 1:
            time.sleep(задержка)
            задержка = min(задержка * 2, 30)
    return False

def дослать_незавершённые(cfg: dict) -> None:
    ctx = _ctx(cfg)
    for op_uid, зап in list(история().items()):
        if зап.get("ctx") != ctx or зап.get("delivered") or зап.get("conflict"):
            continue
        if зап.get("deliver"):
            доставить(cfg, op_uid, попыток=3)

def обработать(cfg: dict, cmd: dict) -> None:
    cid = cmd["command_id"]
    op_uid = cmd.get("op_uid") or ""
    отп = cmd.get("payload_sha256") or ""
    сод = канон_содержимого(cmd)                                              
    ctx = _ctx(cfg)

    ошибка = проверить_команду(cfg, cmd)
    if ошибка:
        журнал("команда %d отклонена проверкой: %s" % (cid, ошибка))
        if op_uid:
            задать_доставку(op_uid, "declined", "проверка: %s" % ошибка, cid, отп=отп, ctx=ctx, payload_sha256=отп)
            доставить(cfg, op_uid, попыток=3)
        return

    прежняя = история_запись(op_uid)
    if прежняя:
        if прежняя.get("ctx") not in (None, ctx):
            журнал("операция %s: чужой контекст установки - отказ" % op_uid)
            задать_доставку(op_uid, "declined", "операция принадлежит другой установке", cid, отп=отп, ctx=ctx, payload_sha256=отп)
            доставить(cfg, op_uid, попыток=3)
            return
                                                                                    
        if прежняя.get("content_hash") and прежняя.get("content_hash") != сод:
            журнал("операция %s: request_id повторно использован с другим содержимым - отказ" % op_uid)
            задать_доставку(op_uid, "declined", "request_id повторно использован с другим содержимым", cid, отп=отп)
            доставить(cfg, op_uid, попыток=3)
            return
        if прежняя.get("executed") or прежняя.get("exec_status"):
            журнал("операция %s уже выполнялась - повторно НЕ выполняю" % op_uid)
                                                                                   
            прежний = прежняя.get("exec_status") or "неизвестен"
            если_нет = (прежняя.get("deliver") or {}).get("status") != "completed"                                    
            поясн = ("операция уже выполнялась ранее (исход: %s)%s" %
                     (прежний, ", результат не был доставлен - требуется сведение по op_uid " + op_uid if если_нет else ""))
            задать_доставку(op_uid, "declined", поясн, cid, отп=отп)                                
            доставить(cfg, op_uid, попыток=5)
            return

    задание = str(cmd.get("task") or "")
    if задание:
        print("\nЗадание ИИ (команда %d): %s" % (cid, задание))
        журнал("команда %d: задание ИИ: %s" % (cid, задание))
    журнал("команда %d (операция %s, request_id %s) получена. Полный текст:\n%s"
           % (cid, op_uid, cmd.get("request_id") or "", cmd.get("script_text") or ""))

    global _доверие_на_сеанс
    if _доверие_на_сеанс:
        print("\n[РЕЖИМ ДОВЕРИЯ] выполняю без подтверждения, команда %d:" % cid)
        print("    " + (cmd.get("script_text") or "").replace("\n", "\n    "))
        журнал("команда %d: режим доверия, выполнение без окна (полный текст выше)" % cid)
    else:
        решение = показать_подтверждение(cmd)
        if решение == "session":
            _доверие_на_сеанс = True
            print("\n[РЕЖИМ ДОВЕРИЯ ВКЛЮЧЕН] до остановки помощника команды выполняются без окна.")
            print("Чтобы выключить - остановите помощника (Ctrl+C) и запустите снова.")
            журнал("ВКЛЮЧЕН режим доверия на сеанс (человек нажал «Разрешить все»)")
        elif решение != "once":
            журнал("команда %d ОТКЛОНЕНА человеком/таймаутом" % cid)
            задать_доставку(op_uid, "declined", "declined_by_user", cid, отп=отп, ctx=ctx, payload_sha256=отп)
            доставить(cfg, op_uid, попыток=5)
            return

    задать_доставку(op_uid, "failed", "unknown: прервано на этапе разрешения запуска, выполнение не подтверждено",
                    cid, отп=отп, ctx=ctx, payload_sha256=отп, content_hash=сод, start_attempted=True)
    st = запрос(cfg, "/api/v1/desktop/start",
                {"install_id": cfg["install_id"], "command_id": cid, "op_uid": op_uid, "payload_sha256": отп},
                cfg.get("agent_secret", ""))
    if not st.get("ok"):
                                                                                
        http = st.get("http")
        if http in (400, 403, 404):
            журнал("команда %d: старт отклонён сервером (http %s: %s) - не выполняю, задание снято"
                   % (cid, http, st.get("detail")))
            история_записать(op_uid, {"deliver": None})
        else:
            журнал("команда %d: исход старта не определён (http %s / %s) - закроет досыл, без повтора"
                   % (cid, http, st.get("error") or st.get("detail")))
        return

    задать_доставку(op_uid, "failed", "unknown: выполнение прервано, исход неизвестен", cid, отп=отп,
                    content_hash=сод, executed=True)
    кто = os.environ.get("USERNAME") or (os.getlogin() if hasattr(os, "getlogin") else "")
    res = выполнить_с_ходом(cfg, cid, op_uid, отп, cmd["script_text"], int(cmd["timeout_sec"]))
    статус = "completed" if "error" not in res else "failed"
    res["approved_by"] = кто

    история_записать(op_uid, {"exec_status": статус, "exec_result": res if статус == "completed" else None,
                              "exec_error": res.get("error", ""), "content_hash": сод})
    задать_доставку(op_uid, статус, res.get("error", ""), cid, отп=отп)
    доставить(cfg, op_uid, попыток=5)

def цикл(cfg: dict) -> None:
    try:
        дослать_незавершённые(cfg)
    except ПовреждённаяИстория as e:
        print("История операций повреждена - помощник остановлен до разбора:", e)
        журнал("история повреждена: %s - остановка" % e)
        sys.exit(4)
    print("Помощник работает. Опрос каждые %d с. Ctrl+C для остановки." % POLL_IDLE_SEC)
    последний_досыл = time.time()
    while True:
                                                                             
        if time.time() - последний_досыл > RESEND_EVERY_SEC:
            try:
                дослать_незавершённые(cfg)
            except ПовреждённаяИстория as e:
                print("История операций повреждена - помощник остановлен до разбора:", e)
                sys.exit(4)
            последний_досыл = time.time()
        отв = запрос(cfg, "/api/v1/desktop/pull", {"install_id": cfg["install_id"]}, cfg.get("agent_secret", ""))
        if not отв.get("ok"):
            time.sleep(POLL_IDLE_SEC * 2)
            continue
        cmd = отв.get("command")
        if not cmd:
            time.sleep(POLL_IDLE_SEC)
            continue
        try:
            обработать(cfg, cmd)
        except ПовреждённаяИстория as e:
            print("История операций повреждена - помощник остановлен до разбора:", e)
            журнал("история повреждена во время работы: %s - остановка" % e)
            sys.exit(4)

def _занять_старый_замок(путь):
    try:
        fh = open(путь, "a+")
    except OSError:
        return None                             
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fh                                       
    except OSError:
        try:
            fh.close()
        except OSError:
            pass
        return None                          

def миграция_раскладки() -> bool:
    if _защита_файла is not None:
        return True         
    корень = ЗДЕСЬ
    старый_lock = os.path.join(корень, "helper.lock")
    пары = [
        (os.path.join(корень, "history.json"), HISTORY),
        (os.path.join(корень, "history.legacy.json"), HISTORY_LEGACY),
    ]
    старый_cfg = os.path.join(корень, "config.json")
    есть_что = (any(os.path.exists(с) and os.path.abspath(с) != os.path.abspath(н) for с, н in пары)
                or (os.path.exists(старый_cfg) and os.path.abspath(старый_cfg) != os.path.abspath(CONFIG))
                or (os.path.exists(старый_lock) and os.path.abspath(старый_lock) != os.path.abspath(LOCK)))
    if not есть_что:
        return True
    держатель = _занять_старый_замок(старый_lock)
    if держатель is None:
        журнал("переезд раскладки: старый помощник ещё работает (замок занят) - отказ")
        print("ОТКАЗ: похоже, работает СТАРАЯ версия помощника из этой папки.")
        print("Остановите её (закройте окно), затем запустите снова.")
        return False
    try:
                                                                                         
        есть_оба_cfg = (os.path.exists(старый_cfg) and os.path.abspath(старый_cfg) != os.path.abspath(CONFIG)
                        and os.path.exists(CONFIG))
        if есть_оба_cfg:
            ст = _чит(старый_cfg); нов = _чит(CONFIG)
            if (ст.get("token"), ст.get("base_url")) != (нов.get("token"), нов.get("base_url")):
                журнал("переезд раскладки: старый и новый config.json РАЗНЫЕ - отказ до изменений")
                print("ОТКАЗ: в корне и в config\\ РАЗНЫЕ настройки (ключ/адрес).")
                print("Оставьте одну актуальную конфигурацию, вторую уберите, затем запустите снова.")
                return False
                                                                                        
        try:
            if os.path.exists(старый_cfg) and os.path.abspath(старый_cfg) != os.path.abspath(CONFIG):
                if not os.path.exists(CONFIG):
                    shutil.move(старый_cfg, CONFIG)
                    журнал("переезд раскладки: config.json -> config\\")
                else:
                    os.remove(старый_cfg)
                    журнал("переезд раскладки: старый config.json удалён (ключ уже в config\\)")
        except OSError as e:
            журнал("переезд раскладки: не удалось вывести старый config.json (%s) - отказ, история НЕ тронута" % str(e)[:80])
            print("ОТКАЗ: не удалось убрать старый config.json из корня. История не тронута,")
            print("повтора нет. Проверьте права на файл и запустите снова.")
            return False                                                                        
        for старый, новый in пары:                                                                
            if not os.path.exists(старый) or os.path.abspath(старый) == os.path.abspath(новый):
                continue
            if os.path.exists(новый):
                журнал("переезд раскладки: есть и старая, и новая %s - отказ до разбора" % os.path.basename(новый))
                print("ОТКАЗ: найдены ДВЕ истории операций - старая (в корне) и новая (в runtime\\).")
                print("Оставьте одну актуальную, вторую удалите, затем запустите снова.")
                return False
            try:
                shutil.move(старый, новый)
                журнал("переезд раскладки: %s -> runtime\\" % os.path.basename(старый))
            except OSError as e:
                журнал("переезд раскладки: ошибка с %s (%s) - отказ" % (os.path.basename(старый), str(e)[:80]))
                return False                                                                 
    finally:
        if держатель is not None:
            try:
                держатель.close()                                     
            except OSError:
                pass
                                                                                      
    for имя in ("helper.lock", "helper.pid"):
        try:
            p = os.path.join(корень, имя)
            if os.path.exists(p) and os.path.abspath(p) != os.path.abspath(os.path.join(RUNTIME_DIR, имя)):
                os.remove(p)
        except OSError:
            pass
    return True

def _pid_метка() -> str:
    pid = os.getpid()
    if os.name != "nt":
        return str(pid)
    try:
        from ctypes import wintypes
        k = ctypes.windll.kernel32
        creation = wintypes.FILETIME(); exitt = wintypes.FILETIME()
        kern = wintypes.FILETIME(); user = wintypes.FILETIME()
        if k.GetProcessTimes(k.GetCurrentProcess(), ctypes.byref(creation),
                             ctypes.byref(exitt), ctypes.byref(kern), ctypes.byref(user)):
            ft = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
            return "%d\n%d" % (pid, ft)
    except Exception:                
        pass
    return str(pid)

def main() -> int:
    argparse.ArgumentParser().parse_args()                                                           
    if запущен_админом():
        print("ОТКАЗ: помощник запущен с правами администратора. Перезапустите под обычным пользователем.")
        журнал("запуск с высокими правами отклонён")
        return 3
    if not миграция_раскладки():                                                   
        return 8
    if not взять_замок():
        print("ОТКАЗ: %s" % (_причина_отказа_замка or "не удалось взять helper.lock"))
        return 5
    if not защитить_окружение():                                                         
        print("ОТКАЗ: не удалось закрыть доступ к файлам помощника только своей учёткой.")
        print("Ключ в config.json мог быть доступен другим - подробности в helper.log.")
        журнал("защита окружения не удалась - старт отклонён")
        return 6
    try:
        переход_ок = миграция_истории()
    except ПовреждённаяИстория as e:
        print("История операций повреждена - помощник остановлен до разбора:", e)
        return 4
    if not переход_ок:
        print("ОТКАЗ: история прежнего формата содержит ВЫПОЛНЕННЫЕ операции.")
        print("После смены формата идентификатора их повтор не распознаётся автоматически,")
        print("а по истории нельзя доказать, что они относятся к другому ключу.")
        print("Нужно РУЧНОЕ сведение: убедиться, что результаты этих операций доставлены,")
        print("затем заархивировать старую историю (обратитесь к разработчику).")
        print("Перевыпуск ключа сам по себе НЕ снимает запрет; удалять history.json нельзя -")
        print("это снимет защиту от повторного исполнения.")
        журнал("переходный запрет истории прежнего формата - старт отклонён")
        return 7
    cfg = первичная_настройка()
    if not cfg.get("agent_secret"):
        print("Регистрация не удалась - смотрите ответ выше и helper.log.")
        return 1
    try:
        открытьpid = os.open(PIDFILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(открытьpid, "w") as f:
            f.write(_pid_метка())
        защитить_файл(PIDFILE)
    except OSError:
        pass
                                                                                    
    установить_обработчик_закрытия(cfg)
    try:
        if ждать_подтверждения(cfg):
            цикл(cfg)
    finally:
        _финал(cfg)                                                                    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nОстановлено.")
