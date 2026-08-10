# -*- coding: utf-8 -*-
"""Локальный TLS-прокси для onecdatalink на старых Windows/1С (без TLS 1.2).

Слушает plain-TCP на 127.0.0.1:8080 и туннелирует всё в TLS 1.2/1.3 к
api.onecdatalink.ru:443. 1С-обработка (сборка для старых 1С через прокси) ходит
на http://127.0.0.1:8080 - обычным HTTP, без TLS. Свой современный OpenSSL
(внутри Python 3.8) делает TLS сам, в обход старой системы.

Собирается в один .exe (PyInstaller на Python 3.8 - последняя версия под
Windows 7 / Server 2008 R2). Пишет подробный лог рядом с .exe и делает само-тест
соединения при старте, чтобы сразу видеть, работает ли TLS до сервера.

Настройки можно переопределить файлом onecdatalink-proxy.ini рядом с .exe:
    [proxy]
    listen_host = 127.0.0.1
    listen_port = 8080
    target_host = api.onecdatalink.ru
    target_port = 443
    verify = true       ; false -> проверку цепочки выключить (небезопасно,
                        ;          только для разовой диагностики)
"""
import socket
import ssl
import sys
import os
import threading
import tempfile
import logging
from logging.handlers import RotatingFileHandler

APP_NAME = "onecdatalink-proxy"
BUFSIZE = 65536

# --- значения по умолчанию (можно переопределить в .ini рядом с .exe) ---
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8080
TARGET_HOST = "api.onecdatalink.ru"
TARGET_PORT = 443
# Проверка сертификата включена по умолчанию. Шифрование без проверки цепочки
# от подмены не защищает: перехватчик встает посередине, забирает ключ доступа
# и может подсунуть базе поддельную команду. Выключается только вручную в .ini
# и только для разовой диагностики.
VERIFY_CERT = True


def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def load_ini():
    """Необязательный onecdatalink-proxy.ini рядом с .exe."""
    global LISTEN_HOST, LISTEN_PORT, TARGET_HOST, TARGET_PORT, VERIFY_CERT
    path = os.path.join(base_dir(), APP_NAME + ".ini")
    if not os.path.exists(path):
        return None
    try:
        import configparser
        cp = configparser.ConfigParser()
        cp.read(path, encoding="utf-8")
        s = cp["proxy"]
        LISTEN_HOST = s.get("listen_host", LISTEN_HOST).strip()
        LISTEN_PORT = int(s.get("listen_port", str(LISTEN_PORT)))
        TARGET_HOST = s.get("target_host", TARGET_HOST).strip()
        TARGET_PORT = int(s.get("target_port", str(TARGET_PORT)))
        VERIFY_CERT = s.get("verify", "true").strip().lower() in ("1", "true", "yes", "on")
        return path
    except Exception as e:  # noqa
        return "ERROR:" + repr(e)


def setup_logging():
    log = logging.getLogger(APP_NAME)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    chosen = None
    for d in (base_dir(), tempfile.gettempdir()):
        try:
            p = os.path.join(d, APP_NAME + ".log")
            h = RotatingFileHandler(p, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
            h.setFormatter(fmt)
            log.addHandler(h)
            chosen = p
            break
        except Exception:
            continue
    if sys.stdout is not None:
        try:
            sh = logging.StreamHandler(sys.stdout)
            sh.setFormatter(fmt)
            log.addHandler(sh)
        except Exception:
            pass
    log.log_path = chosen
    return log


log = setup_logging()


def make_context():
    ctx = ssl.create_default_context()
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    if VERIFY_CERT:
        try:
            import certifi
            ctx.load_verify_locations(certifi.where())
            log.info("cert verification: ON (certifi %s)", certifi.where())
        except Exception as e:
            log.warning("certifi недоступен, проверка по системному хранилищу: %s", e)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        log.warning("cert verification: OFF - канал шифруется, но подмену сервера "
                    "распознать нельзя. Так работать постоянно нельзя: верните "
                    "verify = true в onecdatalink-proxy.ini.")
    return ctx


def selftest(ctx):
    """Пробное TLS-соединение к серверу — сразу видно, работает ли TLS."""
    try:
        raw = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=20)
        s = ctx.wrap_socket(raw, server_hostname=TARGET_HOST)
        ver, cipher = s.version(), s.cipher()
        req = ("GET /healthz HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % TARGET_HOST)
        s.sendall(req.encode("ascii"))
        data = s.recv(4096)
        try:
            s.close()
        except Exception:
            pass
        first = data.split(b"\r\n", 1)[0].decode("latin1", "replace") if data else "(пусто)"
        log.info("SELFTEST OK: TLS=%s cipher=%s | ответ сервера: %s", ver, cipher[0] if cipher else "?", first)
        return True
    except Exception as e:
        log.error("SELFTEST FAILED (TLS до сервера не поднялся): %r", e)
        return False


def recv_until(sock, marker, limit=1_000_000):
    """Читает из сокета, пока не встретит marker (или limit/EOF). Возвращает буфер."""
    buf = b""
    while marker not in buf:
        chunk = sock.recv(BUFSIZE)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            break
    return buf


def read_http_request(client, cid):
    """Читает HTTP-запрос от 1С: строка + заголовки + тело (по Content-Length)."""
    buf = recv_until(client, b"\r\n\r\n")
    if b"\r\n\r\n" not in buf:
        return None
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request_line = lines[0]
    content_length = 0
    expect_continue = False
    for h in lines[1:]:
        hl = h.lower()
        if hl.startswith(b"content-length:"):
            try:
                content_length = int(h.split(b":", 1)[1].strip())
            except Exception:
                content_length = 0
        elif hl.startswith(b"expect:") and b"100-continue" in hl:
            expect_continue = True
    # старый клиент может ждать "100 Continue" перед отправкой тела
    if expect_continue:
        try:
            client.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        except Exception:
            pass
    body = rest
    while len(body) < content_length:
        chunk = client.recv(BUFSIZE)
        if not chunk:
            break
        body += chunk
    return request_line, lines[1:], body


def rebuild_request(request_line, headers, body, target_host):
    """Переписывает Host на реальный хост моста и форсирует Connection: close."""
    out = [request_line]
    for h in headers:
        hl = h.lower()
        if hl.startswith(b"host:") or hl.startswith(b"connection:") or hl.startswith(b"proxy-connection:") \
                or (hl.startswith(b"expect:") and b"100-continue" in hl):
            continue
        out.append(h)
    out.append(b"Host: " + target_host.encode("ascii"))
    out.append(b"Connection: close")
    return b"\r\n".join(out) + b"\r\n\r\n" + body


def handle(client, addr, ctx, cid):
    client.settimeout(120)
    server = None
    try:
        parsed = read_http_request(client, cid)
        if parsed is None:
            log.info("[%s] клиент %s закрылся без запроса", cid, addr)
            return
        request_line, headers, body = parsed
        log.info("[%s] запрос от %s: %s (тело %d б)", cid, addr,
                 request_line.decode("latin1", "replace"), len(body))
        req = rebuild_request(request_line, headers, body, TARGET_HOST)

        raw = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=30)
        server = ctx.wrap_socket(raw, server_hostname=TARGET_HOST)
        server.settimeout(120)
        server.sendall(req)

        # Ответ читаем целиком до закрытия (мы форсировали Connection: close),
        # сразу отдавая байты клиенту.
        total = 0
        first_line = b""
        while True:
            try:
                chunk = server.recv(BUFSIZE)
            except socket.timeout:
                log.error("[%s] таймаут ожидания ответа сервера", cid)
                break
            if not chunk:
                break
            if not first_line and b"\r\n" in (first_line + chunk):
                first_line = (first_line + chunk).split(b"\r\n", 1)[0]
            try:
                client.sendall(chunk)
            except Exception as e:
                log.info("[%s] клиент отвалился при отдаче ответа: %r", cid, e)
                break
            total += len(chunk)
        log.info("[%s] ответ сервера: %s | %d байт | TLS=%s", cid,
                 first_line.decode("latin1", "replace") or "(пусто)", total, server.version())
    except Exception as e:
        log.error("[%s] ошибка обработки: %r", cid, e)
    finally:
        for s in (server, client):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass


def main():
    ini = load_ini()
    ctx = make_context()
    log.info("================ %s ================", APP_NAME)
    log.info("слушаю http://%s:%s  ->  TLS https://%s:%s", LISTEN_HOST, LISTEN_PORT, TARGET_HOST, TARGET_PORT)
    log.info("лог-файл: %s", getattr(log, "log_path", "n/a"))
    if ini:
        log.info(".ini: %s", ini)
    selftest(ctx)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((LISTEN_HOST, LISTEN_PORT))
        srv.listen(64)
    except Exception as e:
        log.error("НЕ удалось занять %s:%s: %r (порт занят? уже запущена копия?)", LISTEN_HOST, LISTEN_PORT, e)
        return 1
    log.info("готов, жду подключения 1С на %s:%s", LISTEN_HOST, LISTEN_PORT)

    cid = 0
    while True:
        try:
            client, addr = srv.accept()
        except Exception as e:
            log.error("ошибка accept: %r", e)
            continue
        cid += 1
        threading.Thread(target=handle, args=(client, addr, ctx, cid), daemon=True).start()


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        pass
    except Exception as e:  # noqa
        log.exception("ФАТАЛЬНО: %r", e)
        sys.exit(2)
