"""AirDrop receiver: `airdrop receive`.

Advertises `_airdrop._tcp` on awdl0, runs an HTTPS server, and answers the
sender's /Discover, /Ask and /Upload requests. Received files land in
~/Downloads/AirDrop-RE; with --verbose every request is also printed, and
each session's raw requests are kept under ~/.airdrop-re/sessions.
"""
import datetime
import json
import os
import plistlib
import secrets
import socket
import ssl
import subprocess
import sys
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import dvzip
from .bonjour import HostRecord, Registration

STATE = os.path.expanduser("~/.airdrop-re")
CERT_DIR = os.path.join(STATE, "certs")
DEFAULT_OUT = os.path.expanduser("~/Downloads/AirDrop-RE")

C = {"dim": "\033[90m", "b": "\033[1m", "g": "\033[32m", "y": "\033[33m",
     "m": "\033[35m", "c": "\033[36m", "r": "\033[31m", "0": "\033[0m"}


def log(msg, color=""):
    t = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{C['dim']}{t}{C['0']} {C.get(color, '')}{msg}{C['0']}", flush=True)


def ensure_cert(cert_dir, kind="rsa"):
    cert, key = os.path.join(cert_dir, f"cert-{kind}.pem"), os.path.join(cert_dir, f"key-{kind}.pem")
    if not os.path.exists(cert):
        os.makedirs(cert_dir, exist_ok=True)
        newkey = ["-newkey", "rsa:2048"] if kind == "rsa" else \
                 ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]
        subprocess.run(["openssl", "req", "-x509", *newkey, "-nodes", "-keyout", key,
                        "-out", cert, "-days", "3650", "-subj",
                        f"/CN={secrets.token_hex(16)}"], check=True, capture_output=True)
    return cert, key


def summarize(obj, depth=0, max_bytes=48):
    """Pretty-print a decoded plist, abbreviating large blobs."""
    pad = "  " * depth
    lines = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}:")
                lines += summarize(v, depth + 1, max_bytes)
            else:
                lines.append(f"{pad}{k}: {fmt_val(v, max_bytes)}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            lines.append(f"{pad}[{i}]")
            lines += summarize(v, depth + 1, max_bytes)
    else:
        lines.append(pad + fmt_val(obj, max_bytes))
    return lines


def fmt_val(v, max_bytes):
    if isinstance(v, bytes):
        head = v[:max_bytes].hex()
        return f"<{len(v)} bytes> {head}{'…' if len(v) > max_bytes else ''}"
    return repr(v)


def decode_cms(blob: bytes, workdir: str, stem: str):
    """SenderRecordData is a CMS-signed plist; let macOS unwrap it."""
    src = os.path.join(workdir, stem + ".p7")
    with open(src, "wb") as f:
        f.write(blob)
    r = subprocess.run(["security", "cms", "-D", "-i", src], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        return None
    try:
        return plistlib.loads(r.stdout)
    except Exception:
        return r.stdout


def unique_path(path):
    base, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(path):
        path = f"{base} ({i}){ext}"
        i += 1
    return path


def sniff_image_ext(b: bytes):
    if b[:3] == b"\xff\xd8\xff":
        return "jpg"
    if b[:12] == b"\x00\x00\x00\x0cjP  \r\n\x87\n" or b[:4] == b"\xff\x4f\xff\x51":
        return "jp2"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[4:8] == b"ftyp":
        return "heic"
    return "bin"


class AirDropHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AirDrop/1.0"
    sys_version = ""

    # ---- plumbing -------------------------------------------------------
    def log_message(self, fmt, *args):
        pass

    def iter_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                line = self.rfile.readline()
                if not line:
                    return
                size = int(line.split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return
                remaining = size
                while remaining:
                    chunk = self.rfile.read(min(remaining, 1 << 20))
                    if not chunk:
                        return
                    remaining -= len(chunk)
                    yield chunk
                self.rfile.readline()
        else:
            remaining = int(self.headers.get("Content-Length") or 0)
            while remaining:
                chunk = self.rfile.read(min(remaining, 1 << 20))
                if not chunk:
                    return
                remaining -= len(chunk)
                yield chunk

    def read_body(self):
        return b"".join(self.iter_body())

    def reply(self, code=200, plist=None):
        body = plistlib.dumps(plist, fmt=plistlib.FMT_BINARY) if plist is not None else b""
        self.send_response(code)
        if plist is not None:
            self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def save(self, stem, data: bytes):
        path = os.path.join(self.server.session_dir, stem)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def stem(self, name):
        self.server.counter += 1
        return f"{self.server.counter:03d}-{name}"

    def log_request_head(self):
        if not self.server.verbose:
            return
        peer = self.client_address[0]
        log(f"{self.command} {self.path}  from [{peer}]", "b")
        for k, v in self.headers.items():
            log(f"    {k}: {v}", "dim")

    def dump_plist(self, stem, raw):
        try:
            obj = plistlib.loads(raw)
        except Exception as e:
            log(f"    (body not a plist: {e}; {len(raw)} bytes saved)", "r")
            return None
        with open(os.path.join(self.server.session_dir, stem + ".txt"), "w") as f:
            f.write("\n".join(summarize(obj, max_bytes=10_000_000)))
        if self.server.verbose:
            for line in summarize(obj):
                log("    " + line, "c")
        return obj

    # ---- endpoints ------------------------------------------------------
    def do_POST(self):
        self.log_request_head()
        route = self.path.split("?")[0]
        handler = {"/Discover": self.discover, "/Ask": self.ask, "/Upload": self.upload}.get(route)
        try:
            (handler or self.unknown)()
        except Exception as e:
            log(f"    handler error: {e!r}", "r")
            raise

    def do_GET(self):
        self.log_request_head()
        self.unknown()

    def unknown(self):
        stem = self.stem(self.path.strip("/").replace("/", "_") or "root")
        raw = self.read_body()
        self.save(stem + ".bin", raw)
        self.dump_plist(stem, raw) if raw else None
        self.reply(200)

    def discover(self):
        stem = self.stem("discover")
        raw = self.read_body()
        self.save(stem + ".bin", raw)
        obj = self.dump_plist(stem, raw) or {}
        rec = obj.get("SenderRecordData")
        if isinstance(rec, bytes):
            inner = decode_cms(rec, self.server.session_dir, stem + "-sender-record")
            if isinstance(inner, dict) and self.server.verbose:
                log("    SenderRecordData (CMS unwrapped):", "m")
                for line in summarize(inner):
                    log("      " + line, "m")
                with open(os.path.join(self.server.session_dir, stem + "-sender-record.txt"), "w") as f:
                    f.write("\n".join(summarize(inner, max_bytes=10_000_000)))
            elif inner and self.server.verbose:
                log(f"    SenderRecordData CMS payload: {inner[:200]!r}", "m")
        caps = json.dumps({"Version": 1}).encode()
        self.reply(200, {
            "ReceiverComputerName": self.server.name,
            "ReceiverMediaCapabilities": caps,
        })
        log(f"discovered by a nearby device (answered as '{self.server.name}')", "dim")

    def ask(self):
        stem = self.stem("ask")
        raw = self.read_body()
        self.save(stem + ".bin", raw)
        obj = self.dump_plist(stem, raw) or {}
        icon = obj.get("FileIcon")
        if isinstance(icon, bytes):
            p = self.save(stem + "-icon." + sniff_image_ext(icon), icon)
            if self.server.verbose:
                log(f"    thumbnail saved: {p}", "y")
        sender = obj.get("SenderComputerName", "?")
        files = [f.get("FileName") for f in obj.get("Files", []) if isinstance(f, dict)]
        log(f"{sender} wants to send: {', '.join(files)}", "y")
        if self.server.reject:
            log("  -> rejecting (--reject)", "r")
            self.reply(403)
            return
        self.reply(200, {
            "ReceiverModelName": self.server.model,
            "ReceiverComputerName": self.server.name,
        })
        log("accepted", "g")

    def upload(self):
        stem = self.stem("upload")
        path = os.path.join(self.server.session_dir, stem + ".archive")
        total = 0
        t0 = datetime.datetime.now()
        with open(path, "wb") as f:
            for chunk in self.iter_body():
                f.write(chunk)
                total += len(chunk)
        secs = max((datetime.datetime.now() - t0).total_seconds(), 1e-6)
        if self.server.verbose:
            log(f"    received {total:,} bytes in {secs:.2f}s ({total * 8 / secs / 1e6:.0f} Mbit/s)", "y")
        out = os.path.join(self.server.session_dir, stem + "-files")
        os.makedirs(out, exist_ok=True)
        ctype = self.headers.get("Content-Type", "")
        archive = path
        if ctype == "application/x-dvzip":
            archive = path + ".cpio"
            try:
                blocks, raw, n = dvzip.decode_file(path, archive)
                if self.server.verbose:
                    log(f"    dvzip: {blocks} blocks ({raw} stored raw) -> {n:,} bytes of cpio", "dim")
            except Exception as e:
                log(f"    dvzip decode failed: {e!r}", "r")
        r = subprocess.run(["tar", "-xf", archive, "-C", out], capture_output=True, text=True)
        if r.returncode == 0:
            for dp, _, fns in os.walk(out):
                for fn in fns:
                    if fn.startswith("._"):
                        continue
                    p = os.path.join(dp, fn)
                    dest = unique_path(os.path.join(self.server.out_dir, fn))
                    shutil.copy2(p, dest)
                    log(f"saved {dest} ({os.path.getsize(p):,} bytes)", "g")
        else:
            log(f"    extract failed: {r.stderr.strip()}", "r")
        self.reply(200)


class AirDropServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def finish_request(self, request, client_address):
        # Handshake per connection (in the worker thread) so failures get logged
        # instead of being swallowed by socketserver's accept loop.
        peer = client_address[0]
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except Exception as e:
            log(f"TLS handshake with [{peer}] failed: {e!r}", "r")
            request.close()
            return
        if self.verbose:
            log(f"TLS {tls.version()} {tls.cipher()[0]} with [{peer}]", "dim")
        super().finish_request(tls, client_address)

    def server_bind(self):
        # awdl0 is a "restricted" interface on macOS: without SO_RECV_ANYIF the
        # kernel answers every incoming SYN with RST (seen in discovery2.pcap).
        SO_RECV_ANYIF = 0x1104
        self.socket.setsockopt(socket.SOL_SOCKET, SO_RECV_ANYIF, 1)
        super().server_bind()

    def handle_error(self, request, client_address):
        log(f"connection error from {client_address[0]}: {sys.exc_info()[1]!r}", "r")


def add_args(ap):
    ap.add_argument("--name", default=socket.gethostname().split(".")[0] + " (AirDrop-RE)",
                    help="name shown in the sender's share sheet")
    ap.add_argument("--out", default=DEFAULT_OUT, help="where received files are saved")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every request in plaintext")
    ap.add_argument("--model", default="MacBookPro17,1")
    ap.add_argument("--port", type=int, default=8771)
    ap.add_argument("--flags", default="1019", help="TXT flags value (our Mac advertises 1019)")
    ap.add_argument("--cert", choices=["rsa", "ec"], default="rsa", help="server certificate key type")
    ap.add_argument("--reject", action="store_true", help="decline every /Ask")
    ap.add_argument("--no-bonjour", action="store_true", help="skip mDNS (for local testing)")


def run(args):
    os.makedirs(args.out, exist_ok=True)
    cert, key = ensure_cert(CERT_DIR, args.cert)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    session_dir = os.path.join(STATE, "sessions", datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(session_dir, exist_ok=True)

    srv = AirDropServer(("::", args.port), AirDropHandler)
    ctx.keylog_filename = os.path.join(session_dir, "tls-keys.log")  # lets tshark decrypt our captures
    srv.ctx = ctx
    srv.name, srv.model, srv.reject = args.name, args.model, args.reject
    srv.session_dir, srv.counter = session_dir, 0
    srv.verbose, srv.out_dir = args.verbose, args.out

    reg = None
    if not args.no_bonjour:
        instance = secrets.token_hex(6)
        import uuid
        hostname = f"{uuid.uuid4()}.local."

        def host_status(err, name, addr):
            if not args.verbose and not err:
                return
            log(f"Bonjour: host {name} -> {addr} on awdl0" + (f" (error {err})" if err else ""),
                "r" if err else "g")
        host_rec = HostRecord(hostname, on_status=host_status)

        def status(err, name, domain):
            if err == 0 and args.verbose:
                log(f"Bonjour: registered {name}._airdrop._tcp.{domain} on awdl0", "g")
            elif err:
                log(f"Bonjour: registration error {err}", "r")
        reg = Registration(instance, "_airdrop._tcp", args.port, {"flags": args.flags}, on_status=status,
                           host=hostname)

    log(f"Receiving as '{args.name}'. Files go to {args.out}  (Ctrl-C to stop)", "b")
    log("On your iPhone: AirDrop -> 'Everyone for 10 Minutes', then share and pick this name.", "dim")
    if args.verbose:
        log(f"raw session log: {session_dir}", "dim")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if reg:
            reg.close()
            host_rec.close()
        srv.server_close()

