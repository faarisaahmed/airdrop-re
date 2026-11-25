"""AirDrop sender: `airdrop send` / `airdrop list`.

The receiving iPhone must be unlocked with AirDrop on "Everyone for 10
Minutes". By default we open Finder's AirDrop window first so macOS
broadcasts the Bluetooth beacon that makes nearby iPhones start
advertising on AWDL (pass --no-wake to skip).
"""
import gzip
import http.client
import io
import os
import plistlib
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from . import bonjour, dvzip
from .receiver import CERT_DIR, ensure_cert, summarize

SO_RECV_ANYIF = 0x1104
AWDL = "awdl0"

UTIS = {
    ".png": "public.png", ".jpg": "public.jpeg", ".jpeg": "public.jpeg", ".heic": "public.heic",
    ".gif": "com.compuserve.gif", ".mp4": "public.mpeg-4", ".mov": "com.apple.quicktime-movie",
    ".txt": "public.plain-text", ".pdf": "com.adobe.pdf", ".zip": "public.zip-archive",
}


def say(msg, color=""):
    codes = {"g": "\033[32m", "y": "\033[33m", "r": "\033[31m", "c": "\033[36m", "b": "\033[1m", "dim": "\033[90m"}
    print(f"{codes.get(color, '')}{msg}\033[0m", flush=True)


class AWDLConnection(http.client.HTTPSConnection):
    """HTTPS over awdl0 with a scoped link-local address and SO_RECV_ANYIF."""

    def __init__(self, addr, port, ctx, timeout=10):
        super().__init__(addr, port, context=ctx, timeout=timeout)
        self._addr = addr

    def connect(self):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, SO_RECV_ANYIF, 1)
        s.settimeout(self.timeout)
        s.connect((self._addr, self.port, 0, socket.if_nametoindex(AWDL)))
        self.sock = self._context.wrap_socket(s, server_hostname=None)


def make_ctx(kind="rsa"):
    """kind: 'none' (no client cert), 'rsa' or 'ec' (self-signed client cert)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if kind != "none":
        cert, key = ensure_cert(CERT_DIR, kind)
        ctx.load_cert_chain(cert, key)
    return ctx


CERT_ORDER = ["none", "ec", "rsa"]


def post(conn, path, body=b"", headers=None, timeout=None):
    if timeout:
        conn.sock.settimeout(timeout) if conn.sock else None
        conn.timeout = timeout
    h = {"User-Agent": "AirDrop/1.0", "Accept": "*/*", "Content-Type": "application/octet-stream"}
    h.update(headers or {})
    conn.request("POST", path, body, h)
    r = conn.getresponse()
    data = r.read()
    return r.status, data


def find_receivers(seconds, skip_ports=()):
    out = []
    for name, dom in bonjour.browse(seconds=seconds):
        r = bonjour.resolve(name, domain=dom)
        if not r:
            continue
        host, port, txt = r
        if port in skip_ports:
            continue
        addr = bonjour.addr_v6(host)
        if addr:
            out.append({"instance": name, "host": host, "port": port, "txt": txt, "addr": addr})
    return out


def discover(ctx, rx):
    conn = AWDLConnection(rx["addr"], rx["port"], ctx, timeout=6)
    try:
        status, data = post(conn, "/Discover", plistlib.dumps({}, fmt=plistlib.FMT_BINARY))
    finally:
        conn.close()
    info = {}
    if data:
        try:
            info = plistlib.loads(data)
        except Exception:
            info = {"raw": data[:80]}
    return status, info


def thumbnail(path):
    """Small JPEG preview via sips, if it's an image or video sips understands."""
    tmp = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False).name
    r = subprocess.run(["sips", "-Z", "540", "-s", "format", "jpeg", path, "--out", tmp], capture_output=True)
    if r.returncode == 0 and os.path.getsize(tmp) > 0:
        data = open(tmp, "rb").read()
        os.unlink(tmp)
        return data
    return None


def add_args(ap, listing=False):
    if not listing:
        ap.add_argument("files", nargs="+")
        ap.add_argument("--to", required=True, help="part of the receiver's name, e.g. iPhone")
    ap.add_argument("--name", default=socket.gethostname().split(".")[0] + " (AirDrop-RE)", help="sender name shown on the iPhone")
    ap.add_argument("--format", choices=["dvzip", "cpio"], default="dvzip")
    ap.add_argument("--browse-seconds", type=float, default=6)
    ap.add_argument("--client-cert", choices=["auto", "none", "ec", "rsa"], default="auto",
                    help="TLS client cert to present; auto tries none, ec, rsa")
    ap.add_argument("--no-wake", action="store_true")
    ap.add_argument("--include-self", action="store_true", help="also list our own receiver (port 8771)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.set_defaults(listing=listing)


def run(args):
    if not args.listing and not all(os.path.isfile(p) for p in args.files):
        sys.exit("every argument must be an existing file")

    if not args.no_wake:
        say("waking AirDrop (opening Finder's AirDrop window so macOS sends the BLE beacon)…", "dim")
        subprocess.run(["open", "/System/Library/CoreServices/Finder.app/Contents/Applications/AirDrop.app"])
        time.sleep(2)

    skip = () if args.include_self else (8771,)
    say(f"browsing _airdrop._tcp on {AWDL} for {args.browse_seconds:.0f}s…", "dim")
    receivers = find_receivers(args.browse_seconds, skip)
    named = []
    kinds = CERT_ORDER if args.client_cert == "auto" else [args.client_cert]
    for rx in receivers:
        status = info = None
        for kind in kinds:
            try:
                status, info = discover(make_ctx(kind), rx)
                rx["ctx"] = make_ctx(kind)
                if args.verbose:
                    say(f"  {rx['instance']}: /Discover OK with client cert = {kind}", "g")
                break
            except Exception as e:
                if args.verbose:
                    say(f"  {rx['instance']}  [{rx['addr']}]:{rx['port']}  client cert={kind}: {e!r}", "r")
        if info is None:
            continue
        rx["name"] = info.get("ReceiverComputerName", "?")
        rx["discover"] = info
        if args.verbose:
            say(f"  {rx['name']!r:28} {rx['instance']}  [{rx['addr']}]:{rx['port']}  flags={rx['txt'].get('flags')}  HTTP {status}", "c")
            for line in summarize({k: v for k, v in info.items() if k != "ReceiverComputerName"}):
                say("      " + line, "dim")
        else:
            say(f"  • {rx['name']}", "c")
        named.append(rx)

    if not named:
        say("No one answered. Is the iPhone unlocked with AirDrop on 'Everyone for 10 Minutes'?", "y")
        sys.exit(1)
    if args.listing:
        return
    targets = [rx for rx in named if args.to.lower() in rx["name"].lower()]
    if not targets:
        sys.exit(f"no receiver matching {args.to!r}")
    rx = targets[0]

    paths = [os.path.abspath(p) for p in args.files]
    files_meta = [{
        "FileName": os.path.basename(p),
        "FileType": UTIS.get(os.path.splitext(p)[1].lower(), "public.data"),
        "FileBomPath": "./" + os.path.basename(p),
        "FileIsDirectory": False,
        "ConvertMediaFormats": False,
    } for p in paths]
    ask = {
        "SenderComputerName": args.name,
        "BundleID": "com.apple.finder",
        "SenderModelName": "MacBookPro17,1",
        "SenderID": secrets.token_hex(6),
        "ConvertMediaFormats": False,
        "Items": [],
        "Files": files_meta,
    }
    icon = thumbnail(paths[0])
    if icon:
        ask["FileIcon"] = icon

    conn = AWDLConnection(rx["addr"], rx["port"], rx["ctx"], timeout=120)
    say(f"Asking {rx['name']} to accept {', '.join(f['FileName'] for f in files_meta)}. Tap Accept on the iPhone.", "y")
    status, data = post(conn, "/Ask", plistlib.dumps(ask, fmt=plistlib.FMT_BINARY), timeout=120)
    if args.verbose:
        say(f"/Ask -> HTTP {status}", "g" if status == 200 else "r")
    if data and args.verbose:
        try:
            for line in summarize(plistlib.loads(data)):
                say("    " + line, "dim")
        except Exception:
            say(f"    {data[:200]!r}", "dim")
    if status != 200:
        sys.exit(f"Declined (HTTP {status}).")

    body = io.BytesIO()
    archive = [("./" + os.path.basename(p), p) for p in paths]
    if args.format == "dvzip":
        dvzip.encode_stream(dvzip.cpio_odc(archive), body)
        ctype = "application/x-dvzip"
    else:
        body.write(gzip.compress(b"".join(dvzip.cpio_odc(archive))))
        ctype = "application/x-cpio"
    payload = body.getvalue()
    total = sum(os.path.getsize(p) for p in paths)
    t0 = time.time()
    status, data = post(conn, "/Upload", payload, {"Content-Type": ctype, "TotalBytes": str(total)}, timeout=300)
    secs = time.time() - t0
    if status == 200:
        say(f"Sent {total:,} bytes in {secs:.1f}s.", "g")
    else:
        sys.exit(f"Upload failed (HTTP {status}).")
    conn.close()

