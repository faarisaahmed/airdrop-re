"""Minimal ctypes binding to Apple's dns_sd API (mDNSResponder).

We need DNSServiceRegister with kDNSServiceFlagsIncludeAWDL so the service is
advertised on the awdl0 interface -- the `dns-sd` CLI can't do that.
"""
import ctypes
import select
import socket
import threading

_lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")

kDNSServiceFlagsIncludeAWDL = 0x00100000
kDNSServiceErr_NoError = 0

RegisterReply = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32,
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p)

_lib.DNSServiceRegister.argtypes = [
    ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_uint32,
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_uint16, ctypes.c_uint16, ctypes.c_void_p, RegisterReply, ctypes.c_void_p]
_lib.DNSServiceRegister.restype = ctypes.c_int32
_lib.DNSServiceRefSockFD.argtypes = [ctypes.c_void_p]
_lib.DNSServiceRefSockFD.restype = ctypes.c_int
_lib.DNSServiceProcessResult.argtypes = [ctypes.c_void_p]
_lib.DNSServiceProcessResult.restype = ctypes.c_int32
_lib.DNSServiceRefDeallocate.argtypes = [ctypes.c_void_p]
_lib.DNSServiceRefDeallocate.restype = None


def txt_record(pairs: dict) -> bytes:
    out = b""
    for k, v in pairs.items():
        entry = f"{k}={v}".encode()
        out += bytes([len(entry)]) + entry
    return out


class Registration:
    def __init__(self, name, regtype, port, txt: dict, interface="awdl0", on_status=None, host=None):
        self.ref = ctypes.c_void_p()
        self._on_status = on_status or (lambda *a: None)

        def _cb(ref, flags, err, name, regtype, domain, ctx):
            self._on_status(err, name.decode() if name else None, domain.decode() if domain else None)
        self._cb = RegisterReply(_cb)  # keep a reference alive

        txt_bytes = txt_record(txt)
        self._txt = ctypes.create_string_buffer(txt_bytes, len(txt_bytes))
        err = _lib.DNSServiceRegister(
            ctypes.byref(self.ref), kDNSServiceFlagsIncludeAWDL,
            socket.if_nametoindex(interface), name.encode(), regtype.encode(),
            None, host.encode() if host else None, socket.htons(port), len(txt_bytes), self._txt, self._cb, None)
        if err != kDNSServiceErr_NoError:
            raise OSError(f"DNSServiceRegister failed: {err}")
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        fd = _lib.DNSServiceRefSockFD(self.ref)
        while not self._stop:
            r, _, _ = select.select([fd], [], [], 0.5)
            if r:
                _lib.DNSServiceProcessResult(self.ref)

    def close(self):
        self._stop = True
        self._thread.join(timeout=1)
        _lib.DNSServiceRefDeallocate(self.ref)


# ---- host records (AAAA for a private hostname on awdl0) -------------------
kDNSServiceFlagsUnique = 0x20
kDNSServiceType_AAAA = 28
kDNSServiceClass_IN = 1

RegisterRecordReply = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32, ctypes.c_void_p)
_lib.DNSServiceCreateConnection.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
_lib.DNSServiceCreateConnection.restype = ctypes.c_int32
_lib.DNSServiceRegisterRecord.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_uint32,
    ctypes.c_char_p, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_void_p,
    ctypes.c_uint32, RegisterRecordReply, ctypes.c_void_p]
_lib.DNSServiceRegisterRecord.restype = ctypes.c_int32
_lib.DNSServiceUpdateRecord.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_void_p, ctypes.c_uint32]
_lib.DNSServiceUpdateRecord.restype = ctypes.c_int32


def awdl_address(interface="awdl0"):
    """Current IPv6 link-local address of awdl0 (it rotates)."""
    import subprocess
    out = subprocess.run(["ifconfig", interface], capture_output=True, text=True).stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet6 fe80:"):
            return line.split()[1].split("%")[0]
    return None


class HostRecord:
    """Publishes <hostname> AAAA <awdl0 addr> on awdl0 and follows address rotation."""

    def __init__(self, hostname, interface="awdl0", on_status=None):
        self.hostname, self.interface = hostname, interface
        self._on_status = on_status or (lambda *a: None)
        self.conn = ctypes.c_void_p()
        err = _lib.DNSServiceCreateConnection(ctypes.byref(self.conn))
        if err:
            raise OSError(f"DNSServiceCreateConnection failed: {err}")

        def _cb(sd, rec, flags, err, ctx):
            self._on_status(err, self.hostname, self.addr)
        self._cb = RegisterRecordReply(_cb)
        self.rec = ctypes.c_void_p()
        self.addr = awdl_address(interface)
        if not self.addr:
            raise OSError(f"{interface} has no link-local address")
        rdata = socket.inet_pton(socket.AF_INET6, self.addr)
        self._rdata = ctypes.create_string_buffer(rdata, 16)
        err = _lib.DNSServiceRegisterRecord(
            self.conn, ctypes.byref(self.rec), kDNSServiceFlagsUnique | kDNSServiceFlagsIncludeAWDL,
            socket.if_nametoindex(interface), hostname.encode(), kDNSServiceType_AAAA,
            kDNSServiceClass_IN, 16, self._rdata, 120, self._cb, None)
        if err:
            raise OSError(f"DNSServiceRegisterRecord failed: {err}")
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()
        threading.Thread(target=self._watch, daemon=True).start()

    def _loop(self):
        fd = _lib.DNSServiceRefSockFD(self.conn)
        while not self._stop:
            r, _, _ = select.select([fd], [], [], 0.5)
            if r:
                _lib.DNSServiceProcessResult(self.conn)

    def _watch(self):
        import time
        while not self._stop:
            time.sleep(2)
            new = awdl_address(self.interface)
            if new and new != self.addr:
                self.addr = new
                self._rdata = ctypes.create_string_buffer(socket.inet_pton(socket.AF_INET6, new), 16)
                err = _lib.DNSServiceUpdateRecord(self.conn, self.rec, 0, 16, self._rdata, 120)
                self._on_status(err, self.hostname, new)

    def close(self):
        self._stop = True
        _lib.DNSServiceRefDeallocate(self.conn)


# ---- browsing / resolving (for the sender) ---------------------------------
kDNSServiceProtocol_IPv6 = 2
kDNSServiceFlagsAdd = 0x2

BrowseReply = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int32,
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p)
ResolveReply = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int32,
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint16, ctypes.c_uint16,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_void_p)
AddrInfoReply = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int32,
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32, ctypes.c_void_p)

_lib.DNSServiceBrowse.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_uint32,
                                  ctypes.c_char_p, ctypes.c_char_p, BrowseReply, ctypes.c_void_p]
_lib.DNSServiceBrowse.restype = ctypes.c_int32
_lib.DNSServiceResolve.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_uint32,
                                   ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ResolveReply, ctypes.c_void_p]
_lib.DNSServiceResolve.restype = ctypes.c_int32
_lib.DNSServiceGetAddrInfo.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_uint32,
                                       ctypes.c_uint32, ctypes.c_char_p, AddrInfoReply, ctypes.c_void_p]
_lib.DNSServiceGetAddrInfo.restype = ctypes.c_int32


def _pump(ref, seconds, done=lambda: False):
    import time
    fd = _lib.DNSServiceRefSockFD(ref)
    end = time.time() + seconds
    while time.time() < end and not done():
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            _lib.DNSServiceProcessResult(ref)


def parse_txt(ptr, length):
    raw = bytes(ptr[:length]) if length else b""
    out, i = {}, 0
    while i < len(raw):
        n = raw[i]
        entry = raw[i + 1:i + 1 + n].decode(errors="replace")
        k, _, v = entry.partition("=")
        out[k] = v
        i += 1 + n
    return out


def browse(regtype="_airdrop._tcp", seconds=4.0, interface="awdl0"):
    """Return [(instance_name, domain)] seen on the interface (AWDL included)."""
    found = {}

    def cb(ref, flags, ifi, err, name, rt, domain, ctx):
        if err == 0 and flags & kDNSServiceFlagsAdd:
            found[name.decode()] = domain.decode()
    cbf = BrowseReply(cb)
    ref = ctypes.c_void_p()
    err = _lib.DNSServiceBrowse(ctypes.byref(ref), kDNSServiceFlagsIncludeAWDL,
                                socket.if_nametoindex(interface), regtype.encode(), None, cbf, None)
    if err:
        raise OSError(f"DNSServiceBrowse failed: {err}")
    _pump(ref, seconds)
    _lib.DNSServiceRefDeallocate(ref)
    return list(found.items())


def resolve(name, regtype="_airdrop._tcp", domain="local.", interface="awdl0", seconds=3.0):
    """Resolve an instance to (hosttarget, port, txt dict) or None."""
    res = {}

    def cb(ref, flags, ifi, err, fullname, host, port, txtlen, txt, ctx):
        if err == 0:
            res["v"] = (host.decode(), socket.ntohs(port), parse_txt(txt, txtlen))
    cbf = ResolveReply(cb)
    ref = ctypes.c_void_p()
    err = _lib.DNSServiceResolve(ctypes.byref(ref), kDNSServiceFlagsIncludeAWDL,
                                 socket.if_nametoindex(interface), name.encode(),
                                 regtype.encode(), domain.encode(), cbf, None)
    if err:
        return None
    _pump(ref, seconds, lambda: "v" in res)
    _lib.DNSServiceRefDeallocate(ref)
    return res.get("v")


def addr_v6(host, interface="awdl0", seconds=3.0):
    """Resolve a hostname to an IPv6 address string on the interface."""
    res = {}

    def cb(ref, flags, ifi, err, hostname, sa, ttl, ctx):
        if err == 0 and sa and sa[1] == socket.AF_INET6:
            res["v"] = socket.inet_ntop(socket.AF_INET6, bytes(sa[8:24]))
    cbf = AddrInfoReply(cb)
    ref = ctypes.c_void_p()
    err = _lib.DNSServiceGetAddrInfo(ctypes.byref(ref), kDNSServiceFlagsIncludeAWDL,
                                     socket.if_nametoindex(interface), kDNSServiceProtocol_IPv6,
                                     host.encode(), cbf, None)
    if err:
        return None
    _pump(ref, seconds, lambda: "v" in res)
    _lib.DNSServiceRefDeallocate(ref)
    return res.get("v")
