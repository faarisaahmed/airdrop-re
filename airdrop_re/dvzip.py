"""Decoder for AirDrop's `application/x-dvzip` upload body (seen on iOS 18.4).

Reverse-engineered from a captured iPhone -> receiver transfer of a PNG:

    body   := block*
    block  := u32be header, payload[header & 0x7fffffff]
    header bit 31 set   -> payload is stored raw
    header bit 31 clear -> payload is a zlib stream
    each block decodes to <= 128 KiB (131072) of output

The concatenated output is an odc ("070707") cpio archive containing the
files plus AppleDouble `._name` metadata entries.
"""
import struct
import zlib

RAW_FLAG = 0x80000000


def iter_blocks(f):
    """Yield decoded chunks from a file-like object positioned at the body start."""
    while True:
        hdr = f.read(4)
        if not hdr:
            return
        if len(hdr) < 4:
            raise ValueError("truncated block header")
        (h,) = struct.unpack(">I", hdr)
        n = h & ~RAW_FLAG
        payload = f.read(n)
        if len(payload) < n:
            raise ValueError(f"truncated block: wanted {n}, got {len(payload)}")
        yield payload if h & RAW_FLAG else zlib.decompress(payload)


def decode_file(src_path, dst_path):
    """Decode a saved x-dvzip body into a cpio file. Returns (blocks, raw_blocks, out_bytes)."""
    blocks = raw = total = 0
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        while True:
            hdr = src.read(4)
            if not hdr:
                break
            (h,) = struct.unpack(">I", hdr)
            n = h & ~RAW_FLAG
            payload = src.read(n)
            chunk = payload if h & RAW_FLAG else zlib.decompress(payload)
            raw += bool(h & RAW_FLAG)
            blocks += 1
            total += len(chunk)
            dst.write(chunk)
    return blocks, raw, total


# ---- encoding (for the sender) ---------------------------------------------
BLOCK = 128 * 1024


def encode_stream(data_iter, out):
    """Write x-dvzip blocks for a stream of bytes. Stores raw when zlib doesn't help."""
    buf = bytearray()

    def flush(chunk):
        z = zlib.compress(chunk)
        if len(z) < len(chunk):
            out.write(struct.pack(">I", len(z)) + z)
        else:
            out.write(struct.pack(">I", len(chunk) | RAW_FLAG) + chunk)

    for data in data_iter:
        buf += data
        while len(buf) >= BLOCK:
            flush(bytes(buf[:BLOCK]))
            del buf[:BLOCK]
    if buf:
        flush(bytes(buf))


def cpio_odc(files):
    """Yield an odc cpio archive for [(archive_name, local_path)], like iOS builds it."""
    import os
    import time

    def header(name, mode, size, mtime, ino, nlink=1):
        nb = name.encode() + b"\0"
        h = (b"070707" + b"%06o" % 0 + b"%06o" % ino + b"%06o" % mode + b"%06o" % 501 +
             b"%06o" % 20 + b"%06o" % nlink + b"%06o" % 0 + b"%011o" % int(mtime) +
             b"%06o" % len(nb) + b"%011o" % size)
        return h + nb

    now = time.time()
    yield header(".", 0o040755, 0, now, 1, nlink=2)
    for i, (name, path) in enumerate(files, start=2):
        st = os.stat(path)
        yield header(name, 0o100644, st.st_size, st.st_mtime, i)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                yield chunk
    yield header("TRAILER!!!", 0, 0, 0, 0)
