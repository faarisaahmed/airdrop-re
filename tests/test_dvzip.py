import io
import os
import subprocess
import tempfile

from airdrop_re import dvzip


def roundtrip(data: bytes):
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "f.bin")
        open(src, "wb").write(data)
        body = io.BytesIO()
        dvzip.encode_stream(dvzip.cpio_odc([("./f.bin", src)]), body)
        enc = os.path.join(d, "body.dvzip")
        open(enc, "wb").write(body.getvalue())
        dvzip.decode_file(enc, os.path.join(d, "out.cpio"))
        os.mkdir(os.path.join(d, "x"))
        subprocess.run(["tar", "-xf", os.path.join(d, "out.cpio"), "-C", os.path.join(d, "x")], check=True)
        return open(os.path.join(d, "x", "f.bin"), "rb").read()


def test_compressible():
    data = b"hello airdrop " * 50_000
    assert roundtrip(data) == data


def test_incompressible_uses_raw_blocks():
    data = os.urandom(400_000)
    assert roundtrip(data) == data


def test_raw_flag_parsing():
    # one raw block (bit 31 set) of 3 bytes
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "b")
        open(p, "wb").write(b"\x80\x00\x00\x03abc")
        out = os.path.join(d, "o")
        assert dvzip.decode_file(p, out) == (1, 1, 3)
        assert open(out, "rb").read() == b"abc"
