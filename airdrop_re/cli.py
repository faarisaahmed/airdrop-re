"""`airdrop` command line: receive, send, list, sniff."""
import argparse
import platform
import socket
import sys

from . import __version__


def preflight():
    if platform.system() != "Darwin":
        sys.exit("airdrop-re currently needs macOS (it uses the Mac's awdl0 interface). Linux support is planned.")
    try:
        socket.if_nametoindex("awdl0")
    except OSError:
        sys.exit("No awdl0 interface found. Is Wi-Fi turned on?")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="airdrop", description="Open-source AirDrop for your Mac's terminal.")
    ap.add_argument("--version", action="version", version=f"airdrop-re {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    from . import receiver, sender, sniff
    p = sub.add_parser("receive", help="show up in nearby share sheets and save incoming files")
    receiver.add_args(p)
    p.set_defaults(func=receiver.run, needs_awdl=True)

    p = sub.add_parser("send", help="send files to a nearby iPhone, iPad or Mac")
    sender.add_args(p)
    p.set_defaults(func=sender.run, needs_awdl=True)

    p = sub.add_parser("list", help="list nearby devices that can receive")
    sender.add_args(p, listing=True)
    p.set_defaults(func=sender.run, needs_awdl=True)

    p = sub.add_parser("sniff", help="decode nearby Apple Bluetooth (Continuity) advertisements")
    sniff.add_args(p)
    p.set_defaults(func=sniff.run, needs_awdl=False)

    args = ap.parse_args(argv)
    if args.needs_awdl:
        preflight()
    try:
        args.func(args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
