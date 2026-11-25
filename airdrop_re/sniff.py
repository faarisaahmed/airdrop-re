"""Bluetooth LE sniffer for Apple Continuity advertisements: `airdrop sniff`.

Prints a line whenever a nearby Apple device's Continuity payload changes,
so opening the share sheet, locking a phone, copying text, etc. show up.
"""
import asyncio
import json
import time

from .continuity import APPLE_COMPANY_ID, decode, identity_hashes

COLORS = {
    "AirDrop": "\033[1;35m", "Handoff": "\033[1;36m", "NearbyInfo": "\033[34m",
    "NearbyAction": "\033[1;33m", "ProximityPairing": "\033[32m", "FindMy": "\033[90m",
}
RESET = "\033[0m"


def add_args(ap):
    ap.add_argument("--only", nargs="*", help="message types to show, e.g. AirDrop Handoff")
    ap.add_argument("--min-rssi", type=int, default=-100, help="ignore weaker devices (e.g. -60 = close only)")
    ap.add_argument("--phone", nargs="*", default=[], help="your phone number(s), to match AirDrop hashes")
    ap.add_argument("--email", nargs="*", default=[], help="your Apple ID email(s), to match AirDrop hashes")
    ap.add_argument("--log", help="append every raw advertisement to this JSONL file")
    ap.add_argument("--seconds", type=float, default=0, help="stop after N seconds (0 = forever)")


def run(args):
    from bleak import BleakScanner

    known = identity_hashes(args.phone, args.email)
    last = {}          # device id -> last payload
    short_ids = {}     # device id -> short number for readability
    logf = open(args.log, "a") if args.log else None
    t0 = time.time()

    def on_adv(device, adv):
        data = adv.manufacturer_data.get(APPLE_COMPANY_ID)
        if data is None or adv.rssi < args.min_rssi:
            return
        if logf:
            logf.write(json.dumps({"t": time.time(), "id": device.address, "name": adv.local_name,
                                   "rssi": adv.rssi, "data": data.hex()}) + "\n")
            logf.flush()
        if last.get(device.address) == data:
            return
        last[device.address] = data
        msgs = decode(data, known)
        if args.only:
            msgs = [m for m in msgs if m[0] in args.only]
            if not msgs:
                return
        sid = short_ids.setdefault(device.address, len(short_ids) + 1)
        name = f" '{adv.local_name}'" if adv.local_name else ""
        stamp = f"{time.time() - t0:7.1f}s"
        for mtype, fields in msgs:
            c = COLORS.get(mtype, "")
            body = "  ".join(f"{k}={v}" for k, v in fields.items())
            print(f"{stamp}  dev#{sid:<3}{name} {adv.rssi:>4}dBm  {c}{mtype:<16}{RESET} {body}")

    async def run():
        async with BleakScanner(detection_callback=on_adv):
            print(f"Sniffing Apple Continuity adverts... (Ctrl-C to stop)  known hashes: {len(known)}")
            while not args.seconds or time.time() - t0 < args.seconds:
                await asyncio.sleep(0.5)
        print(f"\n{len(short_ids)} Apple devices seen.")

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print(f"\n{len(short_ids)} Apple devices seen.")

