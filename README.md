# airdrop-re

An independent, open-source implementation of the **AirDrop** protocol, written from scratch in Python.

Receive files from an iPhone, and send files to one, from your Mac's terminal. It uses our own code for discovery, TLS and the transfer format, and doesn't go through Apple's AirDrop service. Everything we learned along the way is documented in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

```
$ airdrop receive
Receiving as 'my-mac (AirDrop-RE)'. Files go to ~/Downloads/AirDrop-RE  (Ctrl-C to stop)
iPhone wants to send: IMG_0001.PNG
accepted
saved ~/Downloads/AirDrop-RE/IMG_0001.PNG (2,355,389 bytes)

$ airdrop send --to iPhone notes.txt
  • iPhone
Asking iPhone to accept notes.txt. Tap Accept on the iPhone.
Sent 1,204 bytes in 1.1s.
```

> **Status:** early research project. Tested with an M1 Mac on macOS 13.5 and an iPhone 11 Pro Max on iOS 18.4, in AirDrop's *Everyone for 10 Minutes* mode. *Contacts Only* mode needs Apple-signed identity certificates and isn't supported.

## Setup

Requirements: a Mac with Wi-Fi turned on and Python 3.9 or newer.

```
git clone https://github.com/faarisaahmed/airdrop-re.git
cd airdrop-re
./setup.sh
```

This creates a virtualenv and links an `airdrop` command into `~/.local/bin`.

## Usage

On the iPhone, open **Control Center → AirDrop → Everyone for 10 Minutes**. AirDrop on the Mac also needs to be on (Contacts Only or Everyone), because macOS only keeps the AirDrop Wi-Fi link up when it is.

| Command | What it does |
|---|---|
| `airdrop receive` | Shows up as a separate device in nearby share sheets and saves incoming files to `~/Downloads/AirDrop-RE` |
| `airdrop list` | Lists nearby devices that can receive |
| `airdrop send --to <name> <files…>` | Sends files to the first nearby device whose name contains `<name>` |
| `airdrop sniff` | Decodes nearby Apple Bluetooth LE (Continuity) advertisements live |

Useful flags:
- `-v` / `--verbose` prints every protocol message in plaintext.
- `receive --name "Kitchen Mac"` sets the name senders see.
- `receive --out DIR` changes where files are saved.
- `send --no-wake` skips opening Finder's AirDrop window.

## How it works

AirDrop is a stack of four layers:

1. **Bluetooth LE beacons.** A sender broadcasts a short Apple "Continuity" advertisement that wakes nearby receivers.
2. **AWDL (Apple Wireless Direct Link).** A peer-to-peer Wi-Fi link that hops channels so devices can talk directly while staying on their normal Wi-Fi. macOS exposes it as `awdl0`.
3. **Bonjour (mDNS/DNS-SD) over AWDL.** Receivers advertise `_airdrop._tcp`.
4. **HTTPS (TLS 1.3).** The sender calls `POST /Discover`, then `/Ask` (the receiver shows Accept/Decline), then `/Upload` with the files.

On a Mac, macOS runs layers 1 and 2 for us. This project implements layers 3 and 4 from scratch:
- `airdrop_re/bonjour.py` is a ctypes binding to `dns_sd` that registers services and a private hostname on `awdl0`.
- `airdrop_re/receiver.py` is our own TLS server.
- `airdrop_re/sender.py` is our own client.
- `airdrop_re/dvzip.py` encodes and decodes the `application/x-dvzip` transfer format current iOS uses, which isn't documented in the earlier research we found.

## Roadmap

- [x] Bluetooth LE Continuity sniffer
- [x] Receive from iPhone (iOS 18)
- [x] Send to iPhone (iOS 18)
- [x] Decode the `x-dvzip` upload format
- [ ] Decode the TXT `flags` capability bitfield
- [ ] Throughput: our receiver gets ~20 Mbit/s vs ~185 Mbit/s between Apple devices
- [ ] Linux, starting with a Raspberry Pi: our own AWDL link layer and BLE beacon
- [ ] Windows

## Prior work

Earlier academic work on AirDrop and AWDL by the [Open Wireless Link](https://owlink.org) project (TU Darmstadt SEEMOO lab), including OpenDrop and OWL, mapped much of this protocol in 2019. iOS has changed since then: TLS 1.3, a new upload format, and different certificate handling. This project documents the current behavior.

## Legal

This is independent interoperability research and is not affiliated with or endorsed by Apple Inc. "AirDrop", "iPhone" and "Mac" are trademarks of Apple Inc. Only use it with devices you own or have permission to use.

## License

MIT
