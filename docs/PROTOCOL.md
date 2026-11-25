# AirDrop protocol notes

These are black-box observations from packet captures and from running our own receiver and sender. The test devices were an iPhone 11 Pro Max on iOS 18.4 and an M1 Mac on macOS 13.5, in "Everyone" mode. Anything marked **?** is a hypothesis.

## 1. Bluetooth LE (Continuity)

Apple devices advertise manufacturer data under company ID `0x004C`. The data is a sequence of TLVs: 1-byte type, 1-byte length, value. `airdrop_re/continuity.py` decodes them.

| Type | Name | Notes |
|---|---|---|
| `0x05` | AirDrop | 8 zero bytes, a version byte, then truncated 2-byte SHA-256 hashes of Apple ID, phone, email and email2 |
| `0x07` | Proximity Pairing | AirPods/Beats. Newer models don't match the older published layout |
| `0x09` | AirPlay Target | **Contains the receiver's LAN IPv4 address and port (7000) in cleartext**: `flags, seed?, ip[4], port[2]` |
| `0x0C` | Handoff | byte 0 = clipboard?; bytes 1–2 = **little-endian counter** that increments with each activity update; byte 3 = auth tag?; rest is encrypted |
| `0x0F` | Nearby Action | Wi-Fi password sharing, setup flows, etc. |
| `0x10` | Nearby Info | low nibble of byte 0 = activity level (screen on, locked, driving, call…) |
| `0x12` | Find My | |
| `0x16`, `0x1C` | unknown | `0x16` always appears alongside AirPlay Target |

## 2. AWDL addressing

- All AirDrop traffic is IPv6 link-local on `awdl0`.
- **The AWDL MAC and IPv6 address rotate.** We saw several different addresses from the same Mac within minutes.
- Receivers advertise under a **random UUID hostname** (`xxxxxxxx-xxxx-…-xxxxxxxxxxxx.local`) that exists only on AWDL, not the machine's normal `.local` name.
- The Bonjour instance name is 12 hex characters and also rotates.

## 3. Bonjour

- Service type `_airdrop._tcp`. Apple's receivers listen on TCP **8770**; any port works, since it's advertised in the SRV record.
- The TXT record contains `flags=<decimal>`. Observed values: `1019` (`0x3FB`) from a MacBook, `14335` (`0x37FF`) from an iPhone, `111611` (`0x1B3FB`) from a Mac mini. It's a capability bitfield; decoding it is still TODO.
- iPhones only start advertising and answering after they see a sender's BLE AirDrop beacon.

### macOS specifics for third-party code

- Register with `kDNSServiceFlagsIncludeAWDL` (`0x00100000`) on the `awdl0` interface index. The `dns-sd` CLI can't do this.
- Publish your own AAAA record for a private hostname with `DNSServiceRegisterRecord`, and update it when the awdl0 address rotates.
- **`awdl0` is a restricted interface.** Sockets need `setsockopt(SOL_SOCKET, SO_RECV_ANYIF /* 0x1104 */, 1)`. Without it, the kernel answers every incoming SYN with RST.

## 4. TLS

- **TLS 1.3** (`TLS_AES_128_GCM_SHA256` between Apple devices), x25519, GREASE, `compress_certificate`. Because it's TLS 1.3, the certificates are encrypted and passive observers can no longer see sender identity the way they could with TLS 1.2.
- Between Apple devices it's **mutual TLS**: the client sends roughly 2.8 KB of certificate data.
- **Receiver certificate (us acting as the server):** iOS 18.4 rejected a self-signed **EC P-256** certificate and accepted a self-signed **RSA-2048** one. One test each.
- **Sender certificate (us acting as the client):** a self-signed RSA client certificate was rejected with `certificate_unknown`. Presenting **no client certificate** worked, against both an iPhone and a Mac in Everyone mode.

## 5. HTTP exchange

All requests are `POST`, `User-Agent: AirDrop/1.0`. Request bodies use `Transfer-Encoding: chunked`. Plist bodies are binary plists.

### `/Discover`
- Sent on its own connection with `Connection: close`, often twice.
- Request: `{ SenderRecordData: <CMS blob> }`. The blob is about 3.8 KB of PKCS#7 signed data and unwraps with `security cms -D`. It contains `Version`, `altDsID`, `encDsID`, `ValidAsOf`, `SuggestValidDuration` (2,592,000 s = 30 days), `ValidatedEmailHashes`, `ValidatedPhoneHashes` (full SHA-256 hex).
- Response: `{ ReceiverComputerName, ReceiverMediaCapabilities, [ReceiverRecordData], [IsAirDropable] }`. `ReceiverMediaCapabilities` is UTF-8 JSON:
  - A minimal receiver sends `{"Version": 1}`.
  - Apple devices send `Version: 3` with a VideoToolbox codec table (HEVC profiles, Dolby Vision levels, ProRes, HDR flags). This is probably how senders decide whether to transcode HEIC or HEVC.

### `/Ask`
- Sent on a keep-alive connection that's then reused for `/Upload`. It blocks until the user taps Accept or Decline.
- Request keys seen from iOS 18.4: `TransferID {id}`, `TransferType`, `SenderRecordData`, `SenderID` (12 hex), `BundleID` (e.g. `com.apple.mobileslideshow`), `SenderComputerName`, `SenderModelName` (just `"iPhone"`, not the model identifier), `Items`, `ConvertMediaFormats`, `FileIcon` (thumbnail, **JPEG 2000**), and `Files[ {FileName, FileType (UTI), FileSize, FileBomPath, FileIsDirectory, ShouldConvertMediaFormats} ]`.
- A minimal accepted request needs only `SenderComputerName`, `BundleID`, `SenderModelName`, `SenderID`, `ConvertMediaFormats` and `Files`. `FileIcon` is optional.
- Response `200` = accepted. Body: `{ ReceiverComputerName, ReceiverModelName, … }`. iOS also includes `SupportsContactExchange` and `IDSSessionID`, among others.

### `/Upload`
- Headers from iOS 18.4: `Content-Type: application/x-dvzip`, `TotalBytes`, `TransferID`, and further sender-identifying headers.
- iOS 18.4 accepts an `x-dvzip` body generated by us.

## 6. `application/x-dvzip`

```
body   := block*
block  := u32be header || payload[header & 0x7fffffff]
          header bit 31 set   -> payload stored raw
          header bit 31 clear -> payload is a zlib stream
          each block decodes to at most 128 KiB
```

The concatenated output is an **odc cpio** archive (magic `070707`) containing `.`, `./<name>`, and AppleDouble `./._<name>` metadata entries. Example: a 2.3 MB PNG became 20 blocks, 9 of them stored raw because PNG data barely compresses. It decoded byte-exact to the sender's `TotalBytes`.

Older research describes a gzip-compressed cpio body (`application/x-cpio`). We haven't tested whether current iOS still accepts that; `airdrop send --format cpio` sends it.

## 7. Observed timing (Apple ↔ Apple, 41 MB video)

| t | event |
|---|---|
| 0.18 s | `/Discover` |
| 3.47 s | `/Ask` (≈92 KB incl. thumbnail) |
| 6.69 s | Accept (human delay) |
| 7.08 s → 8.9 s | `/Upload`, ≈185 Mbit/s |
