# dcc-csc — dcc cleartext & security checker

`dcc-csc` is a small Windows GUI tool that verifies the
[dcc](https://github.com/DSNR/dcc) end-to-end-encrypted chat app is actually
sending **no readable content** over the network legs dcc is responsible for
encrypting. It works **alongside Wireshark**: Wireshark does the packet capture,
`dcc-csc` does the dcc-specific decoding and gives a plain PASS/FAIL verdict.

It is a testing/validation tool for dcc, not a general packet sniffer.

---

## Why a separate tool

dcc is serverless. Two peers find each other through a Cloudflare Quick Tunnel
and then talk directly over WebRTC; Cloudflare is only meant to be a meeting
point, never able to read messages. That promise rests entirely on dcc's **own**
cryptography, applied *before* anything leaves the app:

| Leg | Transport | Protected by |
| --- | --- | --- |
| Peer ⇄ Cloudflare edge | WebSocket over HTTPS | Cloudflare's TLS — Cloudflare can read inside it |
| **`cloudflared` ⇄ dcc Rendezvous** (loopback, on the Host) | plain HTTP/WS: `/v1/signal`, `/v1/relay` | **dcc only** — Noise (signal) + DTLS (relay) |
| **Peer ⇄ Peer direct** | WebRTC / UDP | **dcc only** — DTLS + SRTP |

The rows marked *dcc only* are what an intermediary such as Cloudflare actually
sees once its own TLS wrapping is stripped away. If any of your text is readable
there, encryption is not doing its job. Wireshark will show you those packets,
but it has no idea what dcc's frames should look like. `dcc-csc` does: it
unmasks WebSocket frames, recognises the Noise / DTLS / SRTP layers, hunts for a
marker you sent, and tells you whether anything leaked.

> **Capture on the Host.** The Host machine runs `cloudflared` and the
> Rendezvous, so the revealing loopback leg only exists there. Capturing on the
> Peer shows only TLS to Cloudflare and proves nothing about dcc's own crypto.

---

## How it works alongside Wireshark

Wireshark (with Npcap) already has everything needed to *capture* traffic —
including loopback and UDP — and it needs administrator rights and a capture
driver to do so. `dcc-csc` deliberately does **not** duplicate that. Instead:

```
  ┌─────────────┐   captures    ┌──────────────┐   .pcap / .pcapng   ┌──────────┐
  │  Wireshark  │ ────────────► │   file on    │ ──────────────────► │ dcc-csc  │
  │  / dumpcap  │   (Npcap)     │   disk       │   open or follow    │ verdict  │
  └─────────────┘               └──────────────┘                     └──────────┘
```

### Mode 1 — Open a finished capture

1. In Wireshark, capture the loopback / UDP traffic on the **Host** while you use
   dcc. Filter to dcc's ports if you like. Stop the capture.
2. Save it (Wireshark's native `.pcapng` is fine — no need to convert).
3. In `dcc-csc`: **File → Open capture**, pick the file.
4. Type a **canary** (see below) into the *Canary(ies)* box and click
   **Run tests**.

### Mode 2 — Follow a live capture

1. Start a capture that writes to a file, e.g. with the bundled dumpcap:
   ```
   dumpcap -w dcc.pcapng
   ```
   (or in Wireshark, capture and *Save* to a known file).
2. In `dcc-csc`: **File → Follow file (live)**, pick that same file.
3. `dcc-csc` tails the file once a second, adds new packets, and updates the
   verdict as traffic arrives. Send your canary in dcc and watch whether it ever
   surfaces — the tool **beeps the instant a leak is detected**.
4. **File → Stop following** when done.

Only complete records are ever read, so tailing a file that Wireshark is still
writing is safe.

---

## Canaries

A *canary* is a unique marker you send through dcc so the tool can search for it
in the raw traffic. Good canaries:

- a **chat message** like `CANARY-7Q2X9` (type it into dcc and send it);
- your **display name**, set to a canary — it travels inside the Noise handshake
  and must never be readable;
- the **invite password** — it must never appear on the wire in any form.

Enter one or several (comma- or newline-separated). Each is searched for both
raw and base64-encoded, in raw payloads and inside unmasked WebSocket frames.

---

## What the checks mean

| Check | Meaning |
| --- | --- |
| **Canary hunt** | Your marker (raw + base64) must appear in **no** packet. A hit is a hard FAIL — that content went out readable. |
| **Application-layer readability** | WebSocket frames are unmasked and inspected; readable signaling JSON / SDP where ciphertext is expected is flagged. |
| **Ciphertext entropy** | Encrypted bytes are pooled and scored; real ciphertext sits near 8.0 bits/byte. A low score is suspicious. |
| **Protocol view** | Every packet is classified — STUN / DTLS / SRTP-RTP (UDP, via the RFC 7983 first-byte demux) and HTTP / WebSocket / TLS (TCP). |

Select any packet to see its classification, entropy and a hex + ASCII dump of
its payload. **File → Save report** writes the verdict to a text file.

### Scope — read this

A clean result proves **no cleartext crossed the inspected legs**. It does
**not** verify that the cryptography is correctly *designed*: it says nothing
about key exchange, nonce reuse, certificate/identity checking, or algorithm
strength. Those require a review of the dcc source, not traffic inspection.

---

## Build

Self-contained: the compiler lives under `tools\`, downloaded on first setup.
Nothing is installed system-wide and `PATH` is never changed permanently.

```
setup.bat          (once) downloads the portable GCC toolchain (w64devkit) into tools\
build.bat          release build  -> build\dcc-csc.exe
build.bat run      build and launch
build.bat debug    debug build with a console window (std::cout works)
```

Every `.cpp` under `src\` is compiled automatically, so new files need no
build-script changes. `tools\` and `build\` are git-ignored.

---

## Project layout

```
src/main.cpp            entry point (WinMain)
src/app/MainWindow.*    the dcc-csc UI and workflow
src/gui/Gui.h/.cpp      a small reusable Win32 GUI wrapper
src/capture/Packet.h    one parsed packet — the seam a live sniffer would feed
src/net/IpParse.*       IPv4/IPv6 + TCP/UDP parser
src/net/Pcap.*          incremental .pcap / .pcapng reader (open + follow)
src/analyze/Analyze.*   entropy, base64, WebSocket unmask, classify, canary, report
res/app.rc, app.manifest  resources (icon slot, common-controls v6, DPI aware)
setup.bat, build.bat    toolchain fetch + build
```

---

## Current limitation & roadmap

`dcc-csc` relies on Wireshark/dumpcap for the actual packet capture. Native
capture (so Wireshark is not required) is **not yet implemented** — see the
issue *"Add native packet capture so Wireshark is not required"*.

The code is already structured for it: everything downstream consumes a
`capture::Packet`, and packets enter the UI through a single `addPacketRow()`
path. A native capture backend (e.g. WinDivert, loaded at runtime) only has to
produce `capture::Packet`s into that path — the parsing, analysis, UI and file
handling stay unchanged.

---

## The `gui::` wrapper

`src/gui/` is a standalone, reusable Win32 wrapper you can build any small
Windows app on. Widgets: `Label`, `Button`, `CheckBox`, `TextBox`
(single/multi-line), `ListBox`, `ComboBox`, `ListView`. Window features: menus,
timers, `message` / `error` / `ask` dialogs, open/save file dialogs, `onResize`,
`onClose`, and `handleMessage()` for raw Win32 messages. Coordinates are 96-DPI
logical pixels (auto-scaled for high-DPI displays); all strings are UTF-8.
