// Analyze.h - encryption checks over captured packets. Pure data inspection.
//
// The point of these checks: on the legs dcc protects with its OWN crypto
// (the loopback WebSocket to cloudflared, and the WebRTC UDP path), nothing an
// intermediary could read should ever be readable here. So we (a) hunt for a
// canary string you sent, (b) flag any application-layer plaintext that should
// have been encrypted, and (c) measure byte entropy as a sanity check.
//
// A clean result proves no cleartext went over the wire. It does NOT prove the
// cryptography is correctly designed - that needs a code review.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "capture/Packet.h"

namespace analyze {

// -------- primitives ------------------------------------------------------

// Shannon entropy in bits/byte, 0..8. Encrypted data sits near 8; text is far
// lower. Meaningless on very short buffers, so callers pass enough bytes.
double entropy(const uint8_t* data, size_t len);

// A printable-looking hex+ASCII dump, like a debugger's memory view.
std::string hexDump(const uint8_t* data, size_t len, size_t maxBytes = 2048);

// Standard base64 of the input (used to search for a canary that a protocol
// may have base64-encoded, e.g. an identity key).
std::string base64(const uint8_t* data, size_t len);

// -------- WebSocket -------------------------------------------------------

struct WsFrame {
    uint8_t opcode = 0;         // 1=text 2=binary 8=close 9=ping 10=pong
    bool masked = false;
    std::vector<uint8_t> payload; // already unmasked
};

// Best-effort parse of one TCP segment's payload as one or more WebSocket
// frames, unmasking client->server frames. Returns empty if it doesn't look
// like WebSocket. (Frames split across TCP segments aren't reassembled yet.)
std::vector<WsFrame> parseWebSocket(const uint8_t* data, size_t len);

// -------- classification --------------------------------------------------

struct Classification {
    std::string label;   // "STUN", "DTLS app-data", "WS binary", "HTTP", "TLS", ...
    std::string detail;  // extra note, e.g. DTLS version or WS opcode
    bool shouldBeEncrypted = false; // this byte range is meant to be ciphertext
    bool looksReadable = false;     // we found structured/printable cleartext in it
};

// Classify one packet's transport payload. proto disambiguates the RFC 7983
// UDP demux (STUN/DTLS/RTP) from the TCP stream (HTTP/WS/TLS).
Classification classify(const capture::Packet& pkt);

// -------- test report -----------------------------------------------------

enum class Result { Pass, Fail, Warn, Info };

struct Finding {
    Result result;
    std::string test;
    std::string detail;
    uint64_t packetSeq = 0; // 0 = not tied to one packet
};

struct Report {
    std::vector<Finding> findings;
    int passes = 0, fails = 0, warns = 0;
    void add(Result r, std::string test, std::string detail, uint64_t seq = 0);
    bool passed() const { return fails == 0; }
    std::string text() const; // formatted for a read-only text box
};

// Run every check over the capture. `canaries` are marker strings you sent in
// chat / display name / invite; each is searched for raw and base64-encoded.
Report runTests(const std::vector<capture::Packet>& packets, const std::vector<std::string>& canaries);

} // namespace analyze
