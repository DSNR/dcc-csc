#include "analyze/Analyze.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace analyze {
namespace {

bool contains(const std::vector<uint8_t>& hay, const std::string& needle) {
    if (needle.empty() || hay.size() < needle.size()) return false;
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end()) != hay.end();
}

// Does this buffer look like dcc signaling JSON we'd never want in the clear?
bool looksLikeSignalingJson(const std::vector<uint8_t>& b) {
    auto has = [&](const char* s) { return contains(b, s); };
    // A wire frame is a flat JSON object; signaling carries these tell-tales.
    return has("{\"t\":\"") || has("\"sdp\"") || has("\"candidate\"") || has("\"session_id\"");
}

double printableRatio(const uint8_t* d, size_t n) {
    if (n == 0) return 0;
    size_t p = 0;
    for (size_t i = 0; i < n; ++i)
        if (d[i] == '\t' || d[i] == '\n' || d[i] == '\r' || (d[i] >= 0x20 && d[i] < 0x7f)) ++p;
    return (double)p / n;
}

} // namespace

// -------------------------------------------------------------- primitives
double entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0;
    std::array<size_t, 256> freq{};
    for (size_t i = 0; i < len; ++i) ++freq[data[i]];
    double e = 0;
    for (size_t c : freq)
        if (c) {
            double p = (double)c / len;
            e -= p * std::log2(p);
        }
    return e;
}

std::string hexDump(const uint8_t* data, size_t len, size_t maxBytes) {
    std::string out;
    size_t n = std::min(len, maxBytes);
    char line[128];
    for (size_t i = 0; i < n; i += 16) {
        std::snprintf(line, sizeof(line), "%04zx  ", i);
        out += line;
        std::string ascii;
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < n) {
                std::snprintf(line, sizeof(line), "%02x ", data[i + j]);
                out += line;
                uint8_t c = data[i + j];
                ascii += (c >= 0x20 && c < 0x7f) ? (char)c : '.';
            } else {
                out += "   ";
            }
            if (j == 7) out += ' ';
        }
        out += " |" + ascii + "|\n";
    }
    if (len > maxBytes) {
        std::snprintf(line, sizeof(line), "... (%zu more bytes)\n", len - maxBytes);
        out += line;
    }
    return out;
}

std::string base64(const uint8_t* data, size_t len) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = data[i] << 16;
        if (i + 1 < len) n |= data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];
        out += t[(n >> 18) & 63];
        out += t[(n >> 12) & 63];
        out += (i + 1 < len) ? t[(n >> 6) & 63] : '=';
        out += (i + 2 < len) ? t[n & 63] : '=';
    }
    return out;
}

// -------------------------------------------------------------- WebSocket
std::vector<WsFrame> parseWebSocket(const uint8_t* data, size_t len) {
    std::vector<WsFrame> frames;
    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t b0 = data[pos], b1 = data[pos + 1];
        if (b0 & 0x70) return {};                 // reserved bits set: not WS
        uint8_t opcode = b0 & 0x0f;
        static const uint8_t ok[] = {0, 1, 2, 8, 9, 10};
        if (std::find(std::begin(ok), std::end(ok), opcode) == std::end(ok)) return {};
        bool masked = (b1 & 0x80) != 0;
        uint64_t plen = b1 & 0x7f;
        size_t hdr = 2;
        if (plen == 126) {
            if (pos + 4 > len) break;
            plen = (data[pos + 2] << 8) | data[pos + 3];
            hdr = 4;
        } else if (plen == 127) {
            if (pos + 10 > len) break;
            plen = 0;
            for (int i = 0; i < 8; ++i) plen = (plen << 8) | data[pos + 2 + i];
            hdr = 10;
        }
        uint8_t key[4] = {0, 0, 0, 0};
        if (masked) {
            if (pos + hdr + 4 > len) break;
            std::memcpy(key, data + pos + hdr, 4);
            hdr += 4;
        }
        if (plen > len - pos - hdr) break;         // frame runs past this segment
        WsFrame f;
        f.opcode = opcode;
        f.masked = masked;
        f.payload.resize(plen);
        for (uint64_t i = 0; i < plen; ++i) f.payload[i] = data[pos + hdr + i] ^ (masked ? key[i & 3] : 0);
        frames.push_back(std::move(f));
        pos += hdr + plen;
    }
    return frames;
}

// -------------------------------------------------------------- classify
Classification classify(const capture::Packet& pkt) {
    Classification c;
    const auto& p = pkt.payload;
    if (p.empty()) {
        c.label = "empty";
        return c;
    }
    const uint8_t b0 = p[0];

    if (pkt.proto == capture::Proto::Udp) {
        // RFC 7983 demux by first byte.
        if (b0 <= 3) {
            c.label = "STUN";
            c.detail = "ICE connectivity - usernames are visible by design";
            return c;
        }
        if (b0 >= 20 && b0 <= 63) {
            uint8_t ct = b0;
            c.shouldBeEncrypted = (ct == 23);
            c.label = ct == 23 ? "DTLS app-data" : "DTLS handshake";
            if (p.size() >= 3 && p[1] == 0xfe) {
                const char* v = p[2] == 0xff ? "1.0" : p[2] == 0xfd ? "1.2" : "1.x";
                c.detail = std::string("DTLS ") + v;
            }
            if (c.shouldBeEncrypted && (looksLikeSignalingJson(p) || printableRatio(p.data(), p.size()) > 0.85))
                c.looksReadable = true;
            return c;
        }
        if (b0 >= 128 && b0 <= 191) {
            uint8_t pt = p.size() > 1 ? p[1] : 0;
            c.label = (pt >= 200 && pt <= 204) ? "RTCP" : "SRTP/RTP";
            c.detail = "media - header visible, payload must be encrypted";
            c.shouldBeEncrypted = true; // the payload, not the RTP header
            return c;
        }
        c.label = "UDP other";
        return c;
    }

    // TCP stream.
    auto starts = [&](const char* s) {
        size_t n = std::strlen(s);
        return p.size() >= n && std::memcmp(p.data(), s, n) == 0;
    };
    if (starts("GET ") || starts("POST ") || starts("PUT ") || starts("HEAD ") || starts("HTTP/")) {
        c.label = "HTTP";
        c.detail = contains(p, "Upgrade: websocket") || contains(p, "Sec-WebSocket-Key")
                       ? "WebSocket upgrade" : "plain HTTP";
        return c;
    }
    if (b0 >= 20 && b0 <= 23 && p.size() >= 3 && p[1] == 3 && p[2] <= 4) {
        c.label = "TLS";
        c.detail = "outer transport (e.g. to Cloudflare) - opaque here";
        return c;
    }
    auto ws = parseWebSocket(p.data(), p.size());
    if (!ws.empty()) {
        const auto& f = ws.front();
        static const char* names[] = {"cont", "text", "binary"};
        c.label = std::string("WS ") + (f.opcode < 3 ? names[f.opcode]
                                        : f.opcode == 8 ? "close" : f.opcode == 9 ? "ping" : "pong");
        // WS binary here carries Noise: handshake msgs then ciphertext. Text
        // frames or readable JSON in a binary frame would be a leak.
        c.shouldBeEncrypted = (f.opcode == 2);
        for (const auto& fr : ws) {
            if (fr.opcode == 1 && printableRatio(fr.payload.data(), fr.payload.size()) > 0.85) c.looksReadable = true;
            if (fr.opcode == 2 && looksLikeSignalingJson(fr.payload)) c.looksReadable = true;
        }
        return c;
    }

    c.label = "TCP other";
    if (printableRatio(p.data(), p.size()) > 0.9 && p.size() > 8) {
        c.detail = "high printable ratio";
    }
    return c;
}

// -------------------------------------------------------------- report
void Report::add(Result r, std::string test, std::string detail, uint64_t seq) {
    findings.push_back({r, std::move(test), std::move(detail), seq});
    if (r == Result::Pass) ++passes;
    else if (r == Result::Fail) ++fails;
    else if (r == Result::Warn) ++warns;
}

std::string Report::text() const {
    std::string out;
    for (const auto& f : findings) {
        const char* tag = f.result == Result::Pass ? "[PASS]"
                          : f.result == Result::Fail ? "[FAIL]"
                          : f.result == Result::Warn ? "[WARN]" : "[info]";
        out += tag;
        out += ' ';
        out += f.test;
        if (f.packetSeq) out += " (packet #" + std::to_string(f.packetSeq) + ")";
        if (!f.detail.empty()) out += "\r\n        " + f.detail;
        out += "\r\n";
    }
    out += "\r\n";
    out += std::to_string(passes) + " passed, " + std::to_string(fails) + " failed, " +
           std::to_string(warns) + " warnings.\r\n";
    out += passed() ? "RESULT: no cleartext found on the inspected legs.\r\n"
                    : "RESULT: potential exposure found - see FAIL lines.\r\n";
    return out;
}

Report runTests(const std::vector<capture::Packet>& packets, const std::vector<std::string>& canaries) {
    Report rep;
    if (packets.empty()) {
        rep.add(Result::Info, "No packets", "Load a .pcap capture first.");
        return rep;
    }

    // Build the set of byte-strings to hunt for: each canary raw, and base64.
    std::vector<std::string> needles;
    for (const auto& c : canaries) {
        if (c.empty()) continue;
        needles.push_back(c);
        needles.push_back(base64(reinterpret_cast<const uint8_t*>(c.data()), c.size()));
    }

    // 1. Canary hunt - raw payload and any unmasked WebSocket payload.
    int canaryHits = 0;
    for (const auto& pkt : packets) {
        auto hunt = [&](const std::vector<uint8_t>& buf, const char* where) {
            for (const auto& n : needles)
                if (contains(buf, n)) {
                    rep.add(Result::Fail, "Canary found in cleartext",
                            std::string("marker visible in ") + where, pkt.seq);
                    ++canaryHits;
                }
        };
        hunt(pkt.payload, "raw payload");
        if (pkt.proto == capture::Proto::Tcp)
            for (const auto& f : parseWebSocket(pkt.payload.data(), pkt.payload.size()))
                hunt(f.payload, "WebSocket payload");
    }
    if (!needles.empty() && canaryHits == 0)
        rep.add(Result::Pass, "Canary hunt", "no marker string appeared in any packet");
    else if (needles.empty())
        rep.add(Result::Info, "Canary hunt", "no canary provided - set one and send it in the app");

    // 2 & 3. Application-layer readability + entropy on encrypted legs.
    int readableHits = 0, encFrames = 0;
    std::vector<uint8_t> encBytes;
    for (const auto& pkt : packets) {
        auto c = classify(pkt);
        if (c.looksReadable) {
            rep.add(Result::Fail, "Readable data where ciphertext expected",
                    c.label + ": " + (c.detail.empty() ? "structured/printable content" : c.detail), pkt.seq);
            ++readableHits;
        }
        if (c.shouldBeEncrypted) {
            ++encFrames;
            // Collect WS-binary and DTLS app-data bytes for a pooled entropy read.
            if (pkt.proto == capture::Proto::Tcp) {
                for (const auto& f : parseWebSocket(pkt.payload.data(), pkt.payload.size()))
                    if (f.opcode == 2) encBytes.insert(encBytes.end(), f.payload.begin(), f.payload.end());
            } else {
                encBytes.insert(encBytes.end(), pkt.payload.begin(), pkt.payload.end());
            }
        }
    }
    if (readableHits == 0 && encFrames > 0)
        rep.add(Result::Pass, "Application-layer readability",
                "no readable signaling/JSON in frames meant to be encrypted");

    if (encBytes.size() >= 512) {
        double e = entropy(encBytes.data(), encBytes.size());
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.3f bits/byte over %zu bytes", e, encBytes.size());
        if (e >= 7.0) rep.add(Result::Pass, "Ciphertext entropy", buf);
        else rep.add(Result::Warn, "Ciphertext entropy low", std::string(buf) + " - expected >= 7.0");
    } else if (encFrames > 0) {
        rep.add(Result::Info, "Ciphertext entropy", "too few encrypted bytes to score reliably");
    }

    // 4. Coverage note so a clean run isn't mistaken for a full audit.
    if (encFrames == 0)
        rep.add(Result::Warn, "No protected traffic seen",
                "capture had no WebSocket-binary or DTLS app-data - are you capturing the right leg?");
    rep.add(Result::Info, "Scope",
            "Proves no cleartext on inspected legs. Does not verify key exchange, "
            "certificate checking, or algorithm choice - review the code for those.");
    return rep;
}

} // namespace analyze
