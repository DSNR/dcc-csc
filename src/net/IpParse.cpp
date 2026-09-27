#include "net/IpParse.h"

#include <cstdio>
#include <cstring>

namespace net {
namespace {

std::string ipv4(const uint8_t* p) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return buf;
}

std::string ipv6(const uint8_t* p) {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%x:%x:%x:%x:%x:%x:%x:%x",
                  (p[0] << 8) | p[1], (p[2] << 8) | p[3], (p[4] << 8) | p[5], (p[6] << 8) | p[7],
                  (p[8] << 8) | p[9], (p[10] << 8) | p[11], (p[12] << 8) | p[13], (p[14] << 8) | p[15]);
    return buf;
}

uint16_t be16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

// Fill transport (TCP/UDP) fields and payload from an L4 buffer.
bool parseL4(uint8_t proto, const uint8_t* p, size_t len, capture::Packet& pkt) {
    if (proto == 6) { // TCP
        if (len < 20) return false;
        pkt.proto = capture::Proto::Tcp;
        pkt.srcPort = be16(p);
        pkt.dstPort = be16(p + 2);
        size_t hdr = (size_t)((p[12] >> 4) & 0xF) * 4;
        if (hdr < 20 || hdr > len) return false;
        pkt.payload.assign(p + hdr, p + len);
        return true;
    }
    if (proto == 17) { // UDP
        if (len < 8) return false;
        pkt.proto = capture::Proto::Udp;
        pkt.srcPort = be16(p);
        pkt.dstPort = be16(p + 2);
        size_t ulen = be16(p + 4);
        if (ulen < 8) ulen = len;         // some stacks leave length 0 on offload
        if (ulen > len) ulen = len;
        pkt.payload.assign(p + 8, p + ulen);
        return true;
    }
    return false;
}

} // namespace

bool parseIp(const uint8_t* data, size_t len, capture::Packet& pkt) {
    if (len < 1) return false;
    uint8_t version = data[0] >> 4;

    if (version == 4) {
        if (len < 20) return false;
        size_t ihl = (size_t)(data[0] & 0xF) * 4;
        if (ihl < 20 || ihl > len) return false;
        uint16_t total = be16(data + 2);
        if (total > len || total < ihl) total = (uint16_t)len;
        pkt.srcIp = ipv4(data + 12);
        pkt.dstIp = ipv4(data + 16);
        return parseL4(data[9], data + ihl, total - ihl, pkt);
    }
    if (version == 6) {
        if (len < 40) return false;
        uint16_t plen = be16(data + 4);
        uint8_t next = data[6];
        size_t off = 40;
        if ((size_t)plen + 40 <= len) plen = plen; else plen = (uint16_t)(len - 40);
        pkt.srcIp = ipv6(data + 8);
        pkt.dstIp = ipv6(data + 24);
        // Only bare TCP/UDP; skip packets with IPv6 extension headers.
        return parseL4(next, data + off, plen, pkt);
    }
    return false;
}

} // namespace net
