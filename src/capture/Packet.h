// Packet.h - one captured network packet, parsed down to the transport payload.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace capture {

enum class Direction { Outbound, Inbound };
enum class Proto { Other, Tcp, Udp };

struct Packet {
    uint64_t seq = 0;         // capture order, 1-based
    double time = 0;          // seconds since capture start
    Direction dir = Direction::Outbound;
    Proto proto = Proto::Other;

    std::string srcIp;        // dotted / colon form
    std::string dstIp;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;

    // payload is the transport payload only: the bytes after the TCP/UDP header,
    // i.e. what the application actually sent. This is what encryption checks run on.
    std::vector<uint8_t> payload;

    std::string dirArrow() const { return dir == Direction::Outbound ? "->" : "<-"; }
    std::string protoName() const {
        switch (proto) {
        case Proto::Tcp: return "TCP";
        case Proto::Udp: return "UDP";
        default: return "?";
        }
    }
};

} // namespace capture
