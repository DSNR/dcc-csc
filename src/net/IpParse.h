// IpParse.h - turn a raw IP packet into a capture::Packet (proto, addrs, payload).
//
// Pure byte parsing: no sockets, no capture. Given a buffer that starts at the
// IP header, it fills in protocol, addresses, ports and the transport payload
// (the bytes after the TCP/UDP header - i.e. what the application sent).
#pragma once

#include <cstdint>

#include "capture/Packet.h"

namespace net {

// Parse an IPv4 or IPv6 packet at data[0..len). Fills proto/ips/ports/payload
// on pkt (leaving dir/seq/time to the caller) and returns true, or returns
// false if it isn't a TCP/UDP IPv4/IPv6 packet we can read.
bool parseIp(const uint8_t* data, size_t len, capture::Packet& pkt);

} // namespace net
