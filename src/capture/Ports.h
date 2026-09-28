// Ports.h - map a local port to the process that owns it.
//
// This is read-only system information: the same port/PID ownership table that
// `netstat -ano` and Get-NetTCPConnection read (via iphlpapi). It captures no
// traffic. dcc-csc uses it to attribute each packet to a process, so the tool
// can show - and run its verdict over - only dcc's own tunnel traffic instead
// of everything on the loopback adapter.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

#include "capture/Packet.h"

namespace capture {

// A snapshot of which process owns each local TCP/UDP port right now.
class OwnerMap {
public:
    // process image name (e.g. "dcc-gui.exe") that owns `port`, or "" if none.
    std::string owner(Proto proto, uint16_t port) const;

    std::unordered_map<uint16_t, std::string> tcp;
    std::unordered_map<uint16_t, std::string> udp;
};

// Take a fresh snapshot. Cheap enough to call once a second while following.
OwnerMap snapshotOwners();

} // namespace capture
