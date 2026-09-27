// Pcap.h - read capture files into capture::Packets, incrementally.
//
// Handles both classic .pcap (libpcap/tcpdump) and .pcapng (Wireshark's
// default). CaptureReader can be polled repeatedly while a file is still being
// written, so the app can "follow" a live Wireshark/dumpcap capture and only
// ever consumes whole records - a half-written trailing record is left for the
// next poll.
//
// Link layers handled: Ethernet (1), raw IPv4/IPv6 (101/12/14/229), and
// NULL/loopback (0) as written by Npcap's loopback adapter.
#pragma once

#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "capture/Packet.h"

namespace net {

struct PcapResult {
    bool ok = false;
    std::string error;
    std::vector<capture::Packet> packets;
    int skipped = 0;
    unsigned linkType = 0;
};

// One-shot read of a whole file. Timestamps are relative to the first packet.
PcapResult readPcap(const std::string& path);

// Incremental reader. open() parses the header; poll() returns packets that
// have become fully available since the previous poll. Safe to call poll()
// on a file another process is appending to.
class CaptureReader {
public:
    bool open(const std::string& path, std::string& error);
    std::vector<capture::Packet> poll();
    int skipped() const { return skipped_; }

private:
    enum class Format { Pcap, PcapNg };

    void parsePcap(const std::vector<uint8_t>& buf, std::vector<capture::Packet>& out);
    void parsePcapNg(const std::vector<uint8_t>& buf, std::vector<capture::Packet>& out);
    void emit(unsigned linkType, const uint8_t* frame, size_t len, double t,
              std::vector<capture::Packet>& out);

    std::string path_;
    Format format_ = Format::Pcap;
    bool swap_ = false;
    unsigned linkType_ = 0;                 // classic pcap: single link type
    std::map<uint32_t, unsigned> ifLink_;   // pcapng: link type per interface id
    uint32_t nextIface_ = 0;
    size_t offset_ = 0;                     // bytes consumed so far
    uint64_t seq_ = 0;
    double t0_ = -1;
    int skipped_ = 0;
};

} // namespace net
