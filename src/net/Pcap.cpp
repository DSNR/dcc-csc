#include "net/Pcap.h"

#include <cstring>

#include "net/IpParse.h"

namespace net {
namespace {

// Offset from the start of a link-layer frame to the IP header, and whether
// the link type is one we understand. For Ethernet we also skip 802.1Q tags.
bool ipOffset(unsigned linkType, const uint8_t* f, size_t len, size_t& off) {
    switch (linkType) {
    case 101: // LINKTYPE_RAW
    case 12:  // DLT_RAW (BSD)
    case 14:  // DLT_RAW (older)
    case 229: // raw IP variants
        off = 0;
        return true;
    case 0: // DLT_NULL / loopback: 4-byte address family
        if (len < 4) return false;
        off = 4;
        return true;
    case 1: { // Ethernet
        if (len < 14) return false;
        size_t o = 12;
        uint16_t ether = (uint16_t)((f[o] << 8) | f[o + 1]);
        o += 2;
        while (ether == 0x8100 || ether == 0x88a8) { // VLAN tags
            if (o + 4 > len) return false;
            ether = (uint16_t)((f[o + 2] << 8) | f[o + 3]);
            o += 4;
        }
        if (ether != 0x0800 && ether != 0x86dd) return false;
        off = o;
        return true;
    }
    default:
        return false;
    }
}

std::vector<uint8_t> readAllFrom(const std::string& path, size_t from) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    in.seekg(0, std::ios::end);
    std::streamoff end = in.tellg();
    if (end < 0 || (size_t)end <= from) return {};
    in.seekg((std::streamoff)from, std::ios::beg);
    std::vector<uint8_t> buf((size_t)end - from);
    in.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
    buf.resize((size_t)in.gcount());
    return buf;
}

} // namespace

// -------------------------------------------------------------- CaptureReader
bool CaptureReader::open(const std::string& path, std::string& error) {
    path_ = path;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open file";
        return false;
    }
    uint8_t hdr[4] = {0};
    in.read(reinterpret_cast<char*>(hdr), 4);
    if (in.gcount() < 4) {
        error = "file too small";
        return false;
    }
    uint32_t magic;
    std::memcpy(&magic, hdr, 4);

    if (magic == 0xa1b2c3d4 || magic == 0xa1b23c4d) { format_ = Format::Pcap; swap_ = false; }
    else if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1) { format_ = Format::Pcap; swap_ = true; }
    else if (magic == 0x0a0d0d0a) { format_ = Format::PcapNg; /* swap set from SHB */ }
    else {
        error = "unrecognized capture format (not pcap or pcapng)";
        return false;
    }

    if (format_ == Format::Pcap) {
        // Read the 24-byte global header to learn the link type.
        std::vector<uint8_t> gh = readAllFrom(path, 0);
        if (gh.size() < 24) { error = "truncated pcap header"; return false; }
        uint32_t lt;
        std::memcpy(&lt, gh.data() + 20, 4);
        if (swap_) lt = __builtin_bswap32(lt);
        linkType_ = lt;
        offset_ = 24;
    } else {
        offset_ = 0; // SHB parsed on first poll, so byte order is set there
    }
    return true;
}

std::vector<capture::Packet> CaptureReader::poll() {
    std::vector<capture::Packet> out;
    std::vector<uint8_t> buf = readAllFrom(path_, offset_);
    if (buf.empty()) return out;
    if (format_ == Format::Pcap) parsePcap(buf, out);
    else parsePcapNg(buf, out);
    return out;
}

void CaptureReader::emit(unsigned linkType, const uint8_t* frame, size_t len, double t,
                         std::vector<capture::Packet>& out) {
    size_t off;
    if (!ipOffset(linkType, frame, len, off)) { ++skipped_; return; }
    capture::Packet pkt;
    if (!net::parseIp(frame + off, len - off, pkt)) { ++skipped_; return; }
    if (t0_ < 0) t0_ = t;
    pkt.time = t - t0_;
    pkt.seq = ++seq_;
    out.push_back(std::move(pkt));
}

void CaptureReader::parsePcap(const std::vector<uint8_t>& buf, std::vector<capture::Packet>& out) {
    auto u32 = [&](const uint8_t* p) {
        uint32_t v;
        std::memcpy(&v, p, 4);
        return swap_ ? __builtin_bswap32(v) : v;
    };
    size_t pos = 0;
    while (pos + 16 <= buf.size()) {
        uint32_t tsSec = u32(buf.data() + pos);
        uint32_t tsUsec = u32(buf.data() + pos + 4);
        uint32_t inclLen = u32(buf.data() + pos + 8);
        if (inclLen == 0 || inclLen > 262144) { offset_ += pos + 16; return; } // guard junk
        if (pos + 16 + inclLen > buf.size()) break;                            // wait for the rest
        emit(linkType_, buf.data() + pos + 16, inclLen, (double)tsSec + tsUsec / 1e6, out);
        pos += 16 + inclLen;
    }
    offset_ += pos;
}

void CaptureReader::parsePcapNg(const std::vector<uint8_t>& buf, std::vector<capture::Packet>& out) {
    auto u32 = [&](const uint8_t* p) {
        uint32_t v;
        std::memcpy(&v, p, 4);
        return swap_ ? __builtin_bswap32(v) : v;
    };
    auto u16 = [&](const uint8_t* p) {
        uint16_t v;
        std::memcpy(&v, p, 2);
        return (uint16_t)(swap_ ? __builtin_bswap16(v) : v);
    };
    size_t pos = 0;
    while (pos + 12 <= buf.size()) {
        uint32_t type;
        std::memcpy(&type, buf.data() + pos, 4);
        // The Section Header Block's byte-order magic tells us the section's
        // endianness; set swap_ before reading its own total length.
        if (type == 0x0a0d0d0a) {
            if (pos + 8 > buf.size()) break;
            uint32_t bom;
            std::memcpy(&bom, buf.data() + pos + 8, 4);
            swap_ = (bom != 0x1a2b3c4d);
            nextIface_ = 0; // interface ids restart each section
        }
        uint32_t total = u32(buf.data() + pos + 4);
        if (total < 12 || total % 4 != 0 || total > 16 * 1024 * 1024) { offset_ += buf.size(); return; }
        if (pos + total > buf.size()) break; // whole block not present yet
        const uint8_t* body = buf.data() + pos + 8;

        if (type == 0x00000001) { // Interface Description Block
            unsigned lt = u16(body);
            ifLink_[nextIface_++] = lt;
        } else if (type == 0x00000006) { // Enhanced Packet Block
            uint32_t iface = u32(body);
            uint64_t ts = ((uint64_t)u32(body + 4) << 32) | u32(body + 8);
            uint32_t cap = u32(body + 12);
            if (28u + cap <= total) {
                unsigned lt = ifLink_.count(iface) ? ifLink_[iface] : 1;
                emit(lt, body + 20, cap, (double)ts / 1e6, out); // default 1us resolution
            }
        } else if (type == 0x00000003) { // Simple Packet Block
            uint32_t orig = u32(body);
            uint32_t avail = total - 12; // block body minus orig_len field and trailing len
            uint32_t cap = orig < avail ? orig : avail;
            unsigned lt = ifLink_.count(0) ? ifLink_[0] : 1;
            emit(lt, body + 4, cap, 0, out);
        }
        pos += total;
    }
    offset_ += pos;
}

// -------------------------------------------------------------- readPcap
PcapResult readPcap(const std::string& path) {
    PcapResult r;
    CaptureReader reader;
    if (!reader.open(path, r.error)) return r;
    r.packets = reader.poll();
    r.skipped = reader.skipped();
    r.ok = true;
    return r;
}

} // namespace net
