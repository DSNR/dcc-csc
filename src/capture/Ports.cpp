#include "capture/Ports.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>  // must precede windows.h; provides AF_INET / AF_INET6
#include <ws2tcpip.h>
#include <windows.h>

#include <iphlpapi.h>
#include <tlhelp32.h>

#include <vector>

namespace capture {
namespace {

// Build a PID -> image-name map with one Toolhelp snapshot.
std::unordered_map<DWORD, std::string> pidNames() {
    std::unordered_map<DWORD, std::string> names;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return names;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            int n = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nullptr, 0, nullptr, nullptr);
            std::string name(n > 0 ? n - 1 : 0, '\0');
            if (n > 0) WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name.data(), n, nullptr, nullptr);
            names[pe.th32ProcessID] = name;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return names;
}

uint16_t portOf(DWORD netOrderLowWord) {
    // The tables store the port in network byte order in the low 16 bits.
    uint16_t p = (uint16_t)(netOrderLowWord & 0xffff);
    return (uint16_t)((p >> 8) | (p << 8));
}

void fillTcp(std::unordered_map<uint16_t, std::string>& out,
             const std::unordered_map<DWORD, std::string>& names, ULONG family) {
    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    if (!size) return;
    std::vector<uint8_t> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;

    if (family == AF_INET) {
        auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            auto it = names.find(t->table[i].dwOwningPid);
            if (it != names.end()) out[portOf(t->table[i].dwLocalPort)] = it->second;
        }
    } else {
        auto* t = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            auto it = names.find(t->table[i].dwOwningPid);
            if (it != names.end()) out[portOf(t->table[i].dwLocalPort)] = it->second;
        }
    }
}

void fillUdp(std::unordered_map<uint16_t, std::string>& out,
             const std::unordered_map<DWORD, std::string>& names, ULONG family) {
    ULONG size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
    if (!size) return;
    std::vector<uint8_t> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, family, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) return;

    if (family == AF_INET) {
        auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            auto it = names.find(t->table[i].dwOwningPid);
            if (it != names.end()) out[portOf(t->table[i].dwLocalPort)] = it->second;
        }
    } else {
        auto* t = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            auto it = names.find(t->table[i].dwOwningPid);
            if (it != names.end()) out[portOf(t->table[i].dwLocalPort)] = it->second;
        }
    }
}

} // namespace

std::string OwnerMap::owner(Proto proto, uint16_t port) const {
    const auto& m = (proto == Proto::Udp) ? udp : tcp;
    auto it = m.find(port);
    return it == m.end() ? std::string{} : it->second;
}

OwnerMap snapshotOwners() {
    OwnerMap m;
    auto names = pidNames();
    fillTcp(m.tcp, names, AF_INET);
    fillTcp(m.tcp, names, AF_INET6);
    fillUdp(m.udp, names, AF_INET);
    fillUdp(m.udp, names, AF_INET6);
    return m;
}

} // namespace capture
