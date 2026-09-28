// MainWindow.cpp - dcc-csc traffic tester.
//
// Capture with Wireshark/dumpcap (it does the sniffing); this tool decodes the
// dcc-specific layers and gives a PASS/FAIL verdict. Two inputs, both reading
// the file Wireshark writes:
//
//   Open capture   - analyze a finished .pcap / .pcapng once.
//   Follow (live)  - tail a file Wireshark/dumpcap is still writing; the verdict
//                    updates as packets arrive and beeps on a leak.
//
// Process attribution: dcc-csc reads the OS port->process table (read-only, the
// same data as `netstat -ano`) and labels each packet with its owning process,
// so you can show - and judge - only dcc's own tunnel traffic instead of
// everything on the loopback adapter. The verdict runs over exactly what the
// list shows.
//
// The leg that matters is the loopback WebSocket between cloudflared and the dcc
// Rendezvous on the HOST, plus the WebRTC UDP path - what an intermediary could
// see once its own TLS is stripped.
#include "app/MainWindow.h"

#include <algorithm>
#include <cctype>
#include <fstream>

#include "analyze/Analyze.h"

namespace {
std::string lower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}
} // namespace

MainWindow::MainWindow() : gui::Window("dcc-csc — dcc cleartext & security checker", 940, 640) {
    menu("&File")
        .item("&Open capture...", [this] { openCapture(); })
        .item("&Follow file (live)...", [this] { followCapture(); })
        .item("&Stop following", [this] { stopFollowing(); })
        .separator()
        .item("&Save report...", [this] { saveReport(); })
        .separator()
        .item("E&xit", [this] { close(); });
    menu("&Help").item("&About", [this] {
        message("Verifies dcc sends no cleartext on the legs it encrypts itself.\n\n"
                "Capture with Wireshark, then Open (or Follow) the file here. dcc-csc attributes "
                "each packet to its process, so 'Show app traffic only' keeps just dcc's tunnel. "
                "Set a canary you sent in dcc, and Run tests.\n\n"
                "A clean result proves no cleartext on the inspected legs; it does not verify key "
                "exchange, certificate checking or algorithm choice.",
                "About");
    });

    // Row 1: canary + actions
    canaryLabel_ = &add<gui::Label>("Canary(ies):", 12, 16, 80, 20);
    canary_ = &add<gui::TextBox>("", 96, 13, 300, 24);
    openButton_ = &add<gui::Button>("Open file", 470, 12, 100, 26);
    runButton_ = &add<gui::Button>("Run tests", 576, 12, 100, 26);
    status_ = &add<gui::Label>("No capture loaded.", 686, 16, 240, 20);

    // Row 2: process attribution filter
    appLabel_ = &add<gui::Label>("App filter:", 12, 46, 80, 20);
    procFilter_ = &add<gui::TextBox>("dcc,cloudflared", 96, 43, 300, 24);
    appOnly_ = &add<gui::CheckBox>("Show app traffic only", 410, 45, 200, 22);
    appOnly_->setChecked(true);

    list_ = &add<gui::ListView>(12, 78, 560, 500);
    list_->addColumn("#", 44);
    list_->addColumn("Time", 60);
    list_->addColumn("Proto", 44);
    list_->addColumn("Source", 112);
    list_->addColumn("Dest", 112);
    list_->addColumn("Len", 48);
    list_->addColumn("App", 96);
    list_->addColumn("Type", 140);

    detail_ = &add<gui::TextBox>("", 580, 78, 348, 500, true);
    detail_->setReadOnly(true);

    openButton_->onClick([this] { openCapture(); });
    runButton_->onClick([this] { runTests(); });
    list_->onSelect([this](int i) { showPacket(i); });
    appOnly_->onToggle([this](bool) { recomputeApp(); rebuildList(); });
    procFilter_->onChange([this] { /* applied on next Run/refresh */ });

    onResize([this](int w, int h) { layout(w, h); });
    onClose([this] { stopFollowing(); return true; });
}

// ------------------------------------------------------------- small helpers
std::vector<std::string> MainWindow::canaries() const {
    std::vector<std::string> out;
    std::string cur;
    for (char ch : canary_->text()) {
        if (ch == ',' || ch == '\n' || ch == '\r') { if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur += ch;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::vector<std::string> MainWindow::procTokens() const {
    std::vector<std::string> out;
    std::string cur;
    for (char ch : lower(procFilter_->text())) {
        if (ch == ',' || ch == '\n' || ch == '\r' || ch == ' ') { if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur += ch;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// No tokens => no filter, everything counts as "app".
bool MainWindow::ownerMatches(const std::string& name) const {
    auto toks = procTokens();
    if (toks.empty()) return true;
    std::string n = lower(name);
    for (const auto& t : toks)
        if (!n.empty() && n.find(t) != std::string::npos) return true;
    return false;
}

// ------------------------------------------------------------- attribution
void MainWindow::refreshOwners() {
    owners_ = capture::snapshotOwners();
    // Accumulate every port currently owned by a matching process, so a packet
    // still attributes even after the socket closes and the owner vanishes.
    for (const auto& [port, name] : owners_.tcp)
        if (ownerMatches(name)) tcpPorts_.insert(port);
    for (const auto& [port, name] : owners_.udp)
        if (ownerMatches(name)) udpPorts_.insert(port);
}

bool MainWindow::appOwned(size_t i) const { return app_[i] != 0; }

bool MainWindow::passesFilter(size_t i) const { return !appOnly_->checked() || appOwned(i); }

void MainWindow::recomputeApp() {
    for (size_t i = 0; i < all_.size(); ++i) {
        const capture::Packet& p = all_[i];
        std::string os = owners_.owner(p.proto, p.srcPort);
        std::string od = owners_.owner(p.proto, p.dstPort);
        const auto& pset = (p.proto == capture::Proto::Udp) ? udpPorts_ : tcpPorts_;
        bool inSet = pset.count(p.srcPort) || pset.count(p.dstPort);
        bool matched = ownerMatches(os) || ownerMatches(od) || inSet;
        // Prefer a name that actually matches for the display column.
        std::string name = ownerMatches(od) && !od.empty() ? od
                           : ownerMatches(os) && !os.empty() ? os
                           : (!od.empty() ? od : os);
        owner_[i] = name;
        app_[i] = matched ? 1 : 0;
    }
}

void MainWindow::ingest(const capture::Packet& p) {
    all_.push_back(p);
    owner_.emplace_back();
    app_.push_back(0);
    size_t i = all_.size() - 1;
    // Evaluate just this one against current state.
    std::string os = owners_.owner(p.proto, p.srcPort);
    std::string od = owners_.owner(p.proto, p.dstPort);
    const auto& pset = (p.proto == capture::Proto::Udp) ? udpPorts_ : tcpPorts_;
    bool inSet = pset.count(p.srcPort) || pset.count(p.dstPort);
    bool matched = ownerMatches(os) || ownerMatches(od) || inSet;
    owner_[i] = ownerMatches(od) && !od.empty() ? od : ownerMatches(os) && !os.empty() ? os
                                                         : (!od.empty() ? od : os);
    app_[i] = matched ? 1 : 0;
    if (passesFilter(i)) addRowFor(i);
}

void MainWindow::addRowFor(size_t i) {
    const capture::Packet& p = all_[i];
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.3f", p.time);
    analyze::Classification c = analyze::classify(p);
    std::string type = c.label;
    if (c.looksReadable) type += " (!)";
    list_->addRow({std::to_string(p.seq), buf, p.protoName(),
                   p.srcIp + ":" + std::to_string(p.srcPort),
                   p.dstIp + ":" + std::to_string(p.dstPort),
                   std::to_string(p.payload.size()),
                   owner_[i].empty() ? "-" : owner_[i], type});
    rowToAll_.push_back((int)i);
}

void MainWindow::rebuildList() {
    list_->clear();
    rowToAll_.clear();
    for (size_t i = 0; i < all_.size(); ++i)
        if (passesFilter(i)) addRowFor(i);
    int shown = (int)rowToAll_.size();
    status_->setText(std::to_string(shown) + " shown / " + std::to_string(all_.size()) + " captured");
}

std::vector<capture::Packet> MainWindow::displayed() const {
    std::vector<capture::Packet> out;
    for (size_t i = 0; i < all_.size(); ++i)
        if (passesFilter(i)) out.push_back(all_[i]);
    return out;
}

// ------------------------------------------------------------- actions
void MainWindow::openCapture() {
    stopFollowing();
    std::string path = openFileDialog("Capture files|*.pcap;*.pcapng;*.cap|All files|*.*");
    if (path.empty()) return;

    net::CaptureReader reader;
    std::string err;
    if (!reader.open(path, err)) { error("Could not read capture:\n" + err); return; }

    all_.clear(); owner_.clear(); app_.clear();
    tcpPorts_.clear(); udpPorts_.clear();
    refreshOwners();                 // attribute against whatever is running now
    for (const auto& p : reader.poll()) ingest(p);
    rebuildList();
    detail_->setText("");
    report_.clear();
    if (!rowToAll_.empty()) { list_->setSelected(0); showPacket(0); }
}

void MainWindow::followCapture() {
    stopFollowing();
    std::string path = openFileDialog("Capture files|*.pcap;*.pcapng;*.cap|All files|*.*");
    if (path.empty()) return;

    std::string err;
    if (!reader_.open(path, err)) { error("Could not follow capture:\n" + err); return; }

    all_.clear(); owner_.clear(); app_.clear();
    tcpPorts_.clear(); udpPorts_.clear();
    list_->clear(); rowToAll_.clear();
    detail_->setText("Following:\r\n" + path + "\r\n\r\nWaiting for packets...");
    alerted_ = false;

    auto tick = [this] {
        refreshOwners();
        auto fresh = reader_.poll();
        for (const auto& p : fresh) ingest(p);
        if (!fresh.empty()) {
            if (!rowToAll_.empty()) list_->ensureVisible((int)rowToAll_.size() - 1);
            refreshVerdict();
        }
    };
    tick();
    followTimer_ = setTimer(1000, tick);
}

void MainWindow::stopFollowing() {
    if (followTimer_) {
        killTimer(followTimer_);
        followTimer_ = 0;
        status_->setText("Stopped. " + std::to_string(rowToAll_.size()) + " shown / " +
                         std::to_string(all_.size()) + " captured.");
    }
}

void MainWindow::refreshVerdict() {
    auto pkts = displayed();
    analyze::Report rep = analyze::runTests(pkts, canaries());
    report_ = rep.text();
    status_->setText(std::string(followTimer_ ? "LIVE " : "") + (rep.passed() ? "PASS" : "FAIL") +
                     "  " + std::to_string(pkts.size()) + " dcc pkts");
    if (!rep.passed() && !alerted_) {
        alerted_ = true;
        MessageBeep(MB_ICONWARNING);
        detail_->setText(report_);
    }
}

void MainWindow::showPacket(int row) {
    if (row < 0 || row >= (int)rowToAll_.size()) return;
    const capture::Packet& p = all_[rowToAll_[row]];
    analyze::Classification c = analyze::classify(p);

    std::string s = "Packet #" + std::to_string(p.seq) + "\r\n";
    s += p.srcIp + ":" + std::to_string(p.srcPort) + " " + p.dirArrow() + " " + p.dstIp + ":" +
         std::to_string(p.dstPort) + "  " + p.protoName() + "\r\n";
    std::string own = owner_[rowToAll_[row]];
    s += "Process: " + (own.empty() ? "(unknown)" : own) + (app_[rowToAll_[row]] ? " [app]" : "") + "\r\n";
    s += "Classification: " + c.label + "\r\n";
    if (!c.detail.empty()) s += "  " + c.detail + "\r\n";
    if (c.shouldBeEncrypted)
        s += c.looksReadable ? "  ** READABLE - should be ciphertext **\r\n" : "  (expected ciphertext)\r\n";
    if (!p.payload.empty()) {
        char e[48];
        std::snprintf(e, sizeof(e), "%.3f bits/byte\r\n", analyze::entropy(p.payload.data(), p.payload.size()));
        s += "Payload entropy: ";
        s += e;
    }
    s += "\r\nPayload (" + std::to_string(p.payload.size()) + " bytes):\r\n";
    s += analyze::hexDump(p.payload.data(), p.payload.size());

    std::string fixed;
    for (char ch : s) { if (ch == '\n' && (fixed.empty() || fixed.back() != '\r')) fixed += '\r'; fixed += ch; }
    detail_->setText(fixed);
}

void MainWindow::runTests() {
    if (all_.empty()) { message("Open or follow a capture first."); return; }
    recomputeApp();       // apply any edit to the process filter
    rebuildList();
    auto pkts = displayed();
    if (pkts.empty()) {
        message("No packets match the app filter. Clear it or untick 'Show app traffic only' "
                "to test everything.");
        return;
    }
    analyze::Report rep = analyze::runTests(pkts, canaries());
    report_ = rep.text();
    detail_->setText(report_);
    status_->setText((rep.passed() ? "PASS" : "FAIL") + std::string("  ") +
                     std::to_string(pkts.size()) + " dcc pkts");
}

void MainWindow::saveReport() {
    if (report_.empty()) { message("Run the tests first."); return; }
    std::string path = saveFileDialog("Text files|*.txt|All files|*.*", "txt");
    if (path.empty()) return;
    std::ofstream out(path, std::ios::binary);
    out << report_;
}

void MainWindow::layout(int w, int h) {
    const int m = 12;
    int rightW = 240;
    int actionsX = w - m - rightW - 8 - 100 - 8 - 100;
    canary_->setBounds(96, 13, std::max(120, actionsX - 8 - 96), 24);
    openButton_->setBounds(actionsX, 12, 100, 26);
    runButton_->setBounds(actionsX + 108, 12, 100, 26);
    status_->setBounds(w - m - rightW, 16, rightW, 20);

    procFilter_->setBounds(96, 43, 300, 24);
    appOnly_->setBounds(410, 45, 200, 22);

    int top = 78, bottom = h - m;
    int listW = (w - 2 * m - 8) * 3 / 5;
    list_->setBounds(m, top, listW, bottom - top);
    detail_->setBounds(m + listW + 8, top, w - m - (m + listW + 8), bottom - top);
}
