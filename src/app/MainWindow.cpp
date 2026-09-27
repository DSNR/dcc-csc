// MainWindow.cpp - dcc traffic tester.
//
// Two ways to feed it, both using Wireshark/dumpcap for the actual capture:
//
//   Open capture   - pick a finished .pcap or .pcapng file and analyze it once.
//   Follow (live)  - pick a file Wireshark/dumpcap is *still writing* to; the
//                    app tails it every second, adds new packets, and updates
//                    the PASS/FAIL verdict live. Send your canary in dcc and
//                    watch whether it ever surfaces.
//
// The leg that matters is the loopback WebSocket between cloudflared and the
// dcc Rendezvous on the HOST, plus the WebRTC UDP path - that is what an
// intermediary (Cloudflare) could see once its own TLS is stripped.
//
// Live sniffing without Wireshark can be added later: point a capture source
// at packets_ / addPacketRow and nothing else needs to change.
#include "app/MainWindow.h"

#include <fstream>

#include "analyze/Analyze.h"

MainWindow::MainWindow() : gui::Window("dcc-csc — dcc cleartext & security checker", 900, 600) {
    menu("&File")
        .item("&Open capture...", [this] { openCapture(); })
        .item("&Follow file (live)...", [this] { followCapture(); })
        .item("&Stop following", [this] { stopFollowing(); })
        .separator()
        .item("&Save report...", [this] { saveReport(); })
        .separator()
        .item("E&xit", [this] { close(); });
    menu("&Help").item("&About", [this] {
        message("Checks that dcc traffic carries no cleartext on the legs it protects itself.\n\n"
                "Capture with Wireshark, then Open the .pcap/.pcapng here (or Follow a file it is "
                "still writing). Set a canary you sent in the app, and Run tests.\n\n"
                "A clean result proves no cleartext on the inspected legs; it does not verify "
                "key exchange, certificate checking or algorithm choice.",
                "About");
    });

    canaryLabel_ = &add<gui::Label>("Canary(ies):", 12, 16, 80, 20);
    canary_ = &add<gui::TextBox>("", 96, 13, 380, 24);
    openButton_ = &add<gui::Button>("Open file", 486, 12, 110, 26);
    runButton_ = &add<gui::Button>("Run tests", 606, 12, 110, 26);
    status_ = &add<gui::Label>("No capture loaded.", 726, 16, 160, 20);

    list_ = &add<gui::ListView>(12, 50, 520, 500);
    list_->addColumn("#", 44);
    list_->addColumn("Time", 66);
    list_->addColumn("Proto", 48);
    list_->addColumn("Source", 120);
    list_->addColumn("Dest", 120);
    list_->addColumn("Len", 56);
    list_->addColumn("Type", 150);

    detail_ = &add<gui::TextBox>("", 540, 50, 348, 500, true);
    detail_->setReadOnly(true);

    openButton_->onClick([this] { openCapture(); });
    runButton_->onClick([this] { runTests(); });
    list_->onSelect([this](int i) { showPacket(i); });

    onResize([this](int w, int h) { layout(w, h); });
    onClose([this] { stopFollowing(); return true; });
}

std::vector<std::string> MainWindow::canaries() const {
    std::vector<std::string> out;
    std::string cur;
    for (char ch : canary_->text()) {
        if (ch == ',' || ch == '\n' || ch == '\r') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur += ch;
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

void MainWindow::addPacketRow(const capture::Packet& p) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.3f", p.time);
    std::string src = p.srcIp + ":" + std::to_string(p.srcPort);
    std::string dst = p.dstIp + ":" + std::to_string(p.dstPort);
    analyze::Classification c = analyze::classify(p);
    std::string type = c.label;
    if (c.looksReadable) type += " (!)";
    list_->addRow({std::to_string(p.seq), buf, p.protoName(), src, dst,
                   std::to_string(p.payload.size()), type});
}

void MainWindow::openCapture() {
    stopFollowing();
    std::string path = openFileDialog("Capture files|*.pcap;*.pcapng;*.cap|All files|*.*");
    if (path.empty()) return;

    net::CaptureReader reader;
    std::string err;
    if (!reader.open(path, err)) {
        error("Could not read capture:\n" + err);
        return;
    }
    packets_ = reader.poll();
    list_->clear();
    for (const auto& p : packets_) addPacketRow(p);
    status_->setText(std::to_string(packets_.size()) + " packets, " +
                     std::to_string(reader.skipped()) + " skipped");
    detail_->setText("");
    report_.clear();
    if (!packets_.empty()) {
        list_->setSelected(0);
        showPacket(0);
    }
}

void MainWindow::followCapture() {
    stopFollowing();
    std::string path = openFileDialog("Capture files|*.pcap;*.pcapng;*.cap|All files|*.*");
    if (path.empty()) return;

    std::string err;
    if (!reader_.open(path, err)) {
        error("Could not follow capture:\n" + err);
        return;
    }
    packets_.clear();
    list_->clear();
    detail_->setText("Following:\r\n" + path + "\r\n\r\nWaiting for packets...");
    alerted_ = false;

    // Poll once immediately, then on a timer.
    auto tick = [this] {
        auto fresh = reader_.poll();
        for (const auto& p : fresh) {
            packets_.push_back(p);
            addPacketRow(p);
        }
        if (!fresh.empty()) {
            list_->ensureVisible((int)packets_.size() - 1);
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
        status_->setText("Stopped. " + std::to_string(packets_.size()) + " packets.");
    }
}

// Live verdict while following: re-run the checks and flag the moment a leak
// appears, with an audible alert the first time.
void MainWindow::refreshVerdict() {
    auto cs = canaries();
    analyze::Report rep = analyze::runTests(packets_, cs);
    report_ = rep.text();
    status_->setText(std::string(followTimer_ ? "LIVE: " : "") +
                     (rep.passed() ? "PASS " : "FAIL ") + std::to_string(packets_.size()) + " pkts");
    if (!rep.passed() && !alerted_) {
        alerted_ = true;
        MessageBeep(MB_ICONWARNING);
        detail_->setText(report_);
    }
}

void MainWindow::showPacket(int index) {
    if (index < 0 || index >= (int)packets_.size()) return;
    const capture::Packet& p = packets_[index];
    analyze::Classification c = analyze::classify(p);

    std::string s = "Packet #" + std::to_string(p.seq) + "\r\n";
    s += p.srcIp + ":" + std::to_string(p.srcPort) + " " + p.dirArrow() + " " + p.dstIp + ":" +
         std::to_string(p.dstPort) + "  " + p.protoName() + "\r\n";
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
    for (char ch : s) {
        if (ch == '\n' && (fixed.empty() || fixed.back() != '\r')) fixed += '\r';
        fixed += ch;
    }
    detail_->setText(fixed);
}

void MainWindow::runTests() {
    if (packets_.empty()) {
        message("Open or follow a capture first.");
        return;
    }
    analyze::Report rep = analyze::runTests(packets_, canaries());
    report_ = rep.text();
    detail_->setText(report_);
    status_->setText(rep.passed() ? "Tests: PASS" : "Tests: FAIL");
}

void MainWindow::saveReport() {
    if (report_.empty()) {
        message("Run the tests first.");
        return;
    }
    std::string path = saveFileDialog("Text files|*.txt|All files|*.*", "txt");
    if (path.empty()) return;
    std::ofstream out(path, std::ios::binary);
    out << report_;
}

void MainWindow::layout(int w, int h) {
    const int m = 12;
    canary_->setBounds(96, 13, std::max(120, w - 96 - 12 - 110 - 110 - 160 - 24), 24);
    int rightX = w - m - 160;
    openButton_->setBounds(rightX - 12 - 110 - 110, 12, 110, 26);
    runButton_->setBounds(rightX - 12 - 110, 12, 110, 26);
    status_->setBounds(rightX, 16, 160, 20);

    int top = 50, bottom = h - m;
    int listW = (w - 2 * m - 8) * 3 / 5;
    list_->setBounds(m, top, listW, bottom - top);
    detail_->setBounds(m + listW + 8, top, w - m - (m + listW + 8), bottom - top);
}
