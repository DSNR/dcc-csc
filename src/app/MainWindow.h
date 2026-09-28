// MainWindow.h - the dcc-csc traffic tester.
#pragma once

#include <set>
#include <string>
#include <vector>

#include "capture/Packet.h"
#include "capture/Ports.h"
#include "gui/Gui.h"
#include "net/Pcap.h"

class MainWindow : public gui::Window {
public:
    MainWindow();

private:
    void openCapture();
    void followCapture();
    void stopFollowing();
    void saveReport();
    void runTests();
    void showPacket(int row);
    void refreshVerdict();

    // process attribution
    void refreshOwners();                 // snapshot the OS port->process table
    bool ownerMatches(const std::string& name) const;
    void recomputeApp();                  // re-evaluate ownership for every packet
    bool appOwned(size_t i) const;
    bool passesFilter(size_t i) const;
    void ingest(const capture::Packet& p); // add one packet + its metadata
    void addRowFor(size_t i);
    void rebuildList();
    std::vector<capture::Packet> displayed() const;

    std::vector<std::string> canaries() const;
    std::vector<std::string> procTokens() const;
    void layout(int w, int h);

    // one entry per captured packet, parallel arrays
    std::vector<capture::Packet> all_;
    std::vector<std::string> owner_;      // owning process image name (may be "")
    std::vector<char> app_;               // 1 if attributed to the process filter
    std::vector<int> rowToAll_;           // list row -> index into all_

    capture::OwnerMap owners_;            // latest snapshot
    std::set<uint16_t> tcpPorts_, udpPorts_; // ports ever seen owned by a match

    std::string report_;
    net::CaptureReader reader_;
    UINT_PTR followTimer_ = 0;
    bool alerted_ = false;

    gui::Label* canaryLabel_;
    gui::TextBox* canary_;
    gui::Button* openButton_;
    gui::Button* runButton_;
    gui::Label* status_;
    gui::Label* appLabel_;
    gui::TextBox* procFilter_;
    gui::CheckBox* appOnly_;
    gui::ListView* list_;
    gui::TextBox* detail_;
};
