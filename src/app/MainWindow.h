// MainWindow.h - the dcc traffic tester.
#pragma once

#include <vector>

#include "capture/Packet.h"
#include "gui/Gui.h"
#include "net/Pcap.h"

class MainWindow : public gui::Window {
public:
    MainWindow();

private:
    void openCapture();
    void followCapture();
    void stopFollowing();
    void addPacketRow(const capture::Packet& p);
    void saveReport();
    void runTests();
    void showPacket(int index);
    void refreshVerdict();
    std::vector<std::string> canaries() const;
    void layout(int w, int h);

    std::vector<capture::Packet> packets_;
    std::string report_;

    net::CaptureReader reader_;
    UINT_PTR followTimer_ = 0;
    bool alerted_ = false;

    gui::Label* canaryLabel_;
    gui::TextBox* canary_;
    gui::Button* openButton_;
    gui::Button* runButton_;
    gui::Label* status_;
    gui::ListView* list_;
    gui::TextBox* detail_;
};
