#include "app/MainWindow.h"

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    MainWindow window;
    window.show();
    return gui::run();
}
