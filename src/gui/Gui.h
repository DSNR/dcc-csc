// Gui.h - a small C++ wrapper around the Win32 API.
//
// Everything takes / returns UTF-8 std::string; conversion to Windows' UTF-16
// happens internally. Positions and sizes are in "logical" pixels (96 DPI) and
// are scaled automatically on high-DPI screens.
//
// Adding a new widget type:
//   1. Derive from gui::Widget.
//   2. In the constructor call create(parent, L"WIN32_CLASS", text, style, exStyle, x, y, w, h).
//   3. Override onCommand(code) to react to WM_COMMAND notifications (BN_CLICKED, EN_CHANGE, ...).
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace gui {

std::wstring widen(const std::string& s);
std::string narrow(const std::wstring& s);

int scale(int logical);    // logical px -> physical px
int unscale(int physical); // physical px -> logical px

class Window;

// ---------------------------------------------------------------- Widget base
class Widget {
public:
    virtual ~Widget() = default;
    Widget(const Widget&) = delete;
    Widget& operator=(const Widget&) = delete;

    HWND handle() const { return hwnd_; }

    void setText(const std::string& text);
    std::string text() const;
    void setBounds(int x, int y, int w, int h);
    void setVisible(bool visible);
    void setEnabled(bool enabled);
    bool enabled() const;
    void focus();

protected:
    Widget() = default;
    void create(Window& parent, const wchar_t* className, const std::string& text,
                DWORD style, DWORD exStyle, int x, int y, int w, int h);

    // Called with the notification code of WM_COMMAND messages sent by this control.
    virtual void onCommand(WORD /*code*/) {}

    HWND hwnd_ = nullptr;
    friend class Window;
};

// ---------------------------------------------------------------- Widgets
class Label : public Widget {
public:
    Label(Window& parent, const std::string& text, int x, int y, int w, int h);
};

class Button : public Widget {
public:
    Button(Window& parent, const std::string& text, int x, int y, int w, int h);
    Button& onClick(std::function<void()> fn) { onClick_ = std::move(fn); return *this; }

protected:
    void onCommand(WORD code) override;

private:
    std::function<void()> onClick_;
};

class CheckBox : public Widget {
public:
    CheckBox(Window& parent, const std::string& text, int x, int y, int w, int h);
    bool checked() const;
    void setChecked(bool checked);
    CheckBox& onToggle(std::function<void(bool)> fn) { onToggle_ = std::move(fn); return *this; }

protected:
    void onCommand(WORD code) override;

private:
    std::function<void(bool)> onToggle_;
};

class TextBox : public Widget {
public:
    TextBox(Window& parent, const std::string& text, int x, int y, int w, int h,
            bool multiline = false);
    void setReadOnly(bool readOnly);
    void append(const std::string& text);     // appends at the end (\n becomes \r\n)
    void appendLine(const std::string& line); // append(line + "\n")
    TextBox& onChange(std::function<void()> fn) { onChange_ = std::move(fn); return *this; }

protected:
    void onCommand(WORD code) override;

private:
    std::function<void()> onChange_;
};

class ListBox : public Widget {
public:
    ListBox(Window& parent, int x, int y, int w, int h);
    int addItem(const std::string& text); // returns the new item's index
    void removeItem(int index);
    void clear();
    int count() const;
    std::string itemText(int index) const;
    int selectedIndex() const; // -1 if nothing selected
    void setSelected(int index);
    ListBox& onSelect(std::function<void(int)> fn) { onSelect_ = std::move(fn); return *this; }
    ListBox& onDoubleClick(std::function<void(int)> fn) { onDoubleClick_ = std::move(fn); return *this; }

protected:
    void onCommand(WORD code) override;

private:
    std::function<void(int)> onSelect_;
    std::function<void(int)> onDoubleClick_;
};

class ComboBox : public Widget {
public:
    ComboBox(Window& parent, int x, int y, int w, int h);
    int addItem(const std::string& text);
    void clear();
    int count() const;
    std::string itemText(int index) const;
    int selectedIndex() const;
    void setSelected(int index);
    ComboBox& onSelect(std::function<void(int)> fn) { onSelect_ = std::move(fn); return *this; }

protected:
    void onCommand(WORD code) override;

private:
    std::function<void(int)> onSelect_;
};

// A report-style ListView: rows of text across named columns. Good for tables
// such as a packet list. Add columns first, then rows.
class ListView : public Widget {
public:
    ListView(Window& parent, int x, int y, int w, int h);
    void addColumn(const std::string& title, int width); // width in logical px
    int addRow(const std::vector<std::string>& cells);    // returns the new row index
    void setCell(int row, int col, const std::string& text);
    std::string cellText(int row, int col) const;
    void clear();
    int count() const;
    int selectedIndex() const; // -1 if nothing selected
    void setSelected(int index);
    void ensureVisible(int index);
    ListView& onSelect(std::function<void(int)> fn) { onSelect_ = std::move(fn); return *this; }

protected:
    // ListView reports selection through WM_NOTIFY, which the parent Window
    // routes here rather than through onCommand.
    void onNotify(NMHDR* hdr);

private:
    int columns_ = 0;
    std::function<void(int)> onSelect_;
    friend class Window;
};

// ---------------------------------------------------------------- Menu
class Menu {
public:
    Menu& item(const std::string& text, std::function<void()> fn);
    Menu& separator();

private:
    Menu(Window& owner, HMENU h) : owner_(owner), h_(h) {}
    Window& owner_;
    HMENU h_;
    friend class Window;
};

// ---------------------------------------------------------------- Window
class Window {
public:
    Window(const std::string& title, int clientWidth, int clientHeight);
    virtual ~Window();
    Window(const Window&) = delete;
    Window& operator=(const Window&) = delete;

    // Create a widget owned by this window:  auto& b = add<Button>("OK", 10, 10, 80, 25);
    template <class T, class... Args>
    T& add(Args&&... args) {
        auto w = std::make_unique<T>(*this, std::forward<Args>(args)...);
        T& ref = *w;
        widgets_.push_back(std::move(w));
        return ref;
    }

    // Top-level menu bar entry, e.g. menu("&File").item("E&xit", [this]{ close(); });
    // Calling again with the same name returns the existing menu.
    Menu& menu(const std::string& name);

    void show();
    void close();
    void setTitle(const std::string& title);
    int clientWidth() const;  // logical px
    int clientHeight() const; // logical px
    HWND handle() const { return hwnd_; }

    // Repeating timer. Returns an id for killTimer().
    UINT_PTR setTimer(int intervalMs, std::function<void()> fn);
    void killTimer(UINT_PTR id);

    // Events
    void onResize(std::function<void(int w, int h)> fn) { onResize_ = std::move(fn); }
    void onClose(std::function<bool()> fn) { onClose_ = std::move(fn); } // return false to cancel

    // Dialogs. Filters look like "Text files|*.txt|All files|*.*". Empty string = cancelled.
    void message(const std::string& text, const std::string& title = "Info");
    void error(const std::string& text, const std::string& title = "Error");
    bool ask(const std::string& text, const std::string& title = "Confirm");
    std::string openFileDialog(const std::string& filter = "All files|*.*");
    std::string saveFileDialog(const std::string& filter = "All files|*.*",
                               const std::string& defaultExt = "");

    // Override for raw access to any Win32 message. Return true if handled.
    virtual bool handleMessage(UINT /*msg*/, WPARAM /*wp*/, LPARAM /*lp*/, LRESULT& /*result*/) {
        return false;
    }

    // Internal: the Win32 window procedure shared by all gui::Window instances.
    static LRESULT CALLBACK windowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

private:
    LRESULT dispatch(UINT msg, WPARAM wp, LPARAM lp);
    UINT registerCommand(std::function<void()> fn);
    std::string fileDialog(bool save, const std::string& filter, const std::string& defaultExt);

    HWND hwnd_ = nullptr;
    HMENU menuBar_ = nullptr;
    int wantedW_, wantedH_;
    UINT nextCommandId_ = 1000;
    UINT_PTR nextTimerId_ = 1;
    std::vector<std::unique_ptr<Widget>> widgets_;
    std::vector<std::pair<std::string, std::unique_ptr<Menu>>> menus_;
    std::unordered_map<UINT, std::function<void()>> commands_;
    std::unordered_map<UINT_PTR, std::function<void()>> timers_;
    std::function<void(int, int)> onResize_;
    std::function<bool()> onClose_;
    friend class Menu;
};

// Runs the message loop until the last window is closed. Returns the exit code.
int run();

} // namespace gui
