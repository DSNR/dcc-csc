#include "gui/Gui.h"

#include <commctrl.h>
#include <commdlg.h>

namespace gui {

namespace {

HFONT g_font = nullptr;
int g_dpi = 96;
int g_openWindows = 0;
const wchar_t* kWindowClass = L"GuiWrapperWindow";

LRESULT CALLBACK windowProcEntry(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

void initOnce() {
    static bool done = false;
    if (done) return;
    done = true;

    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS | ICC_BAR_CLASSES};
    InitCommonControlsEx(&icc);

    HDC dc = GetDC(nullptr);
    g_dpi = GetDeviceCaps(dc, LOGPIXELSX);
    ReleaseDC(nullptr, dc);

    NONCLIENTMETRICSW ncm{};
    ncm.cbSize = sizeof(ncm);
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    g_font = CreateFontIndirectW(&ncm.lfMessageFont);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = windowProcEntry;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = kWindowClass;
    wc.hIcon = LoadIconW(wc.hInstance, MAKEINTRESOURCEW(1));
    if (!wc.hIcon) wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    RegisterClassExW(&wc);
}

} // namespace

// ---------------------------------------------------------------- helpers
std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

std::string narrow(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}

int scale(int logical) { return MulDiv(logical, g_dpi, 96); }
int unscale(int physical) { return MulDiv(physical, 96, g_dpi); }

// ---------------------------------------------------------------- Widget
void Widget::create(Window& parent, const wchar_t* className, const std::string& text,
                    DWORD style, DWORD exStyle, int x, int y, int w, int h) {
    hwnd_ = CreateWindowExW(exStyle, className, widen(text).c_str(), WS_CHILD | WS_VISIBLE | style,
                            scale(x), scale(y), scale(w), scale(h), parent.handle(), nullptr,
                            GetModuleHandleW(nullptr), nullptr);
    SetWindowLongPtrW(hwnd_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    SendMessageW(hwnd_, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
}

void Widget::setText(const std::string& text) { SetWindowTextW(hwnd_, widen(text).c_str()); }

std::string Widget::text() const {
    int len = GetWindowTextLengthW(hwnd_);
    std::wstring buf(len + 1, L'\0');
    GetWindowTextW(hwnd_, buf.data(), len + 1);
    buf.resize(len);
    return narrow(buf);
}

void Widget::setBounds(int x, int y, int w, int h) {
    SetWindowPos(hwnd_, nullptr, scale(x), scale(y), scale(w), scale(h), SWP_NOZORDER | SWP_NOACTIVATE);
}

void Widget::setVisible(bool visible) { ShowWindow(hwnd_, visible ? SW_SHOW : SW_HIDE); }
void Widget::setEnabled(bool enabled) { EnableWindow(hwnd_, enabled); }
bool Widget::enabled() const { return IsWindowEnabled(hwnd_); }
void Widget::focus() { SetFocus(hwnd_); }

// ---------------------------------------------------------------- Label
Label::Label(Window& parent, const std::string& text, int x, int y, int w, int h) {
    create(parent, L"STATIC", text, SS_LEFT | SS_NOPREFIX, 0, x, y, w, h);
}

// ---------------------------------------------------------------- Button
Button::Button(Window& parent, const std::string& text, int x, int y, int w, int h) {
    create(parent, L"BUTTON", text, BS_PUSHBUTTON | WS_TABSTOP, 0, x, y, w, h);
}

void Button::onCommand(WORD code) {
    if (code == BN_CLICKED && onClick_) onClick_();
}

// ---------------------------------------------------------------- CheckBox
CheckBox::CheckBox(Window& parent, const std::string& text, int x, int y, int w, int h) {
    create(parent, L"BUTTON", text, BS_AUTOCHECKBOX | WS_TABSTOP, 0, x, y, w, h);
}

bool CheckBox::checked() const { return SendMessageW(hwnd_, BM_GETCHECK, 0, 0) == BST_CHECKED; }
void CheckBox::setChecked(bool c) { SendMessageW(hwnd_, BM_SETCHECK, c ? BST_CHECKED : BST_UNCHECKED, 0); }

void CheckBox::onCommand(WORD code) {
    if (code == BN_CLICKED && onToggle_) onToggle_(checked());
}

// ---------------------------------------------------------------- TextBox
TextBox::TextBox(Window& parent, const std::string& text, int x, int y, int w, int h, bool multiline) {
    DWORD style = WS_TABSTOP;
    style |= multiline ? (ES_MULTILINE | ES_WANTRETURN | ES_AUTOVSCROLL | WS_VSCROLL) : ES_AUTOHSCROLL;
    create(parent, L"EDIT", text, style, WS_EX_CLIENTEDGE, x, y, w, h);
}

void TextBox::setReadOnly(bool readOnly) { SendMessageW(hwnd_, EM_SETREADONLY, readOnly, 0); }

void TextBox::append(const std::string& text) {
    std::string fixed;
    fixed.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n' && (i == 0 || text[i - 1] != '\r')) fixed += '\r';
        fixed += text[i];
    }
    int len = GetWindowTextLengthW(hwnd_);
    SendMessageW(hwnd_, EM_SETSEL, len, len);
    SendMessageW(hwnd_, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(widen(fixed).c_str()));
}

void TextBox::appendLine(const std::string& line) { append(line + "\n"); }

void TextBox::onCommand(WORD code) {
    if (code == EN_CHANGE && onChange_) onChange_();
}

// ---------------------------------------------------------------- ListBox
ListBox::ListBox(Window& parent, int x, int y, int w, int h) {
    create(parent, L"LISTBOX", "", LBS_NOTIFY | LBS_NOINTEGRALHEIGHT | WS_VSCROLL | WS_TABSTOP,
           WS_EX_CLIENTEDGE, x, y, w, h);
}

int ListBox::addItem(const std::string& text) {
    return (int)SendMessageW(hwnd_, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(text).c_str()));
}
void ListBox::removeItem(int index) { SendMessageW(hwnd_, LB_DELETESTRING, index, 0); }
void ListBox::clear() { SendMessageW(hwnd_, LB_RESETCONTENT, 0, 0); }
int ListBox::count() const { return (int)SendMessageW(hwnd_, LB_GETCOUNT, 0, 0); }
int ListBox::selectedIndex() const { return (int)SendMessageW(hwnd_, LB_GETCURSEL, 0, 0); }
void ListBox::setSelected(int index) { SendMessageW(hwnd_, LB_SETCURSEL, index, 0); }

std::string ListBox::itemText(int index) const {
    int len = (int)SendMessageW(hwnd_, LB_GETTEXTLEN, index, 0);
    if (len < 0) return {};
    std::wstring buf(len + 1, L'\0');
    SendMessageW(hwnd_, LB_GETTEXT, index, reinterpret_cast<LPARAM>(buf.data()));
    buf.resize(len);
    return narrow(buf);
}

void ListBox::onCommand(WORD code) {
    if (code == LBN_SELCHANGE && onSelect_) onSelect_(selectedIndex());
    if (code == LBN_DBLCLK && onDoubleClick_) onDoubleClick_(selectedIndex());
}

// ---------------------------------------------------------------- ComboBox
ComboBox::ComboBox(Window& parent, int x, int y, int w, int h) {
    // The height of a combo box includes its drop-down list, so give it room.
    create(parent, L"COMBOBOX", "", CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 0, x, y, w, h + 200);
}

int ComboBox::addItem(const std::string& text) {
    return (int)SendMessageW(hwnd_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(text).c_str()));
}
void ComboBox::clear() { SendMessageW(hwnd_, CB_RESETCONTENT, 0, 0); }
int ComboBox::count() const { return (int)SendMessageW(hwnd_, CB_GETCOUNT, 0, 0); }
int ComboBox::selectedIndex() const { return (int)SendMessageW(hwnd_, CB_GETCURSEL, 0, 0); }
void ComboBox::setSelected(int index) { SendMessageW(hwnd_, CB_SETCURSEL, index, 0); }

std::string ComboBox::itemText(int index) const {
    int len = (int)SendMessageW(hwnd_, CB_GETLBTEXTLEN, index, 0);
    if (len < 0) return {};
    std::wstring buf(len + 1, L'\0');
    SendMessageW(hwnd_, CB_GETLBTEXT, index, reinterpret_cast<LPARAM>(buf.data()));
    buf.resize(len);
    return narrow(buf);
}

void ComboBox::onCommand(WORD code) {
    if (code == CBN_SELCHANGE && onSelect_) onSelect_(selectedIndex());
}

// ---------------------------------------------------------------- ListView
ListView::ListView(Window& parent, int x, int y, int w, int h) {
    create(parent, WC_LISTVIEWW, "", LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | WS_TABSTOP,
           WS_EX_CLIENTEDGE, x, y, w, h);
    ListView_SetExtendedListViewStyle(hwnd_, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

void ListView::addColumn(const std::string& title, int width) {
    LVCOLUMNW col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    std::wstring w = widen(title);
    col.pszText = w.data();
    col.cx = scale(width);
    col.iSubItem = columns_;
    ListView_InsertColumn(hwnd_, columns_, &col);
    ++columns_;
}

int ListView::addRow(const std::vector<std::string>& cells) {
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(hwnd_);
    std::wstring first = cells.empty() ? L"" : widen(cells[0]);
    item.pszText = first.data();
    int row = ListView_InsertItem(hwnd_, &item);
    for (size_t c = 1; c < cells.size(); ++c) setCell(row, (int)c, cells[c]);
    return row;
}

void ListView::setCell(int row, int col, const std::string& text) {
    std::wstring w = widen(text);
    ListView_SetItemText(hwnd_, row, col, w.data());
}

std::string ListView::cellText(int row, int col) const {
    wchar_t buf[1024];
    ListView_GetItemText(hwnd_, row, col, buf, 1024);
    return narrow(buf);
}

void ListView::clear() { ListView_DeleteAllItems(hwnd_); }
int ListView::count() const { return ListView_GetItemCount(hwnd_); }
int ListView::selectedIndex() const { return ListView_GetNextItem(hwnd_, -1, LVNI_SELECTED); }

void ListView::setSelected(int index) {
    ListView_SetItemState(hwnd_, index, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
}

void ListView::ensureVisible(int index) { ListView_EnsureVisible(hwnd_, index, FALSE); }

void ListView::onNotify(NMHDR* hdr) {
    if (hdr->code == LVN_ITEMCHANGED) {
        auto* nm = reinterpret_cast<NMLISTVIEW*>(hdr);
        if ((nm->uNewState & LVIS_SELECTED) && onSelect_) onSelect_(nm->iItem);
    }
}

// ---------------------------------------------------------------- Menu
Menu& Menu::item(const std::string& text, std::function<void()> fn) {
    UINT id = owner_.registerCommand(std::move(fn));
    AppendMenuW(h_, MF_STRING, id, widen(text).c_str());
    DrawMenuBar(owner_.handle());
    return *this;
}

Menu& Menu::separator() {
    AppendMenuW(h_, MF_SEPARATOR, 0, nullptr);
    return *this;
}

// ---------------------------------------------------------------- Window
Window::Window(const std::string& title, int clientWidth, int clientHeight)
    : wantedW_(clientWidth), wantedH_(clientHeight) {
    initOnce();
    RECT r{0, 0, scale(clientWidth), scale(clientHeight)};
    AdjustWindowRectEx(&r, WS_OVERLAPPEDWINDOW, FALSE, 0);
    // `this` is passed through lpCreateParams and picked up in WM_NCCREATE.
    CreateWindowExW(0, kWindowClass, widen(title).c_str(), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                    CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top, nullptr,
                    nullptr, GetModuleHandleW(nullptr), this);
    ++g_openWindows;
}

Window::~Window() {
    if (hwnd_) DestroyWindow(hwnd_);
}

UINT Window::registerCommand(std::function<void()> fn) {
    UINT id = nextCommandId_++;
    commands_[id] = std::move(fn);
    return id;
}

Menu& Window::menu(const std::string& name) {
    for (auto& [n, m] : menus_)
        if (n == name) return *m;

    bool first = (menuBar_ == nullptr);
    if (first) menuBar_ = CreateMenu();
    HMENU popup = CreatePopupMenu();
    AppendMenuW(menuBar_, MF_POPUP, reinterpret_cast<UINT_PTR>(popup), widen(name).c_str());
    if (first) {
        SetMenu(hwnd_, menuBar_);
        // Keep the requested client size now that the menu bar takes space.
        RECT r{0, 0, scale(wantedW_), scale(wantedH_)};
        AdjustWindowRectEx(&r, WS_OVERLAPPEDWINDOW, TRUE, 0);
        SetWindowPos(hwnd_, nullptr, 0, 0, r.right - r.left, r.bottom - r.top, SWP_NOMOVE | SWP_NOZORDER);
    }
    DrawMenuBar(hwnd_);
    menus_.emplace_back(name, std::unique_ptr<Menu>(new Menu(*this, popup)));
    return *menus_.back().second;
}

void Window::show() {
    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);
}

void Window::close() {
    if (hwnd_) PostMessageW(hwnd_, WM_CLOSE, 0, 0);
}

void Window::setTitle(const std::string& title) { SetWindowTextW(hwnd_, widen(title).c_str()); }

int Window::clientWidth() const {
    RECT r;
    GetClientRect(hwnd_, &r);
    return unscale(r.right);
}

int Window::clientHeight() const {
    RECT r;
    GetClientRect(hwnd_, &r);
    return unscale(r.bottom);
}

UINT_PTR Window::setTimer(int intervalMs, std::function<void()> fn) {
    UINT_PTR id = nextTimerId_++;
    timers_[id] = std::move(fn);
    SetTimer(hwnd_, id, intervalMs, nullptr);
    return id;
}

void Window::killTimer(UINT_PTR id) {
    KillTimer(hwnd_, id);
    timers_.erase(id);
}

void Window::message(const std::string& text, const std::string& title) {
    MessageBoxW(hwnd_, widen(text).c_str(), widen(title).c_str(), MB_OK | MB_ICONINFORMATION);
}

void Window::error(const std::string& text, const std::string& title) {
    MessageBoxW(hwnd_, widen(text).c_str(), widen(title).c_str(), MB_OK | MB_ICONERROR);
}

bool Window::ask(const std::string& text, const std::string& title) {
    return MessageBoxW(hwnd_, widen(text).c_str(), widen(title).c_str(), MB_YESNO | MB_ICONQUESTION) == IDYES;
}

std::string Window::openFileDialog(const std::string& filter) { return fileDialog(false, filter, ""); }

std::string Window::saveFileDialog(const std::string& filter, const std::string& defaultExt) {
    return fileDialog(true, filter, defaultExt);
}

std::string Window::fileDialog(bool save, const std::string& filter, const std::string& defaultExt) {
    std::wstring wfilter = widen(filter);
    for (auto& c : wfilter)
        if (c == L'|') c = L'\0';
    wfilter.push_back(L'\0');
    wfilter.push_back(L'\0');
    std::wstring wext = widen(defaultExt);

    wchar_t path[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = wfilter.c_str();
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = wext.empty() ? nullptr : wext.c_str();
    ofn.Flags = OFN_EXPLORER | OFN_NOCHANGEDIR |
                (save ? OFN_OVERWRITEPROMPT : (OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST));
    BOOL ok = save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
    return ok ? narrow(path) : std::string{};
}

namespace {
LRESULT CALLBACK windowProcEntry(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    return Window::windowProc(hwnd, msg, wp, lp);
}
} // namespace

LRESULT CALLBACK Window::windowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        auto* self = static_cast<Window*>(cs->lpCreateParams);
        self->hwnd_ = hwnd;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    auto* self = reinterpret_cast<Window*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (self) return self->dispatch(msg, wp, lp);
    return DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT Window::dispatch(UINT msg, WPARAM wp, LPARAM lp) {
    LRESULT result = 0;
    if (handleMessage(msg, wp, lp, result)) return result;

    switch (msg) {
    case WM_COMMAND:
        if (lp) { // from a control
            auto* w = reinterpret_cast<Widget*>(GetWindowLongPtrW(reinterpret_cast<HWND>(lp), GWLP_USERDATA));
            if (w) w->onCommand(HIWORD(wp));
        } else { // from a menu
            auto it = commands_.find(LOWORD(wp));
            if (it != commands_.end() && it->second) it->second();
        }
        return 0;
    case WM_NOTIFY: {
        auto* hdr = reinterpret_cast<NMHDR*>(lp);
        auto* w = reinterpret_cast<Widget*>(GetWindowLongPtrW(hdr->hwndFrom, GWLP_USERDATA));
        if (auto* lv = dynamic_cast<ListView*>(w)) lv->onNotify(hdr);
        return 0;
    }
    case WM_TIMER: {
        auto it = timers_.find(wp);
        if (it != timers_.end() && it->second) it->second();
        return 0;
    }
    case WM_SIZE:
        if (onResize_) onResize_(unscale(LOWORD(lp)), unscale(HIWORD(lp)));
        return 0;
    case WM_CLOSE:
        if (onClose_ && !onClose_()) return 0;
        DestroyWindow(hwnd_);
        return 0;
    case WM_DESTROY: {
        HWND h = hwnd_;
        SetWindowLongPtrW(h, GWLP_USERDATA, 0);
        hwnd_ = nullptr;
        if (--g_openWindows == 0) PostQuitMessage(0);
        return DefWindowProcW(h, msg, wp, lp);
    }
    }
    return DefWindowProcW(hwnd_, msg, wp, lp);
}

// ---------------------------------------------------------------- run
int run() {
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        // Gives Tab / Shift+Tab keyboard navigation between controls.
        HWND root = GetAncestor(msg.hwnd, GA_ROOT);
        if (root && IsDialogMessageW(root, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

} // namespace gui
