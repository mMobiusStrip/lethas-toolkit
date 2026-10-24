#include "ui/app.h"

#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstring>
#include <filesystem>

#include "core/arp_monitor.h"
#include "core/common.h"
#include "core/i18n.h"
#include "core/ip_scanner.h"
#include "core/net_tests.h"
#include "core/port_scanner.h"
#include "imgui.h"

namespace ui {
namespace {

using namespace lt;

constexpr const char* kVersion = "0.3.0";

// ---------------------------------------------------------------- tema ----
// Renkler tmog.org (koyu tema) paletinden; metin renkleri okunabilirlik için açıldı.
ImVec4 hex(uint32_t rgb, float a = 1.f) {
    return {((rgb >> 16) & 255) / 255.f, ((rgb >> 8) & 255) / 255.f, (rgb & 255) / 255.f, a};
}
ImVec4 mix(ImVec4 a, ImVec4 b, float t) {
    return {a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, a.z + (b.z - a.z) * t, 1.f};
}
ImVec4 alpha(ImVec4 c, float a) { c.w = a; return c; }
ImU32 U(ImVec4 c) { return ImGui::GetColorU32(c); }

const ImVec4 kInk = hex(0x070b0f), kInk2 = hex(0x0b1117), kPanel = hex(0x0e151c),
             kRaised = hex(0x111a22), kText = hex(0xf4f9fc), kMuted = hex(0xb9c7d1),
             kMuted2 = hex(0x8a9ba8), kLine = ImVec4(164 / 255.f, 204 / 255.f, 224 / 255.f, 0.18f),
             kGreen = hex(0x45ed73), kYellow = hex(0xffe016), kRed = hex(0xff4f55),
             kBrand = hex(0x16c5ff);

struct Theme { const char* name; uint32_t accent; };
constexpr Theme kThemes[] = {
    {"Cyan", 0x16c5ff}, {"Blue", 0x3e8eff}, {"Green", 0x45ed73}, {"Amber", 0xffb336}, {"Mono", 0xd2dadf},
};

ImVec4 gAccent;

void applyTheme(int idx) {
    gAccent = hex(kThemes[idx].accent);
    ImVec4* c = ImGui::GetStyle().Colors;
    c[ImGuiCol_Text] = kText;
    c[ImGuiCol_TextDisabled] = kMuted2;
    c[ImGuiCol_WindowBg] = kInk;
    c[ImGuiCol_ChildBg] = kPanel;
    c[ImGuiCol_PopupBg] = kRaised;
    c[ImGuiCol_Border] = kLine;
    c[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg] = kRaised;
    c[ImGuiCol_FrameBgHovered] = mix(kRaised, gAccent, 0.15f);
    c[ImGuiCol_FrameBgActive] = mix(kRaised, gAccent, 0.25f);
    c[ImGuiCol_TitleBg] = kInk2;
    c[ImGuiCol_TitleBgActive] = kInk2;
    c[ImGuiCol_MenuBarBg] = kInk2;
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab] = alpha(kMuted2, 0.6f);
    c[ImGuiCol_ScrollbarGrabHovered] = kMuted2;
    c[ImGuiCol_ScrollbarGrabActive] = kMuted;
    c[ImGuiCol_CheckMark] = gAccent;
    c[ImGuiCol_SliderGrab] = gAccent;
    c[ImGuiCol_SliderGrabActive] = mix(gAccent, kText, 0.3f);
    c[ImGuiCol_Button] = kRaised;
    c[ImGuiCol_ButtonHovered] = mix(kRaised, gAccent, 0.22f);
    c[ImGuiCol_ButtonActive] = mix(kRaised, gAccent, 0.38f);
    c[ImGuiCol_Header] = alpha(gAccent, 0.18f);
    c[ImGuiCol_HeaderHovered] = alpha(gAccent, 0.10f);
    c[ImGuiCol_HeaderActive] = alpha(gAccent, 0.26f);
    c[ImGuiCol_Separator] = kLine;
    c[ImGuiCol_PlotHistogram] = gAccent;
    c[ImGuiCol_TableHeaderBg] = kInk2;
    c[ImGuiCol_TableBorderStrong] = kLine;
    c[ImGuiCol_TableBorderLight] = alpha(kLine, 0.08f);
    c[ImGuiCol_TableRowBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt] = ImVec4(1, 1, 1, 0.025f);
    c[ImGuiCol_TextSelectedBg] = alpha(gAccent, 0.3f);
}

ImFont *gMono = nullptr, *gBold = nullptr, *gTitle = nullptr;

// ------------------------------------------------------------- durum ------
enum class Page { IpScan, Ports, Arp, Tests };

struct State {
    Page page = Page::IpScan;
    int theme = 0;
    bool quit = false;
    bool showAbout = false, showGuide = false;
    std::string status;
    double statusUntil = 0;

    // IP Scanner
    char range[128] = "";
    IpScanner ips;
    IpScanOptions ipOpt;
    std::string ipErr;
    uint32_t selectedIp = 0;

    // Port Scanner
    char pHost[128] = "127.0.0.1";
    int pFirst = 1, pLast = 1024, pThreads = 128, pTimeout = 400;
    PortScanner ports;
    std::string pErr;

    // ARP
    ArpMonitor arp;
    std::vector<CaptureAdapter> adapters;
    int adIdx = 0;
    std::string arpErr;
    bool adaptersLoaded = false;
    std::vector<ArpEvent> arpCache;
    size_t arpCachedCount = SIZE_MAX;

    // Network Tests
    char tHost[128] = "8.8.8.8";
    NetTests tests;
};

State& S() {
    static State s;
    return s;
}

void setStatus(const std::string& msg) {
    S().status = msg;
    S().statusUntil = ImGui::GetTime() + 6.0;
}

// ------------------------------------------------------- yardımcılar ------
void tip(const char* text) {
    if (!ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort | ImGuiHoveredFlags_AllowWhenDisabled)) return;
    ImGui::BeginTooltip();
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 24.f);
    ImGui::TextUnformatted(T(text));
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
}

bool accentButton(const char* label, bool danger = false, ImVec2 size = {0, 0}) {
    ImVec4 base = danger ? kRed : gAccent;
    ImGui::PushStyleColor(ImGuiCol_Button, base);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, mix(base, ImVec4(1, 1, 1, 1), 0.2f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, mix(base, kInk, 0.25f));
    ImGui::PushStyleColor(ImGuiCol_Text, kInk);
    ImGui::PushFont(gBold);
    bool r = ImGui::Button(T(label), size);
    ImGui::PopFont();
    ImGui::PopStyleColor(4);
    return r;
}

// Tıklanınca örnek değer dolduran küçük etiket.
bool chip(const char* label) {
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, {9, 3});
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 12);
    ImGui::PushStyleColor(ImGuiCol_Button, alpha(gAccent, 0.12f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, alpha(gAccent, 0.28f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, alpha(gAccent, 0.42f));
    ImGui::PushStyleColor(ImGuiCol_Text, mix(gAccent, kText, 0.25f));
    bool r = ImGui::Button(T(label));
    ImGui::PopStyleColor(4);
    ImGui::PopStyleVar(2);
    return r;
}

// Parlayan durum LED'i.
void dot(ImVec4 color, bool glow = true, float yOff = 0.f) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    p.y += yOff;
    float h = ImGui::GetTextLineHeight();
    float r = h * 0.26f;
    ImVec2 c{p.x + r * 2.f, p.y + h * 0.5f};
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (glow) {
        dl->AddCircleFilled(c, r * 2.1f, U(alpha(color, 0.10f)));
        dl->AddCircleFilled(c, r * 1.5f, U(alpha(color, 0.18f)));
    }
    dl->AddCircleFilled(c, r, U(color));
    ImGui::Dummy({r * 4.f, h});
}

// tmog.org tarzı segmentli LED çubuğu (ilerleme göstergesi).
void ledBar(float frac, bool running, ImVec4 color, int leds = 28) {
    frac = std::clamp(frac, 0.f, 1.f);
    const float fs = ImGui::GetFontSize();
    const float cw = fs * 0.46f, gap = fs * 0.17f, h = fs * 0.95f;
    ImVec2 p = ImGui::GetCursorScreenPos();
    p.y += ImGui::GetStyle().FramePadding.y + (ImGui::GetTextLineHeight() - h) * 0.5f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    int lit = static_cast<int>(frac * leds + 0.0001f);
    float pulse = 0.45f + 0.55f * (0.5f + 0.5f * std::sin(float(ImGui::GetTime()) * 8.f));
    for (int i = 0; i < leds; ++i) {
        ImVec2 a{p.x + i * (cw + gap), p.y}, b{a.x + cw, a.y + h};
        if (i < lit) {
            dl->AddRectFilled({a.x - 1.5f, a.y - 1.5f}, {b.x + 1.5f, b.y + 1.5f}, U(alpha(color, 0.14f)), 3.f);
            dl->AddRectFilled(a, b, U(color), 2.f);
        } else if (running && i == lit) {
            dl->AddRectFilled(a, b, U(alpha(color, 0.25f + 0.6f * pulse)), 2.f);
        } else {
            dl->AddRectFilled(a, b, U(mix(kInk2, kMuted2, 0.22f)), 2.f);
        }
    }
    ImGui::Dummy({leds * (cw + gap), ImGui::GetTextLineHeight()});
}

void muted(const char* t) { ImGui::TextColored(kMuted, "%s", T(t)); }

void sectionTitle(const char* title) {
    ImGui::PushFont(gTitle);
    ImGui::TextColored(gAccent, "%s", T(title));
    ImGui::PopFont();
}

// Sayfa üstü açıklaması: ne işe yarar + örnek.
void intro(const char* text) {
    ImGui::PushTextWrapPos(0);
    ImGui::TextColored(kMuted, "%s", T(text));
    ImGui::PopTextWrapPos();
}

void tryLabel() {
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(kMuted2, T("Try:"));
    ImGui::SameLine();
}

void drawLogo(ImDrawList* dl, ImVec2 p, float size) {
    const float s = size / 256.f;
    auto pt = [&](float x, float y) { return ImVec2{p.x + x * s, p.y + y * s}; };
    ImVec2 c = pt(128, 128);
    dl->AddRectFilled(pt(8, 8), pt(248, 248), U(kInk2), 56 * s);
    dl->AddRect(pt(8, 8), pt(248, 248), U(alpha(kBrand, 0.35f)), 56 * s, 0, std::max(1.f, 3 * s));
    dl->AddCircle(c, 84 * s, U(alpha(kBrand, 0.90f)), 48, std::max(1.5f, 6 * s));
    dl->AddCircle(c, 56 * s, U(alpha(kBrand, 0.55f)), 40, std::max(1.2f, 5 * s));
    dl->AddCircle(c, 28 * s, U(alpha(kBrand, 0.30f)), 32, std::max(1.f, 4 * s));
    constexpr float kPi = 3.14159265f;
    const float a1 = -kPi / 2, a2 = -20.f * kPi / 180.f;
    dl->PathLineTo(c);
    dl->PathArcTo(c, 84 * s, a1, a2, 24);
    dl->PathFillConvex(U(alpha(kBrand, 0.26f)));
    dl->AddLine(c, pt(206.93f, 99.27f), U(kBrand), std::max(1.2f, 5 * s));
    dl->AddCircleFilled(pt(176, 84), 17 * s, U(alpha(kGreen, 0.18f)));
    dl->AddCircleFilled(pt(176, 84), 9 * s, U(kGreen));
    dl->AddCircleFilled(pt(82, 152), 7 * s, U(kBrand));
    dl->AddCircleFilled(pt(152, 188), 7 * s, U(kYellow));
    dl->AddCircleFilled(c, 10 * s, U(kText));
}

void drawLog(const char* id, TextLog& log, ImVec2 size) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kInk2);
    ImGui::BeginChild(id, size, ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
    if (gMono) ImGui::PushFont(gMono);
    bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2.f;
    {
        std::lock_guard lk(log.mutex());
        const auto& l = log.lines();
        ImGuiListClipper clip;
        clip.Begin(static_cast<int>(l.size()));
        while (clip.Step())
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) ImGui::TextUnformatted(l[i].c_str());
        static std::pair<const void*, size_t> last{nullptr, 0};
        if (last.first != &log || last.second != l.size()) {
            if (atBottom) ImGui::SetScrollHereY(1.f);
            last = {&log, l.size()};
        }
    }
    if (gMono) ImGui::PopFont();
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

void openShell(const char* file, const std::string& args = {}) {
    ShellExecuteA(nullptr, "open", file, args.empty() ? nullptr : args.c_str(), nullptr, SW_SHOWNORMAL);
}

bool parseRange(std::string s, uint32_t& a, uint32_t& b) {
    s = trim(s);
    if (parseCidr(s, a, b)) return true;
    auto dash = s.find('-');
    if (dash == std::string::npos) {
        if (!parseIPv4(s, a)) return false;
        b = a;
        return true;
    }
    std::string l = trim(s.substr(0, dash)), r = trim(s.substr(dash + 1));
    if (!parseIPv4(l, a)) return false;
    if (r.find('.') == std::string::npos) {  // "192.168.1.1-254" kısayolu
        int n;
        try { n = std::stoi(r); } catch (...) { return false; }
        if (n < 0 || n > 255) return false;
        b = (a & 0xFFFFFF00u) | static_cast<uint32_t>(n);
    } else if (!parseIPv4(r, b)) {
        return false;
    }
    return a <= b;
}

std::string rangeToString(uint32_t a, uint32_t b) {
    if ((a & 0xFFFFFF00u) == (b & 0xFFFFFF00u)) return ipToString(a) + "-" + std::to_string(b & 255);
    return ipToString(a) + " - " + ipToString(b);
}

void copyText(const std::string& t, const char* what) {
    ImGui::SetClipboardText(t.c_str());
    setStatus(fmt(T("%s copied: %s"), T(what), t.c_str()));
}

void goTests(const std::string& ip, int action) {
    State& s = S();
    s.page = Page::Tests;
    std::snprintf(s.tHost, sizeof s.tHost, "%s", ip.c_str());
    if (s.tests.running()) return;
    if (action == 0) s.tests.ping(ip);
    else s.tests.traceroute(ip);
}

void goPorts(const std::string& ip) {
    State& s = S();
    s.page = Page::Ports;
    std::snprintf(s.pHost, sizeof s.pHost, "%s", ip.c_str());
}

// ------------------------------------------------------------ sayfalar ----
void pageIpScan() {
    State& s = S();
    const bool running = s.ips.running();

    sectionTitle("IP SCANNER");
    intro("Finds every device that is switched on in an address range - a roll call for your network. "
          "You get each device's name, MAC address and how fast it answers. Right-click a device for more actions.");
    tryLabel();
    if (chip("192.168.1.1-254")) std::snprintf(s.range, sizeof s.range, "192.168.1.1-254");
    tip("Scans 254 addresses (.1 to .254). The usual size of a home or office network.");
    ImGui::SameLine();
    if (chip("10.0.0.0/24")) std::snprintf(s.range, sizeof s.range, "10.0.0.0/24");
    tip("Same idea written as CIDR: the first 24 bits are the network, so .1 to .254.");
    ImGui::SameLine();
    if (chip("192.168.1.1-192.168.2.254")) std::snprintf(s.range, sizeof s.range, "192.168.1.1 - 192.168.2.254");
    tip("Scans two networks in one go (508 addresses).");
    ImGui::Spacing();

    float btnW = ImGui::CalcTextSize(T("Local subnet")).x + ImGui::GetStyle().FramePadding.x * 2;
    float scanW = ImGui::GetFontSize() * 5.5f;
    float sp = ImGui::GetStyle().ItemSpacing.x;
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - btnW - scanW - sp * 2);
    bool enter = ImGui::InputTextWithHint("##range", T("Type a range, e.g. 192.168.1.1-254"), s.range, sizeof s.range,
                                          ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button(T("Local subnet"))) {
        uint32_t a, b;
        if (localSubnet(a, b)) std::snprintf(s.range, sizeof s.range, "%s", rangeToString(a, b).c_str());
        else setStatus(T("No active network adapter found."));
    }
    tip("Fills in the network this PC is connected to, so you don't have to type it.");
    ImGui::SameLine();
    if (running) {
        if (accentButton("Stop", true, {scanW, 0})) s.ips.requestStop();
    } else if (accentButton("Scan", false, {scanW, 0}) || enter) {
        uint32_t a, b;
        s.ipErr.clear();
        if (!parseRange(s.range, a, b)) s.ipErr = T("Invalid range. Examples: 192.168.1.1-254 or 192.168.1.0/24");
        else if (s.ips.start(a, b, s.ipOpt, s.ipErr)) s.selectedIp = 0;
    }

    ImGui::BeginDisabled(running);
    ImGui::Checkbox(T("Resolve names"), &s.ipOpt.resolveNames);
    tip("Looks up the computer name of each device (for example DESKTOP-4F2A or printer.lan). Slightly slower.");
    ImGui::SameLine();
    ImGui::Checkbox(T("ARP probe"), &s.ipOpt.arpProbe);
    tip("Some devices (phones, PCs with a firewall) ignore ping. ARP finds them anyway, "
        "but only inside your own subnet. They appear as 'ARP only'.");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 9);
    ImGui::SliderInt(T("Threads"), &s.ipOpt.threads, 8, 256);
    tip("How many addresses are checked at the same time. 64 is fast and safe; raise it for very large ranges.");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 9);
    ImGui::SliderInt(T("Timeout"), &s.ipOpt.timeoutMs, 200, 3000, "%d ms");
    tip("How long to wait for each reply. Use 1500 ms or more on slow or Wi-Fi networks.");
    ImGui::EndDisabled();

    if (!s.ipErr.empty()) ImGui::TextColored(kRed, "%s", s.ipErr.c_str());

    auto rows = s.ips.results();
    const float statusH = ImGui::GetFrameHeight() + ImGui::GetStyle().ItemSpacing.y * 2;
    ImVec2 tsize(0, ImGui::GetContentRegionAvail().y - statusH);

    constexpr ImGuiTableFlags tf = ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable |
                                   ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                   ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_Hideable;
    if (ImGui::BeginTable("hosts", 6, tf, tsize)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn(T("Status"), ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 6.8f);
        ImGui::TableSetupColumn(T("Name"), ImGuiTableColumnFlags_WidthStretch, 1.8f);
        ImGui::TableSetupColumn(T("IP"), ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort,
                                ImGui::GetFontSize() * 9.f);
        ImGui::TableSetupColumn(T("MAC address"), ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 11.f);
        ImGui::TableSetupColumn(T("Latency"), ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 6.f);
        ImGui::TableSetupColumn(T("OS (TTL guess)"), ImGuiTableColumnFlags_WidthStretch, 1.5f);
        ImGui::TableHeadersRow();

        if (ImGuiTableSortSpecs* sp2 = ImGui::TableGetSortSpecs(); sp2 && sp2->SpecsCount > 0) {
            auto col = sp2->Specs[0].ColumnIndex;
            bool asc = sp2->Specs[0].SortDirection == ImGuiSortDirection_Ascending;
            std::stable_sort(rows.begin(), rows.end(), [&](const HostRow& a, const HostRow& b) {
                int c = 0;
                switch (col) {
                    case 0: c = int(a.icmp) - int(b.icmp); break;
                    case 1: c = a.hostname.compare(b.hostname); break;
                    case 2: c = a.ip < b.ip ? -1 : a.ip > b.ip; break;
                    case 3: c = a.mac.compare(b.mac); break;
                    case 4: c = a.rttMs < b.rttMs ? -1 : a.rttMs > b.rttMs; break;
                    case 5: c = a.os.compare(b.os); break;
                }
                return asc ? c < 0 : c > 0;
            });
        }

        for (const HostRow& r : rows) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(static_cast<int>(r.ip));
            bool sel = s.selectedIp == r.ip;
            if (ImGui::Selectable("##row", sel,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap))
                s.selectedIp = r.ip;
            const std::string ip = ipToString(r.ip);
            if (ImGui::BeginPopupContextItem("ctx")) {
                s.selectedIp = r.ip;
                ImGui::PushFont(gBold);
                ImGui::TextColored(gAccent, "%s", ip.c_str());
                ImGui::PopFont();
                ImGui::Separator();
                if (ImGui::MenuItem(T("Ping"), T("is it reachable?"))) goTests(ip, 0);
                if (ImGui::MenuItem(T("Traceroute"), T("route to it"))) goTests(ip, 1);
                if (ImGui::MenuItem(T("Scan ports..."), T("e.g. is 80 / 3389 open?"))) goPorts(ip);
                ImGui::Separator();
                if (ImGui::MenuItem(T("Open shared folders"), ("\\\\" + ip).c_str())) openShell(("\\\\" + ip).c_str());
                if (ImGui::MenuItem(T("Remote desktop"), T("mstsc /v:ip"))) openShell("mstsc.exe", "/v:" + ip);
                if (ImGui::MenuItem(T("Open in browser"), ("http://" + ip).c_str())) openShell(("http://" + ip).c_str());
                ImGui::Separator();
                if (ImGui::MenuItem(T("Copy IP"), ip.c_str())) copyText(ip, "IP");
                if (ImGui::MenuItem(T("Copy MAC"), r.mac.c_str(), false, r.mac != "-")) copyText(r.mac, "MAC");
                ImGui::EndPopup();
            }
            ImGui::SameLine(0, 0);
            dot(r.icmp ? kGreen : kYellow);
            ImGui::SameLine();
            ImGui::TextColored(r.icmp ? kGreen : kYellow, "%s", r.icmp ? T("alive") : T("ARP only"));
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(r.hostname.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(ip.c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(r.mac.c_str());
            ImGui::TableSetColumnIndex(4);
            if (r.icmp) ImGui::Text(T("%.1f ms"), r.rttMs);
            else ImGui::TextDisabled("-");
            ImGui::TableSetColumnIndex(5);
            if (r.icmp) ImGui::Text(T("%s  (%d)"), r.os.c_str(), r.ttl);
            else ImGui::TextDisabled("-");
            ImGui::PopID();
        }
        if (rows.empty()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(kMuted2, "%s", running ? T("Scanning...") : T("No results yet - press Scan."));
        }
        ImGui::EndTable();
    }

    // durum çubuğu (alive / dead / unknown + LED ilerleme)
    uint64_t total = s.ips.total(), done = s.ips.done();
    uint64_t alive = rows.size();
    uint64_t dead = done > alive ? done - alive : 0;
    uint64_t unknown = total > done ? total - done : 0;
    ImGui::AlignTextToFramePadding();
    const float fy = ImGui::GetStyle().FramePadding.y;
    dot(kGreen, true, fy); ImGui::SameLine(); ImGui::Text(T("%llu alive"), alive);
    tip("Devices that answered.");
    ImGui::SameLine(0, 18); dot(kRed, true, fy); ImGui::SameLine(); ImGui::Text(T("%llu dead"), dead);
    tip("Addresses that did not answer (nobody home, or hidden by a firewall).");
    ImGui::SameLine(0, 18); dot(kMuted2, false, fy); ImGui::SameLine(); ImGui::Text(T("%llu unknown"), unknown);
    tip("Addresses not checked yet.");
    if (total > 0) {
        ImGui::SameLine(0, 24);
        ledBar(float(done) / float(total), running, done == total ? kGreen : gAccent);
        ImGui::SameLine();
        muted(running ? fmt("%d%%", int(done * 100 / total)).c_str() : "done");
    }
    if (ImGui::GetTime() < s.statusUntil) { ImGui::SameLine(0, 24); ImGui::TextColored(gAccent, "%s", s.status.c_str()); }

    float exportW = ImGui::CalcTextSize(T("Export CSV")).x + ImGui::GetStyle().FramePadding.x * 2;
    ImGui::SameLine(ImGui::GetWindowWidth() - exportW - ImGui::GetStyle().WindowPadding.x);
    if (ImGui::Button(T("Export CSV"))) {
        if (rows.empty()) {
            setStatus(T("Nothing to export."));
        } else {
            std::vector<std::vector<std::string>> out;
            for (auto& r : rows)
                out.push_back({r.icmp ? "alive" : "arp-only", r.hostname, ipToString(r.ip), r.mac,
                               r.icmp ? fmt("%.1f", r.rttMs) : "", r.os});
            std::filesystem::path p = "ip_scan.csv";
            setStatus(writeCsv(p, {"Status", "Name", "IP", "MAC", "Latency (ms)", "OS"}, out)
                          ? fmt(T("Saved %s"), std::filesystem::absolute(p).string().c_str())
                          : std::string(T("Could not write the file.")));
        }
    }
    tip("Saves the table to ip_scan.csv next to the program. Opens in Excel.");
}

void pagePorts() {
    State& s = S();
    const bool running = s.ports.running();
    sectionTitle("PORT SCANNER");
    intro("Checks which 'doors' (ports) are open on a computer. An open port means a program is listening. "
          "For example 80 = web server, 22 = SSH, 3389 = Remote Desktop, 445 = file sharing.");
    tryLabel();
    ImGui::BeginDisabled(running);
    if (chip("Web 80-443")) { s.pFirst = 80; s.pLast = 443; }
    tip("Finds web servers: 80 is http, 443 is https.");
    ImGui::SameLine();
    if (chip("Common 1-1024")) { s.pFirst = 1; s.pLast = 1024; }
    tip("The well-known ports. Takes a few seconds.");
    ImGui::SameLine();
    if (chip("Everything 1-65535")) { s.pFirst = 1; s.pLast = 65535; }
    tip("Every possible port. Slower: lower the timeout or raise the threads.");
    ImGui::SameLine();
    if (chip("This PC")) std::snprintf(s.pHost, sizeof s.pHost, "127.0.0.1");
    tip("127.0.0.1 always means 'this computer' - a safe place to try it out.");
    ImGui::Spacing();

    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 14);
    ImGui::InputTextWithHint("##host", T("IP or host name"), s.pHost, sizeof s.pHost);
    tip("Example: 192.168.1.1 or myserver.local");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 6);
    ImGui::InputInt("##p1", &s.pFirst, 0);
    ImGui::SameLine(); muted("to"); ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 6);
    ImGui::InputInt("##p2", &s.pLast, 0);
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (running) {
        if (accentButton("Stop", true, {ImGui::GetFontSize() * 5.5f, 0})) s.ports.requestStop();
    } else if (accentButton("Scan", false, {ImGui::GetFontSize() * 5.5f, 0})) {
        s.pErr.clear();
        s.ports.start(s.pHost, s.pFirst, s.pLast, s.pThreads, s.pTimeout, s.pErr);
    }
    ImGui::BeginDisabled(running);
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 9);
    ImGui::SliderInt(T("Threads"), &s.pThreads, 8, 512);
    tip("How many ports are tested at the same time.");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 9);
    ImGui::SliderInt(T("Timeout"), &s.pTimeout, 100, 3000, "%d ms");
    tip("How long to wait for each port. Closed ports on a local network answer instantly; filtered ones wait.");
    ImGui::EndDisabled();
    if (!s.pErr.empty()) ImGui::TextColored(kRed, "%s", s.pErr.c_str());

    auto res = s.ports.results();
    int total = s.ports.total(), done = s.ports.done();
    const float statusH = ImGui::GetFrameHeight() + ImGui::GetStyle().ItemSpacing.y * 2;
    if (ImGui::BeginTable("ports", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV,
                          ImVec2(0, ImGui::GetContentRegionAvail().y - statusH))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn(T("State"), ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 6.5f);
        ImGui::TableSetupColumn(T("Port"), ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 6.f);
        ImGui::TableSetupColumn(T("Service"), ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (const auto& p : res) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            dot(kGreen); ImGui::SameLine(); ImGui::TextColored(kGreen, T("open"));
            ImGui::TableSetColumnIndex(1); ImGui::Text("%u", p.port);
            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(p.service.empty() ? "-" : p.service.c_str());
        }
        if (res.empty() && total > 0) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(2);
            ImGui::TextColored(kMuted2, "%s", running ? T("Scanning...") : T("No open ports found."));
        }
        ImGui::EndTable();
    }
    ImGui::AlignTextToFramePadding();
    if (total > 0) {
        ImGui::Text(T("%zu open"), res.size());
        ImGui::SameLine(0, 18);
        ledBar(float(done) / float(total), running, done == total ? kGreen : gAccent);
        ImGui::SameLine();
        muted(fmt("%d / %d   %s", done, total, s.ports.target().c_str()).c_str());
    } else {
        muted("Enter a target and press Scan.");
    }
}

void pageArp() {
    State& s = S();
    sectionTitle("ARP MONITOR");
    intro("Listens to ARP messages - the 'who has 192.168.1.1?' questions devices ask each other. "
          "If one IP address suddenly answers with a different MAC address, someone may be pretending to be it "
          "(ARP spoofing) and that row turns red.  Steps: 1) pick your network adapter  2) press Start.");

    if (!s.adaptersLoaded) {
        s.adaptersLoaded = true;
        s.arpErr.clear();
        s.adapters = ArpMonitor::adapters(s.arpErr);
        s.adIdx = 0;
        for (size_t i = 0; i < s.adapters.size(); ++i)
            if (s.adapters[i].description.find("Loopback") == std::string::npos) { s.adIdx = int(i); break; }
    }
    const bool running = s.arp.running();

    ImGui::BeginDisabled(running);
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - ImGui::GetFontSize() * 26);
    const char* cur = s.adapters.empty() ? T("(no adapters)") : s.adapters[s.adIdx].description.c_str();
    if (ImGui::BeginCombo("##adapter", cur)) {
        for (int i = 0; i < int(s.adapters.size()); ++i)
            if (ImGui::Selectable(s.adapters[i].description.c_str(), i == s.adIdx)) s.adIdx = i;
        ImGui::EndCombo();
    }
    tip("Choose the adapter your traffic goes through - usually the Ethernet or Wi-Fi one.");
    ImGui::SameLine();
    if (ImGui::Button(T("Refresh"))) s.adaptersLoaded = false;
    tip("Reload the list of network adapters.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (running) {
        if (accentButton("Stop", true, {ImGui::GetFontSize() * 5.5f, 0})) s.arp.requestStop();
    } else if (accentButton("Start", false, {ImGui::GetFontSize() * 5.5f, 0})) {
        std::string e;
        if (s.adapters.empty()) s.arpErr = T("No capture adapter available.");
        else if (!s.arp.start(s.adapters[s.adIdx].name, e)) s.arpErr = e;
        else s.arpErr.clear();
    }
    ImGui::SameLine();
    if (ImGui::Button(T("Clear"))) { s.arp.clear(); s.arpCachedCount = SIZE_MAX; }
    tip("Empties the list and forgets which MAC belongs to which IP.");
    ImGui::SameLine();
    if (ImGui::Button(T("Save CSV"))) {
        auto ev = s.arp.events();
        if (ev.empty()) setStatus(T("No data to save."));
        else {
            std::vector<std::vector<std::string>> out;
            for (auto& e : ev) out.push_back({e.time, e.op, e.ip, e.mac, e.warning});
            std::filesystem::path p = "arp_logs.csv";
            setStatus(writeCsv(p, {"Time", "Type", "IP", "MAC", "Warning"}, out)
                          ? fmt(T("Saved %s"), std::filesystem::absolute(p).string().c_str())
                          : std::string(T("Could not write the file.")));
        }
    }
    tip("Saves everything captured so far to arp_logs.csv next to the program.");

    std::string runErr = s.arp.lastError();
    if (!s.arpErr.empty()) ImGui::TextColored(kYellow, "%s", s.arpErr.c_str());
    if (!runErr.empty() && !running) ImGui::TextColored(kRed, "%s", runErr.c_str());

    size_t count = s.arp.eventCount();
    if (count != s.arpCachedCount) { s.arpCache = s.arp.events(); s.arpCachedCount = count; }

    const float statusH = ImGui::GetFrameHeight() + ImGui::GetStyle().ItemSpacing.y * 2;
    if (ImGui::BeginTable("arp", 5, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV,
                          ImVec2(0, ImGui::GetContentRegionAvail().y - statusH))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn(T("Time"), ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 6.f);
        ImGui::TableSetupColumn(T("Type"), ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 6.f);
        ImGui::TableSetupColumn(T("IP"), ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 9.f);
        ImGui::TableSetupColumn(T("MAC"), ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 11.f);
        ImGui::TableSetupColumn(T("Note"), ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2.f;
        ImGuiListClipper clip;
        clip.Begin(int(s.arpCache.size()));
        while (clip.Step())
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                const ArpEvent& e = s.arpCache[i];
                ImGui::TableNextRow();
                if (!e.warning.empty()) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, U(alpha(kRed, 0.18f)));
                ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(e.time.c_str());
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(e.op.c_str());
                ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(e.ip.c_str());
                ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(e.mac.c_str());
                ImGui::TableSetColumnIndex(4);
                if (!e.warning.empty()) ImGui::TextColored(kRed, "%s", e.warning.c_str());
            }
        if (s.arpCache.empty()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(4);
            ImGui::TextColored(kMuted2, "%s", running ? T("Waiting for ARP traffic...") : T("Not monitoring."));
        }
        static size_t lastN = 0;
        if (lastN != s.arpCache.size()) { if (atBottom) ImGui::SetScrollHereY(1.f); lastN = s.arpCache.size(); }
        ImGui::EndTable();
    }
    ImGui::AlignTextToFramePadding();
    const float fy = ImGui::GetStyle().FramePadding.y;
    dot(running ? kGreen : kMuted2, running, fy); ImGui::SameLine();
    ImGui::Text("%s", running ? T("monitoring") : T("stopped"));
    ImGui::SameLine(0, 18);
    ImGui::Text(T("%zu packets"), s.arpCache.size());
    ImGui::SameLine(0, 18);
    int sp = s.arp.spoofCount();
    dot(sp ? kRed : kGreen, sp > 0, fy); ImGui::SameLine();
    ImGui::TextColored(sp ? kRed : kMuted, T(sp == 1 ? "%d spoof warning" : "%d spoof warnings"), sp);
}

void pageTests() {
    State& s = S();
    const bool running = s.tests.running();
    sectionTitle("NETWORK TESTS");
    intro("Quick checks for a host name or IP.  Ping: is it reachable and how fast?  "
          "Traceroute: which routers does the traffic cross on the way?  "
          "DNS lookup: turns a name into an IP address (google.com -> 142.250.x.x) or an IP back into a name.");
    tryLabel();
    if (chip("8.8.8.8")) std::snprintf(s.tHost, sizeof s.tHost, "8.8.8.8");
    tip("Google's public DNS server - a reliable target to test your internet connection.");
    ImGui::SameLine();
    if (chip("google.com")) std::snprintf(s.tHost, sizeof s.tHost, "google.com");
    tip("A name instead of an IP: good for DNS lookup and traceroute.");
    ImGui::SameLine();
    if (chip("192.168.1.1")) std::snprintf(s.tHost, sizeof s.tHost, "192.168.1.1");
    tip("Typical home router address - tests your local network instead of the internet.");
    ImGui::Spacing();

    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 18);
    bool enter = ImGui::InputTextWithHint("##thost", T("host or IP"), s.tHost, sizeof s.tHost,
                                          ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ImGui::BeginDisabled(running);
    if (accentButton("Ping") || enter) s.tests.ping(s.tHost);
    tip("Sends 4 small packets and reports the reply time and packet loss.");
    ImGui::SameLine();
    if (ImGui::Button(T("Traceroute"))) s.tests.traceroute(s.tHost);
    tip("Lists every router between you and the target with its response time (up to 30 hops).");
    ImGui::SameLine();
    if (ImGui::Button(T("DNS lookup"))) s.tests.dns(s.tHost);
    tip("Name -> IP addresses, or IP -> name.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (running) { if (accentButton("Stop", true)) s.tests.requestStop(); }
    else if (ImGui::Button(T("Clear"))) s.tests.log.clear();
    ImGui::SameLine();
    if (ImGui::Button(T("Copy"))) copyText(s.tests.log.joined(), "Output");
    tip("Copies the whole output to the clipboard.");

    drawLog("##testlog", s.tests.log, ImVec2(0, 0));
}

// ------------------------------------------------------------ iskelet -----
bool navItem(const char* label, const char* sub, bool active) {
    ImVec2 size(ImGui::GetContentRegionAvail().x, ImGui::GetFontSize() * 3.1f);
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool clicked = ImGui::Selectable((std::string("##nav") + label).c_str(), active, 0, size);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (active) dl->AddRectFilled(p, {p.x + 3, p.y + size.y}, U(gAccent), 2.f);
    float x = p.x + ImGui::GetFontSize() * 1.0f;
    dl->AddText(gBold, ImGui::GetFontSize(), {x, p.y + size.y * 0.16f}, U(active ? kText : kMuted), T(label));
    dl->AddText(ImGui::GetFont(), ImGui::GetFontSize() * 0.82f, {x, p.y + size.y * 0.56f}, U(kMuted2), T(sub));
    return clicked;
}

void guideSection(const char* title, const char* what, const char* example) {
    ImGui::PushFont(gBold);
    ImGui::TextColored(gAccent, "%s", T(title));
    ImGui::PopFont();
    ImGui::PushTextWrapPos(0);
    ImGui::TextColored(kText, "%s", T(what));
    ImGui::TextColored(kMuted, T("Example: %s"), T(example));
    ImGui::PopTextWrapPos();
    ImGui::Spacing();
    ImGui::Spacing();
}

HWND gHwnd = nullptr;
float gTitleH = 0, gMenuLeft = 0, gMenuRight = 0, gButtonsLeft = 1e9f;

// Gömülü başlık çubuğu: logo + menüler solda, pencere düğmeleri sağda.
void windowButtons(float y0, float h, float viewW) {
    State& s = S();
    const float w = ImGui::GetFontSize() * 2.7f;
    const float u = ImGui::GetFontSize() / 19.f;
    const float langW = w * 0.9f;
    gButtonsLeft = viewW - 3 * w - langW;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const bool zoomed = IsZoomed(gHwnd) != 0;

    {  // dil düğmesi (EN <-> TR)
        ImVec2 a{gButtonsLeft, y0}, b{a.x + langW, y0 + h};
        ImGui::SetCursorScreenPos(a);
        bool clicked = ImGui::InvisibleButton("##lang", {langW, h});
        bool hot = ImGui::IsItemHovered();
        tip("Switch language");
        if (hot) dl->AddRectFilled(a, b, U(ImVec4(1, 1, 1, 0.09f)));
        const char* code = lang() == Lang::TR ? "TR" : "EN";
        ImVec2 ts = ImGui::CalcTextSize(code);
        dl->AddText(gBold, ImGui::GetFontSize() * 0.9f, {a.x + (langW - ts.x) * 0.5f, a.y + (h - ts.y) * 0.5f},
                    U(hot ? gAccent : kMuted), code);
        if (clicked) setLang(lang() == Lang::TR ? Lang::EN : Lang::TR);
    }

    for (int i = 0; i < 3; ++i) {
        ImVec2 a{gButtonsLeft + langW + i * w, y0}, b{a.x + w, y0 + h};
        ImGui::SetCursorScreenPos(a);
        ImGui::PushID(i);
        bool clicked = ImGui::InvisibleButton("##wb", {w, h});
        ImGui::PopID();
        bool hot = ImGui::IsItemHovered();
        if (hot) dl->AddRectFilled(a, b, U(i == 2 ? alpha(kRed, 0.9f) : ImVec4(1, 1, 1, 0.09f)));
        ImVec2 c{(a.x + b.x) * 0.5f, (a.y + b.y) * 0.5f};
        ImU32 col = U(i == 2 && hot ? ImVec4(1, 1, 1, 1) : kMuted);
        float t = std::max(1.f, u * 1.2f), k = 6.f * u;
        if (i == 0) {
            dl->AddLine({c.x - k, c.y}, {c.x + k, c.y}, col, t);
        } else if (i == 1 && !zoomed) {
            dl->AddRect({c.x - k, c.y - k}, {c.x + k, c.y + k}, col, 0, 0, t);
        } else if (i == 1) {
            const float o = 2.8f * u;  // geri al simgesi: iki iç içe kare
            dl->AddRect({c.x - k, c.y - k + o}, {c.x + k - o, c.y + k}, col, 0, 0, t);
            dl->AddLine({c.x - k + o, c.y - k}, {c.x + k, c.y - k}, col, t);
            dl->AddLine({c.x + k, c.y - k}, {c.x + k, c.y + k - o}, col, t);
        } else {
            dl->AddLine({c.x - k, c.y - k}, {c.x + k, c.y + k}, col, t);
            dl->AddLine({c.x + k, c.y - k}, {c.x - k, c.y + k}, col, t);
        }
        if (clicked) {
            if (i == 0) ShowWindow(gHwnd, SW_MINIMIZE);
            else if (i == 1) ShowWindow(gHwnd, zoomed ? SW_RESTORE : SW_MAXIMIZE);
            else s.quit = true;
        }
    }
}

// FramePadding, menü çubuğu yüksekliğini Begin() anında belirlediği için draw() içinde Begin'den ÖNCE verilir.
void menuBar() {
    State& s = S();
    if (ImGui::BeginMenuBar()) {
        const float h = ImGui::GetFrameHeight();
        const ImVec2 wp = ImGui::GetWindowPos();
        gTitleH = h;
        float lg = h * 0.6f;
        ImVec2 p = ImGui::GetCursorScreenPos();
        drawLogo(ImGui::GetWindowDrawList(), {p.x + 12, p.y + (h - lg) * 0.5f}, lg);
        ImGui::Dummy({lg + 24, h});
        gMenuLeft = ImGui::GetItemRectMax().x - wp.x;
        if (ImGui::BeginMenu(T("File"))) {
            if (ImGui::MenuItem(T("Exit"), T("close the program"))) s.quit = true;
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu(T("View"))) {
            if (ImGui::BeginMenu(T("Theme"))) {
                for (int i = 0; i < int(std::size(kThemes)); ++i)
                    if (ImGui::MenuItem(T(kThemes[i].name), i == 0 ? T("default") : "", s.theme == i)) { s.theme = i; applyTheme(i); }
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu(T("Language"))) {
                if (ImGui::MenuItem("English", nullptr, lang() == Lang::EN)) setLang(Lang::EN);
                if (ImGui::MenuItem("Türkçe", nullptr, lang() == Lang::TR)) setLang(Lang::TR);
                ImGui::EndMenu();
            }
            ImGui::EndMenu();
        }
        const bool helpOpen = ImGui::BeginMenu(T("Help"));
        gMenuRight = ImGui::GetItemRectMax().x - wp.x;
        if (helpOpen) {
            if (ImGui::MenuItem(T("Quick guide"), T("what each tool does"))) s.showGuide = true;
            if (ImGui::MenuItem(T("About"))) s.showAbout = true;
            ImGui::EndMenu();
        }
        windowButtons(wp.y, h, ImGui::GetMainViewport()->Size.x);
        ImGui::EndMenuBar();
    }
}

}  // namespace

bool inDragArea(int x, int y) {
    if (y < 0 || y >= static_cast<int>(gTitleH)) return false;
    const float fx = static_cast<float>(x);
    if (fx >= gButtonsLeft) return false;
    return fx < gMenuLeft || fx > gMenuRight;  // menü öğelerinin üstü tıklanabilir kalır
}

void init(float dpiScale, void* hwnd) {
    initLang();
    gHwnd = static_cast<HWND>(hwnd);
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;

    static const ImWchar ranges[] = {0x0020, 0x00FF, 0x011E, 0x011F, 0x0130, 0x0131, 0x015E, 0x015F, 0};
    ImFontConfig cfg;
    cfg.OversampleH = 3;
    cfg.OversampleV = 2;
    const float base = 19.f * dpiScale;
    ImFont* regular = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", base, &cfg, ranges);
    if (!regular) regular = io.Fonts->AddFontDefault();
    gBold = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeuib.ttf", base, &cfg, ranges);
    gTitle = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeuib.ttf", base * 1.45f, &cfg, ranges);
    gMono = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consola.ttf", base * 0.95f, &cfg, ranges);
    if (!gBold) gBold = regular;
    if (!gTitle) gTitle = regular;

    ImGuiStyle& st = ImGui::GetStyle();
    st.WindowRounding = 0;
    st.ChildRounding = 8;
    st.FrameRounding = 6;
    st.PopupRounding = 8;
    st.GrabRounding = 6;
    st.ScrollbarRounding = 8;
    st.FrameBorderSize = 1;
    st.WindowPadding = {16, 14};
    st.FramePadding = {11, 6};
    st.ItemSpacing = {10, 9};
    st.CellPadding = {8, 5};
    st.ScrollbarSize = 12;
    st.ScaleAllSizes(dpiScale);
    applyTheme(0);

    uint32_t a, b;
    State& s = S();
    if (localSubnet(a, b)) std::snprintf(s.range, sizeof s.range, "%s", rangeToString(a, b).c_str());
    else std::snprintf(s.range, sizeof s.range, "192.168.1.1-254");
}

bool wantsQuit() { return S().quit; }

void draw() {
    State& s = S();
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {0, 0});
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, {12, ImGui::GetFontSize() * 0.55f});  // başlık çubuğu yüksekliği
    ImGui::Begin("##root", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                     ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoBringToFrontOnFocus);
    menuBar();
    ImGui::PopStyleVar(2);

    // sol kenar çubuğu
    float sideW = ImGui::GetFontSize() * 13.f;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kInk2);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 0);
    ImGui::BeginChild("##side", ImVec2(sideW, 0), ImGuiChildFlags_AlwaysUseWindowPadding);
    {
        float logo = ImGui::GetFontSize() * 2.6f;
        ImVec2 p = ImGui::GetCursorScreenPos();
        drawLogo(ImGui::GetWindowDrawList(), p, logo);
        ImGui::GetWindowDrawList()->AddText(gTitle, ImGui::GetFontSize() * 1.35f,
                                            {p.x + logo + 10, p.y - 1}, U(gAccent), "LETHAS");
        ImGui::GetWindowDrawList()->AddText(ImGui::GetFont(), ImGui::GetFontSize() * 0.8f,
                                            {p.x + logo + 11, p.y + logo * 0.62f}, U(kMuted), T("NETWORK TOOLKIT"));
        ImGui::Dummy({0, logo + ImGui::GetFontSize() * 0.9f});
    }
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, {0, 4});
    if (navItem("IP Scanner", "Find devices on LAN", s.page == Page::IpScan)) s.page = Page::IpScan;
    if (navItem("Port Scanner", "Check open ports", s.page == Page::Ports)) s.page = Page::Ports;
    if (navItem("ARP Monitor", "Detect ARP spoofing", s.page == Page::Arp)) s.page = Page::Arp;
    if (navItem("Network Tests", "Ping, trace, DNS", s.page == Page::Tests)) s.page = Page::Tests;
    ImGui::PopStyleVar();
    ImGui::SetCursorPosY(ImGui::GetWindowHeight() - ImGui::GetTextLineHeight() * 1.8f);
    ImGui::TextColored(kMuted2, "v%s", kVersion);
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();

    ImGui::SameLine(0, 0);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kInk);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 0);
    ImGui::BeginChild("##content", ImVec2(0, 0), ImGuiChildFlags_AlwaysUseWindowPadding);
    switch (s.page) {
        case Page::IpScan: pageIpScan(); break;
        case Page::Ports: pagePorts(); break;
        case Page::Arp: pageArp(); break;
        case Page::Tests: pageTests(); break;
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    ImGui::End();

    if (!IsZoomed(gHwnd))  // ince pencere çerçevesi (sistem çerçevesi kaldırıldığı için)
        ImGui::GetForegroundDrawList()->AddRect(vp->Pos, {vp->Pos.x + vp->Size.x, vp->Pos.y + vp->Size.y},
                                                U(alpha(kBrand, 0.28f)));

    if (s.showAbout) { ImGui::OpenPopup(T("About")); s.showAbout = false; }
    if (s.showGuide) { ImGui::OpenPopup(T("Quick guide")); s.showGuide = false; }
    ImVec2 c = vp->GetCenter();

    ImGui::SetNextWindowPos(c, ImGuiCond_Appearing, {0.5f, 0.5f});
    if (ImGui::BeginPopupModal(T("About"), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        drawLogo(ImGui::GetWindowDrawList(), ImGui::GetCursorScreenPos(), ImGui::GetFontSize() * 4.f);
        ImGui::Dummy({ImGui::GetFontSize() * 4.f, ImGui::GetFontSize() * 4.f});
        ImGui::SameLine();
        ImGui::BeginGroup();
        sectionTitle("Lethas Toolkit");
        muted(fmt(T("Version %s - C++ edition"), kVersion).c_str());
        muted("Network analysis and diagnostics.");
        muted("Colors: tmog.org palette. Layout inspired by Advanced IP Scanner.");
        ImGui::EndGroup();
        ImGui::Spacing();
        if (ImGui::Button(T("Close"), {ImGui::GetFontSize() * 6, 0})) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    ImGui::SetNextWindowPos(c, ImGuiCond_Appearing, {0.5f, 0.5f});
    ImGui::SetNextWindowSize({std::min(vp->WorkSize.x * 0.9f, ImGui::GetFontSize() * 42.f),
                              std::min(vp->WorkSize.y * 0.9f, ImGui::GetFontSize() * 34.f)});
    if (ImGui::BeginPopupModal(T("Quick guide"), nullptr, ImGuiWindowFlags_NoResize)) {
        ImGui::BeginChild("##guide", ImVec2(0, -ImGui::GetFrameHeightWithSpacing() - 6));
        guideSection("IP Scanner - who is on my network?",
                     "Pings every address in a range and lists the devices that answer, with name, MAC address and speed.",
                     "type 192.168.1.1-254 (or press 'Local subnet') and Scan. Right-click a device to open Remote Desktop.");
        guideSection("Port Scanner - what services does a computer offer?",
                     "Tries to connect to each port. Open ports are listed with the service that usually uses them.",
                     "target 192.168.1.20, ports 1-1024. If 3389 shows up, Remote Desktop is enabled on that PC.");
        guideSection("ARP Monitor - is someone impersonating a device?",
                     "Watches ARP messages. When the same IP shows up with a new MAC address the row turns red. "
                     "Needs Npcap (npcap.com) and usually administrator rights.",
                     "gateway 192.168.1.1 normally has one MAC; if a second MAC claims it, that is a warning sign.");
        guideSection("Network Tests - is the connection healthy?",
                     "Ping measures reachability and delay, Traceroute shows each router on the way, DNS lookup converts names and IPs.",
                     "ping 8.8.8.8 - replies under 50 ms with 0% loss means your internet link is fine.");
        guideSection("Status LEDs",
                     "Green = answered / open / OK, yellow = answered only to ARP, red = no answer or warning, grey = not checked yet. "
                     "The LED bar fills as the scan progresses.",
                     "28 LEDs, 14 lit = 50% done.");
        ImGui::EndChild();
        if (ImGui::Button(T("Close"), {ImGui::GetFontSize() * 6, 0})) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

}  // namespace ui
