#include "core/common.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include <cstdarg>
#include <cstdio>
#include <fstream>

namespace lt {

void TextLog::add(std::string line) {
    std::lock_guard lk(mutex_);
    lines_.push_back(std::move(line));
    if (lines_.size() > 50000) lines_.erase(lines_.begin(), lines_.begin() + 10000);
}

void TextLog::clear() {
    std::lock_guard lk(mutex_);
    lines_.clear();
}

std::string TextLog::joined() const {
    std::lock_guard lk(mutex_);
    std::string out;
    for (const auto& l : lines_) { out += l; out += '\n'; }
    return out;
}

std::string trim(std::string s) {
    const char* ws = " \t\r\n";
    s.erase(0, s.find_first_not_of(ws));
    s.erase(s.find_last_not_of(ws) + 1);
    return s;
}

std::string nowTime() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    return fmt("%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
}

std::string fmt(const char* format, ...) {
    va_list ap, ap2;
    va_start(ap, format);
    va_copy(ap2, ap);
    int n = vsnprintf(nullptr, 0, format, ap);
    va_end(ap);
    std::string out(n > 0 ? n : 0, '\0');
    if (n > 0) vsnprintf(out.data(), out.size() + 1, format, ap2);
    va_end(ap2);
    return out;
}

bool parseIPv4(const std::string& s, uint32_t& out) {
    in_addr a{};
    if (inet_pton(AF_INET, trim(s).c_str(), &a) != 1) return false;
    out = ntohl(a.s_addr);
    return true;
}

std::string ipToString(uint32_t ip) {
    return fmt("%u.%u.%u.%u", (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
}

bool resolveIPv4(const std::string& host, uint32_t& out) {
    std::string h = trim(host);
    if (h.empty()) return false;
    if (parseIPv4(h, out)) return true;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(h.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
    out = ntohl(reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr.s_addr);
    freeaddrinfo(res);
    return true;
}

std::string reverseLookup(uint32_t ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip);
    char name[NI_MAXHOST];
    if (getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof sa, name, sizeof name,
                    nullptr, 0, NI_NAMEREQD) != 0)
        return {};
    return name;
}

bool parseCidr(const std::string& s, uint32_t& first, uint32_t& last) {
    auto slash = s.find('/');
    if (slash == std::string::npos) return false;
    uint32_t ip;
    if (!parseIPv4(s.substr(0, slash), ip)) return false;
    int bits;
    try { bits = std::stoi(trim(s.substr(slash + 1))); } catch (...) { return false; }
    if (bits < 0 || bits > 32) return false;
    uint32_t mask = bits == 0 ? 0 : ~0u << (32 - bits);
    uint32_t net = ip & mask, bcast = net | ~mask;
    if (bits <= 30) { first = net + 1; last = bcast - 1; }
    else            { first = net;     last = bcast; }
    return true;
}

bool localSubnet(uint32_t& first, uint32_t& last) {
    ULONG len = 0;
    GetAdaptersInfo(nullptr, &len);
    std::vector<char> buf(len);
    auto* info = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());
    if (len == 0 || GetAdaptersInfo(info, &len) != NO_ERROR) return false;
    for (auto* a = info; a; a = a->Next) {
        uint32_t ip, mask;
        if (!parseIPv4(a->IpAddressList.IpAddress.String, ip) || ip == 0) continue;
        if (!parseIPv4(a->IpAddressList.IpMask.String, mask) || mask == 0) continue;
        uint32_t net = ip & mask;
        first = net + 1;
        last = (net | ~mask) - 1;
        return true;
    }
    return false;
}

bool arpLookup(uint32_t ip, std::string& mac) {
    uint8_t buf[8] = {};
    ULONG len = sizeof buf;
    if (SendARP(htonl(ip), 0, buf, &len) != NO_ERROR || len < 6) return false;
    mac = macToString(buf, len);
    return true;
}

std::string macToString(const uint8_t* m, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; ++i) out += fmt(i ? ":%02X" : "%02X", m[i]);
    return out;
}

static std::string csvEscape(const std::string& v) {
    if (v.find_first_of(",\"\r\n") == std::string::npos) return v;
    std::string out = "\"";
    for (char c : v) { if (c == '"') out += '"'; out += c; }
    return out + '"';
}

bool writeCsv(const std::filesystem::path& path, const std::vector<std::string>& header,
              const std::vector<std::vector<std::string>>& rows) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f << "\xEF\xBB\xBF";  // UTF-8 BOM: Excel Türkçe karakterleri doğru açsın
    auto line = [&](const std::vector<std::string>& r) {
        for (size_t i = 0; i < r.size(); ++i) f << (i ? "," : "") << csvEscape(r[i]);
        f << "\r\n";
    };
    line(header);
    for (const auto& r : rows) line(r);
    return f.good();
}

}  // namespace lt
