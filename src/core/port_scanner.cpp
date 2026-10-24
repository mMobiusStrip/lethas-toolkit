#include "core/port_scanner.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>

#include "core/common.h"
#include "core/i18n.h"

namespace lt {

const char* serviceName(uint16_t p) {
    switch (p) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 80: return "http";
        case 110: return "pop3";
        case 135: return "msrpc";
        case 139: return "netbios-ssn";
        case 143: return "imap";
        case 443: return "https";
        case 445: return "smb";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "mssql";
        case 1723: return "pptp";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgresql";
        case 5900: return "vnc";
        case 8080: return "http-alt";
        case 8443: return "https-alt";
        default: return "";
    }
}

static bool tryConnect(uint32_t ip, uint16_t port, int timeoutMs) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(ip);

    bool open = false;
    if (connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0) {
        open = true;
    } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set wr, ex;
        FD_ZERO(&wr); FD_ZERO(&ex);
        FD_SET(s, &wr); FD_SET(s, &ex);
        timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
        if (select(0, nullptr, &wr, &ex, &tv) > 0 && FD_ISSET(s, &wr)) {
            int err = 0, len = sizeof err;
            open = getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) == 0 &&
                   err == 0;
        }
    }
    closesocket(s);
    return open;
}

PortScanner::~PortScanner() {
    cancel_ = true;
    join();
}

void PortScanner::join() {
    for (auto& t : workers_) if (t.joinable()) t.join();
    workers_.clear();
}

bool PortScanner::start(const std::string& host, int firstPort, int lastPort, int threads,
                        int timeoutMs, std::string& err) {
    if (running()) { err = T("A scan is already running."); return false; }
    join();

    uint32_t ip;
    if (!resolveIPv4(host, ip)) { err = T("Invalid IP address or host name."); return false; }
    if (firstPort < 1 || lastPort > 65535 || firstPort > lastPort) {
        err = T("Invalid port range (1-65535).");
        return false;
    }

    {
        std::lock_guard lk(mutex_);
        results_.clear();
        target_ = trim(host) == ipToString(ip) ? ipToString(ip)
                                                : trim(host) + " (" + ipToString(ip) + ")";
    }
    cancel_ = false;
    done_ = 0;
    next_ = 0;
    const int count = lastPort - firstPort + 1;
    total_ = count;
    threads = std::clamp(threads, 1, std::min(512, count));
    active_ = threads;
    for (int i = 0; i < threads; ++i)
        workers_.emplace_back(&PortScanner::worker, this, ip, firstPort, timeoutMs);
    return true;
}

void PortScanner::worker(uint32_t ip, int firstPort, int timeoutMs) {
    while (!cancel_) {
        int i = next_++;
        if (i >= total_) break;
        auto port = static_cast<uint16_t>(firstPort + i);
        if (tryConnect(ip, port, timeoutMs)) {
            std::lock_guard lk(mutex_);
            results_.push_back({port, serviceName(port)});
        }
        ++done_;
    }
    --active_;
}

std::string PortScanner::target() const {
    std::lock_guard lk(mutex_);
    return target_;
}

std::vector<OpenPort> PortScanner::results() const {
    std::vector<OpenPort> r;
    {
        std::lock_guard lk(mutex_);
        r = results_;
    }
    std::sort(r.begin(), r.end(), [](auto& a, auto& b) { return a.port < b.port; });
    return r;
}

}  // namespace lt
