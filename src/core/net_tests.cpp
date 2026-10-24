#include "core/net_tests.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <limits>

#include "core/icmp.h"
#include "core/i18n.h"

namespace lt {

NetTests::~NetTests() {
    cancel_ = true;
    if (thread_.joinable()) thread_.join();
}

void NetTests::ping(const std::string& host) { launch(&NetTests::doPing, host); }
void NetTests::traceroute(const std::string& host) { launch(&NetTests::doTrace, host); }
void NetTests::dns(const std::string& host) { launch(&NetTests::doDns, host); }

void NetTests::launch(void (NetTests::*fn)(std::string), std::string host) {
    if (running_) return;
    if (thread_.joinable()) thread_.join();
    cancel_ = false;
    running_ = true;
    thread_ = std::thread([this, fn, h = trim(host)] {
        (this->*fn)(h);
        running_ = false;
    });
}

void NetTests::sleepCancelable(int ms) {
    for (int t = 0; t < ms && !cancel_; t += 50) Sleep(50);
}

void NetTests::doPing(std::string host) {
    uint32_t ip;
    if (!resolveIPv4(host, ip)) { log.add(fmt(T("Ping: could not resolve '%s'."), host.c_str())); return; }
    log.add(fmt(T("Pinging %s [%s] with 32 bytes of data:"), host.c_str(), ipToString(ip).c_str()));

    IcmpSession icmp;
    int sent = 0, recv = 0;
    double mn = std::numeric_limits<double>::max(), mx = 0, sum = 0;
    for (int i = 0; i < 4 && !cancel_; ++i) {
        DWORD t0 = GetTickCount();
        PingReply r = icmp.echo(ip, 128, 2000);
        ++sent;
        if (r.ok) {
            ++recv;
            mn = std::min(mn, r.rttMs); mx = std::max(mx, r.rttMs); sum += r.rttMs;
            log.add(fmt(T("Reply from %s: time=%.2f ms TTL=%d"), ipToString(r.from).c_str(), r.rttMs, r.ttl));
        } else {
            log.add(icmpStatusText(r.status) + ".");
        }
        if (i < 3) sleepCancelable(1000 - static_cast<int>(GetTickCount() - t0));
    }
    if (sent) {
        log.add(fmt(T("Packets: sent=%d, received=%d, lost=%d (%d%% loss)"), sent, recv, sent - recv,
                    (sent - recv) * 100 / sent));
        if (recv) log.add(fmt(T("RTT: min=%.2f ms, max=%.2f ms, avg=%.2f ms"), mn, mx, sum / recv));
    }
    log.add("");
}

void NetTests::doTrace(std::string host) {
    uint32_t dest;
    if (!resolveIPv4(host, dest)) { log.add(fmt(T("Traceroute: could not resolve '%s'."), host.c_str())); return; }
    log.add(fmt(T("Tracing route to %s [%s] over a maximum of 30 hops:"), host.c_str(),
                ipToString(dest).c_str()));

    IcmpSession icmp;
    for (int ttl = 1; ttl <= 30 && !cancel_; ++ttl) {
        std::string times;
        uint32_t hop = 0;
        bool reached = false;
        for (int p = 0; p < 3 && !cancel_; ++p) {
            PingReply r = icmp.echo(dest, ttl, 1500);
            if (r.ok || r.ttlExpired) {
                times += fmt("%7.1f ms ", r.rttMs);
                hop = r.from;
                reached = reached || r.ok;
            } else {
                times += "      *    ";
            }
        }
        std::string where = T("Request timed out.");
        if (hop) {
            where = ipToString(hop);
            std::string name = reverseLookup(hop);
            if (!name.empty()) where = name + " [" + where + "]";
        }
        log.add(fmt("%2d  %s %s", ttl, times.c_str(), where.c_str()));
        if (reached) { log.add(T("Trace complete.")); break; }
    }
    log.add("");
}

void NetTests::doDns(std::string host) {
    if (host.empty()) return;
    uint32_t ip;
    if (parseIPv4(host, ip)) {
        std::string name = reverseLookup(ip);
        log.add(name.empty() ? fmt(T("%s: no PTR record found."), host.c_str()) : host + " -> " + name);
        log.add("");
        return;
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) {
        log.add(fmt(T("DNS error for '%s' (code %d)."), host.c_str(), rc));
        log.add("");
        return;
    }
    log.add(fmt(T("Addresses for %s:"), host.c_str()));
    for (auto* a = res; a; a = a->ai_next) {
        char buf[INET6_ADDRSTRLEN];
        getnameinfo(a->ai_addr, static_cast<socklen_t>(a->ai_addrlen), buf, sizeof buf, nullptr, 0,
                    NI_NUMERICHOST);
        log.add(std::string("  ") + (a->ai_family == AF_INET6 ? "AAAA  " : "A     ") + buf);
    }
    freeaddrinfo(res);
    log.add("");
}

}  // namespace lt
