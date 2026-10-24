// Çekirdek için hızlı duman testi (arayüz yok).
#include <winsock2.h>

#include <chrono>
#include <cstdio>
#include <thread>

#include "core/arp_monitor.h"
#include "core/common.h"
#include "core/ip_scanner.h"
#include "core/net_tests.h"
#include "core/port_scanner.h"

using namespace lt;
using namespace std::chrono_literals;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL: %s (line %d)\n", #c, __LINE__); ++failures; } } while (0)

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    uint32_t a, b;
    CHECK(parseCidr("192.168.1.0/24", a, b) && ipToString(a) == "192.168.1.1" && ipToString(b) == "192.168.1.254");
    CHECK(!parseIPv4("300.1.1.1", a));
    CHECK(parseIPv4(" 10.0.0.5 ", a) && ipToString(a) == "10.0.0.5");

    PortScanner ps;
    std::string err;
    CHECK(!ps.start("not an ip!!", 1, 10, 4, 200, err));
    CHECK(ps.start("127.0.0.1", 130, 140, 8, 300, err));
    while (ps.running()) std::this_thread::sleep_for(20ms);
    auto open = ps.results();
    std::printf("127.0.0.1 open ports in 130-140: %zu (done %d/%d)\n", open.size(), ps.done(), ps.total());
    CHECK(ps.done() == ps.total());
    for (auto& o : open) std::printf("  %u %s\n", o.port, o.service.c_str());

    IpScanner is;
    CHECK(is.start(0x7F000001, 0x7F000003, {}, err));
    while (is.running()) std::this_thread::sleep_for(20ms);
    for (auto& r : is.results())
        std::printf("host %s rtt=%.2f ttl=%d os=%s mac=%s name=%s\n", ipToString(r.ip).c_str(), r.rttMs,
                    r.ttl, r.os.c_str(), r.mac.c_str(), r.hostname.c_str());
    CHECK(!is.results().empty());

    NetTests nt;
    nt.ping("127.0.0.1");
    while (nt.running()) std::this_thread::sleep_for(50ms);
    nt.dns("localhost");
    while (nt.running()) std::this_thread::sleep_for(50ms);
    std::printf("%s", nt.log.joined().c_str());

    std::string e2;
    auto ad = ArpMonitor::adapters(e2);
    std::printf("Npcap adapters: %zu %s\n", ad.size(), e2.c_str());

    std::printf(failures ? "FAILED\n" : "OK\n");
    WSACleanup();
    return failures;
}
