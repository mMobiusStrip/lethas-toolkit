#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace lt {

struct HostRow {
    uint32_t ip = 0;
    double rttMs = 0;       // ICMP yanıtı yoksa 0
    bool icmp = false;      // ping'e yanıt verdi mi
    int ttl = 0;
    std::string os;         // TTL tahmini
    std::string hostname;
    std::string mac;
};

struct IpScanOptions {
    int threads = 64;
    int timeoutMs = 800;
    bool resolveNames = true;
    bool arpProbe = true;   // ICMP'ye yanıt vermeyen cihazları ARP ile de dene
};

class IpScanner {
public:
    ~IpScanner();

    bool start(uint32_t first, uint32_t last, const IpScanOptions& opt, std::string& err);
    void requestStop() { cancel_ = true; }
    bool running() const { return active_ > 0; }

    uint64_t done() const { return done_; }
    uint64_t total() const { return total_; }
    std::vector<HostRow> results() const;  // IP sırasına göre

private:
    void join();
    void worker(IpScanOptions opt);

    std::vector<std::thread> workers_;
    std::atomic<int> active_{0};
    std::atomic<uint64_t> done_{0}, next_{0}, total_{0};
    std::atomic<bool> cancel_{false};
    uint32_t first_ = 0;
    mutable std::mutex mutex_;
    std::vector<HostRow> rows_;
};

}  // namespace lt
