#include "core/ip_scanner.h"

#include <algorithm>

#include "core/common.h"
#include "core/i18n.h"
#include "core/icmp.h"

namespace lt {

static constexpr uint64_t kMaxHosts = 65536;

IpScanner::~IpScanner() {
    cancel_ = true;
    join();
}

void IpScanner::join() {
    for (auto& t : workers_) if (t.joinable()) t.join();
    workers_.clear();
}

bool IpScanner::start(uint32_t first, uint32_t last, const IpScanOptions& opt, std::string& err) {
    if (running()) { err = T("A scan is already running."); return false; }
    join();
    if (first > last) { err = T("Start IP must not be greater than end IP."); return false; }
    uint64_t count = uint64_t(last) - first + 1;
    if (count > kMaxHosts) { err = T("Range too large (max 65536 hosts)."); return false; }

    {
        std::lock_guard lk(mutex_);
        rows_.clear();
    }
    cancel_ = false;
    first_ = first;
    total_ = count;
    done_ = 0;
    next_ = 0;
    int threads = std::clamp(opt.threads, 1, 256);
    active_ = threads;
    for (int i = 0; i < threads; ++i) workers_.emplace_back(&IpScanner::worker, this, opt);
    return true;
}

void IpScanner::worker(IpScanOptions opt) {
    IcmpSession icmp;
    while (!cancel_) {
        uint64_t i = next_++;
        if (i >= total_) break;
        auto ip = static_cast<uint32_t>(first_ + i);

        HostRow row;
        row.ip = ip;
        PingReply r = icmp.echo(ip, 128, opt.timeoutMs);
        row.icmp = r.ok;
        bool alive = r.ok;
        if (r.ok) {
            row.rttMs = r.rttMs;
            row.ttl = r.ttl;
            row.os = guessOsFromTtl(r.ttl);
        }
        // Güvenlik duvarı ICMP'yi engelliyorsa ARP yine de cevap verir (aynı alt ağda).
        if (alive || opt.arpProbe) {
            if (arpLookup(ip, row.mac)) alive = true;
            else row.mac = "-";
        }
        if (alive) {
            row.hostname = opt.resolveNames ? reverseLookup(ip) : std::string();
            if (row.hostname.empty()) row.hostname = "-";
            std::lock_guard lk(mutex_);
            rows_.push_back(std::move(row));
        }
        ++done_;
    }
    --active_;
}

std::vector<HostRow> IpScanner::results() const {
    std::vector<HostRow> r;
    {
        std::lock_guard lk(mutex_);
        r = rows_;
    }
    std::sort(r.begin(), r.end(), [](auto& a, auto& b) { return a.ip < b.ip; });
    return r;
}

}  // namespace lt
