#include "core/arp_monitor.h"

#include <winsock2.h>
#include <windows.h>

#include "core/common.h"

namespace lt {
namespace {

// pcap.h'nin ihtiyacımız olan en küçük alt kümesi.
struct pcap_t;
struct pcap_addr;
struct pcap_if_t {
    pcap_if_t* next;
    char* name;
    char* description;
    pcap_addr* addresses;
    unsigned flags;
};
struct pcap_pkthdr {
    timeval ts;
    unsigned caplen;
    unsigned len;
};
struct bpf_program {
    unsigned bf_len;
    void* bf_insns;
};

struct Pcap {
    HMODULE dll = nullptr;
    int (*findalldevs)(pcap_if_t**, char*) = nullptr;
    void (*freealldevs)(pcap_if_t*) = nullptr;
    pcap_t* (*open_live)(const char*, int, int, int, char*) = nullptr;
    int (*compile)(pcap_t*, bpf_program*, const char*, int, unsigned) = nullptr;
    int (*setfilter)(pcap_t*, bpf_program*) = nullptr;
    void (*freecode)(bpf_program*) = nullptr;
    int (*next_ex)(pcap_t*, pcap_pkthdr**, const unsigned char**) = nullptr;
    char* (*geterr)(pcap_t*) = nullptr;
    void (*close)(pcap_t*) = nullptr;

    bool load(std::string& err) {
        if (dll) return true;
        char sys[MAX_PATH];
        GetSystemDirectoryA(sys, MAX_PATH);
        std::string npcap = std::string(sys) + "\\Npcap\\wpcap.dll";
        dll = LoadLibraryExA(npcap.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!dll) dll = LoadLibraryA("wpcap.dll");  // WinPcap uyumluluk modu
        if (!dll) {
            err = "Npcap not found. Install it from https://npcap.com and restart the app.";
            return false;
        }
        auto get = [&](auto& fn, const char* name) {
            fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(GetProcAddress(dll, name));
            return fn != nullptr;
        };
        bool ok = get(findalldevs, "pcap_findalldevs") && get(freealldevs, "pcap_freealldevs") &&
                  get(open_live, "pcap_open_live") && get(compile, "pcap_compile") &&
                  get(setfilter, "pcap_setfilter") && get(freecode, "pcap_freecode") &&
                  get(next_ex, "pcap_next_ex") && get(geterr, "pcap_geterr") &&
                  get(close, "pcap_close");
        if (!ok) {
            err = "wpcap.dll is missing required functions.";
            FreeLibrary(dll);
            dll = nullptr;
        }
        return ok;
    }
};

Pcap& pcap() {
    static Pcap p;
    return p;
}

}  // namespace

ArpMonitor::~ArpMonitor() {
    cancel_ = true;
    if (thread_.joinable()) thread_.join();
}

bool ArpMonitor::npcapAvailable(std::string& err) { return pcap().load(err); }

std::vector<CaptureAdapter> ArpMonitor::adapters(std::string& err) {
    std::vector<CaptureAdapter> out;
    if (!pcap().load(err)) return out;
    char eb[256] = {};
    pcap_if_t* devs = nullptr;
    if (pcap().findalldevs(&devs, eb) != 0) { err = eb; return out; }
    for (auto* d = devs; d; d = d->next)
        out.push_back({d->name ? d->name : "", d->description ? d->description : d->name});
    pcap().freealldevs(devs);
    if (out.empty()) err = "No capture adapters found (run as administrator?).";
    return out;
}

bool ArpMonitor::start(const std::string& adapterName, std::string& err) {
    if (running_) return true;
    if (!pcap().load(err)) return false;
    if (adapterName.empty()) { err = "Select an adapter."; return false; }
    if (thread_.joinable()) thread_.join();
    {
        std::lock_guard lk(mutex_);
        error_.clear();
    }
    cancel_ = false;
    running_ = true;
    thread_ = std::thread(&ArpMonitor::loop, this, adapterName);
    return true;
}

void ArpMonitor::loop(std::string adapterName) {
    auto& p = pcap();
    char eb[256] = {};
    pcap_t* h = p.open_live(adapterName.c_str(), 128, 1, 200, eb);
    if (!h) {
        std::lock_guard lk(mutex_);
        error_ = std::string("Could not open adapter: ") + eb + " (try running as administrator)";
        running_ = false;
        return;
    }
    bpf_program prog{};
    if (p.compile(h, &prog, "arp", 1, 0xffffffffu) == 0) {
        p.setfilter(h, &prog);
        p.freecode(&prog);
    }

    while (!cancel_) {
        pcap_pkthdr* hdr;
        const unsigned char* d;
        int rc = p.next_ex(h, &hdr, &d);
        if (rc == 0) continue;  // zaman aşımı; iptal bayrağını tekrar kontrol et
        if (rc < 0) {
            std::lock_guard lk(mutex_);
            error_ = std::string("Capture error: ") + p.geterr(h);
            break;
        }
        // Ethernet(14) + ARP(28); ethertype 0x0806
        if (hdr->caplen < 42 || d[12] != 0x08 || d[13] != 0x06) continue;
        const unsigned char* a = d + 14;
        int op = (a[6] << 8) | a[7];
        if (op != 1 && op != 2) continue;

        uint32_t spa = (uint32_t(a[14]) << 24) | (a[15] << 16) | (a[16] << 8) | a[17];
        if (spa == 0) continue;  // ARP probe (0.0.0.0)

        ArpEvent ev;
        ev.time = nowTime();
        ev.op = op == 1 ? "request" : "reply";
        ev.ip = ipToString(spa);
        ev.mac = macToString(a + 8);
        record(std::move(ev));
    }
    p.close(h);
    running_ = false;
}

void ArpMonitor::record(ArpEvent ev) {
    std::lock_guard lk(mutex_);
    auto it = known_.find(ev.ip);
    if (it == known_.end()) {
        known_[ev.ip] = ev.mac;
    } else if (it->second != ev.mac) {
        ev.warning = "Possible ARP spoofing: " + ev.ip + " was " + it->second + ", now " + ev.mac;
        it->second = ev.mac;  // her değişiklik bir kez uyarılsın
        ++spoofs_;
    }
    events_.push_back(std::move(ev));
    if (events_.size() > 20000) events_.erase(events_.begin(), events_.begin() + 5000);
}

std::vector<ArpEvent> ArpMonitor::events() const {
    std::lock_guard lk(mutex_);
    return events_;
}

size_t ArpMonitor::eventCount() const {
    std::lock_guard lk(mutex_);
    return events_.size();
}

void ArpMonitor::clear() {
    std::lock_guard lk(mutex_);
    events_.clear();
    known_.clear();
    spoofs_ = 0;
}

std::string ArpMonitor::lastError() const {
    std::lock_guard lk(mutex_);
    return error_;
}

}  // namespace lt
