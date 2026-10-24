#pragma once
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace lt {

struct ArpEvent {
    std::string time;
    std::string op;       // "request" / "reply"
    std::string ip;
    std::string mac;
    std::string warning;  // boş değilse olası ARP spoofing
};

struct CaptureAdapter {
    std::string name;         // \Device\NPF_{...}
    std::string description;
};

// Npcap (wpcap.dll) çalışma zamanında yüklenir; SDK gerekmez.
class ArpMonitor {
public:
    ~ArpMonitor();

    static bool npcapAvailable(std::string& err);
    static std::vector<CaptureAdapter> adapters(std::string& err);

    bool start(const std::string& adapterName, std::string& err);
    void requestStop() { cancel_ = true; }
    bool running() const { return running_; }

    std::vector<ArpEvent> events() const;
    size_t eventCount() const;
    int spoofCount() const { return spoofs_; }
    void clear();
    std::string lastError() const;

private:
    void loop(std::string adapterName);
    void record(ArpEvent ev);

    std::thread thread_;
    std::atomic<bool> running_{false}, cancel_{false};
    std::atomic<int> spoofs_{0};
    mutable std::mutex mutex_;
    std::vector<ArpEvent> events_;
    std::map<std::string, std::string> known_;  // ip -> mac
    std::string error_;
};

}  // namespace lt
