#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace lt {

struct OpenPort {
    uint16_t port;
    std::string service;
};

// Çok iş parçacıklı, non-blocking connect tabanlı TCP tarayıcı.
class PortScanner {
public:
    ~PortScanner();

    // false dönerse err doldurulur.
    bool start(const std::string& host, int firstPort, int lastPort, int threads, int timeoutMs,
               std::string& err);
    void requestStop() { cancel_ = true; }
    bool running() const { return active_ > 0; }

    int done() const { return done_; }
    int total() const { return total_; }
    std::string target() const;
    std::vector<OpenPort> results() const;  // port sırasına göre

private:
    void join();
    void worker(uint32_t ip, int firstPort, int timeoutMs);

    std::vector<std::thread> workers_;
    std::atomic<int> active_{0}, done_{0}, total_{0}, next_{0};
    std::atomic<bool> cancel_{false};
    mutable std::mutex mutex_;
    std::vector<OpenPort> results_;
    std::string target_;
};

const char* serviceName(uint16_t port);

}  // namespace lt
