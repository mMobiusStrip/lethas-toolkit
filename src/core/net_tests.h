#pragma once
#include <atomic>
#include <string>
#include <thread>

#include "core/common.h"

namespace lt {

// Ping / Traceroute / DNS: arka planda çalışır, çıktıyı log'a yazar.
class NetTests {
public:
    ~NetTests();

    void ping(const std::string& host);
    void traceroute(const std::string& host);
    void dns(const std::string& host);

    void requestStop() { cancel_ = true; }
    bool running() const { return running_; }
    TextLog log;

private:
    void launch(void (NetTests::*fn)(std::string), std::string host);
    void doPing(std::string host);
    void doTrace(std::string host);
    void doDns(std::string host);
    void sleepCancelable(int ms);

    std::thread thread_;
    std::atomic<bool> running_{false}, cancel_{false};
};

}  // namespace lt
