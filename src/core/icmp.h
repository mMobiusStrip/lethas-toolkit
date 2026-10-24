#pragma once
#include <cstdint>
#include <string>

namespace lt {

struct PingReply {
    bool ok = false;          // hedeften echo reply geldi
    bool ttlExpired = false;  // ara router yanıtı (traceroute)
    unsigned long status = 0;
    double rttMs = 0;
    int ttl = 0;
    uint32_t from = 0;        // yanıtlayan adres (host order)
};

// Thread başına bir oturum; IcmpSendEcho kullanır (süreç başlatmaz).
class IcmpSession {
public:
    IcmpSession();
    ~IcmpSession();
    IcmpSession(const IcmpSession&) = delete;
    IcmpSession& operator=(const IcmpSession&) = delete;

    PingReply echo(uint32_t dest, int ttl, int timeoutMs);

private:
    void* handle_;
};

std::string icmpStatusText(unsigned long status);
const char* guessOsFromTtl(int ttl);

}  // namespace lt
