#include "core/icmp.h"
#include "core/i18n.h"

#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <windows.h>

#include <cstring>

namespace lt {

IcmpSession::IcmpSession() : handle_(IcmpCreateFile()) {}

IcmpSession::~IcmpSession() {
    if (handle_ != INVALID_HANDLE_VALUE) IcmpCloseHandle(handle_);
}

PingReply IcmpSession::echo(uint32_t dest, int ttl, int timeoutMs) {
    PingReply r;
    if (handle_ == INVALID_HANDLE_VALUE) { r.status = IP_GENERAL_FAILURE; return r; }

    IP_OPTION_INFORMATION opt{};
    opt.Ttl = static_cast<UCHAR>(ttl);
    char payload[32];
    std::memset(payload, 'a', sizeof payload);
    alignas(8) char buf[512];

    LARGE_INTEGER f, t0, t1;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    DWORD n = IcmpSendEcho(handle_, htonl(dest), payload, sizeof payload, &opt, buf, sizeof buf,
                           static_cast<DWORD>(timeoutMs));
    QueryPerformanceCounter(&t1);

    if (n == 0) { r.status = GetLastError(); return r; }
    auto* e = reinterpret_cast<ICMP_ECHO_REPLY*>(buf);
    r.status = e->Status;
    r.from = ntohl(e->Address);
    r.ttl = e->Options.Ttl;
    r.rttMs = double(t1.QuadPart - t0.QuadPart) * 1000.0 / double(f.QuadPart);
    r.ok = e->Status == IP_SUCCESS;
    r.ttlExpired = e->Status == IP_TTL_EXPIRED_TRANSIT;
    return r;
}

std::string icmpStatusText(unsigned long s) {
    switch (s) {
        case IP_SUCCESS: return T("Success");
        case IP_REQ_TIMED_OUT: return T("Request timed out");
        case IP_DEST_NET_UNREACHABLE: return T("Destination net unreachable");
        case IP_DEST_HOST_UNREACHABLE: return T("Destination host unreachable");
        case IP_TTL_EXPIRED_TRANSIT: return T("TTL expired in transit");
        default: return std::string(T("ICMP error")) + " " + std::to_string(s);
    }
}

const char* guessOsFromTtl(int ttl) {
    if (ttl <= 0) return "-";
    if (ttl <= 64) return "Linux/Unix/Android";
    if (ttl <= 128) return "Windows";
    return T("Network device");
}

}  // namespace lt
