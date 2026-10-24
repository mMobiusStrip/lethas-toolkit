#pragma once
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace lt {

// Thread-safe satır tamponu; worker thread'ler yazar, arayüz okur.
class TextLog {
public:
    void add(std::string line);
    void clear();
    std::string joined() const;

    std::mutex& mutex() const { return mutex_; }
    const std::vector<std::string>& lines() const { return lines_; }

private:
    mutable std::mutex mutex_;
    std::vector<std::string> lines_;
};

std::string trim(std::string s);
std::string nowTime();
std::string fmt(const char* format, ...);

// IPv4 adresleri host byte order uint32 olarak tutulur.
bool parseIPv4(const std::string& s, uint32_t& out);
std::string ipToString(uint32_t ip);
bool resolveIPv4(const std::string& host, uint32_t& out);   // IP veya hostname
std::string reverseLookup(uint32_t ip);                      // bulunamazsa ""
bool parseCidr(const std::string& s, uint32_t& first, uint32_t& last);
bool localSubnet(uint32_t& first, uint32_t& last);           // ilk aktif adaptör
bool arpLookup(uint32_t ip, std::string& mac);               // SendARP
std::string macToString(const uint8_t* mac, size_t len = 6);

bool writeCsv(const std::filesystem::path& path,
              const std::vector<std::string>& header,
              const std::vector<std::vector<std::string>>& rows);

}  // namespace lt
