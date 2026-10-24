#include "core/i18n.h"

#include <windows.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>

namespace lt {
namespace {

std::atomic<Lang> gLang{Lang::EN};

std::filesystem::path settingsPath() {
    char buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("APPDATA", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    return std::filesystem::path(buf) / "LethasToolkit" / "settings.ini";
}

struct Entry { const char* en; const char* tr; };

#include "core/i18n_tr.inc"

const std::unordered_map<std::string_view, const char*>& table() {
    static const auto m = [] {
        std::unordered_map<std::string_view, const char*> t;
        for (const auto& e : kTable) t.emplace(e.en, e.tr);
        return t;
    }();
    return m;
}

}  // namespace

Lang lang() { return gLang; }

void setLang(Lang l) {
    gLang = l;
    auto p = settingsPath();
    if (p.empty()) return;
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    std::ofstream(p) << "lang=" << (l == Lang::TR ? "tr" : "en") << "\n";
}

void initLang() {
    if (auto p = settingsPath(); !p.empty()) {
        std::ifstream f(p);
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("lang=", 0) == 0) {
                gLang = line.substr(5, 2) == "tr" ? Lang::TR : Lang::EN;
                return;
            }
        }
    }
    gLang = (PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_TURKISH) ? Lang::TR : Lang::EN;
}

const char* T(const char* en) {
    if (gLang == Lang::EN || !en) return en;
    const auto& m = table();
    auto it = m.find(en);
    return it == m.end() ? en : it->second;
}

}  // namespace lt
