#pragma once

namespace lt {

enum class Lang { EN, TR };

Lang lang();
void setLang(Lang l);  // seçimi %APPDATA%\LethasToolkit\settings.ini içine de kaydeder
void initLang();       // kayıtlı seçim, yoksa sistem dili (Türkçe ise TR)

// İngilizce metni geçerli dile çevirir; çeviri yoksa metnin kendisini döndürür.
// Dönen işaretçi kalıcıdır. Biçim dizgilerinde (%d, %s ...) çeviri aynı sırada aynı belirteçleri içermelidir.
const char* T(const char* en);

}  // namespace lt
