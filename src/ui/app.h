#pragma once

namespace ui {

void init(float dpiScale, void* hwnd);  // ImGui bağlamı oluşturulduktan sonra, ilk NewFrame'den önce
void draw();                            // her karede, NewFrame/Render arasında
bool wantsQuit();

// Başlık çubuğunun sürüklenebilir boş alanı mı? (istemci koordinatı; WM_NCHITTEST için)
bool inDragArea(int x, int y);

}  // namespace ui
