#pragma once

namespace ui {

void init(float dpiScale);  // ImGui bağlamı oluşturulduktan sonra, ilk NewFrame'den önce
void draw();                // her karede, NewFrame/Render arasında
bool wantsQuit();

}  // namespace ui
