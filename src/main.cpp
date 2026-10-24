// Win32 + Direct3D 11 + Dear ImGui kabuğu.
#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <d3d11.h>
#include <dwmapi.h>

#include <algorithm>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "ui/app.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static ID3D11Device* gDevice = nullptr;
static ID3D11DeviceContext* gCtx = nullptr;
static IDXGISwapChain* gSwap = nullptr;
static ID3D11RenderTargetView* gRtv = nullptr;
static UINT gResizeW = 0, gResizeH = 0;

static void createRtv() {
    ID3D11Texture2D* back = nullptr;
    gSwap->GetBuffer(0, IID_PPV_ARGS(&back));
    gDevice->CreateRenderTargetView(back, nullptr, &gRtv);
    back->Release();
}

static void releaseRtv() {
    if (gRtv) { gRtv->Release(); gRtv = nullptr; }
}

static bool createDevice(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL got;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2,
                                               D3D11_SDK_VERSION, &sd, &gSwap, &gDevice, &got, &gCtx);
    if (FAILED(hr))  // GPU yoksa WARP
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2,
                                           D3D11_SDK_VERSION, &sd, &gSwap, &gDevice, &got, &gCtx);
    if (FAILED(hr)) return false;
    createRtv();
    return true;
}

static void destroyDevice() {
    releaseRtv();
    if (gSwap) { gSwap->Release(); gSwap = nullptr; }
    if (gCtx) { gCtx->Release(); gCtx = nullptr; }
    if (gDevice) { gDevice->Release(); gDevice = nullptr; }
}

static LRESULT hitTest(HWND hwnd, LPARAM lp) {
    POINT pt{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
    RECT rc;
    GetWindowRect(hwnd, &rc);
    if (!IsZoomed(hwnd)) {  // kenar ve köşelerden yeniden boyutlandırma
        UINT dpi = GetDpiForWindow(hwnd);
        int b = GetSystemMetricsForDpi(SM_CXSIZEFRAME, dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
        b = std::max(b, 6);
        bool l = pt.x < rc.left + b, r = pt.x >= rc.right - b, t = pt.y < rc.top + b, bt = pt.y >= rc.bottom - b;
        if (t && l) return HTTOPLEFT;
        if (t && r) return HTTOPRIGHT;
        if (bt && l) return HTBOTTOMLEFT;
        if (bt && r) return HTBOTTOMRIGHT;
        if (l) return HTLEFT;
        if (r) return HTRIGHT;
        if (t) return HTTOP;
        if (bt) return HTBOTTOM;
    }
    ScreenToClient(hwnd, &pt);
    return ui::inDragArea(pt.x, pt.y) ? HTCAPTION : HTCLIENT;
}

static LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp)) return true;
    switch (msg) {
        case WM_NCCALCSIZE:  // sistem başlık çubuğu/çerçevesi yok: istemci alanı tüm pencere
            if (wp) {
                if (IsZoomed(hwnd)) {  // ekranı kaplarken görev çubuğunu örtme
                    MONITORINFO mi{sizeof mi};
                    GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mi);
                    reinterpret_cast<NCCALCSIZE_PARAMS*>(lp)->rgrc[0] = mi.rcWork;
                }
                return 0;
            }
            break;
        case WM_NCHITTEST:
            return hitTest(hwnd, lp);
        case WM_GETMINMAXINFO: {
            float s = GetDpiForWindow(hwnd) / 96.f;
            auto* mm = reinterpret_cast<MINMAXINFO*>(lp);
            mm->ptMinTrackSize = {static_cast<LONG>(980 * s), static_cast<LONG>(640 * s)};
            return 0;
        }
        case WM_SIZE:
            if (wp != SIZE_MINIMIZED) { gResizeW = LOWORD(lp); gResizeH = HIWORD(lp); }
            return 0;
        case WM_SYSCOMMAND:
            if ((wp & 0xfff0) == SC_KEYMENU) return 0;  // Alt menüsünü kapat
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    ImGui_ImplWin32_EnableDpiAwareness();

    HICON icon = LoadIconW(inst, MAKEINTRESOURCEW(1));
    WNDCLASSEXW wc{sizeof wc, CS_CLASSDC, wndProc, 0, 0, inst, icon, LoadCursor(nullptr, IDC_ARROW), nullptr,
                   nullptr, L"LethasToolkit", icon};
    RegisterClassExW(&wc);
    float scale = ImGui_ImplWin32_GetDpiScaleForMonitor(MonitorFromPoint({0, 0}, MONITOR_DEFAULTTOPRIMARY));
    // Çerçevesiz pencere: başlık çubuğunu arayüz çizer; THICKFRAME yeniden boyutlandırma/snap için kalır.
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"Lethas Toolkit",
                              WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU, 100, 100,
                              int(1280 * scale), int(780 * scale), nullptr, nullptr, inst, nullptr);
    MARGINS shadow{1, 1, 1, 1};  // gölge ve yuvarlak köşeler için
    DwmExtendFrameIntoClientArea(hwnd, &shadow);
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

    if (!createDevice(hwnd)) {
        MessageBoxW(hwnd, L"Direct3D 11 could not be initialized.", L"Lethas Toolkit", MB_ICONERROR);
        return 1;
    }
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(gDevice, gCtx);
    ui::init(scale, hwnd);

    const float clear[4] = {0.027f, 0.043f, 0.059f, 1.f};  // #070b0f
    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;
        if (IsIconic(hwnd)) { Sleep(50); continue; }
        if (gResizeW && gResizeH) {
            releaseRtv();
            gSwap->ResizeBuffers(0, gResizeW, gResizeH, DXGI_FORMAT_UNKNOWN, 0);
            gResizeW = gResizeH = 0;
            createRtv();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        ui::draw();
        if (ui::wantsQuit()) PostQuitMessage(0);
        ImGui::Render();

        gCtx->OMSetRenderTargets(1, &gRtv, nullptr);
        gCtx->ClearRenderTargetView(gRtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        gSwap->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    destroyDevice();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, inst);
    WSACleanup();
    return 0;
}
