cmake_minimum_required(VERSION 3.20)

# Statik CRT: tek exe, vcredist gerekmez
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(LethasToolkit VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.91.9
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(imgui)

add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp)
target_include_directories(imgui PUBLIC ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends)

# Arayüzden bağımsız çekirdek
add_library(lt_core STATIC
    src/core/common.cpp
    src/core/icmp.cpp
    src/core/port_scanner.cpp
    src/core/ip_scanner.cpp
    src/core/net_tests.cpp
    src/core/arp_monitor.cpp)
target_include_directories(lt_core PUBLIC src)
target_compile_definitions(lt_core PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_link_libraries(lt_core PUBLIC ws2_32 iphlpapi)
if(MSVC)
    target_compile_options(lt_core PUBLIC /W4 /utf-8 /permissive-)
endif()

add_executable(LethasToolkit WIN32 src/main.cpp src/ui/app.cpp resources/app.rc)
target_link_libraries(LethasToolkit PRIVATE lt_core imgui d3d11 dxgi shell32 dwmapi)

add_executable(core_smoke tests/core_smoke.cpp)
target_link_libraries(core_smoke PRIVATE lt_core)
