cmake_minimum_required(VERSION 3.21)

# ────────── 基本資訊 ──────────
project(HiP11Proxy LANGUAGES C)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_EXTENSIONS ON)           # 保留 MSVC／Clang-cl 的 /clang:-fms-extensions

# ────────── 使用 clang-cl + lld-link ──────────
# 在 Git Bash 或 PowerShell 內：
#   cmake -B build -G "Ninja" -DCMAKE_C_COMPILER=clang-cl -DCMAKE_LINKER=lld-link
if (MSVC AND CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(STATUS "檢測到 clang-cl，將使用 lld-link")
    # 供 VS Code／其他 IDE 自動帶入
    set(CMAKE_LINKER lld-link)
endif()

# ────────── OpenSSL ──────────
# 自行指定：
#   -DOPENSSL_ROOT_DIR=C:/OpenSSL/3
# 或預先設定環境變數 OPENSSL_ROOT_DIR
set(OPENSSL_USE_STATIC_LIBS ON)      # 與 /MT 對應，全部使用靜態 lib
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# ────────── 目標 hiP11.dll ──────────
add_library(hiP11 SHARED hip11.c)

set(RC_FILE "${CMAKE_SOURCE_DIR}/hip11.rc")
if (EXISTS "${RC_FILE}")
    target_sources(hiP11 PRIVATE "${RC_FILE}")
endif()

target_compile_definitions(hiP11 PRIVATE
    _USRDLL
    _WINDLL
    CRYPTOKI_EXPORTS
    OPENSSL_SUPPRESS_DEPRECATED
)

# /MT 與 /Zi（配合 –g）的行為在 clang-cl 下仍以 MSVC 選項傳遞
if (MSVC)
    target_compile_options(hiP11 PRIVATE /MT)
endif()

target_include_directories(hiP11 PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(hiP11 PRIVATE
    OpenSSL::Crypto              # 對應 libcrypto.lib
)

# 關閉自動加 "lib" 與 "dll" 前綴／後綴，使產物名稱正好是 hiP11.dll
set_target_properties(hiP11 PROPERTIES
    PREFIX ""                    # 不加 "lib"
    OUTPUT_NAME "hiP11"
)

# =========  簽章（可選）  =========
option(ENABLE_SIGNING      "Sign hiP11.dll after build" OFF)
set(SIGN_TOOL "" CACHE FILEPATH "批次檔或可執行檔，用來簽署 hiP11.dll")
set(SIGN_TOOL_ARGS "" CACHE STRING "其他參數（不含檔名），用 ; 分隔")

if (ENABLE_SIGNING)
    if (NOT EXISTS "${SIGN_TOOL}")
        message(FATAL_ERROR "ENABLE_SIGNING=ON，但 SIGN_TOOL='${SIGN_TOOL}' 無法找到。")
    endif()

    # -------  在 CMake Configure 階段就提示一次  -------
    message(STATUS "Build 完成後將以 ${SIGN_TOOL} 進行簽章")

    add_custom_command(TARGET hiP11 POST_BUILD
        VERBATIM COMMAND_EXPAND_LISTS            # ← 官方建議，用來處理空白與引號
        # 1. 友善提示（彩色）
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
                --cyan "[sign] 開始簽章 $<TARGET_FILE_NAME:hiP11> ..."
        # 2. 執行簽章腳本
        COMMAND "${SIGN_TOOL}" ${SIGN_TOOL_ARGS} "$<TARGET_FILE:hiP11>"
        # 3. 完成提示
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
                --green "[sign] $<TARGET_FILE_NAME:hiP11> 已簽章完成！"
        COMMENT "Signing hiP11.dll via ${SIGN_TOOL}"
    )
endif()

# ────────── 安裝（可選）──────────
install(TARGETS hiP11
        RUNTIME DESTINATION bin  # hiP11.dll
        LIBRARY DESTINATION bin)
