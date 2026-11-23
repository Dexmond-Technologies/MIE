cmake_minimum_required(VERSION 3.24)
project(mie_ui VERSION 0.0.1 LANGUAGES CXX)

# Standalone CMake project for mie-ui (built and tested in GitHub Actions only).

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

option(MIE_UI_BUILD_TESTS "Build the Qt Test acceptance suite and test helpers" ON)
option(MIE_UI_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer (GCC/Clang)" OFF)

if(MSVC)
  add_compile_options(/W4 /WX /permissive- /utf-8)
  add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

if(MIE_UI_SANITIZE AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(nlohmann_json CONFIG REQUIRED)
find_package(Threads REQUIRED)

# Pin exact Qt 6.8.3 and require ONLY Core, Gui and Widgets for mie-ui.
find_package(Qt6 6.8.3 EXACT REQUIRED COMPONENTS Core Gui Widgets)

foreach(_qt_target IN ITEMS Qt6::Core Qt6::Gui Qt6::Widgets)
  get_target_property(_qt_type ${_qt_target} TYPE)
  if(NOT _qt_type STREQUAL "SHARED_LIBRARY")
    message(FATAL_ERROR "${_qt_target} must be a SHARED_LIBRARY for LGPLv3 dynamic linking, got ${_qt_type}")
  endif()
endforeach()

# ---- read-only engine channel & result sources (no engine files are modified) ------
set(MIE_ENGINE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")

add_library(mie_ui_channel STATIC
  "${MIE_ENGINE_DIR}/src/channel/frame.cpp"
  "${MIE_ENGINE_DIR}/src/core/result.cpp"
)
if(WIN32)
  target_sources(mie_ui_channel PRIVATE "${MIE_ENGINE_DIR}/src/channel/transport_win.cpp")
  target_link_libraries(mie_ui_channel PRIVATE advapi32)
else()
  target_sources(mie_ui_channel PRIVATE "${MIE_ENGINE_DIR}/src/channel/transport_posix.cpp")
endif()
target_include_directories(mie_ui_channel PUBLIC "${MIE_ENGINE_DIR}/include")
target_link_libraries(mie_ui_channel PUBLIC nlohmann_json::nlohmann_json)

# ---- UI core library (shared between mie-ui and mie_ui_tests) ----------------------
add_library(mie_ui_lib STATIC
  src/ui_strings.hpp
  src/ui_strings.cpp
  src/text_sanitize.hpp
  src/text_sanitize.cpp
  src/service_client.hpp
  src/service_client.cpp
  src/main_window.hpp
  src/main_window.cpp
)
target_include_directories(mie_ui_lib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(mie_ui_lib PUBLIC
  mie_ui_channel
  Qt6::Core
  Qt6::Gui
  Qt6::Widgets
  Threads::Threads
)

# ---- Window and tray program: mie-ui -----------------------------------------------
add_executable(mie-ui src/main.cpp)
target_link_libraries(mie-ui PRIVATE mie_ui_lib Qt6::Core Qt6::Gui Qt6::Widgets)

# ---- Acceptance tests (Qt Test, offscreen) -----------------------------------------
if(MIE_UI_BUILD_TESTS)
  enable_testing()
  find_package(Qt6 6.8.3 EXACT REQUIRED COMPONENTS Test)

  # Build the real week 0 mie-service from the read-only source for T-2 and T-9.
  add_executable(mie-service "${MIE_ENGINE_DIR}/src/service/main.cpp")
  target_link_libraries(mie-service PRIVATE mie_ui_channel Threads::Threads)

  add_executable(mie_ui_tests
    tests/fake_service.hpp
    tests/fake_service.cpp
    tests/test_mie_ui.hpp
    tests/test_mie_ui.cpp
  )
  target_link_libraries(mie_ui_tests PRIVATE
    mie_ui_lib
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Test
    Threads::Threads
  )
  if(WIN32)
    target_link_libraries(mie_ui_tests PRIVATE advapi32)
  endif()

  add_test(NAME mie_ui_acceptance COMMAND mie_ui_tests)
  set_tests_properties(mie_ui_acceptance PROPERTIES TIMEOUT 180)
  set_property(TEST mie_ui_acceptance PROPERTY ENVIRONMENT_MODIFICATION
    "QT_QPA_PLATFORM=set:offscreen"
    "MIE_UI_BIN=set:$<TARGET_FILE:mie-ui>"
    "MIE_SERVICE_BIN=set:$<TARGET_FILE:mie-service>"
    "MIE_UI_STRINGS_CPP=set:${CMAKE_CURRENT_SOURCE_DIR}/src/ui_strings.cpp"
    "MIE_UI_SRC_DIR=set:${CMAKE_CURRENT_SOURCE_DIR}/src"
  )
endif()
