cmake_minimum_required(VERSION 3.24)
project(mie_engine VERSION 0.0.1 LANGUAGES CXX)

# Builds happen in CI only (GitHub Actions, Windows and Ubuntu runners).

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(MIE_BUILD_TESTS "Build the unit tests and register the CI tests" ON)
option(MIE_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer (GCC/Clang)" OFF)
option(MIE_FUZZ_ONLY "Build only the fuzz targets (Clang, libFuzzer)" OFF)
set(MIE_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH "Repository root (holds the Python reference)")

if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8)
  add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

if(MIE_SANITIZE AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(nlohmann_json CONFIG REQUIRED)

# ---- fuzz-only build: the channel frame decoder under libFuzzer -------------------
if(MIE_FUZZ_ONLY)
  add_executable(fuzz_frame fuzz/fuzz_frame.cpp src/channel/frame.cpp)
  target_include_directories(fuzz_frame PRIVATE include)
  target_link_libraries(fuzz_frame PRIVATE nlohmann_json::nlohmann_json)
  target_compile_options(fuzz_frame PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g)
  target_link_options(fuzz_frame PRIVATE -fsanitize=fuzzer,address,undefined)
  return()
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# ---- engine library: no interface code, no network code ---------------------------
add_library(mie_core STATIC
  src/core/entropy.cpp
  src/core/hash.cpp
  src/core/io_common.cpp
  src/core/result.cpp
)
if(WIN32)
  target_sources(mie_core PRIVATE src/core/io_win.cpp)
else()
  target_sources(mie_core PRIVATE src/core/io_posix.cpp)
endif()
target_include_directories(mie_core PUBLIC include)
target_link_libraries(mie_core PUBLIC nlohmann_json::nlohmann_json PRIVATE OpenSSL::Crypto)

# ---- local channel -----------------------------------------------------------------
add_library(mie_channel STATIC src/channel/frame.cpp)
if(WIN32)
  target_sources(mie_channel PRIVATE src/channel/transport_win.cpp)
  target_link_libraries(mie_channel PRIVATE advapi32)
else()
  target_sources(mie_channel PRIVATE src/channel/transport_posix.cpp)
endif()
target_include_directories(mie_channel PUBLIC include)
target_link_libraries(mie_channel PUBLIC nlohmann_json::nlohmann_json)

# ---- programs ----------------------------------------------------------------------
add_executable(mie-service src/service/main.cpp)
target_link_libraries(mie-service PRIVATE mie_channel mie_core Threads::Threads)

add_executable(mie src/cli/main.cpp)
target_link_libraries(mie PRIVATE mie_channel)

add_executable(mie-probe src/probe/main.cpp)
target_link_libraries(mie-probe PRIVATE mie_core)

# ---- tests -------------------------------------------------------------------------
if(MIE_BUILD_TESTS)
  enable_testing()
  find_package(Catch2 3 CONFIG REQUIRED)
  add_executable(mie_tests
    tests/test_entropy.cpp
    tests/test_frame.cpp
    tests/test_hash.cpp
    tests/test_result.cpp
    tests/test_transport.cpp
  )
  target_link_libraries(mie_tests PRIVATE mie_core mie_channel Catch2::Catch2WithMain Threads::Threads)
  add_test(NAME unit COMMAND mie_tests)

  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME io_cases
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/io_cases.py $<TARGET_FILE:mie-probe>)
  add_test(NAME parity_primitives
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/parity_primitives.py
                   $<TARGET_FILE:mie-probe> ${MIE_REPO_ROOT})
  add_test(NAME service_smoke
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/service_smoke.py
                   $<TARGET_FILE:mie-service> $<TARGET_FILE:mie>)
  set_tests_properties(unit io_cases parity_primitives service_smoke PROPERTIES TIMEOUT 180)
endif()
