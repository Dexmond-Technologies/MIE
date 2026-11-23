cmake_minimum_required(VERSION 3.24)
project(mie_engine VERSION 0.0.1 LANGUAGES CXX)

# Builds happen in CI only (GitHub Actions, Windows and Ubuntu runners).

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(MIE_BUILD_TESTS "Build the unit tests and register the CI tests" ON)
option(MIE_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer (GCC/Clang)" OFF)
option(MIE_FUZZ_ONLY "Build only the fuzz targets (Clang, libFuzzer)" OFF)
option(MIE_WITH_RULES "Build the rules engine (YARA 4.5.1 from engine/vcpkg-ports, manifest feature 'rules')" OFF)
set(MIE_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH "Repository root (holds the Python reference)")

if(MSVC)
  add_compile_options(/W4 /WX /permissive- /utf-8)
  add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

if(MIE_SANITIZE AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# Decompression for the zip and tar readers (also needed by their fuzz targets).
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)
find_package(LibLZMA REQUIRED)
set(MIE_ARCHIVE_SOURCES
  src/archive/archive.cpp
  src/archive/codec.cpp
  src/archive/zip_reader.cpp
  src/archive/tar_reader.cpp)

# ---- fuzz-only build: the channel frame decoder under libFuzzer -------------------
if(MIE_FUZZ_ONLY)
  add_executable(fuzz_frame fuzz/fuzz_frame.cpp src/channel/frame.cpp)
  target_include_directories(fuzz_frame PRIVATE include)
  target_link_libraries(fuzz_frame PRIVATE nlohmann_json::nlohmann_json)
  target_compile_options(fuzz_frame PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g)
  target_link_options(fuzz_frame PRIVATE -fsanitize=fuzzer,address,undefined)

  add_executable(fuzz_signature fuzz/fuzz_signature.cpp src/signature/authenticode.cpp src/signature/second_check.cpp)
  target_include_directories(fuzz_signature PRIVATE include)
  target_link_libraries(fuzz_signature PRIVATE OpenSSL::Crypto nlohmann_json::nlohmann_json)
  target_compile_options(fuzz_signature PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g)
  target_link_options(fuzz_signature PRIVATE -fsanitize=fuzzer,address,undefined)

  foreach(target fuzz_zip fuzz_tar)
    add_executable(${target} fuzz/${target}.cpp ${MIE_ARCHIVE_SOURCES})
    target_include_directories(${target} PRIVATE include)
    target_link_libraries(${target} PRIVATE ZLIB::ZLIB BZip2::BZip2 LibLZMA::LibLZMA)
    target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g)
    target_link_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()

  add_executable(fuzz_pe fuzz/fuzz_pe.cpp src/pe/pe_reader.cpp)
  target_include_directories(fuzz_pe PRIVATE include)
  target_compile_options(fuzz_pe PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g)
  target_link_options(fuzz_pe PRIVATE -fsanitize=fuzzer,address,undefined)

  # The target as it was when it stopped in run 45117930444: built only for the regression check.
  add_executable(fuzz_pe_old_ee62e76 fuzz/regress/fuzz_pe_ee62e76.cpp src/pe/pe_reader.cpp)
  target_include_directories(fuzz_pe_old_ee62e76 PRIVATE include)
  target_compile_options(fuzz_pe_old_ee62e76 PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g)
  target_link_options(fuzz_pe_old_ee62e76 PRIVATE -fsanitize=fuzzer,address,undefined)
  return()
endif()

find_package(Threads REQUIRED)

# ---- engine library: no interface code, no network code ---------------------------
add_library(mie_core STATIC
  src/core/entropy.cpp
  src/core/hash.cpp
  src/core/io_common.cpp
  src/core/result.cpp
  src/core/rule_sources.cpp
  src/core/scoring.cpp
  src/core/strings.cpp
)
if(WIN32)
  target_sources(mie_core PRIVATE src/core/io_win.cpp)
else()
  target_sources(mie_core PRIVATE src/core/io_posix.cpp)
endif()
target_include_directories(mie_core PUBLIC include)
target_link_libraries(mie_core PUBLIC nlohmann_json::nlohmann_json PRIVATE OpenSSL::Crypto)

# ---- worker confinement ---------------------------------------------------------------
if(WIN32)
  add_library(mie_sandbox STATIC src/sandbox/sandbox_win.cpp)
  target_link_libraries(mie_sandbox PUBLIC mie_core PRIVATE userenv advapi32 Threads::Threads)
else()
  add_library(mie_sandbox STATIC src/sandbox/sandbox_posix.cpp)
  target_link_libraries(mie_sandbox PUBLIC mie_core PRIVATE Threads::Threads)
endif()
target_include_directories(mie_sandbox PUBLIC include)

# Test programs of the confinement: never installed, never packaged.
add_executable(mie-sandbox-testchild src/sandbox/testchild.cpp)
target_link_libraries(mie-sandbox-testchild PRIVATE mie_sandbox mie_core)
if(WIN32)
  target_link_libraries(mie-sandbox-testchild PRIVATE ws2_32)
endif()
add_executable(mie-sandbox-testparent src/sandbox/testparent.cpp)
target_link_libraries(mie-sandbox-testparent PRIVATE mie_sandbox mie_core)

# ---- reader for Windows executables (own code, standard library only) --------------
add_library(mie_pe STATIC src/pe/pe_reader.cpp)
target_include_directories(mie_pe PUBLIC include)

# ---- analysis of Windows executables (the reference's judgement, parity profile) ---
add_library(mie_pe_analysis STATIC src/pe/pe_analysis.cpp)
target_include_directories(mie_pe_analysis PUBLIC include)
target_link_libraries(mie_pe_analysis PUBLIC mie_pe mie_core)

# ---- zip and tar container readers (own code; decompression by zlib, bzip2, liblzma) ----
add_library(mie_archive STATIC ${MIE_ARCHIVE_SOURCES})
target_include_directories(mie_archive PUBLIC include)
target_link_libraries(mie_archive PRIVATE ZLIB::ZLIB BZip2::BZip2 LibLZMA::LibLZMA)

# ---- rules engine (YARA) -----------------------------------------------------------
if(MIE_WITH_RULES)
  find_package(unofficial-libyara CONFIG REQUIRED)
  add_library(mie_rules STATIC src/rules/rules_yara.cpp)
  target_include_directories(mie_rules PUBLIC include)
  target_link_libraries(mie_rules PUBLIC mie_core PRIVATE unofficial::libyara::libyara)

  # ---- the scan pipeline: joins the parts into one scan (parity profile) -------------
  add_library(mie_engine STATIC src/engine/engine.cpp)
  target_include_directories(mie_engine PUBLIC include)
  target_link_libraries(mie_engine PUBLIC mie_core mie_rules mie_pe_analysis mie_archive)

  add_executable(mie-parity-run src/tools/parity_run.cpp)
  target_link_libraries(mie-parity-run PRIVATE mie_engine)

  # ---- the worker: the confined process that parses untrusted bytes, and its parent side ----
  add_library(mie_worker_protocol STATIC src/worker/protocol.cpp)
  target_include_directories(mie_worker_protocol PUBLIC include)
  target_link_libraries(mie_worker_protocol PUBLIC mie_core mie_sandbox)

  add_library(mie_worker_host STATIC src/worker/host.cpp)
  target_include_directories(mie_worker_host PUBLIC include)
  target_link_libraries(mie_worker_host PUBLIC mie_worker_protocol mie_sandbox mie_channel mie_core)

  # The shipped worker: no arguments, no test switch.
  add_executable(mie-worker src/worker/main.cpp)
  target_link_libraries(mie-worker PRIVATE mie_engine mie_worker_protocol mie_sandbox mie_channel)

  # The same source with the test hooks: NEVER installed, NEVER packaged; only tests start it.
  add_executable(mie-worker-testhooks src/worker/main.cpp)
  target_compile_definitions(mie-worker-testhooks PRIVATE MIE_WORKER_TEST_HOOKS=1)
  target_link_libraries(mie-worker-testhooks PRIVATE mie_engine mie_worker_protocol mie_sandbox mie_channel)

  # Test runner: the table of mie-parity-run, every scan through a confined worker.
  add_executable(mie-worker-run src/worker/worker_run.cpp)
  target_link_libraries(mie-worker-run PRIVATE mie_worker_host)
endif()

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

if(MIE_WITH_RULES)
  target_link_libraries(mie-probe PRIVATE mie_rules)
  target_compile_definitions(mie-probe PRIVATE MIE_WITH_RULES)
endif()

add_executable(mie-pe-probe src/probe/pe_probe.cpp)
target_link_libraries(mie-pe-probe PRIVATE mie_pe nlohmann_json::nlohmann_json)

# ---- Authenticode signature check (own code on OpenSSL; copies the reference's portable path) ----
add_library(mie_signature STATIC src/signature/authenticode.cpp src/signature/second_check.cpp)
target_include_directories(mie_signature PUBLIC include)
target_link_libraries(mie_signature PRIVATE OpenSSL::Crypto nlohmann_json::nlohmann_json)
if(WIN32)
  # The second, independent check of the shipped profile is Windows' own (WinVerifyTrust).
  target_link_libraries(mie_signature PRIVATE wintrust crypt32)
endif()

add_executable(mie-signature-probe src/probe/signature_probe.cpp)
target_link_libraries(mie-signature-probe PRIVATE mie_signature nlohmann_json::nlohmann_json)

add_executable(mie-archive-probe src/probe/archive_probe.cpp)
target_link_libraries(mie-archive-probe PRIVATE mie_archive mie_core nlohmann_json::nlohmann_json)

add_executable(mie-pe-analysis-probe src/probe/pe_analysis_probe.cpp)
target_link_libraries(mie-pe-analysis-probe PRIVATE mie_pe_analysis nlohmann_json::nlohmann_json)

add_executable(mie-scoring-check src/probe/scoring_check.cpp)
target_link_libraries(mie-scoring-check PRIVATE mie_core)

# ---- tests -------------------------------------------------------------------------
if(MIE_BUILD_TESTS)
  enable_testing()
  find_package(Catch2 3 CONFIG REQUIRED)
  add_executable(mie_tests
    tests/test_entropy.cpp
    tests/test_frame.cpp
    tests/test_hash.cpp
    tests/test_result.cpp
    tests/test_scoring.cpp
    tests/test_transport.cpp
  )
  target_link_libraries(mie_tests PRIVATE mie_core mie_channel Catch2::Catch2WithMain Threads::Threads)
  target_compile_definitions(mie_tests PRIVATE "MIE_SCORING_TABLE_FILE=\"${CMAKE_CURRENT_SOURCE_DIR}/data/scoring.reference.json\"")
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
  add_test(NAME scoring_vectors
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/scoring_vectors_test.py
                   $<TARGET_FILE:mie-scoring-check> ${MIE_REPO_ROOT})
  set_tests_properties(unit io_cases parity_primitives service_smoke scoring_vectors PROPERTIES TIMEOUT 300)
  add_test(NAME strings_parity
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/strings_parity.py
                   $<TARGET_FILE:mie-probe> ${MIE_REPO_ROOT})
  set_tests_properties(strings_parity PROPERTIES TIMEOUT 600)
  add_test(NAME sandbox_cases
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/sandbox_cases.py
                   $<TARGET_FILE:mie-sandbox-testparent> $<TARGET_FILE:mie-sandbox-testchild>)
  set_tests_properties(sandbox_cases PROPERTIES TIMEOUT 600)
  add_test(NAME pe_parity
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/pe_parity.py
                   $<TARGET_FILE:mie-pe-probe> ${MIE_REPO_ROOT})
  set_tests_properties(pe_parity PROPERTIES TIMEOUT 900)
  add_test(NAME pe_analysis_parity
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/pe_analysis_parity.py
                   $<TARGET_FILE:mie-pe-analysis-probe> ${MIE_REPO_ROOT})
  set_tests_properties(pe_analysis_parity PROPERTIES TIMEOUT 1200)
  add_test(NAME signature_parity
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/signature_parity.py
                   $<TARGET_FILE:mie-signature-probe> ${MIE_REPO_ROOT})
  set_tests_properties(signature_parity PROPERTIES TIMEOUT 1800)
  add_test(NAME archive_parity
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/archive_parity.py
                   $<TARGET_FILE:mie-archive-probe> ${MIE_REPO_ROOT})
  set_tests_properties(archive_parity PROPERTIES TIMEOUT 3600)
  if(MIE_WITH_RULES)
    # Gate 2: parity set S through the whole C++ engine, compared with the Python reference.
    add_test(NAME worker_cases
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/worker_cases.py
                     $<TARGET_FILE:mie-worker-run> $<TARGET_FILE:mie-worker> $<TARGET_FILE:mie-worker-testhooks>
                     $<TARGET_FILE:mie-parity-run> ${MIE_REPO_ROOT})
    set_tests_properties(worker_cases PROPERTIES TIMEOUT 3000)
    add_test(NAME set_s_parity
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/set_s_parity.py
                     $<TARGET_FILE:mie-parity-run> ${MIE_REPO_ROOT})
    set_tests_properties(set_s_parity PROPERTIES TIMEOUT 1800)
    add_test(NAME rules_parity
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/rules_parity.py
                     $<TARGET_FILE:mie-probe> ${MIE_REPO_ROOT})
    set_tests_properties(rules_parity PROPERTIES TIMEOUT 600)
  endif()
endif()
