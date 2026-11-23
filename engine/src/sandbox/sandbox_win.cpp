// Worker confinement on Windows.
//
// Everything is applied by the PARENT when it creates the process:
//   - AppContainer token with NO capabilities (no network, no user files, no user registry);
//   - a job object: memory limit, one process only, killed when the parent's handle closes,
//     no desktop / clipboard / global-atom access;
//   - an explicit handle list: the child inherits its three standard pipes and at most the
//     one handed-over file, nothing else;
//   - a minimal environment.
// The child's enter_confinement() only CHECKS that it really runs that way and refuses to
// work if it does not.
//
// NOT VERIFIED BY A RUN: this file has not been compiled or run by its author. The calls I am
// unsure of are marked "UNSURE" here and listed in SANDBOX_NOTES.md.
#include "mie/sandbox.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <new>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <windows.h>
#include <io.h>
#include <sddl.h>
#include <userenv.h>

namespace mie::sandbox {

namespace {

constexpr wchar_t kContainerName[] = L"Dexmond.MIE.Worker";

std::string win_error(const char* what, DWORD code) {
    return std::string(what) + ": Windows error " + std::to_string(code);
}

std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int size = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(size > 0 ? size : 0), L'\0');
    if (size > 0) {
        ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
    }
    return out;
}

std::string narrow(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }
    const int size =
        ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(size > 0 ? size : 0), '\0');
    if (size > 0) {
        ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size, nullptr,
                              nullptr);
    }
    return out;
}

// One argument, quoted the way the Microsoft C runtime splits a command line.
void append_quoted(std::wstring& line, const std::wstring& argument) {
    if (!line.empty()) {
        line.push_back(L' ');
    }
    if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        line += argument;
        return;
    }
    line.push_back(L'"');
    std::size_t backslashes = 0;
    for (const wchar_t c : argument) {
        if (c == L'\\') {
            ++backslashes;
            continue;
        }
        if (c == L'"') {
            line.append(backslashes * 2 + 1, L'\\');
        } else {
            line.append(backslashes, L'\\');
        }
        backslashes = 0;
        line.push_back(c);
    }
    line.append(backslashes * 2, L'\\');
    line.push_back(L'"');
}

std::wstring environment_value(const wchar_t* name) {
    std::vector<wchar_t> buffer(32768);  // the longest value Windows allows
    const DWORD n = ::GetEnvironmentVariableW(name, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (n == 0 || n >= buffer.size()) {
        return {};
    }
    return std::wstring(buffer.data(), n);
}

// The user's default environment as Windows builds it at logon (not this process's own).
// Used only to look up a name that this process does not have.
std::vector<std::wstring> default_environment() {
    std::vector<std::wstring> variables;
    HANDLE token = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &token)) {
        LPVOID block = nullptr;
        if (::CreateEnvironmentBlock(&block, token, FALSE) && block != nullptr) {
            for (const wchar_t* entry = static_cast<const wchar_t*>(block); *entry != L'\0';) {
                const std::wstring text(entry);
                entry += text.size() + 1;
                variables.push_back(text);
            }
            ::DestroyEnvironmentBlock(block);
        }
        ::CloseHandle(token);
    }
    return variables;
}

// The variables the child starts with (without the MIE_* ones, added by the caller): an
// ALLOW LIST of names. Nothing else of the service's or the user's environment is passed.
//
// History: with only SystemRoot, windir and SystemDrive, CreateProcessW for the AppContainer
// failed with error 203 ("environment variable not found"); with the user's whole default
// environment it worked, but that can hold secrets (review finding). The list below is the
// first three plus the five names Windows rewrites for a container, plus a PATH of the system
// folders only. NOT KNOWN: whether these five are the ones whose absence gave error 203; if
// 203 comes back the error text lists the names passed.
std::vector<std::wstring> child_environment() {
    std::vector<std::wstring> variables;
    std::vector<std::wstring> defaults;
    bool defaults_read = false;
    for (const wchar_t* name :
         {L"SystemRoot", L"windir", L"SystemDrive", L"LOCALAPPDATA", L"APPDATA", L"USERPROFILE", L"TEMP", L"TMP"}) {
        std::wstring value = environment_value(name);
        if (value.empty()) {
            if (!defaults_read) {
                defaults = default_environment();
                defaults_read = true;
            }
            const std::wstring prefix = std::wstring(name) + L"=";
            for (const std::wstring& entry : defaults) {
                if (entry.size() > prefix.size() && ::_wcsnicmp(entry.c_str(), prefix.c_str(), prefix.size()) == 0) {
                    value = entry.substr(prefix.size());
                    break;
                }
            }
        }
        if (!value.empty()) {
            variables.push_back(std::wstring(name) + L"=" + value);
        }
    }
    const std::wstring root = environment_value(L"SystemRoot");
    if (!root.empty()) {
        variables.push_back(L"PATH=" + root + L"\\System32;" + root);  // the system folders only
    }
    return variables;
}

// A few exit codes of a process that could not start or crashed, in words.
std::string status_words(DWORD code) {
    switch (code) {
        case 0xC0000005u: return "access violation";
        case 0xC0000008u: return "an invalid handle was used (Windows ends an AppContainer process for that)";
        case 0xC0000017u: return "no memory";
        case 0xC0000022u: return "access denied (a program file or library could not be read)";
        case 0xC000007Bu: return "invalid image format";
        case 0xC00000FDu: return "stack overflow";
        case 0xC0000135u: return "a library (DLL) was not found";
        case 0xC0000139u: return "an entry point was not found in a library";
        case 0xC0000142u: return "a library failed to initialise";
        case 0xC0000409u: return "fast fail / stack buffer overrun";
        case 0xC0000428u: return "image refused by a signature or image-load policy";
        case 259u: return "still running";
        default: return "";
    }
}

std::string hex_code(DWORD code) {
    char text[32];
    std::snprintf(text, sizeof text, "0x%08lX", static_cast<unsigned long>(code));
    const std::string words = status_words(code);
    return words.empty() ? std::string(text) : std::string(text) + " (" + words + ")";
}

bool starts_with_mie(const std::wstring& variable) {
    return variable.size() >= 4 && (variable[0] == L'M' || variable[0] == L'm') &&
           (variable[1] == L'I' || variable[1] == L'i') && (variable[2] == L'E' || variable[2] == L'e') &&
           variable[3] == L'_';
}

void close_handle(HANDLE& handle) {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(handle);
    }
    handle = nullptr;
}

// The AppContainer's SID. The profile is created on first use (it is kept in the user's
// profile: a registry key and a folder under %LOCALAPPDATA%\Packages); afterwards the SID is
// derived from the name. UNSURE: whether a process can be started under a derived SID whose
// profile was never created; that path is taken only if creating the profile fails.
PSID container_sid(std::string& how, std::string& error) {
    PSID sid = nullptr;
    const HRESULT created = ::CreateAppContainerProfile(kContainerName, L"Dexmond MIE worker",
                                                        L"Confined process that reads files for Dexmond MIE",
                                                        nullptr, 0, &sid);
    if (SUCCEEDED(created) && sid != nullptr) {
        how = "profile created";
        return sid;
    }
    sid = nullptr;
    const HRESULT derived = ::DeriveAppContainerSidFromAppContainerName(kContainerName, &sid);
    if (SUCCEEDED(derived) && sid != nullptr) {
        how = created == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) ? "existing profile" : "derived SID, no profile";
        return sid;
    }
    error = "AppContainer profile: HRESULT " + std::to_string(static_cast<unsigned long>(created)) +
            ", derive: HRESULT " + std::to_string(static_cast<unsigned long>(derived));
    return nullptr;
}

// ---- the container's own folder (reviewer's item SW-1) -----------------------------------
//
// An AppContainer has a profile folder, %LOCALAPPDATA%\Packages\<container name>, which the
// confined worker CAN write. Nothing in the product reads it. So that what one worker leaves
// there is not found by the next one, the parent EMPTIES the folder before every confined
// start: every file is removed, and every folder below the second level (the folders Windows
// itself made, the root's children and their children, stay as empty folders).
//
// Discipline, because the content was written by a process that may be hostile:
//   - nothing is ever followed: every entry is opened WITHOUT following a link or junction
//     (FILE_FLAG_OPEN_REPARSE_POINT); a link is removed as a link, never entered;
//   - every opened entry is asked for its real, final path, which must lie inside the
//     folder's own real path; an entry that leads elsewhere (a swapped parent) is left alone
//     and counted;
//   - removal is done through the opened handle, not by name again;
//   - bounded: 10,000 entries, 3 seconds, 32 levels.
// A failure to empty is REPORTED in ChildResult::confinement and does not stop the start:
// leftover content is data only a later confined worker could read (no network, no other
// place to put it), while refusing to start would let one hostile file that leaves an
// undeletable entry switch off all later scanning.

std::wstring container_folder() {
    const std::wstring local = environment_value(L"LOCALAPPDATA");
    if (local.empty()) {
        return {};
    }
    return local + L"\\Packages\\" + kContainerName;
}

std::wstring final_path_of(HANDLE handle) {
    std::vector<wchar_t> buffer(32768);
    const DWORD n = ::GetFinalPathNameByHandleW(handle, buffer.data(), static_cast<DWORD>(buffer.size()),
                                                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (n == 0 || n >= buffer.size()) {
        return {};
    }
    return std::wstring(buffer.data(), n);
}

// Opens a file, a folder or a link ITSELF (the last part of the path is not followed).
HANDLE open_entry(const std::wstring& path) {
    return ::CreateFileW(path.c_str(), DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                         FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
}

bool delete_by_handle(HANDLE handle) {
    FILE_DISPOSITION_INFO gone{};
    gone.DeleteFile = TRUE;
    if (::SetFileInformationByHandle(handle, FileDispositionInfo, &gone, sizeof gone)) {
        return true;
    }
    FILE_BASIC_INFO basic{};  // times of zero = unchanged; clears a read-only mark
    basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    ::SetFileInformationByHandle(handle, FileBasicInfo, &basic, sizeof basic);
    return ::SetFileInformationByHandle(handle, FileDispositionInfo, &gone, sizeof gone) != FALSE;
}

struct EmptyState {
    std::wstring root;  // the folder's real, final path
    int removed = 0;
    int links = 0;      // links removed as links
    int failed = 0;     // could not be opened or removed
    int outside = 0;    // led outside the folder: left alone
    int budget = 10000;
    ULONGLONG deadline = 0;
    bool cut = false;   // a bound was reached
};

void empty_directory(const std::wstring& path, int depth, EmptyState& state) {
    if (depth > 32) {
        state.cut = true;
        return;
    }
    std::vector<std::wstring> names;
    WIN32_FIND_DATAW found{};
    const HANDLE search = ::FindFirstFileExW((path + L"\\*").c_str(), FindExInfoBasic, &found,
                                             FindExSearchNameMatch, nullptr, 0);
    if (search == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        const std::wstring name = found.cFileName;
        if (name != L"." && name != L"..") {
            names.push_back(name);
        }
    } while (::FindNextFileW(search, &found));
    ::FindClose(search);

    for (const std::wstring& name : names) {
        if (--state.budget < 0 || ::GetTickCount64() > state.deadline) {
            state.cut = true;
            return;
        }
        const std::wstring child = path + L"\\" + name;
        HANDLE entry = open_entry(child);
        if (entry == INVALID_HANDLE_VALUE) {
            ++state.failed;
            continue;
        }
        const std::wstring real = final_path_of(entry);
        const bool inside = real.size() > state.root.size() &&
                            ::_wcsnicmp(real.c_str(), state.root.c_str(), state.root.size()) == 0 &&
                            real[state.root.size()] == L'\\';
        BY_HANDLE_FILE_INFORMATION info{};
        if (!inside) {
            ++state.outside;
        } else if (!::GetFileInformationByHandle(entry, &info)) {
            ++state.failed;
        } else if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            delete_by_handle(entry) ? ++state.links : ++state.failed;  // the link itself; never entered
        } else if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            empty_directory(child, depth + 1, state);
            if (depth + 1 > 2) {  // the first two levels are the folders Windows made: kept, empty
                delete_by_handle(entry) ? ++state.removed : ++state.failed;
            }
        } else {
            delete_by_handle(entry) ? ++state.removed : ++state.failed;
        }
        ::CloseHandle(entry);
    }
}

// True if the sentence of empty_container_folder() says that the folder is now empty.
bool folder_is_empty_now(const std::string& sentence) {
    return sentence.rfind("emptied before the start", 0) == 0 && sentence.find("COULD NOT") == std::string::npos &&
           sentence.find("LEFT ALONE") == std::string::npos && sentence.find("STOPPED") == std::string::npos;
}

// Empties the container's folder; returns the sentence for ChildResult::confinement.
std::string empty_container_folder() {
    const std::wstring folder = container_folder();
    if (folder.empty()) {
        return "NOT EMPTIED: LOCALAPPDATA is not set, the folder's place is unknown";
    }
    HANDLE root = open_entry(folder);
    if (root == INVALID_HANDLE_VALUE) {
        const DWORD code = ::GetLastError();
        return code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND
                   ? std::string("no folder at the expected place (nothing to empty)")
                   : win_error("NOT EMPTIED: the folder could not be opened", code);
    }
    EmptyState state;
    BY_HANDLE_FILE_INFORMATION info{};
    const bool is_link =
        !::GetFileInformationByHandle(root, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    state.root = final_path_of(root);
    ::CloseHandle(root);
    if (is_link || state.root.empty()) {
        return "NOT EMPTIED: the folder is a link or its real path cannot be read; refused";
    }
    state.deadline = ::GetTickCount64() + 3000;
    empty_directory(folder, 0, state);
    std::string text = "emptied before the start: " + std::to_string(state.removed) + " removed";
    if (state.links > 0) {
        text += ", " + std::to_string(state.links) + " links removed without following them";
    }
    if (state.failed > 0) {
        text += ", " + std::to_string(state.failed) + " COULD NOT BE REMOVED";
    }
    if (state.outside > 0) {
        text += ", " + std::to_string(state.outside) + " entries LEFT ALONE because they led outside the folder";
    }
    if (state.cut) {
        text += ", STOPPED at the bound (10000 entries, 3 s, 32 levels): the folder is NOT empty";
    }
    return text;
}

// The one message of a hand-over (ruling M-13): fixed size, written whole to the worker's
// standard input. `handle_value` is the value, inside the worker, of the file's handle.
constexpr std::uint32_t kFrameMagic = 0x3145494Du;  // the bytes "MIE1"
struct HandOverFrame {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint64_t handle_value;
    std::uint32_t job_length;
    std::uint32_t reserved;
    std::uint8_t job[kMaxJobBytes];
};

struct PipeReader {
    HANDLE handle = nullptr;
    std::string text;
    std::atomic<std::size_t> received{0};  // every byte that arrived, kept or not
    std::size_t limit = 0;
    bool kill_on_overflow = false;
    HANDLE job = nullptr;
    std::atomic<bool> overflow{false};

    void run() {
        char buffer[64 * 1024];
        for (;;) {
            DWORD got = 0;
            if (!::ReadFile(handle, buffer, static_cast<DWORD>(sizeof buffer), &got, nullptr) || got == 0) {
                return;  // the pipe is broken: every write end is closed (the child is gone)
            }
            received += got;
            const std::size_t room = text.size() < limit ? limit - text.size() : 0;
            const std::size_t take = got < room ? got : room;
            text.append(buffer, take);
            if (take < got && kill_on_overflow && !overflow.exchange(true)) {
                ::TerminateJobObject(job, 1);  // more output than allowed: the child is stopped
            }
        }
    }
};

}  // namespace

const char* to_string(ChildResult::End end) {
    switch (end) {
        case ChildResult::End::Exited: return "exited";
        case ChildResult::End::KilledByTimeLimit: return "killed_by_time_limit";
        case ChildResult::End::KilledByMemoryLimit: return "killed_by_memory_limit";
        case ChildResult::End::Crashed: return "crashed";
        case ChildResult::End::StartFailed: return "start_failed";
    }
    return "start_failed";
}

bool sanitizer_build() {
#if defined(__SANITIZE_ADDRESS__)
    return true;
#else
    return false;
#endif
}

void exit_on_out_of_memory() {
    std::set_new_handler([] { std::_Exit(kOutOfMemoryExitCode); });
}

std::string appcontainer_folder_text() { return narrow(container_folder()); }

std::string appcontainer_sid_text(std::string& error) {
    error.clear();
    std::string how;
    PSID sid = container_sid(how, error);
    if (sid == nullptr) {
        return {};
    }
    std::string out;
    LPWSTR text = nullptr;
    if (::ConvertSidToStringSidW(sid, &text) && text != nullptr) {
        out = narrow(text);
        ::LocalFree(text);
    } else {
        error = win_error("ConvertSidToStringSid", ::GetLastError());
    }
    ::FreeSid(sid);
    return out;
}

std::unique_ptr<io::File> inherited_file(std::string& error) {
    error.clear();
    const std::wstring value = environment_value(L"MIE_INHERITED_FILE");
    if (value.empty()) {
        error = "no file was handed over";
        return nullptr;
    }
    wchar_t* end = nullptr;
    const unsigned long long number = std::wcstoull(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != L'\0' || number == 0) {
        error = "the handed-over file's handle value is not valid";
        return nullptr;
    }
    io::IoError io_error;
    auto file = io::adopt_native_handle(static_cast<std::intptr_t>(number), io_error);
    if (!file) {
        error = std::string("the handed-over file cannot be used: ") + io::to_string(io_error.code);
    }
    return file;
}

std::unique_ptr<io::File> inherited_file() {
    std::string ignored;
    return inherited_file(ignored);
}

// What a waiting start keeps of a child that run_or_start created (ruling M-13).
struct StartedChild {
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
    HANDLE job = nullptr;
    HANDLE port = nullptr;  // the job's completion port (may be null)
    HANDLE in = nullptr;    // the parent's end of the child's standard input
    HANDLE out = nullptr;   // ... of its standard output
    HANDLE err = nullptr;   // ... of its standard error
    std::string confinement;
    std::string folder_note;
};

static ChildResult run_or_start(const std::filesystem::path& program, const std::vector<std::string>& arguments,
                                const io::File* inherited, std::span<const std::uint8_t> input, const Limits& limits,
                                std::size_t max_output_bytes, const RunOptions& options, StartedChild* keep);

ChildResult run_confined(const std::filesystem::path& program, const std::vector<std::string>& arguments,
                         const io::File* inherited, std::span<const std::uint8_t> input, const Limits& limits,
                         std::size_t max_output_bytes, const RunOptions& options) {
    return run_or_start(program, arguments, inherited, input, limits, max_output_bytes, options, nullptr);
}

// Creates a child and, for run_confined (keep == nullptr), runs it to its end. With `keep` (a
// waiting start, ruling M-13) it returns as soon as the child runs, handing the process, the
// job and the parent's ends of the pipes to *keep.
static ChildResult run_or_start(const std::filesystem::path& program, const std::vector<std::string>& arguments,
                                const io::File* inherited, std::span<const std::uint8_t> input, const Limits& limits,
                                std::size_t max_output_bytes, const RunOptions& options, StartedChild* keep) {
    ChildResult result;
    const auto started = std::chrono::steady_clock::now();
    const auto elapsed = [&] {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    };

    HANDLE child_in = nullptr, parent_in = nullptr;    // the child's standard input
    HANDLE parent_out = nullptr, child_out = nullptr;  // the child's standard output
    HANDLE parent_err = nullptr, child_err = nullptr;  // the child's standard error
    HANDLE file_copy = nullptr;                        // inheritable, read-only copy of the file
    HANDLE job = nullptr;
    HANDLE port = nullptr;
    PSID sid = nullptr;
    PROCESS_INFORMATION process{};
    std::vector<unsigned char> attribute_store;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr;
    const auto cleanup = [&] {
        for (HANDLE* handle : {&child_in, &parent_in, &parent_out, &child_out, &parent_err, &child_err, &file_copy,
                               &port, &process.hThread, &process.hProcess}) {
            close_handle(*handle);
        }
        if (job != nullptr) {
            // Closing the last handle of the job kills whatever is still in it.
            ::TerminateJobObject(job, 1);
            close_handle(job);
        }
        if (attributes != nullptr) {
            ::DeleteProcThreadAttributeList(attributes);
            attributes = nullptr;
        }
        if (sid != nullptr) {
            ::FreeSid(sid);
            sid = nullptr;
        }
    };
    const auto fail_start = [&](const std::string& why) {
        cleanup();
        result.end = ChildResult::End::StartFailed;
        result.detail = why;
        result.seconds = elapsed();
        return result;
    };

    // The test switches of RunOptions work only in the test build of this library (reviewer's
    // finding SB-1). In the shipped build they are not looked at: the confinement is applied
    // in full or the start fails, and the two MIE_SANDBOX_* test names are never passed on.
    bool hook_allow_weaker = false;
    bool hook_break = false;
    bool hook_without_policies = false;
#if defined(MIE_SANDBOX_TEST_HOOKS)
    hook_allow_weaker = options.allow_weaker;
    hook_break = options.test_break_confinement;
    hook_without_policies = options.test_without_mitigations;
#endif

    // ---- the AppContainer --------------------------------------------------------------
    std::string container_text = "none (confinement not requested)";
    bool in_container = false;
    if (options.confine) {
        std::string how;
        std::string why_not;
        if (hook_break) {
            why_not = "test hook: the confinement was deliberately not applied";
        } else {
            sid = container_sid(how, why_not);
        }
        if (sid != nullptr) {
            in_container = true;
            container_text = "appcontainer (no capabilities; " + how + ")";
        } else if (hook_allow_weaker) {
            container_text = "WEAKER: no AppContainer: " + why_not;
        } else {
            return fail_start("the worker's AppContainer could not be set up: " + why_not);
        }
    }

    // ---- the container's own folder is emptied before the worker starts (item SW-1) --------
    std::string folder_text = "not used (no container)";
    std::string folder_note;  // for ChildResult::container_folder_note: only when NOT emptied
    if (in_container) {
        folder_text = empty_container_folder();
        if (!folder_is_empty_now(folder_text)) {
            folder_note = "the worker's own folder could not be emptied before this scan: " + folder_text;
        }
    }

    // ---- pipes: the child's ends are inheritable, the parent's are not ---------------------
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof inheritable;
    inheritable.bInheritHandle = TRUE;
    // A waiting start gets a larger pipe to the child: its preparation (rules, tables) is
    // megabytes, written without ever waiting inside the system.
    if (!::CreatePipe(&child_in, &parent_in, &inheritable, keep != nullptr ? 1024 * 1024 : 0) ||
        !::CreatePipe(&parent_out, &child_out, &inheritable, 0) ||
        !::CreatePipe(&parent_err, &child_err, &inheritable, 0)) {
        return fail_start(win_error("CreatePipe", ::GetLastError()));
    }
    ::SetHandleInformation(parent_in, HANDLE_FLAG_INHERIT, 0);
    ::SetHandleInformation(parent_out, HANDLE_FLAG_INHERIT, 0);
    ::SetHandleInformation(parent_err, HANDLE_FLAG_INHERIT, 0);

    std::vector<HANDLE> handle_list = {child_in, child_out, child_err};
    if (inherited != nullptr) {
        // An inheritable copy of the file handle with READ rights only. A handle carries its
        // own rights: the child can read this file although its token could not open it by
        // path. The copy has no write, delete or change-attributes right.
        const HANDLE original = reinterpret_cast<HANDLE>(inherited->native_handle());
        if (!::DuplicateHandle(::GetCurrentProcess(), original, ::GetCurrentProcess(), &file_copy,
                               FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, TRUE, 0)) {
            return fail_start(win_error("DuplicateHandle (file)", ::GetLastError()));
        }
        handle_list.push_back(file_copy);
    }

    // ---- the job object -----------------------------------------------------------------
    job = ::CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr) {
        return fail_start(win_error("CreateJobObject", ::GetLastError()));
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits{};
    // KILL_ON_JOB_CLOSE: if the parent dies, the worker dies. ACTIVE_PROCESS = 1: the worker
    // cannot start another process. DIE_ON_UNHANDLED_EXCEPTION: a crash ends the process, no
    // error dialog waits for a click. PROCESS_MEMORY / JOB_MEMORY: the committed memory of
    // the worker cannot go over the limit; an allocation beyond it is REFUSED (the process is
    // not killed by the system, it gets an allocation failure). It limits committed memory,
    // which is at least the private resident memory; it does not limit mapped files backed by
    // a file on disk.
    job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                                                  JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    job_limits.BasicLimitInformation.ActiveProcessLimit = 1;
    if (limits.memory_bytes > 0) {
        job_limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
        job_limits.ProcessMemoryLimit = static_cast<SIZE_T>(limits.memory_bytes);
        job_limits.JobMemoryLimit = static_cast<SIZE_T>(limits.memory_bytes);
    }
    if (!::SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_limits, sizeof job_limits)) {
        return fail_start(win_error("SetInformationJobObject (limits)", ::GetLastError()));
    }
    // No access to the desktop's shared objects: clipboard, global atoms, other windows'
    // handles, display and system settings, logging off. (The worker creates no window.)
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                             JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                             JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD |
                             JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
    if (!::SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof ui)) {
        return fail_start(win_error("SetInformationJobObject (UI)", ::GetLastError()));
    }
    // A completion port on which the job says "a memory limit was reached". UNSURE: that the
    // message is posted when an allocation is refused (documented as "exceeded its limit").
    // If it does not come, the child's exit code kOutOfMemoryExitCode still tells.
    port = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (port != nullptr) {
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT association{};
        association.CompletionKey = job;
        association.CompletionPort = port;
        if (!::SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &association,
                                       sizeof association)) {
            close_handle(port);
        }
    }

    // ---- process attributes: the AppContainer and the handle list --------------------------
    SECURITY_CAPABILITIES capabilities{};
    capabilities.AppContainerSid = sid;
    capabilities.Capabilities = nullptr;  // NO capability: no internet, no private network,
    capabilities.CapabilityCount = 0;     // no documents / pictures / music library
    // Mitigation policies, fixed for the life of the process (the child cannot turn them off):
    //   extension points off: no AppInit DLLs, no window hooks, no legacy input-method or
    //     Winsock-provider DLLs are loaded INTO the worker by something else on the machine;
    //   no images from remote devices: a DLL cannot be loaded from a network share;
    //   no images with a Low integrity label: a DLL written by a low-rights process (the
    //     worker's own package folder is such a place) cannot be loaded.
    // And the child-process policy: the worker cannot create a process (the job's limit of
    // one process says the same; this is the second lock).
    // Not set, with the reason, in SANDBOX_NOTES.md: win32k lock-down, no dynamic code,
    // strict handle checks, prefer System32, signed-only images.
    DWORD64 mitigation = 0;
    DWORD child_policy = 0;
    std::string mitigation_text;
    std::string not_built;
#ifdef PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
    mitigation |= PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON;
    mitigation_text += " no-extension-points";
#else
    not_built += " extension-point policy";
#endif
#ifdef PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
    mitigation |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON;
    mitigation_text += " no-remote-images";
#else
    not_built += " no-remote-images policy";
#endif
#ifdef PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
    mitigation |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON;
    mitigation_text += " no-low-label-images";
#else
    not_built += " no-low-label-images policy";
#endif
#if defined(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY) && defined(PROCESS_CREATION_CHILD_PROCESS_RESTRICTED)
    child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    mitigation_text += " no-child-process";
#else
    not_built += " child-process policy";
    (void)child_policy;
#endif
    if (in_container && !not_built.empty()) {
        // The Windows headers this was built with lack a policy: never silently without it.
        if (!hook_allow_weaker) {
            return fail_start("this build lacks:" + not_built);
        }
        container_text += " WEAKER: built without:" + not_built;
    }
    // Test hook: start in the container WITHOUT the policies, to tell whether a policy is
    // what keeps a child from starting. The result says WEAKER.
    const bool with_policies = in_container && !hook_without_policies;
    if (in_container && !with_policies) {
        container_text += " WEAKER: test hook: no mitigation or child-process policy";
    }
    const DWORD attribute_count = 4;  // the most that are ever set below
    SIZE_T attribute_size = 0;
    ::InitializeProcThreadAttributeList(nullptr, attribute_count, 0, &attribute_size);
    attribute_store.resize(attribute_size);
    attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_store.data());
    if (!::InitializeProcThreadAttributeList(attributes, attribute_count, 0, &attribute_size)) {
        attributes = nullptr;
        return fail_start(win_error("InitializeProcThreadAttributeList", ::GetLastError()));
    }
    // Only the handles in this list are inherited, even if other inheritable handles exist
    // in the parent (for example in another thread starting another process).
    if (!::UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handle_list.data(),
                                     handle_list.size() * sizeof(HANDLE), nullptr, nullptr)) {
        return fail_start(win_error("UpdateProcThreadAttribute (handle list)", ::GetLastError()));
    }
    if (in_container) {
        // The process gets an AppContainer ("low box") token made from the parent's token:
        // low integrity, the package SID, no capability SIDs. An object is reachable only if
        // its access list names the package SID, ALL APPLICATION PACKAGES or a held
        // capability, IN ADDITION to the ordinary check. Without the internet / private
        // network capabilities the Windows Filtering Platform refuses its connections,
        // loopback included.
        if (!::UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities,
                                         sizeof capabilities, nullptr, nullptr)) {
            return fail_start(win_error("UpdateProcThreadAttribute (AppContainer)", ::GetLastError()));
        }
        if (with_policies && mitigation != 0 &&
            !::UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation,
                                         sizeof mitigation, nullptr, nullptr)) {
            return fail_start(win_error("UpdateProcThreadAttribute (mitigation policy)", ::GetLastError()));
        }
#if defined(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY) && defined(PROCESS_CREATION_CHILD_PROCESS_RESTRICTED)
        if (with_policies &&
            !::UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy,
                                         sizeof child_policy, nullptr, nullptr)) {
            return fail_start(win_error("UpdateProcThreadAttribute (child-process policy)", ::GetLastError()));
        }
#endif
    }

    // ---- command line and a minimal environment ---------------------------------------------
    std::wstring command_line;
    append_quoted(command_line, program.wstring());
    for (const std::string& argument : arguments) {
        append_quoted(command_line, widen(argument));
    }
    std::vector<std::wstring> variables = child_environment();
    // No MIE_* variable comes from anywhere but the lines below.
    variables.erase(std::remove_if(variables.begin(), variables.end(), starts_with_mie), variables.end());
    if (options.confine) {
        variables.push_back(L"MIE_SANDBOX=1");
#if defined(MIE_SANDBOX_TEST_HOOKS)
        if (hook_allow_weaker) {
            variables.push_back(L"MIE_SANDBOX_ALLOW_WEAKER=1");  // test builds only
        }
#endif
    }
    if (file_copy != nullptr) {
        variables.push_back(L"MIE_INHERITED_FILE=" + std::to_wstring(reinterpret_cast<std::uintptr_t>(file_copy)));
    }
    // Windows wants the block sorted by name without regard to case.
    std::sort(variables.begin(), variables.end(), [](const std::wstring& a, const std::wstring& b) {
        return ::_wcsicmp(a.c_str(), b.c_str()) < 0;
    });
    std::string variable_names;  // names only, for the result text; never the values
    for (const std::wstring& variable : variables) {
        variable_names += (variable_names.empty() ? "" : " ") + narrow(variable.substr(0, variable.find(L'=')));
    }
    std::wstring environment;
    for (const std::wstring& variable : variables) {
        environment += variable;
        environment.push_back(L'\0');
    }
    environment.push_back(L'\0');

    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof startup;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_in;
    startup.StartupInfo.hStdOutput = child_out;
    startup.StartupInfo.hStdError = child_err;
    startup.lpAttributeList = attributes;

    // Created SUSPENDED: the process does not run one instruction before it is in the job.
    const std::wstring program_text = program.wstring();
    // No error dialogs, ever. A process that cannot start (a library it cannot read, an image
    // a policy refuses) otherwise makes Windows show a dialog and WAIT for a click that never
    // comes in a service; the child would sit until the time limit (second CI run: every
    // confined child was killed at the limit having used almost no memory). The error mode is
    // inherited by the child from this process, so it is set here, for the whole service
    // process, and left set. With it a failed start ENDS the child with a status code.
    ::SetErrorMode(::GetErrorMode() | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    // The child's current folder: the system folder, which every container can read. (It
    // would otherwise be the service's current folder, which the container may not open.)
    std::vector<wchar_t> system_folder(MAX_PATH + 1);
    const UINT folder_length = ::GetSystemDirectoryW(system_folder.data(), static_cast<UINT>(system_folder.size()));
    const wchar_t* current_folder =
        folder_length > 0 && folder_length < system_folder.size() ? system_folder.data() : nullptr;
    // DETACHED_PROCESS: no console at all. The child talks through its three pipes; a console
    // would need a console host process, which the one-process job and the child-process
    // policy are there to forbid.
    if (!::CreateProcessW(program_text.c_str(), command_line.data(), nullptr, nullptr, TRUE,
                          CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT |
                              DETACHED_PROCESS,
                          environment.data(), current_folder, &startup.StartupInfo, &process)) {
        const DWORD code = ::GetLastError();
        return fail_start(win_error("CreateProcess", code) +
                          (code == ERROR_ENVVAR_NOT_FOUND
                               ? " (names of the variables passed: " + variable_names + ")"
                               : "") +
                          (code == ERROR_ACCESS_DENIED && in_container
                               ? " (inside an AppContainer the program file and its folder must be readable by"
                                 " the worker's AppContainer SID or by ALL APPLICATION PACKAGES)"
                               : ""));
    }
    if (!::AssignProcessToJobObject(job, process.hProcess)) {
        const DWORD code = ::GetLastError();
        ::TerminateProcess(process.hProcess, 1);
        return fail_start(win_error("AssignProcessToJobObject", code));
    }
    // The child's ends of the pipes are now the child's only; the parent lets go of them so
    // that the pipes break when the child ends.
    close_handle(child_in);
    close_handle(child_out);
    close_handle(child_err);
    close_handle(file_copy);
    // ResumeThread returns the thread's suspend count before the call: 1 for a thread created
    // suspended and now running, (DWORD)-1 on failure.
    const DWORD resumed = ::ResumeThread(process.hThread);
    if (resumed == static_cast<DWORD>(-1)) {
        const DWORD code = ::GetLastError();
        ::TerminateProcess(process.hProcess, 1);
        return fail_start(win_error("ResumeThread", code));
    }

    if (keep != nullptr) {
        // A waiting start ends here: the caller owns the process, the job and the pipes now.
        keep->process = process.hProcess;
        keep->thread = process.hThread;
        keep->job = job;
        keep->port = port;
        keep->in = parent_in;
        keep->out = parent_out;
        keep->err = parent_err;
        keep->confinement = container_text + (with_policies ? "+mitigations (" + mitigation_text + " )" : "") +
                            "+job (memory limit " + std::to_string(limits.memory_bytes) +
                            " bytes, one process, kill on close, UI restrictions)+handle list (three pipes, no"
                            " file); environment (names): " +
                            variable_names + "; container folder: " + folder_text;
        keep->folder_note = folder_note;
        process.hProcess = nullptr;
        process.hThread = nullptr;
        job = nullptr;
        port = nullptr;
        parent_in = nullptr;
        parent_out = nullptr;
        parent_err = nullptr;
        cleanup();  // every handle was moved: this frees the attribute list and the SID only
        result.end = ChildResult::End::Exited;
        return result;
    }

    // ---- run: three threads move the bytes, this thread watches the clock ------------------
    PipeReader out_reader;
    out_reader.handle = parent_out;
    out_reader.limit = max_output_bytes;
    out_reader.kill_on_overflow = true;
    out_reader.job = job;
    PipeReader err_reader;
    err_reader.handle = parent_err;
    err_reader.limit = 16 * 1024;
    std::thread out_thread([&] { out_reader.run(); });
    std::thread err_thread([&] { err_reader.run(); });
    std::atomic<std::size_t> input_written{0};
    std::thread in_thread([&] {
        std::size_t written = 0;
        while (written < input.size()) {
            input_written = written;
            const std::size_t part = std::min<std::size_t>(input.size() - written, 64 * 1024);
            DWORD done = 0;
            if (!::WriteFile(parent_in, input.data() + written, static_cast<DWORD>(part), &done, nullptr)) {
                break;  // the child no longer reads: not an error by itself
            }
            written += done;
        }
        input_written = written;
        close_handle(parent_in);  // the child sees the end of its input
    });

    const DWORD wall_ms = static_cast<DWORD>(limits.wall_seconds > 0 ? limits.wall_seconds : 0) * 1000u;
    bool killed_time = false;
    std::string at_limit;  // what the child looked like when the time limit came
    if (::WaitForSingleObject(process.hProcess, wall_ms) != WAIT_OBJECT_0) {
        killed_time = true;
        DWORD code_then = 0;
        ::GetExitCodeProcess(process.hProcess, &code_then);
        // ResumeThread again only to READ the suspend count (0 = the thread was running or
        // waiting, 1 or more = it was still suspended); the child is killed on the next line.
        const DWORD suspend_count = ::ResumeThread(process.hThread);
        FILETIME created{}, ended{}, kernel{}, user{};
        unsigned long long cpu_ms = 0;
        if (::GetProcessTimes(process.hProcess, &created, &ended, &kernel, &user)) {
            const unsigned long long ticks =
                ((static_cast<unsigned long long>(kernel.dwHighDateTime) << 32) | kernel.dwLowDateTime) +
                ((static_cast<unsigned long long>(user.dwHighDateTime) << 32) | user.dwLowDateTime);
            cpu_ms = ticks / 10000;
        }
        at_limit = "at the limit: process state " + hex_code(code_then) + ", main thread suspend count " +
                   (suspend_count == static_cast<DWORD>(-1) ? std::string("unreadable")
                                                            : std::to_string(suspend_count)) +
                   ", processor time used " + std::to_string(cpu_ms) + " ms; ";
        ::TerminateJobObject(job, 1);  // kills every process of the job at once
        ::WaitForSingleObject(process.hProcess, 5000);
    }
    DWORD exit_code = 0;
    ::GetExitCodeProcess(process.hProcess, &exit_code);
    ::TerminateJobObject(job, 1);  // nothing of the job may be left holding a pipe
    out_thread.join();
    err_thread.join();
    in_thread.join();
    result.seconds = elapsed();

    // Peak memory as the SYSTEM counted it for the job (committed bytes), not as the child says.
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION measured{};
    if (::QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &measured, sizeof measured, nullptr)) {
        result.peak_memory_bytes = static_cast<std::uint64_t>(
            measured.PeakProcessMemoryUsed > measured.PeakJobMemoryUsed ? measured.PeakProcessMemoryUsed
                                                                       : measured.PeakJobMemoryUsed);
    }
    bool memory_message = false;
    if (port != nullptr) {
        for (;;) {
            DWORD message = 0;
            ULONG_PTR key = 0;
            LPOVERLAPPED extra = nullptr;
            if (!::GetQueuedCompletionStatus(port, &message, &key, &extra, 0)) {
                break;
            }
            if (message == JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT || message == JOB_OBJECT_MSG_JOB_MEMORY_LIMIT) {
                memory_message = true;
            }
        }
    }

    result.output = std::move(out_reader.text);
    result.confinement = container_text + (with_policies ? "+mitigations (" + mitigation_text + " )" : "") +
                         "+job (memory limit " + std::to_string(limits.memory_bytes) +
                         " bytes, one process, kill on close, UI restrictions)+handle list; environment (names): " +
                         variable_names + "; container folder: " + folder_text;
    result.container_folder_note = folder_note;
    if (!err_reader.text.empty()) {
        result.detail = "standard error: " + err_reader.text;
    }
    const auto with_detail = [&](const std::string& text) {
        result.detail = result.detail.empty() ? text : text + "; " + result.detail;
    };
    result.exit_code = static_cast<int>(exit_code);
    const bool overflow = out_reader.overflow.load();
    // What the parent saw, for a child that did not end by itself in the ordinary way.
    const std::string diagnosis =
        "diagnosis: ResumeThread at start returned " + std::to_string(resumed) + " (1 = was suspended, now runs); " +
        at_limit + "exit code " + hex_code(exit_code) + "; bytes received from standard output " +
        std::to_string(out_reader.received.load()) + ", from standard error " +
        std::to_string(err_reader.received.load()) + "; bytes of input written " +
        std::to_string(input_written.load()) + " of " + std::to_string(input.size());
    cleanup();

    if (killed_time) {
        result.end = ChildResult::End::KilledByTimeLimit;
        with_detail("killed at the time limit of " + std::to_string(limits.wall_seconds) + " seconds; " + diagnosis);
    } else if (overflow) {
        result.end = ChildResult::End::Crashed;
        with_detail("killed: more output than the allowed " + std::to_string(max_output_bytes) + " bytes");
    } else if (memory_message || exit_code == static_cast<DWORD>(kOutOfMemoryExitCode)) {
        result.end = ChildResult::End::KilledByMemoryLimit;
        with_detail(memory_message ? "the job reported that the memory limit was reached"
                                   : "the child ran out of its memory limit (an allocation was refused)");
    } else if ((exit_code & 0xC0000000u) == 0xC0000000u) {
        result.end = ChildResult::End::Crashed;  // an NTSTATUS error code: unhandled exception
        with_detail("could not start or ended by an unhandled exception; " + diagnosis);
    } else {
        result.end = ChildResult::End::Exited;
    }
    return result;
}

// ================== pre-started one-shot workers (ruling M-13): the parent ==================
//
// The worker is created by the same code as a one-shot child (run_or_start), without a file
// in its handle list. It is in its AppContainer and its job from its first instruction. The
// file reaches it later: the parent duplicates the file's handle INTO the worker process,
// read-only and not inheritable, and sends the handle's value in one fixed-size message on
// the worker's standard input, which the parent then closes.
//
// No thread is used: the pipes from the worker are read with PeekNamedPipe (never waits), and
// the pipe to the worker is put in no-wait mode. UNSURE (not run): the exact behaviour of a
// no-wait write on an anonymous pipe; the code treats "nothing written" as "try again".

struct WaitingChild::Impl {
    StartedChild child;
    WaitingState state = WaitingState::Ended;
    std::string failure;
    bool confine = true;
    bool finished = false;  // the process is gone and every handle closed
    std::uint64_t memory_bytes = 0;
    std::size_t max_output = 0;
    std::chrono::steady_clock::time_point started{};
    std::chrono::steady_clock::time_point handed_over{};
    std::string output;
    std::size_t output_total = 0;
    std::size_t out_received = 0;
    std::size_t err_received = 0;
    std::string error_text;
    bool killed_output = false;
    bool killed_time = false;
    bool ended = false;          // the process has ended; exit_code is valid
    DWORD exit_code = 0;
    bool memory_message = false; // the job said that the memory limit was reached
    std::uint64_t peak_memory = 0;
    std::string at_limit;        // what the worker looked like at the time limit
};

namespace {

// Reads what is in a pipe NOW, without waiting, and gives it to `sink`. A broken pipe (the
// worker closed its end or is gone) is closed here.
template <typename Sink>
void read_available(HANDLE& pipe, Sink sink) {
    while (pipe != nullptr) {
        DWORD available = 0;
        if (!::PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
            close_handle(pipe);
            return;
        }
        if (available == 0) {
            return;
        }
        char buffer[64 * 1024];
        const DWORD want = available < sizeof buffer ? available : static_cast<DWORD>(sizeof buffer);
        DWORD got = 0;
        if (!::ReadFile(pipe, buffer, want, &got, nullptr) || got == 0) {
            close_handle(pipe);
            return;
        }
        sink(buffer, got);
    }
}

// One round: read what the worker wrote, notice its end. Never waits.
void pump(WaitingChild::Impl& c) {
    if (c.finished || c.child.process == nullptr) {
        return;
    }
    read_available(c.child.out, [&](const char* data, DWORD size) {
        c.out_received += size;
        const std::size_t room = c.output_total < c.max_output ? c.max_output - c.output_total : 0;
        const std::size_t take = size < room ? size : room;
        c.output.append(data, take);
        c.output_total += take;
        if (take < size && !c.killed_output) {
            c.killed_output = true;  // more output than allowed: the worker is stopped
            ::TerminateJobObject(c.child.job, 1);
        }
    });
    read_available(c.child.err, [&](const char* data, DWORD size) {
        c.err_received += size;
        if (c.error_text.size() < 16 * 1024) {
            c.error_text.append(data, size);
        }
    });
    if (!c.ended && ::WaitForSingleObject(c.child.process, 0) == WAIT_OBJECT_0) {
        c.ended = true;
        ::GetExitCodeProcess(c.child.process, &c.exit_code);
    }
}

// Ends whatever is left of the worker, takes the job's measurements, closes every handle.
void finish_child(WaitingChild::Impl& c) {
    if (c.finished) {
        return;
    }
    if (c.child.process != nullptr) {
        ::TerminateJobObject(c.child.job, 1);  // kills every process of the job; harmless if none is left
        ::WaitForSingleObject(c.child.process, 5000);
        if (!c.ended) {
            c.ended = true;
            ::GetExitCodeProcess(c.child.process, &c.exit_code);
        }
        pump(c);  // what was still in the pipes
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION measured{};
        if (::QueryInformationJobObject(c.child.job, JobObjectExtendedLimitInformation, &measured, sizeof measured,
                                        nullptr)) {
            c.peak_memory = static_cast<std::uint64_t>(
                measured.PeakProcessMemoryUsed > measured.PeakJobMemoryUsed ? measured.PeakProcessMemoryUsed
                                                                           : measured.PeakJobMemoryUsed);
        }
        while (c.child.port != nullptr) {
            DWORD message = 0;
            ULONG_PTR key = 0;
            LPOVERLAPPED extra = nullptr;
            if (!::GetQueuedCompletionStatus(c.child.port, &message, &key, &extra, 0)) {
                break;
            }
            if (message == JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT || message == JOB_OBJECT_MSG_JOB_MEMORY_LIMIT) {
                c.memory_message = true;
            }
        }
    }
    for (HANDLE* handle : {&c.child.in, &c.child.out, &c.child.err, &c.child.port, &c.child.thread,
                           &c.child.process, &c.child.job}) {
        close_handle(*handle);  // closing the job's last handle kills anything still in it
    }
    c.finished = true;
}

void update_state(WaitingChild::Impl& c) {
    if (c.state == WaitingState::Waiting && (c.ended || c.killed_output)) {
        finish_child(c);
        c.failure = (c.killed_output ? std::string("ended by the parent: more output than allowed while waiting")
                                     : std::string("the worker ended while waiting")) +
                    " (exit code " + hex_code(c.exit_code) + ")";
        if (!c.error_text.empty()) {
            c.failure += "; standard error: " + c.error_text;
        }
        c.state = WaitingState::Ended;
    }
}

// Writes `size` bytes to the worker's standard input without ever waiting inside the system:
// the pipe is in no-wait mode, so a full pipe gives "nothing written" and this loop looks at
// the worker and the clock in between. False if the pipe broke or the time ran out.
bool write_to_worker(WaitingChild::Impl& c, const void* data, std::size_t size, int timeout_seconds,
                     std::string& error) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::size_t written = 0;
    while (written < size) {
        if (c.child.in == nullptr) {
            error = "the worker's standard input is closed";
            return false;
        }
        const std::size_t part = std::min<std::size_t>(size - written, 16 * 1024);
        DWORD done = 0;
        if (!::WriteFile(c.child.in, bytes + written, static_cast<DWORD>(part), &done, nullptr)) {
            error = win_error("writing to the worker", ::GetLastError());
            return false;
        }
        written += done;
        pump(c);
        if (c.ended) {
            error = "the worker ended (exit code " + hex_code(c.exit_code) + ")";
            return false;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            error = "not written within " + std::to_string(timeout_seconds) + " seconds";
            return false;
        }
        if (done == 0) {
            ::WaitForSingleObject(c.child.process, 2);  // the pipe is full: a short pause
        }
    }
    return true;
}

const char* state_in_words(WaitingState state) {
    switch (state) {
        case WaitingState::Starting: return "the worker has not yet started";
        case WaitingState::Waiting: return "the worker waits";
        case WaitingState::HandedOver: return "this worker was already given its one file";
        case WaitingState::Ended: return "the worker has ended";
    }
    return "the worker has ended";
}

// After the one message: standard input is closed (the worker reads one job, then the end),
// and the clock of collect() starts.
void after_hand_over(WaitingChild::Impl& c) {
    close_handle(c.child.in);
    c.handed_over = std::chrono::steady_clock::now();
    c.state = WaitingState::HandedOver;
}

}  // namespace

WaitingChild::WaitingChild(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

WaitingChild::~WaitingChild() {
    if (impl_) {
        finish_child(*impl_);
    }
}

std::unique_ptr<WaitingChild> start_waiting(const std::filesystem::path& program,
                                            const std::vector<std::string>& arguments,
                                            const WaitingOptions& options) {
    auto impl = std::make_unique<WaitingChild::Impl>();
    impl->started = std::chrono::steady_clock::now();
    impl->confine = options.run.confine;
    impl->memory_bytes = options.memory_bytes;
    impl->max_output = options.max_output_bytes;
    Limits limits;
    limits.memory_bytes = options.memory_bytes;
    const ChildResult created = run_or_start(program, arguments, nullptr, {}, limits, 0, options.run, &impl->child);
    if (impl->child.process == nullptr) {
        impl->state = WaitingState::Ended;
        impl->failure = created.detail.empty() ? "the worker could not be started" : created.detail;
        impl->finished = true;
        return std::make_unique<WaitingChild>(std::move(impl));
    }
    // The pipe to the worker never makes the parent wait.
    DWORD mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
    if (!::SetNamedPipeHandleState(impl->child.in, &mode, nullptr, nullptr)) {
        const DWORD code = ::GetLastError();
        finish_child(*impl);
        impl->state = WaitingState::Ended;
        impl->failure = win_error("the pipe to the worker could not be put in no-wait mode", code);
        return std::make_unique<WaitingChild>(std::move(impl));
    }
    // The confinement was applied by this process when it created the worker: there is no
    // "stage 1" to wait for on Windows.
    impl->state = WaitingState::Waiting;
    return std::make_unique<WaitingChild>(std::move(impl));
}

WaitingState poll(WaitingChild& child) {
    WaitingChild::Impl& c = child.impl();
    pump(c);
    update_state(c);
    return c.state;
}

bool send_preparation(WaitingChild& child, std::span<const std::uint8_t> bytes, int timeout_seconds,
                      std::string& error) {
    WaitingChild::Impl& c = child.impl();
    error.clear();
    pump(c);
    update_state(c);
    if (c.state != WaitingState::Waiting) {
        error = std::string("the preparation was not sent: ") + state_in_words(c.state) +
                (c.failure.empty() ? "" : ": " + c.failure);
        return false;
    }
    if (!write_to_worker(c, bytes.data(), bytes.size(), timeout_seconds, error)) {
        error = "the preparation was not sent: " + error;
        update_state(c);
        return false;
    }
    return true;
}

std::string take_output(WaitingChild& child) {
    WaitingChild::Impl& c = child.impl();
    pump(c);
    update_state(c);
    std::string taken;
    taken.swap(c.output);
    return taken;
}

bool hand_over_file(WaitingChild& child, const io::File& file, std::span<const std::uint8_t> job,
                    std::string& error) {
    WaitingChild::Impl& c = child.impl();
    error.clear();
    pump(c);
    update_state(c);
    if (c.state != WaitingState::Waiting) {
        error = std::string("the file was not handed over: ") + state_in_words(c.state) +
                (c.failure.empty() ? "" : ": " + c.failure);
        return false;
    }
    if (job.size() > kMaxJobBytes) {
        error = "the file was not handed over: the job is longer than " + std::to_string(kMaxJobBytes) + " bytes";
        return false;
    }
    // A copy of the file's handle INSIDE the worker process, with read rights only
    // (FILE_GENERIC_READ: read data, attributes and extended attributes, read the access
    // list, synchronize; no write, append, delete or change right), NOT inheritable. A handle
    // carries its own rights: the worker can read this one file although its token could not
    // open it by path.
    const HANDLE original = reinterpret_cast<HANDLE>(file.native_handle());
    HANDLE in_worker = nullptr;
    if (!::DuplicateHandle(::GetCurrentProcess(), original, c.child.process, &in_worker, FILE_GENERIC_READ, FALSE,
                           0)) {
        error = win_error("the file was not handed over: DuplicateHandle into the worker", ::GetLastError());
        return false;
    }
    HandOverFrame frame{};
    frame.magic = kFrameMagic;
    frame.version = 1;
    frame.handle_value = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(in_worker));
    frame.job_length = static_cast<std::uint32_t>(job.size());
    if (!job.empty()) {
        std::memcpy(frame.job, job.data(), job.size());
    }
    if (!write_to_worker(c, &frame, sizeof frame, 5, error)) {
        // Half a message may be in the pipe: this worker cannot be used any more.
        error = "the file was not handed over: " + error;
        finish_child(c);
        c.failure = error;
        c.state = WaitingState::Ended;
        return false;
    }
    after_hand_over(c);
    return true;
}

ChildResult collect(WaitingChild& child, const Limits& limits) {
    WaitingChild::Impl& c = child.impl();
    ChildResult result;
    result.confinement = c.child.confinement;
    result.container_folder_note = c.child.folder_note;
    if (c.state != WaitingState::HandedOver) {
        const std::string why = c.state == WaitingState::Ended
                                    ? "the worker had ended before it was given a file: " + c.failure
                                    : std::string("collect() was called on a worker that was given no file");
        end_waiting(child);
        result.end = ChildResult::End::StartFailed;
        result.detail = why;
        return result;
    }
    const auto deadline = c.handed_over + std::chrono::seconds(limits.wall_seconds > 0 ? limits.wall_seconds : 0);
    for (;;) {
        pump(c);
        if (c.ended) {
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            c.killed_time = true;
            FILETIME created{}, ended{}, kernel{}, user{};
            unsigned long long cpu_ms = 0;
            if (::GetProcessTimes(c.child.process, &created, &ended, &kernel, &user)) {
                cpu_ms = ((((static_cast<unsigned long long>(kernel.dwHighDateTime) << 32) | kernel.dwLowDateTime) +
                           ((static_cast<unsigned long long>(user.dwHighDateTime) << 32) | user.dwLowDateTime))) /
                         10000;
            }
            c.at_limit = "at the limit: processor time used " + std::to_string(cpu_ms) + " ms; ";
            break;  // finish_child ends the job
        }
        ::WaitForSingleObject(c.child.process, 10);  // the pause between two looks
    }
    finish_child(c);
    c.state = WaitingState::Ended;

    result.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - c.handed_over).count();
    result.peak_memory_bytes = c.peak_memory;
    result.exit_code = static_cast<int>(c.exit_code);
    if (!c.error_text.empty()) {
        result.detail = "standard error: " + c.error_text;
    }
    const auto with_detail = [&](const std::string& text) {
        result.detail = result.detail.empty() ? text : text + "; " + result.detail;
    };
    const std::string diagnosis = c.at_limit + "exit code " + hex_code(c.exit_code) +
                                  "; bytes received from standard output " + std::to_string(c.out_received) +
                                  ", from standard error " + std::to_string(c.err_received);
    if (!c.killed_time && c.exit_code == static_cast<DWORD>(kHandOverRefusedExitCode)) {
        // The worker refused the hand-over (not exactly one read-only disk file): no answer.
        result.end = ChildResult::End::StartFailed;
        with_detail("the worker refused the hand-over; nothing it wrote is used");
        return result;
    }
    result.output = std::move(c.output);
    if (c.killed_time) {
        result.end = ChildResult::End::KilledByTimeLimit;
        with_detail("killed at the time limit of " + std::to_string(limits.wall_seconds) +
                    " seconds after the hand-over; " + diagnosis);
    } else if (c.killed_output) {
        result.end = ChildResult::End::Crashed;
        with_detail("killed: more output than the allowed " + std::to_string(c.max_output) + " bytes");
    } else if (c.memory_message || c.exit_code == static_cast<DWORD>(kOutOfMemoryExitCode)) {
        result.end = ChildResult::End::KilledByMemoryLimit;
        with_detail(c.memory_message ? "the job reported that the memory limit was reached"
                                     : "the child ran out of its memory limit (an allocation was refused)");
    } else if ((c.exit_code & 0xC0000000u) == 0xC0000000u) {
        result.end = ChildResult::End::Crashed;
        with_detail("ended by an unhandled exception; " + diagnosis);
    } else {
        result.end = ChildResult::End::Exited;
    }
    return result;
}

void end_waiting(WaitingChild& child) {
    WaitingChild::Impl& c = child.impl();
    finish_child(c);
    if (c.failure.empty()) {
        c.failure = "ended by the parent without having been used";
    }
    c.state = WaitingState::Ended;
}

std::string confinement_at_start(const WaitingChild& child) { return child.impl().child.confinement; }

std::string failure(const WaitingChild& child) { return child.impl().failure; }

double seconds_since_start(const WaitingChild& child) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - child.impl().started).count();
}

#if defined(MIE_SANDBOX_TEST_HOOKS)
// Tests only: a hand-over that is not as required. The worker must refuse it.
bool hand_over_malformed(WaitingChild& child, MalformedHandOver kind, const std::filesystem::path& file,
                         std::string& error) {
    WaitingChild::Impl& c = child.impl();
    error.clear();
    pump(c);
    update_state(c);
    if (c.state != WaitingState::Waiting) {
        error = std::string("not sent: ") + state_in_words(c.state);
        return false;
    }
    HandOverFrame frame{};
    frame.magic = kFrameMagic;
    frame.version = 1;
    std::size_t size = sizeof frame;
    HANDLE local = nullptr;
    HANDLE in_worker = nullptr;
    switch (kind) {
        case MalformedHandOver::NoDescriptor:
            break;  // handle value 0
        case MalformedHandOver::TwoDescriptors:
            error = "not applicable on Windows: the message names one handle value";
            return false;
        case MalformedHandOver::NotARegularFile:
            local = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
            break;
        case MalformedHandOver::Writable:
        case MalformedHandOver::ShortMessage:
            local = ::CreateFileW(file.wstring().c_str(),
                                  kind == MalformedHandOver::Writable ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
            if (local == INVALID_HANDLE_VALUE) {
                local = nullptr;
            }
            if (kind == MalformedHandOver::ShortMessage) {
                size = 8;
            }
            break;
    }
    if (kind != MalformedHandOver::NoDescriptor) {
        if (local == nullptr ||
            !::DuplicateHandle(::GetCurrentProcess(), local, c.child.process, &in_worker, 0, FALSE,
                               DUPLICATE_SAME_ACCESS)) {
            error = win_error("test set-up: the object could not be made or duplicated", ::GetLastError());
            close_handle(local);
            return false;
        }
        close_handle(local);
        frame.handle_value = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(in_worker));
    }
    if (!write_to_worker(c, &frame, size, 5, error)) {
        finish_child(c);
        c.state = WaitingState::Ended;
        return false;
    }
    after_hand_over(c);
    return true;
}
#endif

// =============================== the child's side ===============================

namespace {

struct SelfState {
    bool known = false;
    bool appcontainer = false;
    DWORD integrity = 0;
    bool in_job = false;
    int capabilities = -1;  // capability SIDs in the token; -1 = could not be read
};

SelfState self_state() {
    SelfState state;
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return state;
    }
    DWORD is_container = 0;
    DWORD size = 0;
    if (::GetTokenInformation(token, TokenIsAppContainer, &is_container, sizeof is_container, &size)) {
        state.known = true;
        state.appcontainer = is_container != 0;
    }
    unsigned char label_store[256];
    if (::GetTokenInformation(token, TokenIntegrityLevel, label_store, sizeof label_store, &size)) {
        const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(label_store);
        const UCHAR count = *::GetSidSubAuthorityCount(label->Label.Sid);
        if (count > 0) {
            state.integrity = *::GetSidSubAuthority(label->Label.Sid, static_cast<DWORD>(count - 1));
        }
    }
    // The capabilities are what would let a container use the network (internetClient,
    // privateNetworkClientServer, ...). The worker is created with none.
    std::vector<unsigned char> capability_store(4096);
    if (::GetTokenInformation(token, TokenCapabilities, capability_store.data(),
                              static_cast<DWORD>(capability_store.size()), &size)) {
        state.capabilities =
            static_cast<int>(reinterpret_cast<const TOKEN_GROUPS*>(capability_store.data())->GroupCount);
    }
    ::CloseHandle(token);
    BOOL in_job = FALSE;
    if (::IsProcessInJob(::GetCurrentProcess(), nullptr, &in_job)) {
        state.in_job = in_job != FALSE;
    }
    return state;
}

}  // namespace

bool enter_confinement(std::string& what_applied, std::string& error) {
    what_applied.clear();
    error.clear();
    // No error dialogs from this process, whatever fails.
    ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    const SelfState state = self_state();
    what_applied = describe_self();
    if (state.known && state.appcontainer && state.in_job) {
        return true;
    }
    error = !state.known          ? "the process token could not be read"
            : !state.appcontainer ? "this process does not run in an AppContainer"
                                  : "this process is not in a job object";
#if defined(MIE_SANDBOX_TEST_HOOKS)
    // Test builds only: the shipped library does not read this name.
    if (environment_value(L"MIE_SANDBOX_ALLOW_WEAKER") == L"1") {
        what_applied += " WEAKER: " + error;
        return true;
    }
#endif
    return false;
}

// ================== pre-started one-shot workers (ruling M-13): the worker ==================
//
// On Windows the worker is in its AppContainer and its job from its first instruction; there
// is nothing to apply later. So:
//   enter_confinement_stage1()  = the same check as enter_confinement();
//   receive_file_and_seal()     = read ONE job message of fixed size from standard input,
//     close standard input (no second job), check the handle the message names (it must not
//     be inheritable, must hold no write right, must be a disk file), take it over as an
//     io::File. Nothing of the file is read before those checks. A message that is not as
//     required ends the worker with kHandOverRefusedExitCode and no answer; the end of
//     standard input without a message, with kNoJobExitCode.
// The preparation that precedes the job on the same pipe must have been read with
// exact-length, unbuffered reads.

namespace {

[[noreturn]] void refuse_hand_over(const std::string& why) {
    const std::string line = "mie sandbox: hand-over refused: " + why + "\n";
    DWORD written = 0;
    ::WriteFile(::GetStdHandle(STD_ERROR_HANDLE), line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    ::ExitProcess(static_cast<UINT>(kHandOverRefusedExitCode));
}

// The first fields of what NtQueryObject(ObjectBasicInformation = 0) answers.
struct ObjectBasics {
    ULONG attributes;      // OBJ_INHERIT = 0x2
    ACCESS_MASK granted;   // the rights this handle carries
    ULONG handle_count;
    ULONG pointer_count;
    ULONG reserved[10];
};
static_assert(sizeof(ObjectBasics) == 56, "object basic information layout");
using QueryObjectFunction = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

}  // namespace

bool enter_confinement_stage1(std::string& what_applied, std::string& error) {
    return enter_confinement(what_applied, error);
}

std::unique_ptr<io::File> receive_file_and_seal(std::vector<std::uint8_t>& job, std::string& what_applied) {
    job.clear();
    what_applied.clear();
    const HANDLE input = ::GetStdHandle(STD_INPUT_HANDLE);
    HandOverFrame frame{};
    std::size_t have = 0;
    while (have < sizeof frame) {
        DWORD got = 0;
        if (!::ReadFile(input, reinterpret_cast<unsigned char*>(&frame) + have, static_cast<DWORD>(sizeof frame - have),
                        &got, nullptr) ||
            got == 0) {
            break;  // the end of standard input
        }
        have += got;
    }
    if (have == 0) {
        ::ExitProcess(static_cast<UINT>(kNoJobExitCode));  // the parent closed the pipe: never used
    }
    // One job per worker: standard input is closed, whatever follows.
    ::_close(0);
    if (have != sizeof frame) {
        refuse_hand_over("the job message is incomplete");
    }
    if (frame.magic != kFrameMagic || frame.version != 1 || frame.job_length > kMaxJobBytes) {
        refuse_hand_over("the job message is not in the expected form");
    }
    if (frame.handle_value == 0) {
        refuse_hand_over("the job message names no file");
    }
    const HANDLE file_handle = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(frame.handle_value));

    // What the handle is and what it may do, asked of the system; nothing is read from it.
    // (A value that is no handle at all ends an AppContainer process at this call: no answer.)
    const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    const QueryObjectFunction query =
        ntdll != nullptr ? reinterpret_cast<QueryObjectFunction>(::GetProcAddress(ntdll, "NtQueryObject")) : nullptr;
    ObjectBasics basics{};
    ULONG needed = 0;
    if (query == nullptr || query(file_handle, 0, &basics, static_cast<ULONG>(sizeof basics), &needed) != 0) {
        refuse_hand_over("the handed-over handle cannot be asked what it may do");
    }
    constexpr ACCESS_MASK kChangeRights = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                                          FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
    if ((basics.granted & kChangeRights) != 0) {
        refuse_hand_over("the handed-over handle is not read-only");
    }
    if ((basics.attributes & 0x2u) != 0) {
        refuse_hand_over("the handed-over handle is inheritable");
    }
    if (::GetFileType(file_handle) != FILE_TYPE_DISK) {
        refuse_hand_over("the handed-over handle is not a disk file");
    }
    io::IoError io_error;
    std::unique_ptr<io::File> file = io::adopt_native_handle(static_cast<std::intptr_t>(frame.handle_value), io_error);
    if (!file) {
        refuse_hand_over(std::string("the handed-over file cannot be used: ") + io::to_string(io_error.code));
    }
    what_applied = describe_self();
    job.assign(frame.job, frame.job + frame.job_length);
    return file;
}

std::string describe_self() {
    const SelfState state = self_state();
    char integrity[32];
    std::snprintf(integrity, sizeof integrity, "0x%lx", static_cast<unsigned long>(state.integrity));
    return std::string("appcontainer=") + (state.appcontainer ? "1" : "0") + " integrity=" + integrity +
           " in_job=" + (state.in_job ? "1" : "0") + " capabilities=" + std::to_string(state.capabilities);
}

}  // namespace mie::sandbox
