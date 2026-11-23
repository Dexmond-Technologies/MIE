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
#include <cwchar>
#include <iterator>
#include <new>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <windows.h>
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

ChildResult run_confined(const std::filesystem::path& program, const std::vector<std::string>& arguments,
                         const io::File* inherited, std::span<const std::uint8_t> input, const Limits& limits,
                         std::size_t max_output_bytes, const RunOptions& options) {
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

    // ---- the AppContainer --------------------------------------------------------------
    std::string container_text = "none (confinement not requested)";
    bool in_container = false;
    if (options.confine) {
        std::string how;
        std::string why_not;
        if (options.test_break_confinement) {
            why_not = "test hook: the confinement was deliberately not applied";
        } else {
            sid = container_sid(how, why_not);
        }
        if (sid != nullptr) {
            in_container = true;
            container_text = "appcontainer (no capabilities; " + how + ")";
        } else if (options.allow_weaker) {
            container_text = "WEAKER: no AppContainer: " + why_not;
        } else {
            return fail_start("the worker's AppContainer could not be set up: " + why_not);
        }
    }

    // ---- pipes: the child's ends are inheritable, the parent's are not ---------------------
    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof inheritable;
    inheritable.bInheritHandle = TRUE;
    if (!::CreatePipe(&child_in, &parent_in, &inheritable, 0) ||
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
        if (!options.allow_weaker) {
            return fail_start("this build lacks:" + not_built);
        }
        container_text += " WEAKER: built without:" + not_built;
    }
    // Test hook: start in the container WITHOUT the policies, to tell whether a policy is
    // what keeps a child from starting. The result says WEAKER.
    const bool with_policies = in_container && !options.test_without_mitigations;
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
        if (options.allow_weaker) {
            variables.push_back(L"MIE_SANDBOX_ALLOW_WEAKER=1");
        }
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
                         variable_names;
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

// =============================== the child's side ===============================

namespace {

struct SelfState {
    bool known = false;
    bool appcontainer = false;
    DWORD integrity = 0;
    bool in_job = false;
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
    if (environment_value(L"MIE_SANDBOX_ALLOW_WEAKER") == L"1") {
        what_applied += " WEAKER: " + error;
        return true;
    }
    return false;
}

std::string describe_self() {
    const SelfState state = self_state();
    char integrity[32];
    std::snprintf(integrity, sizeof integrity, "0x%lx", static_cast<unsigned long>(state.integrity));
    return std::string("appcontainer=") + (state.appcontainer ? "1" : "0") + " integrity=" + integrity +
           " in_job=" + (state.in_job ? "1" : "0");
}

}  // namespace mie::sandbox
