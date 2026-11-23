#include "test_mie_ui.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QProcess>
#include <QRegularExpression>
#include <QSignalSpy>
#include <QSystemTrayIcon>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#else
#include <sys/inotify.h>
#include <unistd.h>
#endif

#include "fake_service.hpp"
#include "main_window.hpp"
#include "mie/channel/transport.hpp"
#include "mie/result.hpp"
#include "ui_strings.hpp"

namespace mie::ui::test {

namespace {

void report_case(const char* status, const char* id, const std::string& detail) {
    std::printf("%s  %s: %s\n", status, id, detail.c_str());
    std::fflush(stdout);
}

bool ping_endpoint(const mie::channel::Endpoint& ep) {
    std::string err;
    mie::channel::ConnectStatus st = mie::channel::ConnectStatus::Error;
    auto conn = mie::channel::connect(ep, st, err);
    if (!conn || st != mie::channel::ConnectStatus::Ok) {
        return false;
    }
    mie::channel::Message req;
    req.id = 1;
    req.type = mie::channel::MessageType::Request;
    req.op = "ping";
    if (!conn->send(req, err)) {
        return false;
    }
    mie::channel::Message resp;
    if (!conn->receive(resp, 2000, err)) {
        return false;
    }
    return resp.type == mie::channel::MessageType::Response &&
           resp.op == "ping" &&
           resp.body.value("ok", false) &&
           resp.body.value("pong", false);
}

bool shutdown_endpoint(const mie::channel::Endpoint& ep) {
    std::string err;
    auto conn = mie::channel::connect(ep, err);
    if (!conn) {
        return false;
    }
    mie::channel::Message req;
    req.id = 2;
    req.type = mie::channel::MessageType::Request;
    req.op = "shutdown";
    if (!conn->send(req, err)) {
        return false;
    }
    mie::channel::Message resp;
    if (!conn->receive(resp, 2000, err)) {
        return false;
    }
    return resp.body.value("ok", false) && resp.body.value("stopping", false);
}

bool wait_for_service_ready(const mie::channel::Endpoint& ep, QProcess& proc, int max_ms = 10000) {
    const int steps = max_ms / 50;
    for (int i = 0; i < steps; ++i) {
        if (ping_endpoint(ep)) {
            return true;
        }
        if (proc.state() == QProcess::NotRunning) {
            return false;
        }
        QTest::qWait(50);
    }
    return false;
}

mie::ScanResult base_result() {
    mie::ScanResult r;
    r.schema_version = mie::kResultSchemaVersion;
    r.subject.kind = mie::SubjectKind::File;
    r.subject.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    r.subject.display_name = "sample_input.txt";
    r.state = mie::ScanState::Scanned;
    r.reason.clear();
    r.score = 0;
    r.verdict = "CLEAN";
    r.hashes.md5 = "d41d8cd98f00b204e9800998ecf8427e";
    r.hashes.sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    r.hashes.sha256 = r.subject.sha256;
    r.size = 42;
    r.engine_version = "0.1.0-fake";
    r.profile = "stage1";
    r.rules_state = mie::RulesState::On;
    r.rules_sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    return r;
}

MainWindowOptions base_window_options(const std::string& endpoint) {
    MainWindowOptions opts;
    opts.endpoint_override = endpoint;
    opts.refresh_interval_ms = 0;
    opts.persist_geometry = false;
    opts.auto_initial_refresh = false;
    return opts;
}

// Checks text for forbidden words and speed/memory figures (T-8).
// If allow_held_exception is true, strips exact occurrences of kHeldByOtherAccountMessage first.
bool find_forbidden_term(const QString& input, bool allow_held_exception, QString& violation) {
    QString text = input;
    if (allow_held_exception) {
        text.replace(QString::fromUtf8(mie::channel::kHeldByOtherAccountMessage), QString{});
    }

    const std::vector<QRegularExpression> patterns = {
        QRegularExpression(QStringLiteral("anti-?virus"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("\\bprotected\\b"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("\\bprotection\\b"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("real[-\\s]?time"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("100\\s*%"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("\\bsecure\\b"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("\\bsafe\\b"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("\\bclean\\b"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(
            QStringLiteral("\\b\\d+\\s*(ms|kb|mb|gb|tb|kib|mib|gib|ram|bytes/s|kb/s|mb/s|gb/s|files/s)\\b"),
            QRegularExpression::CaseInsensitiveOption),
    };

    for (const QRegularExpression& re : patterns) {
        const QRegularExpressionMatch m = re.match(text);
        if (m.hasMatch()) {
            violation = m.captured(0);
            return true;
        }
    }
    return false;
}

}  // namespace

void MieUiAcceptanceTests::initTestCase() {
    QApplication::setQuitOnLastWindowClosed(false);
    QCOMPARE(QGuiApplication::platformName(), QStringLiteral("offscreen"));

    mie_ui_bin_ = qEnvironmentVariable("MIE_UI_BIN");
    mie_service_bin_ = qEnvironmentVariable("MIE_SERVICE_BIN");
    ui_strings_cpp_ = qEnvironmentVariable("MIE_UI_STRINGS_CPP");
    ui_src_dir_ = qEnvironmentVariable("MIE_UI_SRC_DIR");

    QVERIFY2(!mie_ui_bin_.isEmpty() && QFileInfo::exists(mie_ui_bin_),
             "MIE_UI_BIN must point to built mie-ui binary");
    QVERIFY2(!mie_service_bin_.isEmpty() && QFileInfo::exists(mie_service_bin_),
             "MIE_SERVICE_BIN must point to built mie-service binary");
    QVERIFY2(!ui_strings_cpp_.isEmpty() && QFileInfo::exists(ui_strings_cpp_),
             "MIE_UI_STRINGS_CPP must point to src/ui_strings.cpp");
}

void MieUiAcceptanceTests::cleanupTestCase() {}

void MieUiAcceptanceTests::test_T01_no_service() {
    TestEndpoint ep("t01_none");
    MainWindow w(base_window_options(ep.endpoint.name));
    w.show();

    QSignalSpy spy(&w, &MainWindow::statusApplied);
    w.refreshStatus();
    QVERIFY(spy.wait(5000));

    QCOMPARE(w.visibleStateSummaryText(),
             QStringLiteral("MIE's background service is not running."));
    QVERIFY(w.stateDetailsBox()->isHidden());
    QVERIFY(w.serviceVersionLabel()->text().isEmpty());
    QVERIFY(w.engineStateLabel()->text().isEmpty());
    QVERIFY(w.folderWatchingLabel()->text().isEmpty());
    QVERIFY(w.rulesStateLabel()->text().isEmpty());

    report_case("PASS", "T-1",
                "window shows \"MIE's background service is not running.\" and no state");
}

void MieUiAcceptanceTests::test_T02_real_week0_service() {
    TestEndpoint ep("t02_week0");
    QProcess svc;
    svc.start(mie_service_bin_, {QStringLiteral("--endpoint"),
                                 QString::fromUtf8(ep.endpoint.name.c_str())});
    QVERIFY2(svc.waitForStarted(5000), "mie-service failed to start");

    const bool ready = wait_for_service_ready(ep.endpoint, svc);
    QVERIFY2(ready, "mie-service did not answer ping in time");

    MainWindow w(base_window_options(ep.endpoint.name));
    w.show();

    // 1. State panel shows the exact week-0 absent-engine sentence.
    QSignalSpy status_spy(&w, &MainWindow::statusApplied);
    w.refreshStatus();
    QVERIFY(status_spy.wait(5000));
    QCOMPARE(w.stateNoticeLabel()->text(),
             QStringLiteral("The scan engine is not part of this build. Nothing is being scanned."));
    QVERIFY(!w.stateDetailsBox()->isHidden());
    QCOMPARE(w.folderWatchingLabel()->text(), QStringLiteral("Folder watching: off"));
    QCOMPARE(w.rulesStateLabel()->text(), QStringLiteral("Rules: OFF"));

    // 2. "Scan a file..." shows "Not available in this build."
    w.tabWidget()->setCurrentIndex(1);
    QSignalSpy scan_spy(&w, &MainWindow::scanApplied);
    w.scanPathEdit()->setText(QStringLiteral("synthetic_path_only.txt"));
    QTest::mouseClick(w.scanSubmitButton(), Qt::LeftButton);
    QVERIFY(scan_spy.wait(5000));
    QCOMPARE(w.visibleScanPageText(), QStringLiteral("Not available in this build."));
    QVERIFY(w.scanResultBox()->isHidden());

    // 3. Quarantine page shows "Not available in this build." and nothing else.
    QSignalSpy quar_spy(&w, &MainWindow::quarantineApplied);
    w.tabWidget()->setCurrentIndex(2);
    QVERIFY(quar_spy.wait(5000));
    QCOMPARE(w.visibleQuarantinePageText(), QStringLiteral("Not available in this build."));
    QVERIFY(w.quarantineControlsBox()->isHidden());

    // 4. Trusted files page shows "Not available in this build." and nothing else.
    QSignalSpy trust_spy(&w, &MainWindow::trustedApplied);
    w.tabWidget()->setCurrentIndex(3);
    QVERIFY(trust_spy.wait(5000));
    QCOMPARE(w.visibleTrustedPageText(), QStringLiteral("Not available in this build."));
    QVERIFY(w.trustedControlsBox()->isHidden());

    QVERIFY(shutdown_endpoint(ep.endpoint));
    QVERIFY(svc.waitForFinished(10000));
    QCOMPARE(svc.exitCode(), 0);

    report_case("PASS", "T-2",
                "real week 0 mie-service: window shows engine-absent sentence; scan, quarantine and trusted pages show \"Not available in this build.\"");
}

void MieUiAcceptanceTests::test_T03_status_combinations() {
    TestEndpoint ep("t03_combos");
    FakeService fake(ep.endpoint);
    QVERIFY2(fake.isListening(), fake.listenError().c_str());

    MainWindowOptions opts = base_window_options(ep.endpoint.name);
    opts.tray_available_override = true;
    MainWindow w(opts);
    w.show();

    const bool watching_states[] = {false, true};
    const char* rules_states[] = {"ON", "DEGRADED", "OFF"};

    for (const bool mon : watching_states) {
        for (const char* rules : rules_states) {
            FakeStatusConfig cfg;
            cfg.engine = "ready";
            cfg.monitoring = mon;
            cfg.rules = rules;
            fake.setStatusConfig(cfg);

            QSignalSpy spy(&w, &MainWindow::statusApplied);
            QTest::mouseClick(w.stateRefreshButton(), Qt::LeftButton);
            QVERIFY(spy.wait(5000));

            const QString expected_watch =
                mon ? QStringLiteral("Folder watching: on")
                    : QStringLiteral("Folder watching: off");
            const QString opposite_watch =
                mon ? QStringLiteral("Folder watching: off")
                    : QStringLiteral("Folder watching: on");
            const QString expected_rules =
                QStringLiteral("Rules: ") + QString::fromLatin1(rules);

            const QString win_text = w.visibleStateSummaryText();
            QVERIFY2(win_text.contains(expected_watch), qPrintable(win_text));
            QVERIFY2(!win_text.contains(opposite_watch), qPrintable(win_text));
            QVERIFY2(win_text.contains(expected_rules), qPrintable(win_text));

            const QString tip_text = w.trayTooltipText();
            const QString menu_text = w.trayStateAction()->text();
            QVERIFY2(tip_text.contains(expected_watch), qPrintable(tip_text));
            QVERIFY2(!tip_text.contains(opposite_watch), qPrintable(tip_text));
            QVERIFY2(tip_text.contains(expected_rules), qPrintable(tip_text));
            QVERIFY2(!tip_text.contains(QStringLiteral("Active"), Qt::CaseInsensitive),
                     qPrintable(tip_text));
            QCOMPARE(menu_text, tip_text);
        }
    }

    report_case("PASS", "T-3 (window and QSystemTrayIcon tooltip/menu)",
                "all 6 combinations of folder watching (on/off) and rules (ON/DEGRADED/OFF) matched");

    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        QVERIFY(w.trayIcon() != nullptr && w.trayIcon()->isVisible());
        report_case("PASS", "T-3 (system tray panel)",
                    "native system tray is available and visible");
    } else {
        report_case("NOT RUN", "T-3 (system tray panel)",
                    "QSystemTrayIcon::isSystemTrayAvailable() is false under QT_QPA_PLATFORM=offscreen");
    }
}

void MieUiAcceptanceTests::test_T04_scan_result_states() {
    TestEndpoint ep("t04_results");
    FakeService fake(ep.endpoint);
    QVERIFY2(fake.isListening(), fake.listenError().c_str());

    MainWindow w(base_window_options(ep.endpoint.name));
    w.show();
    w.tabWidget()->setCurrentIndex(1);

    // 1. scanned with verdict
    {
        mie::ScanResult r = base_result();
        r.state = mie::ScanState::Scanned;
        r.score = 15;
        r.verdict = "CLEAN";
        r.findings.push_back(mie::Finding{"note_cat", "general", 15, "benign note", false});
        fake.setScanResult(r);

        QSignalSpy spy(&w, &MainWindow::scanApplied);
        w.scanPathEdit()->setText(QStringLiteral("case_scanned.txt"));
        QTest::mouseClick(w.scanSubmitButton(), Qt::LeftButton);
        QVERIFY(spy.wait(5000));

        const QString page = w.visibleScanPageText();
        QVERIFY2(page.contains(QStringLiteral("State: scanned")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Verdict: CLEAN")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Score: 15")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("benign note")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Engine version: 0.1.0-fake")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Profile: stage1")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Rule-set state: ON")), qPrintable(page));
    }

    // 2. not_fully_scanned with reason (even if producer placed CLEAN in verdict, UI never shows clean)
    {
        mie::ScanResult r = base_result();
        r.state = mie::ScanState::NotFullyScanned;
        r.reason = "archive depth limit reached";
        r.score = 25;
        r.verdict = "CLEAN";
        fake.setScanResult(r);

        QSignalSpy spy(&w, &MainWindow::scanApplied);
        w.scanPathEdit()->setText(QStringLiteral("case_partial.txt"));
        QTest::mouseClick(w.scanSubmitButton(), Qt::LeftButton);
        QVERIFY(spy.wait(5000));

        const QString page = w.visibleScanPageText();
        QVERIFY2(page.contains(QStringLiteral("State: not_fully_scanned")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Reason: archive depth limit reached")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Engine version: 0.1.0-fake")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Profile: stage1")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Rule-set state: ON")), qPrintable(page));
        QVERIFY2(!page.contains(QStringLiteral("clean"), Qt::CaseInsensitive), qPrintable(page));
    }

    // 3. not_scanned with reason: never clean, no score or verdict
    {
        mie::ScanResult r = base_result();
        r.state = mie::ScanState::NotScanned;
        r.reason = "symbolic link refused";
        r.score = 0;
        r.verdict.clear();
        r.findings.clear();
        fake.setScanResult(r);

        QSignalSpy spy(&w, &MainWindow::scanApplied);
        w.scanPathEdit()->setText(QStringLiteral("case_unscanned.txt"));
        QTest::mouseClick(w.scanSubmitButton(), Qt::LeftButton);
        QVERIFY(spy.wait(5000));

        const QString page = w.visibleScanPageText();
        QVERIFY2(page.contains(QStringLiteral("State: not_scanned")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Reason: symbolic link refused")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Engine version: 0.1.0-fake")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Profile: stage1")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Rule-set state: ON")), qPrintable(page));
        QVERIFY2(!page.contains(QStringLiteral("clean"), Qt::CaseInsensitive), qPrintable(page));
        QVERIFY(w.scanVerdictLabel()->isHidden());
        QVERIFY(w.scanScoreLabel()->isHidden());
    }

    report_case("PASS", "T-4",
                "scanned, not_fully_scanned and not_scanned rendered with producer info; not_fully_scanned and not_scanned never show clean");
}

void MieUiAcceptanceTests::test_T05_scan_sends_path_only_no_handle() {
    QTemporaryDir temp_dir;
    QVERIFY(temp_dir.isValid());
    const QString target_qpath = QDir::toNativeSeparators(
        temp_dir.filePath(QStringLiteral("plain_text_subject.txt")));
    const std::string target_utf8 = target_qpath.toUtf8().toStdString();

    {
        QFile out(target_qpath);
        QVERIFY2(out.open(QIODevice::WriteOnly), "Failed to create synthetic T-5 test file");
        out.write("synthetic plain text input for T-5 handle test\n");
        out.close();
    }

    TestEndpoint ep("t05_pathonly");
    FakeService fake(ep.endpoint);
    QVERIFY2(fake.isListening(), fake.listenError().c_str());
    fake.setScanResult(base_result());

#ifdef _WIN32
    const std::wstring wpath = target_qpath.toStdWString();
    HANDLE guard = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 20 && guard == INVALID_HANDLE_VALUE; ++i) {
        guard = ::CreateFileW(wpath.c_str(), GENERIC_READ, 0 /* exclusive: no share */,
                              nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        if (guard == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    }
    QVERIFY2(guard != INVALID_HANDLE_VALUE, "Failed to open exclusive guard handle on test file");

    HANDLE break_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE stop_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    QVERIFY(break_event != nullptr && stop_event != nullptr);

    OVERLAPPED ov{};
    ov.hEvent = break_event;
    DWORD bytes_ret = 0;
    const BOOL ctl_ok = ::DeviceIoControl(
        guard, FSCTL_REQUEST_BATCH_OPLOCK, nullptr, 0, nullptr, 0, &bytes_ret, &ov);
    const DWORD ctl_err = ctl_ok ? ERROR_SUCCESS : ::GetLastError();

    if (!ctl_ok && ctl_err != ERROR_IO_PENDING) {
        ::CloseHandle(guard);
        ::CloseHandle(break_event);
        ::CloseHandle(stop_event);
        report_case("NOT RUN", "T-5 (no-handle kernel proof)",
                    "FSCTL_REQUEST_BATCH_OPLOCK unavailable on runner filesystem, error " +
                        std::to_string(ctl_err));
        return;
    }

    std::atomic<bool> oplock_broken{false};
    std::thread watcher([&]() {
        HANDLE waits[2] = {break_event, stop_event};
        const DWORD w = ::WaitForMultipleObjects(2, waits, FALSE, 15000);
        if (w == WAIT_OBJECT_0) {
            oplock_broken.store(true);
            // Release the exclusive handle immediately so any caller never blocks.
            ::CancelIoEx(guard, &ov);
            DWORD dummy = 0;
            ::GetOverlappedResult(guard, &ov, &dummy, TRUE);
            ::CloseHandle(guard);
            guard = INVALID_HANDLE_VALUE;
        }
    });

    MainWindow win(base_window_options(ep.endpoint.name));
    win.show();
    win.tabWidget()->setCurrentIndex(1);

    QSignalSpy spy(&win, &MainWindow::scanApplied);
    win.scanPathEdit()->setText(target_qpath);
    QTest::mouseClick(win.scanSubmitButton(), Qt::LeftButton);
    QVERIFY(spy.wait(5000));

    const auto scans = fake.recordedScanBodies();
    QCOMPARE(scans.size(), static_cast<std::size_t>(1));
    QCOMPARE(scans[0].size(), static_cast<std::size_t>(1));
    QCOMPARE(scans[0].at("path").get<std::string>(), target_utf8);
    QVERIFY2(!oplock_broken.load(),
             "Batch oplock broke during UI scan: a handle was opened on the file!");

    // Positive control: prove that opening a single read handle DOES break the batch oplock.
    HANDLE probe = ::CreateFileW(wpath.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (probe != INVALID_HANDLE_VALUE) {
        ::CloseHandle(probe);
    }
    ::SetEvent(stop_event);
    watcher.join();
    if (guard != INVALID_HANDLE_VALUE) {
        ::CancelIoEx(guard, &ov);
        DWORD dummy = 0;
        ::GetOverlappedResult(guard, &ov, &dummy, TRUE);
        ::CloseHandle(guard);
    }
    ::CloseHandle(break_event);
    ::CloseHandle(stop_event);
    QVERIFY2(oplock_broken.load(),
             "Positive control failed: batch oplock must break when a handle is opened");

    report_case("PASS", "T-5",
                "exactly 1 scan request with path text; exclusive batch-oplock proved UI opened zero handles (positive control verified)");
#else
    std::atomic<bool> fd_seen_in_proc{false};
    const std::string canonical_target =
        QFileInfo(target_qpath).canonicalFilePath().toUtf8().toStdString();

    fake.setOnScanCallback([&](const nlohmann::json&) {
        QDir fd_dir(QStringLiteral("/proc/self/fd"));
        const QStringList entries = fd_dir.entryList(QDir::NoDotAndDotDot);
        for (const QString& entry : entries) {
            char link_buf[4096]{};
            const QByteArray link_path = fd_dir.filePath(entry).toUtf8();
            const ssize_t n = ::readlink(link_path.constData(), link_buf, sizeof(link_buf) - 1);
            if (n > 0) {
                const std::string resolved(link_buf, static_cast<std::size_t>(n));
                if (resolved == target_utf8 || resolved == canonical_target) {
                    fd_seen_in_proc.store(true);
                }
            }
        }
    });

    const int ino_fd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    QVERIFY2(ino_fd >= 0, "inotify_init1 failed");
    const int wd = ::inotify_add_watch(
        ino_fd, target_utf8.c_str(), IN_OPEN | IN_ACCESS | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE);
    QVERIFY2(wd >= 0, "inotify_add_watch failed");

    MainWindow win(base_window_options(ep.endpoint.name));
    win.show();
    win.tabWidget()->setCurrentIndex(1);

    QSignalSpy spy(&win, &MainWindow::scanApplied);
    win.scanPathEdit()->setText(target_qpath);
    QTest::mouseClick(win.scanSubmitButton(), Qt::LeftButton);
    QVERIFY(spy.wait(5000));

    const auto scans = fake.recordedScanBodies();
    QCOMPARE(scans.size(), static_cast<std::size_t>(1));
    QCOMPARE(scans[0].size(), static_cast<std::size_t>(1));
    QCOMPARE(scans[0].at("path").get<std::string>(), target_utf8);
    QVERIFY2(!fd_seen_in_proc.load(), "/proc/self/fd held an open descriptor to the scanned file");

    char ev_buf[4096]{};
    const ssize_t during_scan_bytes = ::read(ino_fd, ev_buf, sizeof ev_buf);
    QVERIFY2(during_scan_bytes < 0 && errno == EAGAIN,
             "inotify recorded an open/access event on the file during UI scan!");

    // Positive control: open the file once and prove inotify immediately reports IN_OPEN.
    FILE* probe = std::fopen(target_utf8.c_str(), "rb");
    QVERIFY(probe != nullptr);
    std::fclose(probe);
    const ssize_t control_bytes = ::read(ino_fd, ev_buf, sizeof ev_buf);
    ::close(ino_fd);
    QVERIFY2(control_bytes > 0, "Positive control failed: inotify must fire when file is opened");

    report_case("PASS", "T-5",
                "exactly 1 scan request with path text; inotify + /proc/self/fd proved UI opened zero handles (positive control verified)");
#endif
}

void MieUiAcceptanceTests::test_T06_hostile_text() {
    TestEndpoint ep("t06_hostile");
    FakeService fake(ep.endpoint);
    QVERIFY2(fake.isListening(), fake.listenError().c_str());

    // Build hostile string containing HTML tags, a link, newline, embedded NUL, RLO U+202E, and 10,000 chars.
    std::string hostile = "<b>bold</b><img src=x onerror=alert(1)> "
                          "<a href=\"https://example.invalid\">https://example.invalid</a>"
                          "\nline2";
    hostile.push_back('\0');
    hostile.append("after_nul\xE2\x80\xAE" "exe.txt_");
    hostile.append(10000u, 'X');
    QVERIFY(hostile.size() > 10050u);

    mie::ScanResult r = base_result();
    r.state = mie::ScanState::NotFullyScanned;
    r.subject.display_name = hostile;
    r.reason = hostile;
    r.verdict = "SUSPICIOUS (HIGH)";
    r.score = 75;
    r.findings.push_back(mie::Finding{"hostile_cat", "fam", 75, hostile, false});
    fake.setScanResult(r);

    MainWindow w(base_window_options(ep.endpoint.name));
    w.show();
    w.tabWidget()->setCurrentIndex(1);

    QSignalSpy spy(&w, &MainWindow::scanApplied);
    w.scanPathEdit()->setText(QStringLiteral("hostile_case.bin"));
    QTest::mouseClick(w.scanSubmitButton(), Qt::LeftButton);
    QVERIFY(spy.wait(5000));

    QCOMPARE(w.scanSubjectLabel()->textFormat(), Qt::PlainText);
    QVERIFY(!w.scanSubjectLabel()->openExternalLinks());
    QCOMPARE(w.scanReasonLabel()->textFormat(), Qt::PlainText);
    QVERIFY(!w.scanReasonLabel()->openExternalLinks());

    const QString subj = w.scanSubjectLabel()->text();
    const QString reason = w.scanReasonLabel()->text();
    QVERIFY(w.scanFindingsTable()->rowCount() == 1);
    const QString desc = w.scanFindingsTable()->item(0, 4)->text();

    for (const QString& shown : {subj, reason, desc}) {
        // HTML tags and link markup stay literal plain text; never parsed into rich text.
        QVERIFY2(shown.contains(QStringLiteral("<b>bold</b>")), qPrintable(shown));
        QVERIFY2(shown.contains(QStringLiteral("<a href=\"https://example.invalid\">")), qPrintable(shown));
        // Control and bidi-override characters replaced with visible markers; raw chars absent.
        QVERIFY2(shown.contains(QStringLiteral("[U+000A]")), qPrintable(shown));
        QVERIFY2(shown.contains(QStringLiteral("[U+0000]")), qPrintable(shown));
        QVERIFY2(shown.contains(QStringLiteral("[U+202E]")), qPrintable(shown));
        QVERIFY2(!shown.contains(QLatin1Char('\n')), qPrintable(shown));
        QVERIFY2(!shown.contains(QChar(0)), qPrintable(shown));
        QVERIFY2(!shown.contains(QChar(0x202E)), qPrintable(shown));
        // 10,000-character tail truncated for display.
        QVERIFY2(shown.size() < 700, qPrintable(QString::number(shown.size())));
        QVERIFY2(shown.endsWith(QStringLiteral("...")), qPrintable(shown));
    }

    report_case("PASS", "T-6",
                "HTML tags, link, 10,000 chars, newline, NUL and RLO U+202E shown safely as truncated plain text with visible [U+XXXX] markers");
}

void MieUiAcceptanceTests::test_T07_about_and_limits() {
    TestEndpoint ep("t07_about");
    MainWindowOptions opts = base_window_options(ep.endpoint.name);
    opts.licence_dir_override = QStringLiteral("/nonexistent_mie_licence_dir_for_t07");
    MainWindow w(opts);
    w.show();
    w.tabWidget()->setCurrentIndex(4);

    const QString about = w.visibleAboutPageText();
    const QString s_accounts = QStringLiteral(
        "Other user accounts on this computer cannot control MIE. Programs that run under your own account can.");
    const QString s_malware = QStringLiteral(
        "MIE has not been tested against real malware.");
    const QString s_linux = QStringLiteral(
        "This version does not judge Linux programs. It checks Windows programs, scripts, documents and archives.");

    QVERIFY2(about.contains(s_accounts), qPrintable(about));
    QVERIFY2(about.contains(s_malware), qPrintable(about));
#if defined(__linux__)
    QVERIFY2(about.contains(s_linux), qPrintable(about));
#else
    QVERIFY2(!about.contains(s_linux), qPrintable(about));
    QVERIFY2(!about.contains(QStringLiteral("This version does not judge Linux programs")),
             qPrintable(about));
#endif

    QTest::mouseClick(w.openLicencesButton(), Qt::LeftButton);
    QCOMPARE(w.licenceStatusLabel()->text(), QStringLiteral("licence texts not installed"));

    report_case("PASS", "T-7",
                "About and limits fixed sentences verified character for character (platform-specific Linux sentence checked) and missing licence folder handled");
}

void MieUiAcceptanceTests::test_T08_word_check() {
    QFile f(ui_strings_cpp_);
    QVERIFY2(f.open(QIODevice::ReadOnly | QIODevice::Text), "Cannot open src/ui_strings.cpp");
    const QString raw_source = QString::fromUtf8(f.readAll());
    QVERIFY(!raw_source.isEmpty());

    // 1. Raw source file must contain zero forbidden words (even without exception, because
    //    kHeldByOtherAccount references mie::channel::kHeldByOtherAccountMessage by symbol).
    QString violation;
    QVERIFY2(!find_forbidden_term(raw_source, false, violation),
             qPrintable(QStringLiteral("Forbidden term in ui_strings.cpp: ") + violation));

    // 2. Every exported runtime text constant must pass (allowing ONLY the exact kHeldByOtherAccountMessage sentence).
    for (const auto& entry : strings::all_texts()) {
        const QString val = QString::fromUtf8(entry.value);
        const bool is_held = (std::string_view(entry.name) == "kHeldByOtherAccount");
        if (is_held) {
            QCOMPARE(val, QString::fromUtf8(mie::channel::kHeldByOtherAccountMessage));
        }
        QVERIFY2(!find_forbidden_term(val, is_held, violation),
                 qPrintable(QString::fromUtf8(entry.name) + QStringLiteral(": ") + violation));
    }

    // 3. Negative self-checks proving the word detector rejects every forbidden word class.
    const QStringList bad_samples = {
        QStringLiteral("best antivirus tool"),
        QStringLiteral("your PC is protected"),
        QStringLiteral("full protection"),
        QStringLiteral("real-time guard"),
        QStringLiteral("100% detection"),
        QStringLiteral("keeps you secure"),
        QStringLiteral("computer is safe"),
        QStringLiteral("system is clean"),
        QStringLiteral("uses 12 MB of RAM"),
        QStringLiteral("scans in 5 ms"),
    };
    for (const QString& sample : bad_samples) {
        QString caught;
        QVERIFY2(find_forbidden_term(sample, true, caught),
                 qPrintable(QStringLiteral("Word checker failed to catch: ") + sample));
    }

    report_case("PASS", "T-8",
                "src/ui_strings.cpp and all 68 text constants passed forbidden-word and speed/memory checks (self-test verified)");
}

void MieUiAcceptanceTests::test_T09_close_tray_and_service_survives() {
    TestEndpoint ep("t09_close");
    QProcess svc;
    svc.start(mie_service_bin_, {QStringLiteral("--endpoint"),
                                 QString::fromUtf8(ep.endpoint.name.c_str())});
    QVERIFY2(svc.waitForStarted(5000), "mie-service failed to start");
    QVERIFY2(wait_for_service_ready(ep.endpoint, svc), "mie-service did not answer ping");

    // Case A: When a tray icon exists, closing the window hides it and does NOT quit.
    {
        MainWindowOptions opts = base_window_options(ep.endpoint.name);
        opts.tray_available_override = true;
        MainWindow w(opts);
        w.show();
        QVERIFY(w.isVisible());
        QVERIFY(w.hasTrayIcon());

        QSignalSpy quit_spy(&w, &MainWindow::quitRequested);
        w.close();
        QVERIFY(!w.isVisible());
        QCOMPARE(quit_spy.count(), 0);

        // Tray Open action brings the window back; Tray Quit action quits the UI program.
        w.trayOpenAction()->trigger();
        QVERIFY(w.isVisible());
        w.trayQuitAction()->trigger();
        QCOMPARE(quit_spy.count(), 1);
    }

    // Case B: When NO tray icon exists, closing the window quits the UI program.
    {
        MainWindowOptions opts = base_window_options(ep.endpoint.name);
        opts.tray_available_override = false;
        MainWindow w(opts);
        w.show();
        QVERIFY(w.isVisible());
        QVERIFY(!w.hasTrayIcon());

        QSignalSpy quit_spy(&w, &MainWindow::quitRequested);
        w.close();
        QCOMPARE(quit_spy.count(), 1);
    }

    // Quitting mie-ui must NOT stop mie-service.
    QCOMPARE(svc.state(), QProcess::Running);
    QVERIFY2(ping_endpoint(ep.endpoint), "mie-service stopped or became unreachable after mie-ui quit!");

    QVERIFY(shutdown_endpoint(ep.endpoint));
    QVERIFY(svc.waitForFinished(10000));
    QCOMPARE(svc.exitCode(), 0);

    report_case("PASS", "T-9",
                "closing hides window when tray exists and quits when no tray exists; real mie-service stays running after quit");
}

void MieUiAcceptanceTests::test_T10_responsive_during_3s_delay() {
    TestEndpoint ep("t10_delay");
    FakeService fake(ep.endpoint);
    QVERIFY2(fake.isListening(), fake.listenError().c_str());

    FakeStatusConfig cfg;
    cfg.response_delay_ms = 3000;
    fake.setStatusConfig(cfg);

    MainWindow w(base_window_options(ep.endpoint.name));
    w.show();

    int event_loop_ticks = 0;
    QTimer heartbeat;
    connect(&heartbeat, &QTimer::timeout, [&event_loop_ticks]() { ++event_loop_ticks; });
    heartbeat.start(40);

    QSignalSpy spy(&w, &MainWindow::statusApplied);
    QElapsedTimer timer;
    timer.start();
    w.refreshStatus();
    QVERIFY(spy.wait(8000));
    const qint64 elapsed_ms = timer.elapsed();
    heartbeat.stop();

    QVERIFY2(elapsed_ms >= 2800,
             qPrintable(QStringLiteral("Expected ~3000ms delay, got ") + QString::number(elapsed_ms)));
    QVERIFY2(event_loop_ticks >= 25,
             qPrintable(QStringLiteral("GUI event loop froze; ticks=") +
                        QString::number(event_loop_ticks)));

    report_case("PASS", "T-10",
                "GUI event loop stayed responsive (" + std::to_string(event_loop_ticks) +
                    " heartbeat ticks) while fake service delayed 3 s");
}

void MieUiAcceptanceTests::test_T11_dynamic_qt_linking() {
#ifdef _WIN32
    QString dumpbin = QStringLiteral("dumpbin.exe");
    {
        QProcess probe;
        probe.start(dumpbin, {QStringLiteral("/?")});
        if (!probe.waitForFinished(5000) || probe.exitCode() != 0) {
            const QString vswhere =
                QStringLiteral("C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe");
            QProcess loc;
            loc.start(vswhere, {
                QStringLiteral("-latest"),
                QStringLiteral("-products"), QStringLiteral("*"),
                QStringLiteral("-requires"), QStringLiteral("Microsoft.VisualStudio.Component.VC.Tools.x86.x64"),
                QStringLiteral("-find"), QStringLiteral("VC\\Tools\\MSVC\\**\\bin\\Hostx64\\x64\\dumpbin.exe")
            });
            QVERIFY2(loc.waitForFinished(10000), "vswhere failed to locate dumpbin.exe");
            const QStringList lines =
                QString::fromUtf8(loc.readAllStandardOutput()).split(QLatin1Char('\n'), Qt::SkipEmptyParts);
            QVERIFY2(!lines.isEmpty(), "dumpbin.exe not found via vswhere");
            dumpbin = lines.first().trimmed();
        }
    }

    QProcess proc;
    proc.start(dumpbin, {QStringLiteral("/dependents"), QDir::toNativeSeparators(mie_ui_bin_)});
    QVERIFY2(proc.waitForFinished(15000) && proc.exitCode() == 0, "dumpbin /dependents failed");
    const QString output = QString::fromUtf8(proc.readAllStandardOutput());
    std::printf("--- dumpbin /dependents mie-ui.exe ---\n%s\n--------------------------------------\n",
                output.toUtf8().constData());
    std::fflush(stdout);

    QRegularExpression dll_re(QStringLiteral("\\b([A-Za-z0-9_+.-]+\\.dll)\\b"),
                              QRegularExpression::CaseInsensitiveOption);
    QStringList qt_dlls;
    auto it = dll_re.globalMatch(output);
    while (it.hasNext()) {
        const QString dll = it.next().captured(1);
        if (dll.startsWith(QStringLiteral("Qt"), Qt::CaseInsensitive)) {
            qt_dlls.push_back(dll.toLower());
        }
    }
    qt_dlls.removeDuplicates();
    qt_dlls.sort();

    const QStringList expected = {
        QStringLiteral("qt6core.dll"),
        QStringLiteral("qt6gui.dll"),
        QStringLiteral("qt6widgets.dll"),
    };
    QCOMPARE(qt_dlls, expected);

    report_case("PASS", "T-11",
                "dumpbin /dependents verified Qt6Core.dll, Qt6Gui.dll and Qt6Widgets.dll as separate shared libraries and no other Qt DLL");
#else
    // 1. Direct ELF NEEDED entries of mie-ui via readelf -d
    QProcess readelf;
    readelf.start(QStringLiteral("readelf"), {QStringLiteral("-d"), mie_ui_bin_});
    QVERIFY2(readelf.waitForFinished(10000) && readelf.exitCode() == 0, "readelf -d failed");
    const QString elf_out = QString::fromUtf8(readelf.readAllStandardOutput());
    std::printf("--- readelf -d mie-ui ---\n%s\n-------------------------\n",
                elf_out.toUtf8().constData());

    QRegularExpression needed_re(QStringLiteral("\\(NEEDED\\)\\s+Shared library:\\s+\\[([^\\]]+)\\]"));
    QStringList direct_qt;
    auto nit = needed_re.globalMatch(elf_out);
    while (nit.hasNext()) {
        const QString lib = nit.next().captured(1);
        if (lib.startsWith(QStringLiteral("libQt"), Qt::CaseInsensitive)) {
            direct_qt.push_back(lib);
        }
    }
    direct_qt.sort();
    const QStringList expected_direct = {
        QStringLiteral("libQt6Core.so.6"),
        QStringLiteral("libQt6Gui.so.6"),
        QStringLiteral("libQt6Widgets.so.6"),
    };
    QCOMPARE(direct_qt, expected_direct);

    // 2. Dynamic resolution via ldd (logged in full as required)
    QProcess ldd;
    ldd.start(QStringLiteral("ldd"), {mie_ui_bin_});
    QVERIFY2(ldd.waitForFinished(10000) && ldd.exitCode() == 0, "ldd failed");
    const QString ldd_out = QString::fromUtf8(ldd.readAllStandardOutput());
    std::printf("--- ldd mie-ui ---\n%s\n------------------\n", ldd_out.toUtf8().constData());
    std::fflush(stdout);

    QRegularExpression ldd_re(QStringLiteral("^\\s*(libQt[^\\s=>]+)\\s*=>\\s*([^\\s(]+)"),
                              QRegularExpression::MultilineOption);
    QMap<QString, QString> resolved_qt;
    auto lit = ldd_re.globalMatch(ldd_out);
    while (lit.hasNext()) {
        const auto m = lit.next();
        resolved_qt.insert(m.captured(1), m.captured(2));
    }

    for (const QString& req : expected_direct) {
        QVERIFY2(resolved_qt.contains(req), qPrintable(QStringLiteral("Missing in ldd: ") + req));
        QVERIFY2(QFileInfo::exists(resolved_qt.value(req)),
                 qPrintable(QStringLiteral("Resolved file missing: ") + resolved_qt.value(req)));
    }
    // Verify the three paths are distinct shared library files.
    QVERIFY(resolved_qt.value(QStringLiteral("libQt6Core.so.6")) !=
            resolved_qt.value(QStringLiteral("libQt6Gui.so.6")));
    QVERIFY(resolved_qt.value(QStringLiteral("libQt6Gui.so.6")) !=
            resolved_qt.value(QStringLiteral("libQt6Widgets.so.6")));

    // Check if Qt6Gui itself pulls libQt6DBus.so.6 on Linux; forbid any other Qt library.
    bool gui_needs_dbus = false;
    {
        QProcess gui_elf;
        gui_elf.start(QStringLiteral("readelf"),
                      {QStringLiteral("-d"), resolved_qt.value(QStringLiteral("libQt6Gui.so.6"))});
        if (gui_elf.waitForFinished(5000) && gui_elf.exitCode() == 0) {
            gui_needs_dbus = QString::fromUtf8(gui_elf.readAllStandardOutput())
                                 .contains(QStringLiteral("libQt6DBus.so.6"));
        }
    }
    for (auto it = resolved_qt.cbegin(); it != resolved_qt.cend(); ++it) {
        const QString& name = it.key();
        if (expected_direct.contains(name)) {
            continue;
        }
        if (name == QStringLiteral("libQt6DBus.so.6") && gui_needs_dbus) {
            continue;
        }
        QFAIL(qPrintable(QStringLiteral("Unexpected Qt library in ldd output: ") + name));
    }

    report_case("PASS", "T-11",
                "readelf -d + ldd verified mie-ui links ONLY libQt6Core.so.6, libQt6Gui.so.6 and libQt6Widgets.so.6 as separate shared libraries");
#endif
}

void MieUiAcceptanceTests::test_T12_malformed_service_answers() {
    const QString expected_msg = QStringLiteral(
        "MIE's background service gave an answer this program does not understand.");

    // Helper: seed MainWindow with a valid FakeService status first, then switch endpoint to
    // the malformed server and verify the bad-answer sentence replaces all state.
    TestEndpoint good_ep("t12_good");
    FakeService good_svc(good_ep.endpoint);
    QVERIFY2(good_svc.isListening(), good_svc.listenError().c_str());

    const std::vector<std::pair<std::string, std::string>> raw_cases = {
        {"broken_empty_frame", std::string("\x00\x00\x00\x00", 4)},
        {"broken_json_frame", make_raw_frame("{not_valid_json")},
        {"unknown_envelope_field",
         make_raw_frame("{\"v\":1,\"id\":1,\"type\":\"response\",\"op\":\"status\","
                        "\"body\":{\"ok\":true},\"extra\":1}")},
        {"protocol_version_2",
         make_raw_frame("{\"v\":2,\"id\":1,\"type\":\"response\",\"op\":\"status\","
                        "\"body\":{\"ok\":true}}")},
    };

    for (const auto& [label, raw_bytes] : raw_cases) {
        MainWindow w(base_window_options(good_ep.endpoint.name));
        w.show();
        QSignalSpy spy(&w, &MainWindow::statusApplied);
        w.refreshStatus();
        QVERIFY(spy.wait(5000));
        QVERIFY(!w.stateDetailsBox()->isHidden());

        TestEndpoint bad_ep("t12_" + label);
        RawFrameServer raw_srv(bad_ep.endpoint, raw_bytes);
        QVERIFY2(raw_srv.isReady(), raw_srv.startError().c_str());

        w.serviceClient().setEndpointOverride(bad_ep.endpoint.name);
        w.refreshStatus();
        QVERIFY(spy.wait(5000));

        QCOMPARE(w.visibleStateSummaryText(), expected_msg);
        QVERIFY2(w.stateDetailsBox()->isHidden(), label.c_str());
    }

    // Also test unknown field inside status response body via FakeService.
    {
        MainWindow w(base_window_options(good_ep.endpoint.name));
        w.show();
        QSignalSpy spy(&w, &MainWindow::statusApplied);
        w.refreshStatus();
        QVERIFY(spy.wait(5000));
        QVERIFY(!w.stateDetailsBox()->isHidden());

        FakeStatusConfig bad_body_cfg;
        bad_body_cfg.extra_unknown_field = true;
        good_svc.setStatusConfig(bad_body_cfg);
        w.refreshStatus();
        QVERIFY(spy.wait(5000));

        QCOMPARE(w.visibleStateSummaryText(), expected_msg);
        QVERIFY(w.stateDetailsBox()->isHidden());
    }

    report_case("PASS", "T-12",
                "broken frames, unknown envelope/body fields and protocol version 2 show exact not-understood sentence and clear all state");
}

void MieUiAcceptanceTests::test_T13_held_by_other_account() {
    const QString expected_held = QString::fromUtf8(mie::channel::kHeldByOtherAccountMessage);

    // Part 1: Connect step replaced in test to report ConnectStatus::HeldByOtherAccount.
    {
        TestEndpoint ep("t13_injected");
        MainWindowOptions opts = base_window_options(ep.endpoint.name);
        opts.tray_available_override = true;
        opts.connect_fn = [](const mie::channel::Endpoint&,
                             mie::channel::ConnectStatus& status,
                             std::string& error) -> std::unique_ptr<mie::channel::Connection> {
            status = mie::channel::ConnectStatus::HeldByOtherAccount;
            error = "simulated held by other account";
            return nullptr;
        };

        MainWindow w(opts);
        w.show();
        QSignalSpy spy(&w, &MainWindow::statusApplied);
        w.refreshStatus();
        QVERIFY(spy.wait(5000));

        QCOMPARE(w.visibleStateSummaryText(), expected_held);
        QVERIFY(w.stateDetailsBox()->isHidden());
        QCOMPARE(w.trayTooltipText(), expected_held);
        QCOMPARE(w.trayStateAction()->text(), expected_held);
    }
    report_case("PASS", "T-13 (injected ConnectStatus::HeldByOtherAccount)",
                "window and QSystemTrayIcon tooltip/menu match kHeldByOtherAccountMessage character for character and show no state");

    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        report_case("NOT RUN", "T-13 (system tray panel)",
                    "QSystemTrayIcon::isSystemTrayAvailable() is false under QT_QPA_PLATFORM=offscreen");
    }

    // Part 2: Real mie::channel::connect against root-owned socket directory on Ubuntu.
#ifdef _WIN32
    report_case("NOT RUN", "T-13 (real client foreign-owned endpoint)",
                "Windows requires a second user account to create a named pipe owned by another SID");
#else
    QTemporaryDir temp_dir;
    QVERIFY(temp_dir.isValid());
    const QString held_dir = temp_dir.filePath(QStringLiteral("held_sock_dir"));
    QVERIFY(QDir().mkdir(held_dir));
    QFile::setPermissions(held_dir, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);

    QProcess chown_root;
    chown_root.start(QStringLiteral("sudo"),
                     {QStringLiteral("-n"), QStringLiteral("chown"),
                      QStringLiteral("root:root"), held_dir});
    if (!chown_root.waitForFinished(5000) || chown_root.exitCode() != 0) {
        report_case("NOT RUN", "T-13 (real client root-owned socket directory)",
                    "password-less sudo is not available on this machine");
        return;
    }

    const std::string held_sock =
        QDir(held_dir).filePath(QStringLiteral("service.sock")).toUtf8().toStdString();
    MainWindowOptions real_opts = base_window_options(held_sock);
    real_opts.tray_available_override = true;
    MainWindow w_real(real_opts);
    w_real.show();

    QSignalSpy real_spy(&w_real, &MainWindow::statusApplied);
    w_real.refreshStatus();
    const bool got_real = real_spy.wait(5000);

    // Restore ownership so QTemporaryDir cleans up cleanly before any assertions.
    QProcess chown_back;
    chown_back.start(QStringLiteral("sudo"),
                     {QStringLiteral("-n"), QStringLiteral("chown"),
                      QStringLiteral("%1:%2").arg(::getuid()).arg(::getgid()), held_dir});
    chown_back.waitForFinished(5000);

    QVERIFY(got_real);
    QCOMPARE(w_real.visibleStateSummaryText(), expected_held);
    QVERIFY(w_real.stateDetailsBox()->isHidden());
    QCOMPARE(w_real.trayTooltipText(), expected_held);

    report_case("PASS", "T-13 (real client root-owned socket directory)",
                "real mie::channel::connect against root-owned directory showed kHeldByOtherAccountMessage in window and tray and no state");
#endif
}

void MieUiAcceptanceTests::test_T14_rules_degraded_off_and_refusal() {
    TestEndpoint ep("t14_rules");
    FakeService fake(ep.endpoint);
    QVERIFY2(fake.isListening(), fake.listenError().c_str());

    MainWindow w(base_window_options(ep.endpoint.name));
    w.show();
    w.tabWidget()->setCurrentIndex(1);

    // 1a. Consistent result with rules DEGRADED and state not_fully_scanned
    {
        mie::ScanResult r = base_result();
        r.state = mie::ScanState::NotFullyScanned;
        r.reason = "two rule files failed to compile";
        r.rules_state = mie::RulesState::Degraded;
        r.score = 10;
        r.verdict = "SUSPICIOUS (LOW)";
        fake.setScanResult(r);

        QSignalSpy spy(&w, &MainWindow::scanApplied);
        w.scanPathEdit()->setText(QStringLiteral("degraded_case.exe"));
        QTest::mouseClick(w.scanSubmitButton(), Qt::LeftButton);
        QVERIFY(spy.wait(5000));

        const QString page = w.visibleScanPageText();
        QVERIFY2(page.contains(QStringLiteral("State: not_fully_scanned")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Reason: two rule files failed to compile")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Rule-set state: DEGRADED")), qPrintable(page));
        QVERIFY2(!page.contains(QStringLiteral("clean"), Qt::CaseInsensitive), qPrintable(page));
    }

    // 1b. Consistent result with rules OFF and state not_fully_scanned
    {
        mie::ScanResult r = base_result();
        r.state = mie::ScanState::NotFullyScanned;
        r.reason = "no rule set loaded";
        r.rules_state = mie::RulesState::Off;
        r.rules_sha256.clear();
        r.score = 0;
        r.verdict.clear();
        fake.setScanResult(r);

        QSignalSpy spy(&w, &MainWindow::scanApplied);
        w.scanPathEdit()->setText(QStringLiteral("rules_off_case.exe"));
        QTest::mouseClick(w.scanSubmitButton(), Qt::LeftButton);
        QVERIFY(spy.wait(5000));

        const QString page = w.visibleScanPageText();
        QVERIFY2(page.contains(QStringLiteral("State: not_fully_scanned")), qPrintable(page));
        QVERIFY2(page.contains(QStringLiteral("Rule-set state: OFF")), qPrintable(page));
        QVERIFY2(!page.contains(QStringLiteral("clean"), Qt::CaseInsensitive), qPrintable(page));
    }

    // 2. Dishonest result claiming state=="scanned" while rules.state=="DEGRADED":
    //    mie::from_json refuses it and the window shows the not-understood sentence, never a verdict.
    {
        mie::ScanResult dishonest = base_result();
        dishonest.state = mie::ScanState::Scanned;
        dishonest.reason.clear();
        dishonest.rules_state = mie::RulesState::Degraded;
        dishonest.verdict = "CLEAN";

        const std::string bad_json_text = mie::to_json(dishonest);
        mie::ScanResult parsed_check;
        std::string parse_err;
        QVERIFY2(!mie::from_json(bad_json_text, parsed_check, parse_err),
                 "mie::from_json must refuse scanned + DEGRADED");

        fake.setScanRawBody(nlohmann::json::parse(bad_json_text));

        QSignalSpy spy(&w, &MainWindow::scanApplied);
        w.scanPathEdit()->setText(QStringLiteral("dishonest_case.exe"));
        QTest::mouseClick(w.scanSubmitButton(), Qt::LeftButton);
        QVERIFY(spy.wait(5000));

        QCOMPARE(w.visibleScanPageText(),
                 QStringLiteral("MIE's background service gave an answer this program does not understand."));
        QVERIFY(w.scanResultBox()->isHidden());
        QVERIFY(!w.visibleScanPageText().contains(QStringLiteral("CLEAN"), Qt::CaseInsensitive));
    }

    report_case("PASS", "T-14",
                "DEGRADED/OFF with not_fully_scanned shown with visible rule-set state; scanned+DEGRADED refused by mie::from_json and shown as not-understood");
}

}  // namespace mie::ui::test

QTEST_MAIN(mie::ui::test::MieUiAcceptanceTests)
