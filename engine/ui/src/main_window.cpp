#include "main_window.hpp"

#include <utility>

#include <QAbstractItemView>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QPainter>
#include <QPixmap>
#include <QPoint>
#include <QSettings>
#include <QSize>
#include <QUrl>
#include <QVBoxLayout>

#include "text_sanitize.hpp"
#include "ui_strings.hpp"

namespace mie::ui {

namespace {

QLabel* make_plain_label(const QString& text = {}, QWidget* parent = nullptr) {
    auto* label = new QLabel(text, parent);
    label->setTextFormat(Qt::PlainText);
    label->setOpenExternalLinks(false);
    label->setWordWrap(true);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    return label;
}

QIcon make_program_icon() {
    QPixmap pixmap(32, 32);
    pixmap.fill(QColor(34, 58, 94));
    QPainter painter(&pixmap);
    painter.setPen(QColor(240, 244, 248));
    painter.drawRect(2, 2, 27, 27);
    painter.drawRect(7, 7, 17, 17);
    painter.end();
    return QIcon(pixmap);
}

QString rules_label_text(mie::RulesState state) {
    switch (state) {
        case mie::RulesState::On:
            return QString::fromUtf8(strings::kRulesOn);
        case mie::RulesState::Degraded:
            return QString::fromUtf8(strings::kRulesDegraded);
        case mie::RulesState::Off:
            return QString::fromUtf8(strings::kRulesOff);
    }
    return QString::fromUtf8(strings::kRulesOff);
}

void append_if_visible(QStringList& lines, const QWidget* container, const QLabel* label) {
    if (label == nullptr) {
        return;
    }
    if (container != nullptr && container->isHidden()) {
        return;
    }
    if (!label->isHidden() && !label->text().isEmpty()) {
        lines.push_back(label->text());
    }
}

}  // namespace

MainWindow::MainWindow(MainWindowOptions options, QWidget* parent)
    : QMainWindow(parent),
      options_(std::move(options)),
      client_(options_.endpoint_override, options_.connect_fn) {
    setWindowTitle(QString::fromUtf8(strings::kProductName));
    setWindowIcon(make_program_icon());
    resize(760, 540);

    buildUi();
    setupTray();
    loadWindowGeometry();

    connect(&client_, &ServiceClient::statusFinished,
            this, &MainWindow::onStatusFinished);
    connect(&client_, &ServiceClient::scanFinished,
            this, &MainWindow::onScanFinished);
    connect(&client_, &ServiceClient::quarantineListFinished,
            this, &MainWindow::onQuarantineFinished);
    connect(&client_, &ServiceClient::trustedListFinished,
            this, &MainWindow::onTrustedFinished);

    connect(&refresh_timer_, &QTimer::timeout, this, &MainWindow::refreshStatus);
    if (options_.refresh_interval_ms > 0) {
        refresh_timer_.start(options_.refresh_interval_ms);
    }

    if (options_.auto_initial_refresh) {
        refreshStatus();
    }
}

MainWindow::~MainWindow() {
    refresh_timer_.stop();
    if (tray_icon_ != nullptr) {
        tray_icon_->hide();
    }
    delete tray_menu_;
    tray_menu_ = nullptr;
}

void MainWindow::buildUi() {
    tabs_ = new QTabWidget(this);
    tabs_->addTab(buildStatePage(), QString::fromUtf8(strings::kTabState));
    tabs_->addTab(buildScanPage(), QString::fromUtf8(strings::kTabScan));
    tabs_->addTab(buildQuarantinePage(), QString::fromUtf8(strings::kTabQuarantine));
    tabs_->addTab(buildTrustedPage(), QString::fromUtf8(strings::kTabTrusted));
    tabs_->addTab(buildAboutPage(), QString::fromUtf8(strings::kTabAbout));
    connect(tabs_, &QTabWidget::currentChanged, this, &MainWindow::onTabChanged);
    setCentralWidget(tabs_);
}

QWidget* MainWindow::buildStatePage() {
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);

    auto* top_bar = new QHBoxLayout();
    state_refresh_button_ = new QPushButton(QString::fromUtf8(strings::kButtonRefresh), page);
    connect(state_refresh_button_, &QPushButton::clicked, this, &MainWindow::refreshStatus);
    top_bar->addWidget(state_refresh_button_);
    top_bar->addStretch(1);
    layout->addLayout(top_bar);

    state_notice_label_ = make_plain_label(QString::fromUtf8(strings::kCheckingService), page);
    layout->addWidget(state_notice_label_);

    state_details_box_ = new QWidget(page);
    auto* details_layout = new QVBoxLayout(state_details_box_);
    details_layout->setContentsMargins(0, 8, 0, 0);
    service_version_label_ = make_plain_label({}, state_details_box_);
    engine_state_label_ = make_plain_label({}, state_details_box_);
    folder_watching_label_ = make_plain_label({}, state_details_box_);
    rules_state_label_ = make_plain_label({}, state_details_box_);
    details_layout->addWidget(service_version_label_);
    details_layout->addWidget(engine_state_label_);
    details_layout->addWidget(folder_watching_label_);
    details_layout->addWidget(rules_state_label_);
    state_details_box_->setVisible(false);
    layout->addWidget(state_details_box_);

    layout->addStretch(1);
    return page;
}

QWidget* MainWindow::buildScanPage() {
    auto* page = new QWidget(this);
    auto* layout = new QVBoxLayout(page);

    scan_controls_box_ = new QWidget(page);
    auto* controls_layout = new QVBoxLayout(scan_controls_box_);
    controls_layout->setContentsMargins(0, 0, 0, 0);

    scan_prompt_label_ = make_plain_label(QString::fromUtf8(strings::kScanPathPrompt), scan_controls_box_);
    controls_layout->addWidget(scan_prompt_label_);

    auto* row = new QHBoxLayout();
    scan_path_edit_ = new QLineEdit(scan_controls_box_);
    scan_choose_button_ = new QPushButton(QString::fromUtf8(strings::kScanChooseButton), scan_controls_box_);
    scan_submit_button_ = new QPushButton(QString::fromUtf8(strings::kScanSubmitButton), scan_controls_box_);
    connect(scan_choose_button_, &QPushButton::clicked, this, &MainWindow::onChooseScanFile);
    connect(scan_submit_button_, &QPushButton::clicked, this, &MainWindow::submitScan);
    row->addWidget(scan_path_edit_, 1);
    row->addWidget(scan_choose_button_);
    row->addWidget(scan_submit_button_);
    controls_layout->addLayout(row);
    layout->addWidget(scan_controls_box_);

    scan_notice_label_ = make_plain_label({}, page);
    scan_notice_label_->setVisible(false);
    layout->addWidget(scan_notice_label_);

    scan_result_box_ = new QWidget(page);
    auto* result_layout = new QVBoxLayout(scan_result_box_);
    result_layout->setContentsMargins(0, 8, 0, 0);

    scan_subject_label_ = make_plain_label({}, scan_result_box_);
    scan_sha256_label_ = make_plain_label({}, scan_result_box_);
    scan_state_label_ = make_plain_label({}, scan_result_box_);
    scan_state_note_label_ = make_plain_label({}, scan_result_box_);
    scan_reason_label_ = make_plain_label({}, scan_result_box_);
    scan_verdict_label_ = make_plain_label({}, scan_result_box_);
    scan_score_label_ = make_plain_label({}, scan_result_box_);
    scan_engine_version_label_ = make_plain_label({}, scan_result_box_);
    scan_profile_label_ = make_plain_label({}, scan_result_box_);
    scan_rules_state_label_ = make_plain_label({}, scan_result_box_);
    scan_findings_heading_label_ = make_plain_label(
        QString::fromUtf8(strings::kScanFindingsHeading), scan_result_box_);
    scan_no_findings_label_ = make_plain_label(
        QString::fromUtf8(strings::kScanNoFindings), scan_result_box_);

    scan_findings_table_ = new QTableWidget(0, 5, scan_result_box_);
    scan_findings_table_->setHorizontalHeaderLabels({
        QString::fromUtf8(strings::kFindingColCategory),
        QString::fromUtf8(strings::kFindingColFamily),
        QString::fromUtf8(strings::kFindingColWeight),
        QString::fromUtf8(strings::kFindingColFloor),
        QString::fromUtf8(strings::kFindingColDescription),
    });
    scan_findings_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    scan_findings_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    scan_findings_table_->horizontalHeader()->setStretchLastSection(true);

    result_layout->addWidget(scan_subject_label_);
    result_layout->addWidget(scan_sha256_label_);
    result_layout->addWidget(scan_state_label_);
    result_layout->addWidget(scan_state_note_label_);
    result_layout->addWidget(scan_reason_label_);
    result_layout->addWidget(scan_verdict_label_);
    result_layout->addWidget(scan_score_label_);
    result_layout->addWidget(scan_engine_version_label_);
    result_layout->addWidget(scan_profile_label_);
    result_layout->addWidget(scan_rules_state_label_);
    result_layout->addWidget(scan_findings_heading_label_);
    result_layout->addWidget(scan_no_findings_label_);
    result_layout->addWidget(scan_findings_table_, 1);

    scan_result_box_->setVisible(false);
    layout->addWidget(scan_result_box_, 1);
    layout->addStretch(1);
    return page;
}

QWidget* MainWindow::buildQuarantinePage() {
    quarantine_page_ = new QWidget(this);
    auto* layout = new QVBoxLayout(quarantine_page_);

    quarantine_controls_box_ = new QWidget(quarantine_page_);
    auto* bar = new QHBoxLayout(quarantine_controls_box_);
    bar->setContentsMargins(0, 0, 0, 0);
    quarantine_refresh_button_ =
        new QPushButton(QString::fromUtf8(strings::kQuarantineRefreshButton), quarantine_controls_box_);
    connect(quarantine_refresh_button_, &QPushButton::clicked, this, &MainWindow::refreshQuarantine);
    bar->addWidget(quarantine_refresh_button_);
    bar->addStretch(1);
    quarantine_controls_box_->setVisible(false);
    layout->addWidget(quarantine_controls_box_);

    quarantine_notice_label_ =
        make_plain_label(QString::fromUtf8(strings::kCheckingService), quarantine_page_);
    layout->addWidget(quarantine_notice_label_);
    layout->addStretch(1);
    return quarantine_page_;
}

QWidget* MainWindow::buildTrustedPage() {
    trusted_page_ = new QWidget(this);
    auto* layout = new QVBoxLayout(trusted_page_);

    trusted_controls_box_ = new QWidget(trusted_page_);
    auto* bar = new QHBoxLayout(trusted_controls_box_);
    bar->setContentsMargins(0, 0, 0, 0);
    trusted_refresh_button_ =
        new QPushButton(QString::fromUtf8(strings::kTrustedRefreshButton), trusted_controls_box_);
    connect(trusted_refresh_button_, &QPushButton::clicked, this, &MainWindow::refreshTrusted);
    bar->addWidget(trusted_refresh_button_);
    bar->addStretch(1);
    trusted_controls_box_->setVisible(false);
    layout->addWidget(trusted_controls_box_);

    trusted_notice_label_ =
        make_plain_label(QString::fromUtf8(strings::kCheckingService), trusted_page_);
    layout->addWidget(trusted_notice_label_);
    layout->addStretch(1);
    return trusted_page_;
}

QWidget* MainWindow::buildAboutPage() {
    about_page_ = new QWidget(this);
    auto* layout = new QVBoxLayout(about_page_);

    about_heading_label_ = make_plain_label(QString::fromUtf8(strings::kAboutHeading), about_page_);
    about_accounts_label_ =
        make_plain_label(QString::fromUtf8(strings::kAboutAccountsSentence), about_page_);
    about_malware_label_ =
        make_plain_label(QString::fromUtf8(strings::kAboutMalwareSentence), about_page_);

    layout->addWidget(about_heading_label_);
    layout->addWidget(about_accounts_label_);
    layout->addWidget(about_malware_label_);

#if defined(__linux__)
    about_linux_label_ =
        make_plain_label(QString::fromUtf8(strings::kAboutLinuxSentence), about_page_);
    layout->addWidget(about_linux_label_);
#endif

    about_licence_label_ =
        make_plain_label(QString::fromUtf8(strings::kAboutLicenceNote), about_page_);
    layout->addWidget(about_licence_label_);

    auto* btn_row = new QHBoxLayout();
    open_licences_button_ =
        new QPushButton(QString::fromUtf8(strings::kAboutOpenLicencesButton), about_page_);
    connect(open_licences_button_, &QPushButton::clicked, this, &MainWindow::onOpenLicenceTexts);
    btn_row->addWidget(open_licences_button_);
    btn_row->addStretch(1);
    layout->addLayout(btn_row);

    licence_status_label_ = make_plain_label({}, about_page_);
    licence_status_label_->setVisible(false);
    layout->addWidget(licence_status_label_);

    layout->addStretch(1);
    return about_page_;
}

void MainWindow::setupTray() {
    const bool tray_available =
        options_.tray_available_override.has_value()
            ? *options_.tray_available_override
            : QSystemTrayIcon::isSystemTrayAvailable();
    if (!tray_available) {
        return;
    }

    tray_menu_ = new QMenu();
    tray_state_action_ = tray_menu_->addAction(QString::fromUtf8(strings::kTrayChecking));
    tray_state_action_->setEnabled(false);
    tray_menu_->addSeparator();

    tray_open_action_ = tray_menu_->addAction(QString::fromUtf8(strings::kTrayMenuOpen));
    connect(tray_open_action_, &QAction::triggered, this, [this]() {
        show();
        raise();
        activateWindow();
    });

    tray_refresh_action_ = tray_menu_->addAction(QString::fromUtf8(strings::kTrayMenuRefresh));
    connect(tray_refresh_action_, &QAction::triggered, this, &MainWindow::refreshStatus);

    tray_quit_action_ = tray_menu_->addAction(QString::fromUtf8(strings::kTrayMenuQuit));
    connect(tray_quit_action_, &QAction::triggered, this, &MainWindow::quitProgram);

    tray_icon_ = new QSystemTrayIcon(make_program_icon(), this);
    tray_icon_->setContextMenu(tray_menu_);
    updateTrayText(QString::fromUtf8(strings::kTrayChecking));
    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        tray_icon_->show();
    }
}

void MainWindow::updateTrayText(const QString& text) {
    if (tray_icon_ != nullptr) {
        tray_icon_->setToolTip(text);
    }
    if (tray_state_action_ != nullptr) {
        tray_state_action_->setText(text);
    }
}

QString MainWindow::trayTooltipText() const {
    return tray_icon_ != nullptr ? tray_icon_->toolTip() : QString{};
}

void MainWindow::clearStateDetails() {
    service_version_label_->clear();
    engine_state_label_->clear();
    folder_watching_label_->clear();
    rules_state_label_->clear();
    state_details_box_->setVisible(false);
}

void MainWindow::clearScanResult() {
    scan_subject_label_->clear();
    scan_sha256_label_->clear();
    scan_state_label_->clear();
    scan_state_note_label_->clear();
    scan_reason_label_->clear();
    scan_verdict_label_->clear();
    scan_score_label_->clear();
    scan_engine_version_label_->clear();
    scan_profile_label_->clear();
    scan_rules_state_label_->clear();
    scan_findings_table_->setRowCount(0);
    scan_result_box_->setVisible(false);
}

void MainWindow::refreshStatus() {
    client_.requestStatus();
}

void MainWindow::refreshQuarantine() {
    client_.requestQuarantineList();
}

void MainWindow::refreshTrusted() {
    client_.requestTrustedList();
}

void MainWindow::submitScan() {
    const QString path = scan_path_edit_->text();
    clearScanResult();
    if (path.isEmpty()) {
        scan_notice_label_->setText(QString::fromUtf8(strings::kScanEmptyPath));
        scan_notice_label_->setVisible(true);
        return;
    }
    scan_notice_label_->setText(QString::fromUtf8(strings::kScanWaiting));
    scan_notice_label_->setVisible(true);
    client_.requestScan(path);
}

void MainWindow::quitProgram() {
    explicit_quit_ = true;
    saveWindowGeometry();
    if (tray_icon_ != nullptr) {
        tray_icon_->hide();
    }
    hide();
    emit quitRequested();
    QCoreApplication::quit();
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (!explicit_quit_ && tray_icon_ != nullptr) {
        saveWindowGeometry();
        hide();
        event->ignore();
        return;
    }
    saveWindowGeometry();
    event->accept();
    emit quitRequested();
    QCoreApplication::quit();
}

void MainWindow::onStatusFinished(const StatusReply& reply) {
    switch (reply.channel) {
        case ChannelState::ServiceNotRunning:
            clearStateDetails();
            state_notice_label_->setText(QString::fromUtf8(strings::kServiceNotRunning));
            state_notice_label_->setVisible(true);
            updateTrayText(QString::fromUtf8(strings::kTrayServiceNotRunning));
            emit statusApplied();
            return;
        case ChannelState::HeldByOtherAccount: {
            clearStateDetails();
            const QString held = QString::fromUtf8(strings::kHeldByOtherAccount);
            state_notice_label_->setText(held);
            state_notice_label_->setVisible(true);
            updateTrayText(held);
            emit statusApplied();
            return;
        }
        case ChannelState::BadServiceAnswer:
            clearStateDetails();
            state_notice_label_->setText(QString::fromUtf8(strings::kBadServiceAnswer));
            state_notice_label_->setVisible(true);
            updateTrayText(QString::fromUtf8(strings::kTrayBadAnswer));
            emit statusApplied();
            return;
        case ChannelState::Ok:
            break;
    }

    const QString clean_version = sanitize_external_text(reply.status.version);
    const QString clean_engine = sanitize_external_text(reply.status.engine);
    const QString watching_text = QString::fromUtf8(
        reply.status.monitoring ? strings::kFolderWatchingOn : strings::kFolderWatchingOff);
    const QString rules_text = rules_label_text(reply.status.rules);

    service_version_label_->setText(
        QString::fromUtf8(strings::kLabelServiceVersionPrefix) + clean_version);
    engine_state_label_->setText(
        QString::fromUtf8(strings::kLabelEngineStatePrefix) + clean_engine);
    folder_watching_label_->setText(watching_text);
    rules_state_label_->setText(rules_text);
    state_details_box_->setVisible(true);

    const QString joiner = QString::fromUtf8(strings::kTrayJoiner);
    if (reply.status.engine == "absent") {
        const QString absent = QString::fromUtf8(strings::kEngineAbsentNotice);
        state_notice_label_->setText(absent);
        state_notice_label_->setVisible(true);
        updateTrayText(QString::fromUtf8(strings::kTrayPrefix) + absent +
                       joiner + watching_text + joiner + rules_text);
    } else {
        state_notice_label_->clear();
        state_notice_label_->setVisible(false);
        updateTrayText(QString::fromUtf8(strings::kTrayPrefix) +
                       QString::fromUtf8(strings::kLabelEngineStatePrefix) + clean_engine +
                       joiner + watching_text + joiner + rules_text);
    }

    emit statusApplied();
}

void MainWindow::onScanFinished(const ScanReply& reply) {
    clearScanResult();

    switch (reply.kind) {
        case ScanReplyKind::NotAvailableInBuild:
            scan_notice_label_->setText(QString::fromUtf8(strings::kNotAvailableInBuild));
            scan_notice_label_->setVisible(true);
            emit scanApplied();
            return;
        case ScanReplyKind::ServiceNotRunning:
            scan_notice_label_->setText(QString::fromUtf8(strings::kServiceNotRunning));
            scan_notice_label_->setVisible(true);
            emit scanApplied();
            return;
        case ScanReplyKind::HeldByOtherAccount:
            scan_notice_label_->setText(QString::fromUtf8(strings::kHeldByOtherAccount));
            scan_notice_label_->setVisible(true);
            emit scanApplied();
            return;
        case ScanReplyKind::BadServiceAnswer:
            scan_notice_label_->setText(QString::fromUtf8(strings::kBadServiceAnswer));
            scan_notice_label_->setVisible(true);
            emit scanApplied();
            return;
        case ScanReplyKind::Result:
            break;
    }

    scan_notice_label_->clear();
    scan_notice_label_->setVisible(false);

    const mie::ScanResult& r = reply.result;
    scan_subject_label_->setText(
        QString::fromUtf8(strings::kScanSubjectPrefix) +
        sanitize_external_text(r.subject.display_name));
    scan_sha256_label_->setText(
        QString::fromUtf8(strings::kScanSha256Prefix) +
        sanitize_external_text(r.subject.sha256));
    scan_sha256_label_->setVisible(!r.subject.sha256.empty());

    scan_state_label_->setText(
        QString::fromUtf8(strings::kScanStatePrefix) +
        QString::fromUtf8(mie::to_string(r.state)));

    if (r.state == mie::ScanState::Scanned) {
        scan_state_note_label_->setVisible(false);
        scan_reason_label_->setVisible(false);

        const QString verdict_val =
            r.verdict.empty() ? QString::fromUtf8(strings::kScanNoVerdict)
                              : sanitize_external_text(r.verdict);
        scan_verdict_label_->setText(
            QString::fromUtf8(strings::kScanVerdictPrefix) + verdict_val);
        scan_verdict_label_->setVisible(true);

        scan_score_label_->setText(
            QString::fromUtf8(strings::kScanScorePrefix) + QString::number(r.score));
        scan_score_label_->setVisible(true);
    } else if (r.state == mie::ScanState::NotFullyScanned) {
        scan_state_note_label_->setText(QString::fromUtf8(strings::kScanStateNotFullyNote));
        scan_state_note_label_->setVisible(true);

        scan_reason_label_->setText(
            QString::fromUtf8(strings::kScanReasonPrefix) + sanitize_external_text(r.reason));
        scan_reason_label_->setVisible(true);

        // A not_fully_scanned result is NEVER shown as clean.
        QString verdict_val = sanitize_external_text(r.verdict);
        if (r.verdict.empty() || verdict_val.contains(QStringLiteral("clean"), Qt::CaseInsensitive)) {
            verdict_val = QString::fromUtf8(strings::kScanNoVerdict);
        }
        scan_verdict_label_->setText(
            QString::fromUtf8(strings::kScanVerdictPrefix) + verdict_val);
        scan_verdict_label_->setVisible(true);

        scan_score_label_->setText(
            QString::fromUtf8(strings::kScanScorePrefix) + QString::number(r.score));
        scan_score_label_->setVisible(true);
    } else {
        // ScanState::NotScanned: never clean, no score, no verdict, no findings.
        scan_state_note_label_->setText(QString::fromUtf8(strings::kScanStateNotScannedNote));
        scan_state_note_label_->setVisible(true);

        scan_reason_label_->setText(
            QString::fromUtf8(strings::kScanReasonPrefix) + sanitize_external_text(r.reason));
        scan_reason_label_->setVisible(true);

        scan_verdict_label_->setVisible(false);
        scan_score_label_->setVisible(false);
    }

    // Producer fields required on every shown result.
    scan_engine_version_label_->setText(
        QString::fromUtf8(strings::kScanEngineVersionPrefix) +
        sanitize_external_text(r.engine_version));
    scan_profile_label_->setText(
        QString::fromUtf8(strings::kScanProfilePrefix) +
        sanitize_external_text(r.profile));
    scan_rules_state_label_->setText(
        QString::fromUtf8(strings::kScanRulesStatePrefix) +
        QString::fromUtf8(mie::to_string(r.rules_state)));

    if (r.state == mie::ScanState::NotScanned) {
        scan_findings_heading_label_->setVisible(false);
        scan_no_findings_label_->setVisible(false);
        scan_findings_table_->setVisible(false);
    } else if (r.findings.empty()) {
        scan_findings_heading_label_->setVisible(true);
        scan_no_findings_label_->setVisible(true);
        scan_findings_table_->setVisible(false);
    } else {
        scan_findings_heading_label_->setVisible(true);
        scan_no_findings_label_->setVisible(false);
        scan_findings_table_->setRowCount(static_cast<int>(r.findings.size()));
        for (std::size_t i = 0; i < r.findings.size(); ++i) {
            const mie::Finding& f = r.findings[i];
            const int row = static_cast<int>(i);
            scan_findings_table_->setItem(
                row, 0, new QTableWidgetItem(sanitize_external_text(f.category)));
            scan_findings_table_->setItem(
                row, 1, new QTableWidgetItem(sanitize_external_text(f.family)));
            scan_findings_table_->setItem(
                row, 2, new QTableWidgetItem(QString::number(f.weight)));
            scan_findings_table_->setItem(
                row, 3, new QTableWidgetItem(QString::fromUtf8(
                            f.floor ? strings::kFloorYes : strings::kFloorNo)));
            scan_findings_table_->setItem(
                row, 4, new QTableWidgetItem(sanitize_external_text(f.description)));
        }
        scan_findings_table_->setVisible(true);
    }

    scan_result_box_->setVisible(true);
    emit scanApplied();
}

void MainWindow::onQuarantineFinished(const ReservedOpReply& reply) {
    // When unknown_op is returned, the page says "Not available in this build." and nothing else.
    quarantine_controls_box_->setVisible(false);
    switch (reply.kind) {
        case ReservedOpReplyKind::NotAvailableInBuild:
            quarantine_notice_label_->setText(QString::fromUtf8(strings::kNotAvailableInBuild));
            break;
        case ReservedOpReplyKind::ServiceNotRunning:
            quarantine_notice_label_->setText(QString::fromUtf8(strings::kServiceNotRunning));
            break;
        case ReservedOpReplyKind::HeldByOtherAccount:
            quarantine_notice_label_->setText(QString::fromUtf8(strings::kHeldByOtherAccount));
            break;
        case ReservedOpReplyKind::BadServiceAnswer:
            quarantine_notice_label_->setText(QString::fromUtf8(strings::kBadServiceAnswer));
            break;
    }
    quarantine_notice_label_->setVisible(true);
    emit quarantineApplied();
}

void MainWindow::onTrustedFinished(const ReservedOpReply& reply) {
    // When unknown_op is returned, the page says "Not available in this build." and nothing else.
    trusted_controls_box_->setVisible(false);
    switch (reply.kind) {
        case ReservedOpReplyKind::NotAvailableInBuild:
            trusted_notice_label_->setText(QString::fromUtf8(strings::kNotAvailableInBuild));
            break;
        case ReservedOpReplyKind::ServiceNotRunning:
            trusted_notice_label_->setText(QString::fromUtf8(strings::kServiceNotRunning));
            break;
        case ReservedOpReplyKind::HeldByOtherAccount:
            trusted_notice_label_->setText(QString::fromUtf8(strings::kHeldByOtherAccount));
            break;
        case ReservedOpReplyKind::BadServiceAnswer:
            trusted_notice_label_->setText(QString::fromUtf8(strings::kBadServiceAnswer));
            break;
    }
    trusted_notice_label_->setVisible(true);
    emit trustedApplied();
}

void MainWindow::onChooseScanFile() {
    const QString chosen = QFileDialog::getOpenFileName(
        this,
        QString::fromUtf8(strings::kScanDialogTitle),
        QString{},
        QString{},
        nullptr,
        QFileDialog::DontUseNativeDialog | QFileDialog::DontResolveSymlinks | QFileDialog::ReadOnly);
    if (!chosen.isEmpty()) {
        scan_path_edit_->setText(chosen);
    }
}

void MainWindow::onOpenLicenceTexts() {
    QString candidate = options_.licence_dir_override;
    if (candidate.isEmpty()) {
        const QString app_dir = QCoreApplication::applicationDirPath();
        const QString uk_dir = QDir(app_dir).filePath(QStringLiteral("licences"));
        const QString us_dir = QDir(app_dir).filePath(QStringLiteral("licenses"));
        if (QDir(uk_dir).exists()) {
            candidate = uk_dir;
        } else if (QDir(us_dir).exists()) {
            candidate = us_dir;
        }
    }

    if (candidate.isEmpty() || !QDir(candidate).exists()) {
        licence_status_label_->setText(QString::fromUtf8(strings::kLicenceNotInstalled));
        licence_status_label_->setVisible(true);
        return;
    }

    QDesktopServices::openUrl(QUrl::fromLocalFile(candidate));
    licence_status_label_->setText(QString::fromUtf8(strings::kLicenceOpened));
    licence_status_label_->setVisible(true);
}

void MainWindow::onTabChanged(int index) {
    QWidget* current = tabs_->widget(index);
    if (current == quarantine_page_) {
        refreshQuarantine();
    } else if (current == trusted_page_) {
        refreshTrusted();
    }
}

QString MainWindow::visibleStateSummaryText() const {
    QStringList lines;
    append_if_visible(lines, nullptr, state_notice_label_);
    append_if_visible(lines, state_details_box_, service_version_label_);
    append_if_visible(lines, state_details_box_, engine_state_label_);
    append_if_visible(lines, state_details_box_, folder_watching_label_);
    append_if_visible(lines, state_details_box_, rules_state_label_);
    return lines.join(QLatin1Char('\n'));
}

QString MainWindow::visibleScanPageText() const {
    QStringList lines;
    append_if_visible(lines, nullptr, scan_notice_label_);
    append_if_visible(lines, scan_result_box_, scan_subject_label_);
    append_if_visible(lines, scan_result_box_, scan_sha256_label_);
    append_if_visible(lines, scan_result_box_, scan_state_label_);
    append_if_visible(lines, scan_result_box_, scan_state_note_label_);
    append_if_visible(lines, scan_result_box_, scan_reason_label_);
    append_if_visible(lines, scan_result_box_, scan_verdict_label_);
    append_if_visible(lines, scan_result_box_, scan_score_label_);
    append_if_visible(lines, scan_result_box_, scan_engine_version_label_);
    append_if_visible(lines, scan_result_box_, scan_profile_label_);
    append_if_visible(lines, scan_result_box_, scan_rules_state_label_);
    append_if_visible(lines, scan_result_box_, scan_findings_heading_label_);
    append_if_visible(lines, scan_result_box_, scan_no_findings_label_);
    if (!scan_result_box_->isHidden() && !scan_findings_table_->isHidden()) {
        for (int r = 0; r < scan_findings_table_->rowCount(); ++r) {
            QStringList cells;
            for (int c = 0; c < scan_findings_table_->columnCount(); ++c) {
                const QTableWidgetItem* item = scan_findings_table_->item(r, c);
                if (item != nullptr) {
                    cells.push_back(item->text());
                }
            }
            lines.push_back(cells.join(QStringLiteral(" | ")));
        }
    }
    return lines.join(QLatin1Char('\n'));
}

QString MainWindow::visibleQuarantinePageText() const {
    QStringList lines;
    if (!quarantine_controls_box_->isHidden()) {
        lines.push_back(quarantine_refresh_button_->text());
    }
    append_if_visible(lines, nullptr, quarantine_notice_label_);
    return lines.join(QLatin1Char('\n'));
}

QString MainWindow::visibleTrustedPageText() const {
    QStringList lines;
    if (!trusted_controls_box_->isHidden()) {
        lines.push_back(trusted_refresh_button_->text());
    }
    append_if_visible(lines, nullptr, trusted_notice_label_);
    return lines.join(QLatin1Char('\n'));
}

QString MainWindow::visibleAboutPageText() const {
    QStringList lines;
    append_if_visible(lines, nullptr, about_heading_label_);
    append_if_visible(lines, nullptr, about_accounts_label_);
    append_if_visible(lines, nullptr, about_malware_label_);
    append_if_visible(lines, nullptr, about_linux_label_);
    append_if_visible(lines, nullptr, about_licence_label_);
    append_if_visible(lines, nullptr, licence_status_label_);
    return lines.join(QLatin1Char('\n'));
}

void MainWindow::loadWindowGeometry() {
    if (!options_.persist_geometry) {
        return;
    }
    QSettings settings(QString::fromUtf8(strings::kSettingsOrg),
                       QString::fromUtf8(strings::kSettingsApp));
    if (settings.contains(QStringLiteral("window/size"))) {
        const QSize sz = settings.value(QStringLiteral("window/size")).toSize();
        if (sz.isValid() && sz.width() >= 320 && sz.height() >= 240) {
            resize(sz);
        }
    }
    if (settings.contains(QStringLiteral("window/pos"))) {
        move(settings.value(QStringLiteral("window/pos")).toPoint());
    }
}

void MainWindow::saveWindowGeometry() const {
    if (!options_.persist_geometry) {
        return;
    }
    QSettings settings(QString::fromUtf8(strings::kSettingsOrg),
                       QString::fromUtf8(strings::kSettingsApp));
    settings.setValue(QStringLiteral("window/size"), size());
    settings.setValue(QStringLiteral("window/pos"), pos());
}

}  // namespace mie::ui
