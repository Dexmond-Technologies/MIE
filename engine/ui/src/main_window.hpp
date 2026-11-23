// Main window and system tray front end of Dexmond MIE (mie-ui).
#pragma once

#include <optional>
#include <string>

#include <QAction>
#include <QCloseEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMenu>
#include <QPushButton>
#include <QSystemTrayIcon>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>
#include <QWidget>

#include "service_client.hpp"

namespace mie::ui {

struct MainWindowOptions {
    std::string endpoint_override;
    ConnectFunction connect_fn;
    std::optional<bool> tray_available_override;
    int refresh_interval_ms = 5000;
    QString licence_dir_override;
    bool persist_geometry = true;
    bool auto_initial_refresh = true;
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(MainWindowOptions options = {}, QWidget* parent = nullptr);
    ~MainWindow() override;

    ServiceClient& serviceClient() { return client_; }
    bool hasTrayIcon() const { return tray_icon_ != nullptr; }

    // Accessors used by Qt Test acceptance suite (T-1 .. T-14).
    QTabWidget* tabWidget() const { return tabs_; }

    // State page inspection
    QPushButton* stateRefreshButton() const { return state_refresh_button_; }
    QLabel* stateNoticeLabel() const { return state_notice_label_; }
    QWidget* stateDetailsBox() const { return state_details_box_; }
    QLabel* serviceVersionLabel() const { return service_version_label_; }
    QLabel* engineStateLabel() const { return engine_state_label_; }
    QLabel* folderWatchingLabel() const { return folder_watching_label_; }
    QLabel* rulesStateLabel() const { return rules_state_label_; }
    QString visibleStateSummaryText() const;

    // Scan page inspection and controls
    QLineEdit* scanPathEdit() const { return scan_path_edit_; }
    QPushButton* scanSubmitButton() const { return scan_submit_button_; }
    QLabel* scanNoticeLabel() const { return scan_notice_label_; }
    QWidget* scanResultBox() const { return scan_result_box_; }
    QLabel* scanSubjectLabel() const { return scan_subject_label_; }
    QLabel* scanSha256Label() const { return scan_sha256_label_; }
    QLabel* scanStateLabel() const { return scan_state_label_; }
    QLabel* scanStateNoteLabel() const { return scan_state_note_label_; }
    QLabel* scanReasonLabel() const { return scan_reason_label_; }
    QLabel* scanVerdictLabel() const { return scan_verdict_label_; }
    QLabel* scanScoreLabel() const { return scan_score_label_; }
    QLabel* scanEngineVersionLabel() const { return scan_engine_version_label_; }
    QLabel* scanProfileLabel() const { return scan_profile_label_; }
    QLabel* scanRulesStateLabel() const { return scan_rules_state_label_; }
    QTableWidget* scanFindingsTable() const { return scan_findings_table_; }
    QString visibleScanPageText() const;

    // Quarantine and Trusted pages inspection
    QLabel* quarantineNoticeLabel() const { return quarantine_notice_label_; }
    QWidget* quarantineControlsBox() const { return quarantine_controls_box_; }
    QString visibleQuarantinePageText() const;

    QLabel* trustedNoticeLabel() const { return trusted_notice_label_; }
    QWidget* trustedControlsBox() const { return trusted_controls_box_; }
    QString visibleTrustedPageText() const;

    // About and limits page inspection
    QPushButton* openLicencesButton() const { return open_licences_button_; }
    QLabel* licenceStatusLabel() const { return licence_status_label_; }
    QString visibleAboutPageText() const;

    // Tray inspection
    QSystemTrayIcon* trayIcon() const { return tray_icon_; }
    QMenu* trayMenu() const { return tray_menu_; }
    QAction* trayStateAction() const { return tray_state_action_; }
    QAction* trayOpenAction() const { return tray_open_action_; }
    QAction* trayRefreshAction() const { return tray_refresh_action_; }
    QAction* trayQuitAction() const { return tray_quit_action_; }
    QString trayTooltipText() const;

public slots:
    void refreshStatus();
    void refreshQuarantine();
    void refreshTrusted();
    void submitScan();
    void quitProgram();

signals:
    void statusApplied();
    void scanApplied();
    void quarantineApplied();
    void trustedApplied();
    void quitRequested();

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onStatusFinished(const mie::ui::StatusReply& reply);
    void onScanFinished(const mie::ui::ScanReply& reply);
    void onQuarantineFinished(const mie::ui::ReservedOpReply& reply);
    void onTrustedFinished(const mie::ui::ReservedOpReply& reply);
    void onChooseScanFile();
    void onOpenLicenceTexts();
    void onTabChanged(int index);

private:
    void buildUi();
    QWidget* buildStatePage();
    QWidget* buildScanPage();
    QWidget* buildQuarantinePage();
    QWidget* buildTrustedPage();
    QWidget* buildAboutPage();
    void setupTray();
    void updateTrayText(const QString& text);
    void clearStateDetails();
    void clearScanResult();
    void loadWindowGeometry();
    void saveWindowGeometry() const;

    MainWindowOptions options_;
    ServiceClient client_;
    QTimer refresh_timer_;
    bool explicit_quit_ = false;

    QTabWidget* tabs_ = nullptr;

    // State page widgets
    QPushButton* state_refresh_button_ = nullptr;
    QLabel* state_notice_label_ = nullptr;
    QWidget* state_details_box_ = nullptr;
    QLabel* service_version_label_ = nullptr;
    QLabel* engine_state_label_ = nullptr;
    QLabel* folder_watching_label_ = nullptr;
    QLabel* rules_state_label_ = nullptr;

    // Scan page widgets
    QWidget* scan_controls_box_ = nullptr;
    QLabel* scan_prompt_label_ = nullptr;
    QLineEdit* scan_path_edit_ = nullptr;
    QPushButton* scan_choose_button_ = nullptr;
    QPushButton* scan_submit_button_ = nullptr;
    QLabel* scan_notice_label_ = nullptr;
    QWidget* scan_result_box_ = nullptr;
    QLabel* scan_subject_label_ = nullptr;
    QLabel* scan_sha256_label_ = nullptr;
    QLabel* scan_state_label_ = nullptr;
    QLabel* scan_state_note_label_ = nullptr;
    QLabel* scan_reason_label_ = nullptr;
    QLabel* scan_verdict_label_ = nullptr;
    QLabel* scan_score_label_ = nullptr;
    QLabel* scan_engine_version_label_ = nullptr;
    QLabel* scan_profile_label_ = nullptr;
    QLabel* scan_rules_state_label_ = nullptr;
    QLabel* scan_findings_heading_label_ = nullptr;
    QLabel* scan_no_findings_label_ = nullptr;
    QTableWidget* scan_findings_table_ = nullptr;

    // Quarantine page widgets
    QWidget* quarantine_page_ = nullptr;
    QWidget* quarantine_controls_box_ = nullptr;
    QPushButton* quarantine_refresh_button_ = nullptr;
    QLabel* quarantine_notice_label_ = nullptr;

    // Trusted page widgets
    QWidget* trusted_page_ = nullptr;
    QWidget* trusted_controls_box_ = nullptr;
    QPushButton* trusted_refresh_button_ = nullptr;
    QLabel* trusted_notice_label_ = nullptr;

    // About page widgets
    QWidget* about_page_ = nullptr;
    QLabel* about_heading_label_ = nullptr;
    QLabel* about_accounts_label_ = nullptr;
    QLabel* about_malware_label_ = nullptr;
    QLabel* about_linux_label_ = nullptr;
    QLabel* about_licence_label_ = nullptr;
    QPushButton* open_licences_button_ = nullptr;
    QLabel* licence_status_label_ = nullptr;

    // Tray icon and menu
    QSystemTrayIcon* tray_icon_ = nullptr;
    QMenu* tray_menu_ = nullptr;
    QAction* tray_state_action_ = nullptr;
    QAction* tray_open_action_ = nullptr;
    QAction* tray_refresh_action_ = nullptr;
    QAction* tray_quit_action_ = nullptr;
};

}  // namespace mie::ui
