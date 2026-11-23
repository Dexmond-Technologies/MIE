// Headless Qt Test acceptance suite for Dexmond MIE (mie-ui): T-1 through T-14.
#pragma once

#include <QObject>
#include <QString>

namespace mie::ui::test {

class MieUiAcceptanceTests : public QObject {
    Q_OBJECT

private slots:
    void initTestCase();
    void test_T01_no_service();
    void test_T02_real_week0_service();
    void test_T03_status_combinations();
    void test_T04_scan_result_states();
    void test_T05_scan_sends_path_only_no_handle();
    void test_T06_hostile_text();
    void test_T07_about_and_limits();
    void test_T08_word_check();
    void test_T09_close_tray_and_service_survives();
    void test_T10_responsive_during_3s_delay();
    void test_T11_dynamic_qt_linking();
    void test_T12_malformed_service_answers();
    void test_T13_held_by_other_account();
    void test_T14_rules_degraded_off_and_refusal();
    void cleanupTestCase();

private:
    QString mie_ui_bin_;
    QString mie_service_bin_;
    QString ui_strings_cpp_;
    QString ui_src_dir_;
};

}  // namespace mie::ui::test
