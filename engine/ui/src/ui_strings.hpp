// Declarations for all user-facing strings of mie-ui.
// Every literal lives in ui_strings.cpp so all wording can be reviewed in one file.
#pragma once

#include <array>

namespace mie::ui::strings {

extern const char* const kProductName;
extern const char* const kSettingsOrg;
extern const char* const kSettingsApp;
extern const char* const kCliUsage;

// Navigation tabs
extern const char* const kTabState;
extern const char* const kTabScan;
extern const char* const kTabQuarantine;
extern const char* const kTabTrusted;
extern const char* const kTabAbout;

// Fixed service / channel notices
extern const char* const kCheckingService;
extern const char* const kServiceNotRunning;
extern const char* const kHeldByOtherAccount;
extern const char* const kBadServiceAnswer;
extern const char* const kEngineAbsentNotice;
extern const char* const kNotAvailableInBuild;

// State page labels and values
extern const char* const kButtonRefresh;
extern const char* const kLabelServiceVersionPrefix;
extern const char* const kLabelEngineStatePrefix;
extern const char* const kFolderWatchingOn;
extern const char* const kFolderWatchingOff;
extern const char* const kRulesOn;
extern const char* const kRulesDegraded;
extern const char* const kRulesOff;

// Tray tooltip and menu strings
extern const char* const kTrayChecking;
extern const char* const kTrayServiceNotRunning;
extern const char* const kTrayBadAnswer;
extern const char* const kTrayPrefix;
extern const char* const kTrayJoiner;
extern const char* const kTrayMenuOpen;
extern const char* const kTrayMenuRefresh;
extern const char* const kTrayMenuQuit;

// Scan page
extern const char* const kScanPathPrompt;
extern const char* const kScanChooseButton;
extern const char* const kScanDialogTitle;
extern const char* const kScanSubmitButton;
extern const char* const kScanWaiting;
extern const char* const kScanEmptyPath;
extern const char* const kScanSubjectPrefix;
extern const char* const kScanSha256Prefix;
extern const char* const kScanStatePrefix;
extern const char* const kScanStateNotFullyNote;
extern const char* const kScanStateNotScannedNote;
extern const char* const kScanReasonPrefix;
extern const char* const kScanVerdictPrefix;
extern const char* const kScanNoVerdict;
extern const char* const kScanScorePrefix;
extern const char* const kScanEngineVersionPrefix;
extern const char* const kScanProfilePrefix;
extern const char* const kScanRulesStatePrefix;
extern const char* const kScanFindingsHeading;
extern const char* const kScanNoFindings;
extern const char* const kFindingColCategory;
extern const char* const kFindingColFamily;
extern const char* const kFindingColWeight;
extern const char* const kFindingColFloor;
extern const char* const kFindingColDescription;
extern const char* const kFloorYes;
extern const char* const kFloorNo;

// Quarantine page
extern const char* const kQuarantineRefreshButton;

// Trusted files page
extern const char* const kTrustedRefreshButton;

// About and limits page
extern const char* const kAboutHeading;
extern const char* const kAboutAccountsSentence;
extern const char* const kAboutMalwareSentence;
extern const char* const kAboutLinuxSentence;
extern const char* const kAboutLicenceNote;
extern const char* const kAboutOpenLicencesButton;
extern const char* const kLicenceNotInstalled;
extern const char* const kLicenceOpened;

struct NamedText {
    const char* name;
    const char* value;
};

// Every user-facing text constant for automated word auditing (T-8).
std::array<NamedText, 68> all_texts();

}  // namespace mie::ui::strings
