// Single source file holding all user-facing text of Dexmond MIE (mie-ui).
// Reviewed by humans and checked automatically by acceptance test T-8.
#include "ui_strings.hpp"

#include "mie/channel/transport.hpp"

namespace mie::ui::strings {

const char* const kProductName = "Dexmond MIE";
const char* const kSettingsOrg = "Dexmond Technologies";
const char* const kSettingsApp = "Dexmond MIE";
const char* const kCliUsage = "usage: mie-ui [--endpoint NAME]";

const char* const kTabState = "State";
const char* const kTabScan = "Scan a file...";
const char* const kTabQuarantine = "Quarantine";
const char* const kTabTrusted = "Trusted files";
const char* const kTabAbout = "About and limits";

const char* const kCheckingService = "Checking MIE's background service...";
const char* const kServiceNotRunning = "MIE's background service is not running.";
const char* const kHeldByOtherAccount = mie::channel::kHeldByOtherAccountMessage;
const char* const kBadServiceAnswer =
    "MIE's background service gave an answer this program does not understand.";
const char* const kEngineAbsentNotice =
    "The scan engine is not part of this build. Nothing is being scanned.";
const char* const kNotAvailableInBuild = "Not available in this build.";

const char* const kButtonRefresh = "Refresh";
const char* const kLabelServiceVersionPrefix = "Service version: ";
const char* const kLabelEngineStatePrefix = "Engine state: ";
const char* const kFolderWatchingOn = "Folder watching: on";
const char* const kFolderWatchingOff = "Folder watching: off";
const char* const kRulesOn = "Rules: ON";
const char* const kRulesDegraded = "Rules: DEGRADED";
const char* const kRulesOff = "Rules: OFF";

const char* const kTrayChecking = "Dexmond MIE: checking service";
const char* const kTrayServiceNotRunning = "Dexmond MIE: service not running";
const char* const kTrayBadAnswer =
    "Dexmond MIE: MIE's background service gave an answer this program does not understand.";
const char* const kTrayPrefix = "Dexmond MIE \xE2\x80\x94 ";
const char* const kTrayJoiner = " | ";
const char* const kTrayMenuOpen = "Open window";
const char* const kTrayMenuRefresh = "Refresh";
const char* const kTrayMenuQuit = "Quit window program";

const char* const kScanPathPrompt = "File path to send to the service:";
const char* const kScanChooseButton = "Choose file...";
const char* const kScanDialogTitle = "Select a file path";
const char* const kScanSubmitButton = "Scan file";
const char* const kScanWaiting = "Waiting for MIE's background service...";
const char* const kScanEmptyPath = "Enter or choose a file path.";
const char* const kScanSubjectPrefix = "Subject: ";
const char* const kScanSha256Prefix = "SHA-256: ";
const char* const kScanStatePrefix = "State: ";
const char* const kScanStateNotFullyNote = "Summary: not_fully_scanned (incomplete scan)";
const char* const kScanStateNotScannedNote = "Summary: not_scanned (file was not scanned)";
const char* const kScanReasonPrefix = "Reason: ";
const char* const kScanVerdictPrefix = "Verdict: ";
const char* const kScanNoVerdict = "(no verdict)";
const char* const kScanScorePrefix = "Score: ";
const char* const kScanEngineVersionPrefix = "Engine version: ";
const char* const kScanProfilePrefix = "Profile: ";
const char* const kScanRulesStatePrefix = "Rule-set state: ";
const char* const kScanFindingsHeading = "Findings:";
const char* const kScanNoFindings = "No findings in this result.";
const char* const kFindingColCategory = "Category";
const char* const kFindingColFamily = "Family";
const char* const kFindingColWeight = "Weight";
const char* const kFindingColFloor = "Floor";
const char* const kFindingColDescription = "Description";
const char* const kFloorYes = "yes";
const char* const kFloorNo = "no";

const char* const kQuarantineRefreshButton = "Refresh quarantine list";
const char* const kTrustedRefreshButton = "Refresh trusted list";

const char* const kAboutHeading = "Dexmond MIE";
const char* const kAboutAccountsSentence =
    "Other user accounts on this computer cannot control MIE. Programs that run under your own account can.";
const char* const kAboutMalwareSentence =
    "MIE has not been tested against real malware.";
const char* const kAboutLinuxSentence =
    "This version does not judge Linux programs. It checks Windows programs, scripts, documents and archives.";
const char* const kAboutLicenceNote =
    "MIE is free; it uses Qt under the GNU LGPL version 3.";
const char* const kAboutOpenLicencesButton = "Open licence texts";
const char* const kLicenceNotInstalled = "licence texts not installed";
const char* const kLicenceOpened = "Opened licence texts folder.";

std::array<NamedText, 68> all_texts() {
    return {{
        {"kProductName", kProductName},
        {"kSettingsOrg", kSettingsOrg},
        {"kSettingsApp", kSettingsApp},
        {"kCliUsage", kCliUsage},
        {"kTabState", kTabState},
        {"kTabScan", kTabScan},
        {"kTabQuarantine", kTabQuarantine},
        {"kTabTrusted", kTabTrusted},
        {"kTabAbout", kTabAbout},
        {"kCheckingService", kCheckingService},
        {"kServiceNotRunning", kServiceNotRunning},
        {"kHeldByOtherAccount", kHeldByOtherAccount},
        {"kBadServiceAnswer", kBadServiceAnswer},
        {"kEngineAbsentNotice", kEngineAbsentNotice},
        {"kNotAvailableInBuild", kNotAvailableInBuild},
        {"kButtonRefresh", kButtonRefresh},
        {"kLabelServiceVersionPrefix", kLabelServiceVersionPrefix},
        {"kLabelEngineStatePrefix", kLabelEngineStatePrefix},
        {"kFolderWatchingOn", kFolderWatchingOn},
        {"kFolderWatchingOff", kFolderWatchingOff},
        {"kRulesOn", kRulesOn},
        {"kRulesDegraded", kRulesDegraded},
        {"kRulesOff", kRulesOff},
        {"kTrayChecking", kTrayChecking},
        {"kTrayServiceNotRunning", kTrayServiceNotRunning},
        {"kTrayBadAnswer", kTrayBadAnswer},
        {"kTrayPrefix", kTrayPrefix},
        {"kTrayJoiner", kTrayJoiner},
        {"kTrayMenuOpen", kTrayMenuOpen},
        {"kTrayMenuRefresh", kTrayMenuRefresh},
        {"kTrayMenuQuit", kTrayMenuQuit},
        {"kScanPathPrompt", kScanPathPrompt},
        {"kScanChooseButton", kScanChooseButton},
        {"kScanDialogTitle", kScanDialogTitle},
        {"kScanSubmitButton", kScanSubmitButton},
        {"kScanWaiting", kScanWaiting},
        {"kScanEmptyPath", kScanEmptyPath},
        {"kScanSubjectPrefix", kScanSubjectPrefix},
        {"kScanSha256Prefix", kScanSha256Prefix},
        {"kScanStatePrefix", kScanStatePrefix},
        {"kScanStateNotFullyNote", kScanStateNotFullyNote},
        {"kScanStateNotScannedNote", kScanStateNotScannedNote},
        {"kScanReasonPrefix", kScanReasonPrefix},
        {"kScanVerdictPrefix", kScanVerdictPrefix},
        {"kScanNoVerdict", kScanNoVerdict},
        {"kScanScorePrefix", kScanScorePrefix},
        {"kScanEngineVersionPrefix", kScanEngineVersionPrefix},
        {"kScanProfilePrefix", kScanProfilePrefix},
        {"kScanRulesStatePrefix", kScanRulesStatePrefix},
        {"kScanFindingsHeading", kScanFindingsHeading},
        {"kScanNoFindings", kScanNoFindings},
        {"kFindingColCategory", kFindingColCategory},
        {"kFindingColFamily", kFindingColFamily},
        {"kFindingColWeight", kFindingColWeight},
        {"kFindingColFloor", kFindingColFloor},
        {"kFindingColDescription", kFindingColDescription},
        {"kFloorYes", kFloorYes},
        {"kFloorNo", kFloorNo},
        {"kQuarantineRefreshButton", kQuarantineRefreshButton},
        {"kTrustedRefreshButton", kTrustedRefreshButton},
        {"kAboutHeading", kAboutHeading},
        {"kAboutAccountsSentence", kAboutAccountsSentence},
        {"kAboutMalwareSentence", kAboutMalwareSentence},
        {"kAboutLinuxSentence", kAboutLinuxSentence},
        {"kAboutLicenceNote", kAboutLicenceNote},
        {"kAboutOpenLicencesButton", kAboutOpenLicencesButton},
        {"kLicenceNotInstalled", kLicenceNotInstalled},
        {"kLicenceOpened", kLicenceOpened},
    }};
}

}  // namespace mie::ui::strings
