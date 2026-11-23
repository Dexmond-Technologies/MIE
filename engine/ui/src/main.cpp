// Dexmond MIE (mie-ui): Qt 6 Widgets window and tray program.
#include <cstdio>
#include <string>

#include <QApplication>

#include "main_window.hpp"
#include "ui_strings.hpp"

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QString::fromUtf8(mie::ui::strings::kProductName));
    QApplication::setOrganizationName(QString::fromUtf8(mie::ui::strings::kSettingsOrg));
    // Closing the window hides it when a tray icon exists and quits when none exists;
    // MainWindow::closeEvent controls that behaviour explicitly.
    QApplication::setQuitOnLastWindowClosed(false);

    mie::ui::MainWindowOptions options;
    const QStringList args = QCoreApplication::arguments();
    for (qsizetype i = 1; i < args.size(); ++i) {
        const QString& arg = args.at(i);
        if (arg == QStringLiteral("--endpoint") && i + 1 < args.size()) {
            const QByteArray ep = args.at(++i).toUtf8();
            options.endpoint_override.assign(ep.constData(), static_cast<std::size_t>(ep.size()));
        } else {
            std::fprintf(stderr, "%s\n", mie::ui::strings::kCliUsage);
            return 2;
        }
    }

    mie::ui::MainWindow window(std::move(options));
    window.show();
    return QApplication::exec();
}
