#include "text_sanitize.hpp"

#include <cstdio>

#include <QChar>
#include <QList>

namespace mie::ui {

namespace {

bool is_bidi_or_control(char32_t cp) {
    // C0 controls (including NUL 0x00, TAB 0x09, LF 0x0A, CR 0x0D, ESC 0x1B) and DEL
    if (cp <= 0x1Fu || cp == 0x7Fu) {
        return true;
    }
    // C1 controls
    if (cp >= 0x80u && cp <= 0x9Fu) {
        return true;
    }
    // Unicode line / paragraph separators
    if (cp == 0x2028u || cp == 0x2029u) {
        return true;
    }
    // Explicit directional marks, embeddings, overrides (including RLO U+202E) and isolates
    if (cp == 0x061Cu || cp == 0x200Eu || cp == 0x200Fu ||
        (cp >= 0x202Au && cp <= 0x202Eu) ||
        (cp >= 0x2066u && cp <= 0x2069u)) {
        return true;
    }
    // Other Unicode control or format code points (such as BOM / zero-width format chars)
    const QChar::Category cat = QChar::category(static_cast<uint>(cp));
    if (cat == QChar::Other_Control || cat == QChar::Other_Format) {
        return true;
    }
    return false;
}

void append_codepoint_marker(QString& out, char32_t cp) {
    char buf[16]{};
    if (cp <= 0xFFFFu) {
        std::snprintf(buf, sizeof buf, "[U+%04X]", static_cast<unsigned int>(cp));
    } else {
        std::snprintf(buf, sizeof buf, "[U+%06X]", static_cast<unsigned int>(cp));
    }
    out.append(QString::fromLatin1(buf));
}

}  // namespace

QString sanitize_external_text(std::string_view raw, std::size_t max_codepoints) {
    // Bound raw byte scan first so multi-megabyte inputs do not allocate huge temporary buffers.
    const std::size_t max_input_bytes = (max_codepoints + 64u) * 4u;
    const bool pre_cut = raw.size() > max_input_bytes;
    const std::string_view slice = pre_cut ? raw.substr(0, max_input_bytes) : raw;

    const QString decoded = QString::fromUtf8(slice.data(), static_cast<qsizetype>(slice.size()));
    const QList<uint> ucs4 = decoded.toUcs4();

    const auto ucs4_len = static_cast<std::size_t>(ucs4.size());
    const std::size_t reserve_len = ucs4_len < max_codepoints ? ucs4_len : (max_codepoints + 16u);
    QString out;
    out.reserve(static_cast<qsizetype>(reserve_len));

    std::size_t count = 0;
    bool truncated = pre_cut;
    for (const uint raw_cp : ucs4) {
        if (count >= max_codepoints) {
            truncated = true;
            break;
        }
        const auto cp = static_cast<char32_t>(raw_cp);
        if (is_bidi_or_control(cp)) {
            append_codepoint_marker(out, cp);
        } else {
            out.append(QString::fromUcs4(&cp, 1));
        }
        ++count;
    }

    if (truncated) {
        out.append(QStringLiteral("..."));
    }
    return out;
}

}  // namespace mie::ui
