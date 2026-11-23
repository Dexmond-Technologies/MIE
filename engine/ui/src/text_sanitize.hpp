// Sanitization for untrusted text coming from the service or from scanned files.
// Every external string is rendered strictly as plain text, with control characters and
// Unicode direction-override / format characters replaced by visible [U+XXXX] markers
// and excessive length cut for display.
#pragma once

#include <cstddef>
#include <string_view>

#include <QString>

namespace mie::ui {

inline constexpr std::size_t kDefaultMaxDisplayCodepoints = 512;

QString sanitize_external_text(std::string_view raw,
                               std::size_t max_codepoints = kDefaultMaxDisplayCodepoints);

}  // namespace mie::ui
