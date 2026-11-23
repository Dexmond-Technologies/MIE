// libFuzzer target: the PE reader must never crash, hang or read out of bounds on any
// bytes, and what it reports must be consistent with the buffer it was given.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <span>

#include "mie/pe.hpp"

#define REQUIRE(condition) require_at((condition), __LINE__)

namespace {

// Says which rule failed (the line), so a crash in CI can be read from the log alone.
void require_at(bool condition, int line) {
    if (!condition) {
        std::fprintf(stderr, "fuzz_pe: the rule at line %d of fuzz_pe.cpp does not hold\n", line);
        std::abort();
    }
}

void inside(const mie::pe::Range& range, std::size_t size) {
    REQUIRE(range.begin <= range.end && range.end <= size);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace mie::pe;
    const Image image = parse(std::span<const std::uint8_t>(data, size));
    if (!image.parsed) {
        REQUIRE(!image.error.empty());
        REQUIRE(image.sections.empty() && image.imports.empty() && image.directories.empty());
        return 0;
    }
    REQUIRE(image.error.empty());
    REQUIRE(image.directories.size() <= 16);
    REQUIRE(image.sections.size() <= kMaxSections);
    for (const Section& s : image.sections) inside(s.data, size);
    std::size_t symbols = 0;
    for (const auto* list : {&image.imports, &image.delay_imports}) {
        for (const ImportLibrary& library : *list) {
            REQUIRE(!library.dll.empty() && library.dll.size() <= kMaxDllLength);
            REQUIRE(!library.symbols.empty());
            symbols += library.symbols.size();
            for (const ImportSymbol& s : library.symbols) {
                REQUIRE(s.name.size() <= kMaxImportNameLength);
                // An import by ordinal has no name of its own, except in the three libraries whose
                // ordinals the reader names from its tables (oleaut32, ws2_32, wsock32), as the
                // reference's parser does. (The earlier form of this rule forbade any name and was
                // hit in CI run 45117930444 after a mutation produced "oleaut32.dll".)
                REQUIRE(s.by_ordinal ? s.ordinal != 0 : !s.name.empty());
            }
        }
    }
    REQUIRE(symbols <= 2 * (static_cast<std::size_t>(kMaxImportSymbols) + 1));
    REQUIRE(image.resource_data.size() <= kMaxResourceRanges);
    REQUIRE(!image.resource_root_has_entries || image.has_resources);
    REQUIRE(!image.tls.has_callbacks || (image.tls.present && image.tls.first_readable && image.tls.first_callback != 0));
    const Certificates& c = image.certificates;
    REQUIRE(!c.valid || (c.present && c.entries > 0 && c.problems.empty() && c.spans.size() == c.entries));
    REQUIRE(c.valid || c.spans.empty());
    for (const Range& span : c.spans) inside(span, size);
    // The reference's view never holds more DLLs than the import table does.
    REQUIRE(reference_imports(image).size() <= image.imports.size());
    return 0;
}
