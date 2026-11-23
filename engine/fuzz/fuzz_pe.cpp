// libFuzzer target: the PE reader must never crash, hang or read out of bounds on any
// bytes, and what it reports must be consistent with the buffer it was given.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <span>

#include "mie/pe.hpp"

namespace {

void require(bool condition) {
    if (!condition) std::abort();
}

void inside(const mie::pe::Range& range, std::size_t size) {
    require(range.begin <= range.end && range.end <= size);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace mie::pe;
    const Image image = parse(std::span<const std::uint8_t>(data, size));
    if (!image.parsed) {
        require(!image.error.empty());
        require(image.sections.empty() && image.imports.empty() && image.directories.empty());
        return 0;
    }
    require(image.error.empty());
    require(image.directories.size() <= 16);
    require(image.sections.size() <= kMaxSections);
    for (const Section& s : image.sections) inside(s.data, size);
    std::size_t symbols = 0;
    for (const auto* list : {&image.imports, &image.delay_imports}) {
        for (const ImportLibrary& library : *list) {
            require(!library.dll.empty() && library.dll.size() <= kMaxDllLength);
            require(!library.symbols.empty());
            symbols += library.symbols.size();
            for (const ImportSymbol& s : library.symbols) {
                require(s.name.size() <= kMaxImportNameLength);
                require(s.by_ordinal ? (s.name.empty() && s.ordinal != 0) : !s.name.empty());
            }
        }
    }
    require(symbols <= 2 * (static_cast<std::size_t>(kMaxImportSymbols) + 1));
    require(image.resource_data.size() <= kMaxResourceRanges);
    require(!image.resource_root_has_entries || image.has_resources);
    require(!image.tls.has_callbacks || (image.tls.present && image.tls.first_readable && image.tls.first_callback != 0));
    const Certificates& c = image.certificates;
    require(!c.valid || (c.present && c.entries > 0 && c.problems.empty() && c.spans.size() == c.entries));
    require(c.valid || c.spans.empty());
    for (const Range& span : c.spans) inside(span, size);
    // The reference's view never holds more DLLs than the import table does.
    require(reference_imports(image).size() <= image.imports.size());
    return 0;
}
