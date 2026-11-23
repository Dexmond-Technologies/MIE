// Derived work: ported to C++ from CPython 3.12.16 (Lib/zipfile/__init__.py, Lib/tarfile.py,
// Lib/_compression.py, Lib/gzip.py, Lib/bz2.py, Lib/lzma.py, Modules/_bz2module.c,
// Modules/_lzmamodule.c, Modules/zlibmodule.c, Modules/_io/bufferedio.c), Copyright (c) 2001-2023
// Python Software Foundation, licensed under the PSF License Agreement. Changes made: the reading
// rules, limits, error classes and error texts were re-implemented in C++ over in-memory buffers,
// with hard ceilings of our own added (ARCHIVE_SPEC.md sections 9-10). Full notice in THIRD-PARTY-
// NOTICES. This file: Apache License 2.0, Copyright 2026 Dexmond Technologies.
//
// Zip and tar container readers, written to give what the Python reference gives
// (dexmond_mie/core.py at ff313e2: _is_archive, _extract_safely, _extract_zip, _extract_tar,
// _zip_covers_file), which in turn is what CPython 3.12.16's zipfile and tarfile give.
// Reviewer's ruling M-4c (board B-3619): every read goes through one bounds-checked view;
// sizes and offsets are widened and range-checked; caps and hard ceilings; ONE code path for
// the parity profile and the shipped profile, only `Options` (data) differs; members stay in
// memory, no file is ever written. The reference's use of real files is copied in its
// RESULTS (same name = same file, file-versus-folder clashes, name and path length), as on
// Linux. See ARCHIVE_SPEC.md for every rule and its line in the Python sources.
//
// Decompression is done by zlib, bzip2 and liblzma only.
#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace mie::archive {

enum class Kind { NotArchive, Zip, Tar };

// Profile data. The defaults are the PARITY profile: the reference's behaviour, quirks
// included. The shipped profile changes values here, never code.
struct Options {
    // The reference's limits (core.py:42-58).
    std::int64_t max_members_per_archive = 200;
    std::int64_t max_member_bytes = 64ll * 1024 * 1024;
    std::int64_t max_tar_padding = 1024 * 1024;
    std::int64_t zip_descriptor_slack = 24;
    std::int64_t max_uncovered_zip_bytes = 4096;
    std::int64_t max_uncovered_tar_header_bytes = 4096;

    // Hard ceilings, independent of any size an archive declares. Reaching one ends the
    // work with an explicit reason (error type "HardCeiling"); nothing is guessed.
    std::uint64_t hard_produced_bytes = 4ull * 1024 * 1024 * 1024;  // bytes produced per Budget
    std::uint64_t hard_entries = 1u << 20;                 // zip directory entries, tar headers, sparse entries
    std::uint64_t hard_header_data_bytes = 16u * 1024 * 1024;  // one pax or GNU long-name block
    std::uint64_t lzma_memory_limit = 256ull * 1024 * 1024;    // liblzma decoder memory

    // Quirks of the reference, each a numbered difference in the shipped profile.
    // true: members that end up under the same file name are all scanned with the LAST
    // one's bytes (the reference writes real files). false: each member's own bytes.
    bool duplicate_names_last_wins = true;
    // true: a zip found after other data (the directory offsets are shifted) is read as a
    // zip. false: such a file is not taken for a zip.
    bool zip_after_other_data = true;
    // true: a tar header that is not valid, after the first one, ends the archive without
    // a word. false: it gives the reason "invalid tar header at offset N".
    bool tar_bad_header_ends_silently = true;
    // true: a file that begins with a block of zero bytes is an (empty) tar (D-15).
    bool tar_leading_zero_block_is_tar = true;

    // Length in bytes of the temporary folder's path in the reference
    // ("/tmp/dexmond_arc_XXXXXXXX"); it counts toward the 4095-byte path limit there.
    std::int64_t temp_dir_length = 25;
};

// The budget one top-level scan shares over all nesting levels (core.py:92-93).
struct Budget {
    std::int64_t members = 200;
    std::int64_t bytes = 512ll * 1024 * 1024;
    std::uint64_t produced = 0;  // bytes actually produced so far, block by block
};

struct Member {
    std::string name;       // as the reference reports it, as bytes (zip: UTF-8; tar: raw)
    std::string disk_path;  // the path below its temp folder the reference would have written
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;  // what gets scanned for this member
};

struct Extraction {
    Kind kind = Kind::NotArchive;
    std::vector<Member> members;       // in the reference's order
    std::vector<std::string> reasons;  // the reference's texts, in its order (names as bytes)
    bool complete = false;             // no reasons
};

// zipfile.is_zipfile(path) or tarfile.is_tarfile(path), in that order; False on any error.
Kind detect(std::span<const std::uint8_t> file, const Options& options = Options{});

// Engine._extract_safely: the members to scan and the coverage reasons. Never throws on
// bad input; a file that is not an archive gives the reference's reason for that.
Extraction extract(std::span<const std::uint8_t> file, Budget& budget, const Options& options = Options{});

}  // namespace mie::archive
