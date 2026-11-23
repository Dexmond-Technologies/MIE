// Derived work: ported to C++ from CPython 3.12.16 (Lib/zipfile/__init__.py, Lib/tarfile.py,
// Lib/_compression.py, Lib/gzip.py, Lib/bz2.py, Lib/lzma.py, Modules/_bz2module.c,
// Modules/_lzmamodule.c, Modules/zlibmodule.c, Modules/_io/bufferedio.c), Copyright (c) 2001-2023
// Python Software Foundation, licensed under the PSF License Agreement. Changes made: the reading
// rules, limits, error classes and error texts were re-implemented in C++ over in-memory buffers,
// with hard ceilings of our own added (ARCHIVE_SPEC.md sections 9-10). Full notice in THIRD-PARTY-
// NOTICES. This file: Apache License 2.0, Copyright 2026 Dexmond Technologies.
//
// Decompression through zlib, bzip2 and liblzma, driven in the same pieces as CPython 3.12.16
// drives them, so that a damaged or cut stream gives the same bytes before the same error:
//   zlib._ZlibDecompressor / zlib.decompressobj, bz2.BZ2Decompressor, lzma.LZMADecompressor
//   _compression.DecompressReader (Lib/_compression.py:33-153), gzip._GzipReader
//   (Lib/gzip.py:500-600), io.BufferedReader (Modules/_io/bufferedio.c),
//   zipfile.ZipExtFile.read (Lib/zipfile/__init__.py:992-1141).
// Every block produced is charged to the Meter (hard ceiling).
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <optional>

#include <bzlib.h>
#include <lzma.h>
#include <zlib.h>

#include "internal.hpp"

namespace mie::archive::detail {

std::uint32_t crc32_of(Bytes data, std::uint32_t seed) {
    uLong crc = seed;
    std::size_t done = 0;
    while (done < data.size()) {
        const std::size_t step = std::min<std::size_t>(data.size() - done, 1u << 30);
        crc = ::crc32(crc, data.data() + done, static_cast<uInt>(step));
        done += step;
    }
    return static_cast<std::uint32_t>(crc);
}

// seek() of io.BufferedReader with a target of 2^63 or more (Modules/_io/bufferedio.c,
// PyNumber_AsOff_t with ValueError). ARCHIVE_SPEC.md ND-2: type to be confirmed by the test.
void seek_too_far() {
    throw PyError{"ValueError", "cannot fit 'int' into an offset-sized integer"};
}

namespace {

constexpr char kEndedEarly[] = "Compressed file ended before the end-of-stream marker was reached";
constexpr std::size_t kIoBuffer = 8192;         // io.DEFAULT_BUFFER_SIZE
constexpr std::size_t kGzipChunk = 128 * 1024;  // gzip.READ_BUFFER_SIZE

enum class Flavor { Zlib, Bz2, Lzma };

// One Python decompressor object: decompress(data, max_length) with `eof`, `needs_input`
// and `unused_data`; input it could not use yet is kept inside.
class PyDecompressor {
public:
    PyDecompressor(Flavor flavor, Meter meter) : flavor_(flavor), meter_(meter) {}
    virtual ~PyDecompressor() = default;
    PyDecompressor(const PyDecompressor&) = delete;
    PyDecompressor& operator=(const PyDecompressor&) = delete;

    Buffer decompress(Bytes data, std::uint64_t max_length);
    Buffer flush() { return eof || failed_ ? Buffer{} : decompress({}, ~std::uint64_t{0}); }
    bool has_pending_input() const { return !input_.empty(); }

    bool eof = false;
    bool needs_input = true;
    Buffer unused;

protected:
    enum class Step { Ok, End, NoProgress };
    virtual Step code(const std::uint8_t* in, std::size_t in_size, std::uint8_t* out, std::size_t out_size,
                      std::size_t& used, std::size_t& made) = 0;

private:
    Flavor flavor_;
    Meter meter_;
    Buffer input_;
    std::optional<PyError> failed_;  // what a later call raises once a call has failed
};

// The output block sizes of CPython's _BlocksOutputBuffer (Include/internal/pycore_blocks_output_buffer.h).
std::uint64_t block_size(std::size_t index) {
    static constexpr std::uint64_t kSizes[] = {32u << 10, 64u << 10, 256u << 10, 1u << 20, 4u << 20,
                                               8u << 20,  16u << 20, 16u << 20,  32u << 20};
    return kSizes[std::min<std::size_t>(index, std::size(kSizes) - 1)];
}

Buffer PyDecompressor::decompress(Bytes data, std::uint64_t max_length) {
    if (failed_) throw *failed_;
    if (eof) throw PyError{"EOFError", "End of stream already reached"};
    input_.insert(input_.end(), data.begin(), data.end());
    Buffer out;
    std::size_t in_pos = 0, made_total = 0, block = 0;
    try {
        for (;;) {
            if (made_total == out.size()) {
                const std::uint64_t room = std::min<std::uint64_t>(max_length - out.size(), block_size(block++));
                if (room == 0) break;  // max_length reached
                out.resize(out.size() + static_cast<std::size_t>(room));
            }
            std::size_t used = 0, made = 0;
            const Step step = code(input_.data() + in_pos, input_.size() - in_pos, out.data() + made_total,
                                   out.size() - made_total, used, made);
            in_pos += used;
            made_total += made;
            meter_.charge(made);
            if (step == Step::End) {
                eof = true;
                break;
            }
            const bool filled = made_total == out.size();
            const bool in_empty = in_pos == input_.size();
            if (flavor_ == Flavor::Zlib) {
                if (!filled) break;  // zlibmodule.c: do { inflate } while (avail_out == 0)
            } else if (flavor_ == Flavor::Bz2) {
                if (in_empty || (!filled && used == 0 && made == 0)) break;  // _bz2module.c decompress_buf
            } else {
                if (step == Step::NoProgress) {  // _lzmamodule.c decompress_buf
                    if (in_empty && !filled) break;
                    throw PyError{"LZMAError", "Insufficient buffer space"};
                }
                if (!filled && in_empty) break;
            }
        }
    } catch (const PyError& error) {
        failed_ = error;
        // bz2 only (CPython 3.12.16 Modules/_bz2module.c:457-461 and 632-636): an error of
        // libbzip2 makes the object unusable: needs_input becomes False and every later
        // decompress() raises ValueError. zlib and lzma objects are called again and fail again.
        if (flavor_ == Flavor::Bz2 && error.type != "HardCeiling") {
            needs_input = false;
            failed_ = PyError{"ValueError", "Decompressor is unusable after a previous error"};
        }
        throw;
    }
    const bool at_limit = made_total == max_length;
    out.resize(made_total);
    input_.erase(input_.begin(), input_.begin() + static_cast<std::ptrdiff_t>(in_pos));
    if (eof) {
        needs_input = false;
        unused = std::move(input_);
        input_.clear();
    } else if (input_.empty()) {
        // lzma keeps "no input needed" when the output was cut at the limit (it may hold more).
        needs_input = !(flavor_ == Flavor::Lzma && at_limit);
    } else {
        needs_input = false;
    }
    return out;
}

class ZlibDecompressor final : public PyDecompressor {  // raw deflate, wbits = -15
public:
    explicit ZlibDecompressor(Meter meter) : PyDecompressor(Flavor::Zlib, meter) {
        std::memset(&stream_, 0, sizeof(stream_));
        if (inflateInit2(&stream_, -15) != Z_OK) throw PyError{"MemoryError", ""};
    }
    ~ZlibDecompressor() override { inflateEnd(&stream_); }

protected:
    Step code(const std::uint8_t* in, std::size_t in_size, std::uint8_t* out, std::size_t out_size,
              std::size_t& used, std::size_t& made) override {
        const uInt in_now = static_cast<uInt>(std::min<std::size_t>(in_size, 1u << 30));
        const uInt out_now = static_cast<uInt>(std::min<std::size_t>(out_size, 1u << 30));
        stream_.next_in = const_cast<Bytef*>(in);
        stream_.avail_in = in_now;
        stream_.next_out = out;
        stream_.avail_out = out_now;
        const int result = inflate(&stream_, Z_SYNC_FLUSH);
        used = in_now - stream_.avail_in;
        made = out_now - stream_.avail_out;
        if (result == Z_STREAM_END) return Step::End;
        if (result == Z_OK || result == Z_BUF_ERROR) return Step::Ok;
        std::string message = "Error " + std::to_string(result) + " while decompressing data";
        if (stream_.msg != nullptr) message += std::string(": ") + stream_.msg;
        throw PyError{"error", message};  // zlib.error
    }

private:
    z_stream stream_;
};

class Bz2Decompressor final : public PyDecompressor {
public:
    explicit Bz2Decompressor(Meter meter) : PyDecompressor(Flavor::Bz2, meter) {
        std::memset(&stream_, 0, sizeof(stream_));
        if (BZ2_bzDecompressInit(&stream_, 0, 0) != BZ_OK) throw PyError{"MemoryError", ""};
    }
    ~Bz2Decompressor() override { BZ2_bzDecompressEnd(&stream_); }

protected:
    Step code(const std::uint8_t* in, std::size_t in_size, std::uint8_t* out, std::size_t out_size,
              std::size_t& used, std::size_t& made) override {
        const unsigned in_now = static_cast<unsigned>(std::min<std::size_t>(in_size, 1u << 30));
        const unsigned out_now = static_cast<unsigned>(std::min<std::size_t>(out_size, 1u << 30));
        stream_.next_in = const_cast<char*>(reinterpret_cast<const char*>(in));
        stream_.avail_in = in_now;
        stream_.next_out = reinterpret_cast<char*>(out);
        stream_.avail_out = out_now;
        const int result = BZ2_bzDecompress(&stream_);
        used = in_now - stream_.avail_in;
        made = out_now - stream_.avail_out;
        if (result == BZ_STREAM_END) return Step::End;
        if (result == BZ_OK) return Step::Ok;
        if (result == BZ_MEM_ERROR) throw PyError{"MemoryError", ""};
        if (result == BZ_SEQUENCE_ERROR) {
            throw PyError{"RuntimeError", "Internal error - invalid sequence of commands sent to libbzip2"};
        }
        if (result == BZ_PARAM_ERROR) {
            throw PyError{"ValueError", "Internal error - invalid parameters passed to libbzip2"};
        }
        throw PyError{"OSError", "Invalid data stream"};
    }

private:
    bz_stream stream_;
};

class LzmaDecompressor final : public PyDecompressor {
public:
    // format=FORMAT_AUTO as lzma.LZMAFile uses it (.xz and .lzma), with a memory limit of ours.
    LzmaDecompressor(Meter meter, std::uint64_t memory_limit) : PyDecompressor(Flavor::Lzma, meter) {
        check(lzma_auto_decoder(&stream_, memory_limit, LZMA_TELL_ANY_CHECK | LZMA_TELL_NO_CHECK));
    }
    // format=FORMAT_RAW with one LZMA1 filter from its properties (zipfile.LZMADecompressor).
    LzmaDecompressor(Meter meter, std::uint64_t memory_limit, Bytes properties) : PyDecompressor(Flavor::Lzma, meter) {
        lzma_filter filters[2] = {{LZMA_FILTER_LZMA1, nullptr}, {LZMA_VLI_UNKNOWN, nullptr}};
        check(lzma_properties_decode(&filters[0], nullptr, properties.data(), properties.size()));
        const std::uint64_t dictionary = static_cast<const lzma_options_lzma*>(filters[0].options)->dict_size;
        const lzma_ret result = dictionary > memory_limit ? LZMA_MEMLIMIT_ERROR : lzma_raw_decoder(&stream_, filters);
        std::free(filters[0].options);
        if (dictionary > memory_limit) throw PyError{"HardCeiling", "LZMA dictionary over the memory limit"};
        check(result);
    }
    ~LzmaDecompressor() override { lzma_end(&stream_); }

protected:
    Step code(const std::uint8_t* in, std::size_t in_size, std::uint8_t* out, std::size_t out_size,
              std::size_t& used, std::size_t& made) override {
        stream_.next_in = in;
        stream_.avail_in = in_size;
        stream_.next_out = out;
        stream_.avail_out = out_size;
        const lzma_ret result = lzma_code(&stream_, LZMA_RUN);
        used = in_size - stream_.avail_in;
        made = out_size - stream_.avail_out;
        if (result == LZMA_STREAM_END) return Step::End;
        if (result == LZMA_BUF_ERROR) return Step::NoProgress;
        check(result);
        return Step::Ok;
    }

private:
    static void check(lzma_ret result) {  // _lzmamodule.c catch_lzma_error
        switch (result) {
            case LZMA_OK:
            case LZMA_GET_CHECK:
            case LZMA_NO_CHECK:
            case LZMA_STREAM_END:
                return;
            case LZMA_MEM_ERROR:
                throw PyError{"MemoryError", ""};
            case LZMA_MEMLIMIT_ERROR:
                throw PyError{"LZMAError", "Memory usage limit exceeded"};
            case LZMA_FORMAT_ERROR:
                throw PyError{"LZMAError", "Input format not supported by decoder"};
            case LZMA_OPTIONS_ERROR:
                throw PyError{"LZMAError", "Invalid or unsupported options"};
            case LZMA_DATA_ERROR:
                throw PyError{"LZMAError", "Corrupt input data"};
            case LZMA_UNSUPPORTED_CHECK:
                throw PyError{"LZMAError", "Unsupported integrity check"};
            default:
                throw PyError{"LZMAError", "Internal error"};
        }
    }
    lzma_stream stream_ = LZMA_STREAM_INIT;
};

// --- the raw readers below io.BufferedReader ---------------------------------------------------

// _compression.DecompressReader: read(size), and seek() by reading forward (after a rewind
// when the target is behind).
class RawReader {
public:
    RawReader(Bytes file, Meter meter) : file_(file), meter_(meter) {}
    virtual ~RawReader() = default;
    virtual Buffer read(std::uint64_t size) = 0;
    virtual void rewind() = 0;
    void seek(std::uint64_t target) {  // Lib/_compression.py:130-158
        if (target < pos) rewind();
        std::uint64_t skip = target - pos;
        while (skip > 0) {
            const Buffer data = read(std::min<std::uint64_t>(kIoBuffer, skip));
            if (data.empty()) break;
            skip -= data.size();
        }
    }
    std::uint64_t pos = 0;

protected:
    Bytes file_read(std::uint64_t size) {
        const Bytes got = file_.slice(file_pos_, size);
        file_pos_ += got.size();
        return got;
    }
    View file_;
    Meter meter_;
    std::uint64_t file_pos_ = 0;
};

// bz2.BZ2File and lzma.LZMAFile: Lib/_compression.py:72-117. Several streams one after the
// other are read as one; bytes after the last stream that are not a stream are ignored when
// the decoder refuses them at once (trailing_error), and raise when it refuses them later.
class StreamReader final : public RawReader {
public:
    StreamReader(Bytes file, Meter meter, Codec codec, std::uint64_t lzma_limit)
        : RawReader(file, meter), codec_(codec), lzma_limit_(lzma_limit) {
        decoder_ = fresh();
    }
    Buffer read(std::uint64_t size) override {
        if (size == 0 || eof_) return {};
        Buffer data;
        for (;;) {
            if (decoder_->eof) {
                Buffer raw = decoder_->unused;
                if (raw.empty()) {
                    const Bytes more = file_read(kIoBuffer);
                    raw.assign(more.begin(), more.end());
                }
                if (raw.empty()) break;
                decoder_ = fresh();
                try {
                    data = decoder_->decompress(raw, size);
                } catch (const PyError& error) {
                    if (codec_ == Codec::Bzip2 ? is_os_error(error) : error.type == "LZMAError") break;
                    throw;
                }
            } else {
                Bytes raw;
                if (decoder_->needs_input) {
                    raw = file_read(kIoBuffer);
                    if (raw.empty()) throw PyError{"EOFError", kEndedEarly};
                }
                data = decoder_->decompress(raw, size);
            }
            if (!data.empty()) break;
        }
        if (data.empty()) {
            eof_ = true;
            return {};
        }
        pos += data.size();
        return data;
    }
    void rewind() override {
        file_pos_ = 0;
        eof_ = false;
        pos = 0;
        decoder_ = fresh();
    }

private:
    std::unique_ptr<PyDecompressor> fresh() const {
        if (codec_ == Codec::Bzip2) return std::make_unique<Bz2Decompressor>(meter_);
        return std::make_unique<LzmaDecompressor>(meter_, lzma_limit_);
    }
    Codec codec_;
    std::uint64_t lzma_limit_;
    std::unique_ptr<PyDecompressor> decoder_;
    bool eof_ = false;
};

// gzip.GzipFile: Lib/gzip.py:500-600, with _PaddedFile (Lib/gzip.py:83-121) below it.
// Members one after the other are read as one; zero bytes between and after them are
// skipped; anything else after a member is "Not a gzipped file" (BadGzipFile).
class GzipReader final : public RawReader {
public:
    GzipReader(Bytes file, Meter meter) : RawReader(file, meter) { decoder_ = std::make_unique<ZlibDecompressor>(meter_); }
    Buffer read(std::uint64_t size) override {
        if (size == 0) return {};
        Buffer out;
        std::optional<bool> chunk_was_empty;  // Python's local `buf`, unset until a chunk is read
        for (;;) {
            if (decoder_->eof) {
                read_trailer();
                new_member_ = true;
                decoder_ = std::make_unique<ZlibDecompressor>(meter_);
            }
            if (new_member_) {
                crc_ = 0;
                stream_size_ = 0;
                if (!read_header()) return {};
                new_member_ = false;
            }
            if (decoder_->needs_input) {
                const Buffer chunk = padded_read(kGzipChunk);
                chunk_was_empty = chunk.empty();
                out = decoder_->decompress(chunk, size);
            } else {
                out = decoder_->decompress({}, size);
            }
            if (!decoder_->unused.empty()) prepend(decoder_->unused);
            if (!out.empty()) break;
            if (!chunk_was_empty.has_value()) {
                throw PyError{"UnboundLocalError",
                              "cannot access local variable 'buf' where it is not associated with a value"};
            }
            if (*chunk_was_empty) throw PyError{"EOFError", kEndedEarly};
        }
        crc_ = crc32_of(out, crc_);
        stream_size_ += out.size();
        pos += out.size();
        return out;
    }
    void rewind() override {
        file_pos_ = 0;
        padded_.clear();
        padded_at_.reset();
        pos = 0;
        new_member_ = true;
        decoder_ = std::make_unique<ZlibDecompressor>(meter_);
    }

private:
    // _PaddedFile.read and .prepend. padded_at_ unset = Python's `_read is None`.
    Buffer padded_read(std::uint64_t size) {
        Buffer out;
        if (padded_at_ && *padded_at_ + static_cast<std::int64_t>(size) <= static_cast<std::int64_t>(padded_.size())) {
            const std::size_t from = static_cast<std::size_t>(std::max<std::int64_t>(*padded_at_, 0));
            out.assign(padded_.begin() + static_cast<std::ptrdiff_t>(from),
                       padded_.begin() + static_cast<std::ptrdiff_t>(from + size));
            *padded_at_ += static_cast<std::int64_t>(size);
            return out;
        }
        std::uint64_t from_file = size;
        if (padded_at_) {
            const std::size_t from = static_cast<std::size_t>(std::clamp<std::int64_t>(*padded_at_, 0, static_cast<std::int64_t>(padded_.size())));
            out.assign(padded_.begin() + static_cast<std::ptrdiff_t>(from), padded_.end());
            from_file = size - out.size();
            padded_at_.reset();
        }
        const Bytes more = file_read(from_file);
        out.insert(out.end(), more.begin(), more.end());
        return out;
    }
    void prepend(const Buffer& data) {
        if (padded_at_) {
            *padded_at_ -= static_cast<std::int64_t>(data.size());
            return;
        }
        padded_ = data;
        padded_at_ = 0;
    }
    Buffer read_exact(std::uint64_t count) {  // Lib/gzip.py _read_exact
        Buffer data = padded_read(count);
        while (data.size() < count) {
            const Buffer more = padded_read(count - data.size());
            if (more.empty()) throw PyError{"EOFError", kEndedEarly};
            data.insert(data.end(), more.begin(), more.end());
        }
        return data;
    }
    void skip_text() {  // a zero-terminated field; the end of the file also ends it
        for (;;) {
            const Buffer one = padded_read(1);
            if (one.empty() || one[0] == 0) return;
        }
    }
    bool read_header() {  // Lib/gzip.py _read_gzip_header
        const Buffer magic = padded_read(2);
        if (magic.empty()) return false;
        if (magic.size() != 2 || magic[0] != 0x1f || magic[1] != 0x8b) throw PyError{"BadGzipFile", "Not a gzipped file"};
        const Buffer fixed = read_exact(8);
        if (fixed[0] != 8) throw PyError{"BadGzipFile", "Unknown compression method"};
        const std::uint8_t flags = fixed[1];
        if (flags & 4) {
            const Buffer length = read_exact(2);
            read_exact(le16(length, 0));
        }
        if (flags & 8) skip_text();
        if (flags & 16) skip_text();
        if (flags & 2) read_exact(2);
        return true;
    }
    void read_trailer() {  // Lib/gzip.py _read_eof
        const Buffer trailer = read_exact(8);
        if (le32(trailer, 0) != crc_) throw PyError{"BadGzipFile", "CRC check failed"};
        if (le32(trailer, 4) != static_cast<std::uint32_t>(stream_size_ & 0xffffffffu)) {
            throw PyError{"BadGzipFile", "Incorrect length of data produced"};
        }
        for (;;) {
            const Buffer one = padded_read(1);
            if (one.empty()) return;
            if (one[0] != 0) {
                prepend(one);
                return;
            }
        }
    }
    std::unique_ptr<PyDecompressor> decoder_;
    Buffer padded_;
    std::optional<std::int64_t> padded_at_ = 0;
    bool new_member_ = true;
    std::uint32_t crc_ = 0;
    std::uint64_t stream_size_ = 0;
};

// The file itself, as open(path, 'rb') gives it.
class PlainFile final : public PyFile {
public:
    explicit PlainFile(Bytes file) : file_(file) {}
    std::uint64_t tell() override { return pos_; }
    void seek(Num target) override {
        if (target.negative()) throw PyError{"OSError", "[Errno 22] Invalid argument"};
        if (!target.fits_offset()) seek_too_far();
        pos_ = target.lo;
    }
    Buffer read(std::uint64_t count) override {
        const Bytes got = file_.slice(pos_, count);
        pos_ += got.size();
        return Buffer(got.begin(), got.end());
    }

private:
    View file_;
    std::uint64_t pos_ = 0;
};

// io.BufferedReader (buffer of 8192 bytes) over a raw reader: read() and seek() ask the raw
// reader for the same amounts as Modules/_io/bufferedio.c does.
class BufferedFile final : public PyFile {
public:
    explicit BufferedFile(std::unique_ptr<RawReader> raw) : raw_(std::move(raw)) {}
    std::uint64_t tell() override { return believed_ - (buffer_.size() - at_); }
    void seek(Num target) override {
        if (!target.negative() && !target.fits_offset()) seek_too_far();
        const std::size_t ahead = buffer_.size() - at_;
        if (ahead > 0 && !target.negative()) {  // inside the current buffer: no raw read
            const std::uint64_t now = tell();
            if (target.lo >= now - at_ && target.lo <= now + ahead) {
                at_ = static_cast<std::size_t>(target.lo - (now - at_));
                return;
            }
        }
        if (target.negative()) {
            raw_->rewind();
        } else {
            raw_->seek(target.lo);
        }
        believed_ = raw_->pos;  // not reached when the raw seek raised: the old state stays
        buffer_.clear();
        at_ = 0;
    }
    Buffer read(std::uint64_t count) override {
        Buffer out;
        const std::size_t ahead = buffer_.size() - at_;
        if (count <= ahead) {
            out.assign(buffer_.begin() + static_cast<std::ptrdiff_t>(at_),
                       buffer_.begin() + static_cast<std::ptrdiff_t>(at_ + count));
            at_ += static_cast<std::size_t>(count);
            return out;
        }
        out.assign(buffer_.begin() + static_cast<std::ptrdiff_t>(at_), buffer_.end());
        std::uint64_t remaining = count - ahead;
        buffer_.clear();
        at_ = 0;
        while (remaining > 0) {  // whole blocks go straight to the caller
            const std::uint64_t whole = remaining & ~static_cast<std::uint64_t>(kIoBuffer - 1);
            if (whole == 0) break;
            const Buffer data = raw_read(whole);
            if (data.empty()) return out;
            out.insert(out.end(), data.begin(), data.end());
            remaining -= data.size();
        }
        while (remaining > 0 && buffer_.size() < kIoBuffer) {  // the rest through the buffer
            const Buffer data = raw_read(kIoBuffer - buffer_.size());
            if (data.empty()) return out;
            buffer_.insert(buffer_.end(), data.begin(), data.end());
            const std::size_t take = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, data.size()));
            out.insert(out.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(take));
            at_ += take;
            remaining -= take;
        }
        return out;
    }

private:
    Buffer raw_read(std::uint64_t size) {
        Buffer data = raw_->read(size);
        believed_ += data.size();
        return data;
    }
    std::unique_ptr<RawReader> raw_;
    Buffer buffer_;
    std::size_t at_ = 0;
    std::uint64_t believed_ = 0;  // where BufferedReader thinks the raw reader is
};

}  // namespace

std::unique_ptr<PyFile> open_file(Codec codec, Bytes file, Meter meter) {
    if (codec == Codec::Plain) return std::make_unique<PlainFile>(file);
    std::unique_ptr<RawReader> raw;
    if (codec == Codec::Gzip) {
        raw = std::make_unique<GzipReader>(file, meter);
    } else {
        raw = std::make_unique<StreamReader>(file, meter, codec, meter.options->lzma_memory_limit);
    }
    return std::make_unique<BufferedFile>(std::move(raw));
}

// --- one zip member ----------------------------------------------------------------------------

bool zip_method_supported(int method) {
    return method == 0 || method == 8 || method == 12 || method == 14;
}

namespace {

// zipfile.LZMADecompressor (Lib/zipfile/__init__.py:694-727): two version bytes, a 16-bit
// length of the properties, the properties, then raw LZMA1 data.
class ZipLzma {
public:
    ZipLzma(Meter meter, std::uint64_t limit) : meter_(meter), limit_(limit) {}
    bool needs_input() const { return decoder_ ? decoder_->needs_input : true; }
    bool eof() const { return decoder_ && decoder_->eof; }
    Buffer decompress(Bytes data, std::uint64_t max_length) {
        if (decoder_) return decoder_->decompress(data, max_length);
        head_.insert(head_.end(), data.begin(), data.end());
        if (head_.size() <= 4) return {};
        const std::size_t properties = le16(head_, 2);
        if (head_.size() <= 4 + properties) return {};
        decoder_ = std::make_unique<LzmaDecompressor>(meter_, limit_, Bytes(head_).subspan(4, properties));
        const Buffer rest(head_.begin() + static_cast<std::ptrdiff_t>(4 + properties), head_.end());
        head_.clear();
        return decoder_->decompress(rest, max_length);
    }

private:
    Meter meter_;
    std::uint64_t limit_;
    Buffer head_;
    std::unique_ptr<LzmaDecompressor> decoder_;
};

}  // namespace

// ZipExtFile.read(n) with n = max_bytes, on a member whose declared size is at most max_bytes:
// read() loops over _read1() until n bytes are there or the end is reached; _read1 takes
// compressed bytes with _read2, decompresses at most max(n, 4096) bytes, cuts the result to
// what is left of the declared size, and checks the CRC-32 at the end.
Buffer read_zip_member(int method, View file, Num data_start, Num compress_size, std::int64_t file_size,
                       std::uint32_t expected_crc, std::int64_t max_bytes, Meter meter) {
    constexpr std::int64_t kMinRead = 4096;  // ZipExtFile.MIN_READ_SIZE
    Num file_pos = data_start;
    Num compress_left = compress_size;
    std::int64_t left = file_size;
    std::int64_t n = max_bytes;
    bool eof = false;
    std::uint32_t running_crc = 0;
    Buffer result;
    std::unique_ptr<PyDecompressor> decoder;
    std::optional<ZipLzma> lzma;
    if (method == 8) decoder = std::make_unique<ZlibDecompressor>(meter);
    if (method == 12) decoder = std::make_unique<Bz2Decompressor>(meter);
    if (method == 14) lzma.emplace(meter, meter.options->lzma_memory_limit);

    const auto read2 = [&](std::int64_t count) -> Bytes {  // _read2
        if (compress_left <= Num(0)) return {};
        Num want = Num(std::max(count, kMinRead));
        if (compress_left < want) want = compress_left;
        if (!file_pos.fits_offset()) seek_too_far();  // _SharedFile.read seeks first
        const Bytes data = file.slice(file_pos.lo, want.lo);
        file_pos = file_pos + Num::of(data.size());
        compress_left = compress_left - Num::of(data.size());
        if (data.empty()) throw PyError{"EOFError", ""};
        return data;
    };

    while (n > 0 && !eof) {  // read(): one pass = _read1(n)
        Buffer data;
        const std::uint64_t limit = static_cast<std::uint64_t>(std::max(n, kMinRead));
        if (method == 0) {
            const Bytes raw = read2(n);
            data.assign(raw.begin(), raw.end());
            meter.charge(data.size());
            eof = compress_left <= Num(0);
        } else if (method == 8) {
            // The input zlib.decompressobj did not use (unconsumed_tail) is kept in the decoder.
            // It is non-empty only when the output limit was reached, and that limit is at
            // least what is left of the declared size, so the loop ends there: whenever a
            // further pass happens the tail is empty and _read2 is called.
            Bytes raw;
            if (!decoder->has_pending_input()) raw = read2(n);
            data = decoder->decompress(raw, limit);
            eof = decoder->eof || (compress_left <= Num(0) && !decoder->has_pending_input());
            if (eof) {
                const Buffer tail = decoder->flush();
                data.insert(data.end(), tail.begin(), tail.end());
            }
        } else if (method == 12) {
            Bytes raw;
            if (decoder->needs_input) raw = read2(n);
            data = decoder->decompress(raw, limit);
            eof = decoder->eof || (compress_left <= Num(0) && decoder->needs_input);
        } else {
            Bytes raw;
            if (lzma->needs_input()) raw = read2(n);
            data = lzma->decompress(raw, limit);
            eof = lzma->eof() || (compress_left <= Num(0) && lzma->needs_input());
        }
        if (static_cast<std::int64_t>(data.size()) > left) data.resize(static_cast<std::size_t>(std::max<std::int64_t>(left, 0)));
        left -= static_cast<std::int64_t>(data.size());
        if (left <= 0) eof = true;
        running_crc = crc32_of(data, running_crc);  // _update_crc
        if (eof && running_crc != expected_crc) throw PyError{"BadZipFile", "Bad CRC-32"};
        const std::size_t keep = static_cast<std::size_t>(std::min<std::int64_t>(n, static_cast<std::int64_t>(data.size())));
        result.insert(result.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(keep));
        if (static_cast<std::int64_t>(data.size()) > n) break;
        n -= static_cast<std::int64_t>(data.size());
    }
    return result;
}

}  // namespace mie::archive::detail
