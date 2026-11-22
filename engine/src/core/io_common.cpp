#include "mie/io.hpp"

namespace mie::io {

const char* to_string(IoErrorCode code) {
    switch (code) {
        case IoErrorCode::None: return "none";
        case IoErrorCode::NotFound: return "not_found";
        case IoErrorCode::Link: return "link";
        case IoErrorCode::NotRegular: return "not_regular";
        case IoErrorCode::AccessDenied: return "access_denied";
        case IoErrorCode::Changed: return "changed";
        case IoErrorCode::ReadFailed: return "read_failed";
        case IoErrorCode::Other: return "other";
    }
    return "other";
}

}  // namespace mie::io
