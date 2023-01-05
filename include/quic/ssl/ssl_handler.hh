#ifndef __QUIC_FILEHOST_QUIC_DETAIL_SSL_HANDLER_HH__
#define __QUIC_FILEHOST_QUIC_DETAIL_SSL_HANDLER_HH__

#include <openssl/ssl.h>

namespace zpp {
namespace quic {
namespace ssl {

int load_cert(const char *cert_file, const char *key_file, SSL_CTX **ssl_ctx);

} // namespace ssl
} // namespace quic
} // namespace zpp

#endif // __QUIC_FILEHOST_QUIC_DETAIL_SSL_HANDLER_HH__
