#include <quic/ssl/ssl_handler.hh>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include <utils/logger.hh>

#include <cstdint>

namespace zpp {
namespace quic {
namespace ssl {

namespace {

constinit unsigned char server_alpns[] =
    "\x0ahq-interop\x05h3-29\x05hq-28\x05hq-27\x08http/0.9\04echo";

int select_alpn(
    [[maybe_unused]] SSL *ssl,
    const unsigned char **out,
    unsigned char *outlen,
    const unsigned char *in,
    unsigned int inlen,
    [[maybe_unused]] void *arg)
{
    using u8 = std::uint8_t;

    // Dangerous?
    int r = SSL_select_next_proto(
        const_cast<u8**>(reinterpret_cast<const u8**>(out)),
        reinterpret_cast<u8*>(outlen),
        reinterpret_cast<const u8*>(in),
        inlen,
        reinterpret_cast<const u8*>(server_alpns),
        sizeof(server_alpns) - 1
    );

    if (r == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    } else {
        logger::eflog("No supported protocol can be selected from the list.");
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

} // anonymous namespace

int load_cert(const char *cert_file, const char *key_file, SSL_CTX **ssl_ctx) {
    int rv = -1;
    *ssl_ctx = SSL_CTX_new(TLS_method());

    auto end_routine = [&] {
        if (rv != 0) {
            SSL_CTX_free(*ssl_ctx);
        }
        *ssl_ctx = nullptr;
        return rv;
    };

    if (!*ssl_ctx) {
        logger::eflog("SSL_CTX_new has failed");
        return end_routine();
    }
    
    SSL_CTX_set_min_proto_version(*ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(*ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(*ssl_ctx);
    SSL_CTX_set_alpn_select_cb(*ssl_ctx, select_alpn, nullptr);

    if (SSL_CTX_use_certificate_chain_file(*ssl_ctx, cert_file) != 1) {
        logger::eflog("SSL_CTX_use_certificate_chain_file has failed");
        return end_routine();
    }
    if (1 != SSL_CTX_use_PrivateKey_file(*ssl_ctx, key_file, SSL_FILETYPE_PEM)) {
        logger::eflog("SSL_CTX_use_PrivateKey_file has failed");
        return end_routine();
    }
    
    return 0;
}

} // namespace ssl
} // namespace quic
} // namespace zpp
