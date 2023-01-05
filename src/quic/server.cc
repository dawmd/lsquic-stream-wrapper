#include "quic/common.hh"
#include "quic/quic_stream.hh"
#include <lsquic/lsquic.h>
#include <quic/server.hh>

#include <utils/logger.hh>

#include <quic/detail/callbacks.hh>
#include <quic/ssl/ssl_handler.hh>

#include <cstdint>  // std::uint16_t, std::int64_t
#include <cstring>  // std::memset
#include <chrono>

namespace zpp {
namespace quic {

namespace {

constinit lsquic_stream_if SERVER_CALLBACKS = {
    .on_new_conn    = ::zpp::quic::detail::on_new_connection,
    .on_conn_closed = ::zpp::quic::detail::on_connection_closed,
    .on_new_stream  = ::zpp::quic::detail::on_new_stream,
    .on_read        = ::zpp::quic::detail::on_read,
    .on_write       = ::zpp::quic::detail::on_write,
    .on_close       = ::zpp::quic::detail::on_close
};

SSL_CTX *server_ssl_ctx = nullptr;

inline void load_server_cert() {
    if (server_ssl_ctx) {
        return;
    }

    constexpr const char *cert_file = "../ssl/mycert-cert.pem";
    constexpr const char *key_file  = "../ssl/mycert-key.pem";

    if (ssl::load_cert(cert_file, key_file, std::addressof(server_ssl_ctx))) {
        logger::ffail("Cannot load the certificates.");
    }
}

SSL_CTX *get_server_ssl_ctx([[maybe_unused]] void *peer_ctx, [[maybe_unused]] const ::sockaddr *local) {
    return server_ssl_ctx;
}

} // anonymous namespace

server::~server() {
    if (m_stream) {
        delete std::exchange(m_stream, nullptr);
    }
}

void server::init_lsquic(detail::base_quic_stream<quic_stream_value_t> *stream) {
    m_stream = stream;

    logger::flog("Initialising an lsquic engine.");
    if (lsquic_global_init(LSQUIC_GLOBAL_SERVER) != 0) {
        logger::ffail("Initialisation of the engine has failed.");
    }

    load_server_cert();
    if (!server_ssl_ctx) {
        logger::ffail("SSL server context is a null.");
    }

    lsquic_engine_settings settings{};
    lsquic_engine_init_settings(&settings, LSENG_SERVER);

    char errbuf[0x100];

    settings.es_ql_bits = 0;

    if (lsquic_engine_check_settings(&settings, LSENG_SERVER, errbuf, sizeof(errbuf)) != 0) {
        logger::ffail("Invalid settings.");
    }

    lsquic_engine_api eapi{};
    std::memset(&eapi, 0, sizeof(eapi));

    eapi.ea_packets_out     =  ::zpp::quic::detail::packets_out;
    eapi.ea_packets_out_ctx =  this;
    eapi.ea_stream_if       = &SERVER_CALLBACKS;
    eapi.ea_stream_if_ctx   =  m_stream;
    eapi.ea_get_ssl_ctx     =  get_server_ssl_ctx;
    eapi.ea_settings        = &settings;

    m_engine = lsquic_engine_new(LSENG_SERVER,&eapi);
    if (!m_engine) {
        logger::ffail("Creating an engine has failed.");
    }
}

seastar::future<> server::service_loop(quic_stream<quic_stream_value_t> stream) {
    m_timer.set_callback([this] {
        return timer_expired();
    });

    return seastar::keep_doing([this, stream]() mutable {
        quic_stream_value_t buffer[0x1000];
        std::memset(buffer, 'A', sizeof(buffer));
        stream.write(buffer, sizeof(buffer));
        return m_channel.receive().then([this](seastar::net::udp_datagram datagram) {
            return handle_receive(std::move(datagram));
        });
    });
}

seastar::future<> server::timer_expired() {
    return process_connections();
}

seastar::future<> server::process_connections() {
    logger::flog("Ticking the engine.");

    lsquic_engine_process_conns(m_engine);
        
    int diff;
    if (lsquic_engine_earliest_adv_tick(m_engine, &diff)) {
        logger::flog("Diff: ", diff);
        const std::int64_t timeout = diff <= 0
                ? 0
                : (std::max(diff, LSQUIC_DF_CLOCK_GRANULARITY) / 1000);
        
        logger::flog("Tickable connections in: ", timeout);
        m_timer.rearm(std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout));
    } else {
        logger::flog("There are NO tickable connections.");
    }

    return seastar::make_ready_future<>();
}

seastar::future<> server::handle_receive(seastar::net::udp_datagram &&datagram) {
    char buffer[DATAGRAM_SIZE];
    std::memcpy(buffer, datagram.get_data().fragment_array()->base, datagram.get_data().len());
    buffer[datagram.get_data().len()] = '\0';

    const auto result = lsquic_engine_packet_in(
        m_engine,
        reinterpret_cast<unsigned char*>(buffer),
        datagram.get_data().len(),
        &m_channel.local_address().as_posix_sockaddr(),
        &datagram.get_src().as_posix_sockaddr(),
        this,
        0
    );

    switch (result) {
    case 0:
        logger::flog("Packet processed by a connection.");
        break;
    case 1:
        logger::flog("Packet processed, but not by a connection.");
        break;
    default:
        logger::eflog("Packet processing has failed.");
    }

    return process_connections();
}

} // namespace quic
} // namespace zpp
