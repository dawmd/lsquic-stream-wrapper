#ifndef __QUIC_FILEHOST_QUIC_SERVER_HH__
#define __QUIC_FILEHOST_QUIC_SERVER_HH__

#include <seastar/core/future.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/timer.hh>
#include <seastar/net/api.hh>

#include <lsquic/lsquic.h>

#include <quic/common.hh>
#include <quic/quic_stream.hh>
#include <quic/detail/callbacks.hh>

namespace zpp {
namespace quic {

class server {
private:
    seastar::net::udp_channel                       m_channel;
    seastar::future<>                               m_udp_send_queue;
    seastar::timer<>                                m_timer;
    lsquic_engine_t                                *m_engine            = nullptr;
    detail::base_quic_stream<quic_stream_value_t>  *m_stream            = nullptr;

private:
    friend int ::zpp::quic::detail::packets_out(void*, const lsquic_out_spec*, unsigned int);

public:
    server(std::uint16_t port)
    : m_channel(seastar::make_udp_channel(port))
    , m_udp_send_queue(seastar::make_ready_future<>())
    , m_timer() {}

    server(server &&other)
    : m_channel(std::move(other.m_channel))
    , m_udp_send_queue(std::move(other.m_udp_send_queue))
    , m_timer(std::move(other.m_timer)) {}

    // I myself can't believe what's going on in here...
    server &operator=(server &&other) {
        m_channel = std::move(other.m_channel);
        m_udp_send_queue = std::move(other.m_udp_send_queue);

        m_timer.~timer<>();
        new (std::addressof(m_timer)) seastar::timer<>{std::move(other.m_timer)};

        m_stream->~base_quic_stream<quic_stream_value_t>();
        m_stream = std::exchange(other.m_stream, nullptr);

        return *this;
    }

    ~server();

    /** @brief Passes the ownership of `stream` on to the object. */
    void                init_lsquic(detail::base_quic_stream<quic_stream_value_t> *stream);
    seastar::future<>   service_loop(quic_stream<quic_stream_value_t> stream);

private:
    seastar::future<>   timer_expired();
    seastar::future<>   process_connections();
    seastar::future<>   handle_receive(seastar::net::udp_datagram &&datagram);
};

} // namespace quic
} // namespace zpp

#endif // __QUIC_FILEHOST_QUIC_SERVER_HH__
