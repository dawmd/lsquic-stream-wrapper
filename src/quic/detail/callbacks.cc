#include <lsquic/lsquic.h>
#include <quic/detail/callbacks.hh>

#include <quic/common.hh>
#include <quic/quic_stream.hh>
#include <quic/server.hh>

#include <utils/logger.hh>

namespace zpp {
namespace quic {
namespace detail {

namespace {

using quic_stream_t = base_quic_stream<quic_stream_value_t>;

constexpr std::size_t MAX_BYTES_TO_SEND = 1e8;

} // anonymous namespace

lsquic_conn_ctx_t *on_new_connection([[maybe_unused]] void *stream_if_ctx, [[maybe_unused]] lsquic_conn_t *connection) {
    logger::flog("Creating a new connection.");
    return nullptr;
}

void on_connection_closed(lsquic_conn_t *connection) {
    logger::flog("Closed a connection.");
}

lsquic_stream_ctx_t *on_new_stream(void *stream_if_ctx, lsquic_stream *stream) {
    lsquic_stream_wantread(stream, 0);
    lsquic_stream_wantwrite(stream, 1);
    return reinterpret_cast<lsquic_stream_ctx_t*>(stream_if_ctx);   // TODO: To be changed to a map or something of streams
}

void on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx) {
    quic_stream_t *qstream = reinterpret_cast<quic_stream_t*>(stream_ctx);
    unsigned char buffer[1];

    auto read_count = lsquic_stream_read(stream, buffer, sizeof(buffer));

    if (read_count > 0) {
        logger::eflog("Received a non-zero value from lsquic.");
    } else if (read_count == 0) {
        logger::flog("Read an EOF.");
        lsquic_stream_shutdown(stream, 0);
        lsquic_stream_wantwrite(stream, 1);
    } else {
        logger::eflog("Error when reading from a stream. Aborting the connection.");
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}

void on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx) {
    static std::size_t send_counter = 0;

    quic_stream_t *qstream = reinterpret_cast<quic_stream_t*>(stream_ctx);
    if (!qstream->m_ostream.size()) {
        return;
    }

    auto write_count = lsquic_stream_write(
        stream,
        qstream->m_ostream.data(),
        qstream->m_ostream.size()
    );

    if (write_count > 0) {
        qstream->m_ostream.drop(write_count);
        send_counter += write_count;

        if (!qstream->m_ostream.size() && send_counter >= MAX_BYTES_TO_SEND) {
            logger::flog("Finished writing to a stream");
            lsquic_stream_shutdown(stream, 1);
            lsquic_conn_close(lsquic_stream_conn(stream));
        }
    } else if (write_count == -1) {
        logger::eflog("stream_write() has returned ", write_count, ". Aborting the connection.");
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}

void on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx) {
    logger::flog("A stream has been closed.");
}

// void    on_handshake_done(lsquic_conn_t *connection, lsquic_hsk_status handshake_status) {

// }

int packets_out(void *packets_out_ctx, const lsquic_out_spec *specs, unsigned int count) {
    for (std::size_t i = 0; i < count; ++i) {
        server *srv = reinterpret_cast<server*>(specs[i].peer_ctx);
        std::unique_ptr<quic_stream_value_t> data(new quic_stream_value_t[specs[i].iov->iov_len]);
        std::memcpy(data.get(), specs[i].iov->iov_base, specs[i].iov->iov_len);
        srv->m_udp_send_queue = srv->m_udp_send_queue.then(
            [srv, data = std::move(data), dst = *specs[i].dest_sa, data_len = specs[i].iov->iov_len] {
                seastar::socket_address addr(*reinterpret_cast<const sockaddr_in*>(&dst));
                return srv->m_channel.send(addr, seastar::temporary_buffer<quic_stream_value_t>(data.get(), data_len));
            }
        );
    }

    return count;
}

} // namespace detail
} // namespace quic
} // namespace zpp
