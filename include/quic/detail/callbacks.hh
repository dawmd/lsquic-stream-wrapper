#ifndef __QUIC_FILEHOST_QUIC_DETAIL_CALLBACKS_HH__
#define __QUIC_FILEHOST_QUIC_DETAIL_CALLBACKS_HH__

#include <lsquic/lsquic.h>

namespace zpp {
namespace quic {
namespace detail {

lsquic_conn_ctx_t   *on_new_connection(void *stream_if_ctx, lsquic_conn_t *connection);
void                 on_connection_closed(lsquic_conn_t *connection);
lsquic_stream_ctx_t *on_new_stream(void *stream_if_ctx, lsquic_stream *stream);
void                 on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx);
void                 on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx);
void                 on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx);
// void                 on_handshake_done(lsquic_conn_t *connection, lsquic_hsk_status handshake_status);
int                  packets_out(void *packets_out_ctx, const lsquic_out_spec *specs, unsigned int count);


} // namespace detail
} // namespace quic
} // namespace zpp

#endif // __QUIC_FILEHOST_QUIC_DETAIL_CALLBACKS_HH__
