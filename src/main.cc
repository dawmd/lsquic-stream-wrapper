#include <quic/common.hh>
#include <quic/quic_stream.hh>
#include <quic/server.hh>

#include <utils/logger.hh>

#include <seastar/core/app-template.hh>
#include <seastar/core/reactor.hh>

#include <cstdint>
#include <exception>

using namespace zpp;
using namespace quic;

seastar::future<> submit_to_cores(std::uint16_t port, detail::base_quic_stream<quic_stream_value_t> *stream) {
    return seastar::parallel_for_each(boost::irange<unsigned>(0, seastar::smp::count),
            [port, stream] (unsigned core) {
        return seastar::smp::submit_to(core, [port, stream] () {
            server srv(port);
            return seastar::do_with(std::move(srv), [stream](server &srv) {
                srv.init_lsquic(stream);
                return srv.service_loop(stream->get_reversed_wrapper());
            });
        });
    });
}

int main(int argc, char **argv) {
    seastar::app_template app;

    namespace po = boost::program_options;
    app.add_options()("port", po::value<std::uint16_t>()->required(), "listen port");

    try {
        detail::base_quic_stream<quic_stream_value_t> *stream = new detail::base_quic_stream<quic_stream_value_t>{};
        decltype(auto) s = stream->get_wrapper();
        app.run(argc, argv, [&] () {
            decltype(auto) config = app.configuration();
            std::uint16_t port = config["port"].as<std::uint16_t>();
            return submit_to_cores(port, stream);
        });
    } catch (...) {
        logger::ffail("Couldn't start the application: ", std::current_exception());
    }
    return 0;
}
