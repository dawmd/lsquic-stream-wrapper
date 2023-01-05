#ifndef __QUIC_FILEHOST_UTILS_HH__
#define __QUIC_FILEHOST_UTILS_HH__

#include <concepts>     // std::same_as
#include <exception>    // std::terminate
#include <iostream>     // std::ostream, std::cout, std::cerr

namespace zpp {
namespace logger {
namespace detail {

template<typename T, typename Stream = std::ostream>
concept printable = requires (Stream &s, const T &t) {
    { s << t } -> std::same_as<Stream&>;
};

template<typename Stream, typename... Ts>
    requires (printable<Ts, Stream> && ...)
inline void raw_log(Stream &stream, Ts &&...ts) {
    ([&]<typename T>(T &&msg) {
        stream << std::forward<T>(msg);
    }(std::forward<Ts>(ts)), ...);
}

constexpr inline std::ostream &get_std_log_stream() {
    return std::cout;
}

constexpr inline std::ostream &get_std_elog_stream() {
    return std::clog;
}

constexpr inline std::ostream &get_std_fail_stream() {
    return get_std_elog_stream();
}

} // namespace detail

/** Log a message. */
template<typename... Ts>
inline void log(Ts &&...ts) {
    ::zpp::logger::detail::raw_log(::zpp::logger::detail::get_std_log_stream(), std::forward<Ts>(ts)..., '\n');
}

/** Log an error message. */
template<typename... Ts>
inline void elog(Ts &&...ts) {
    ::zpp::logger::detail::raw_log(::zpp::logger::detail::get_std_elog_stream(), std::forward<Ts>(ts)..., '\n');
}

/** Log an error message and terminate the program. */
template<typename... Ts>
inline void fail(Ts &&...ts) {
    ::zpp::logger::detail::raw_log(::zpp::logger::detail::get_std_fail_stream(), std::forward<Ts>(ts)..., '\n');
    std::terminate();
}

namespace detail {

template<typename Stream>
inline void raw_log_location(Stream &stream, const auto &filename, const auto &function_name, const auto &line) {
    ::zpp::logger::detail::raw_log(stream, '[', filename, ", ", function_name, ':', line, "]: ");
}

} // namespace detail
} // namespace logger
} // namespace zpp

#if defined(__cpp_lib_source_location) && __cpp_lib_source_location >= 201907L

#include <source_location>

namespace zpp {
namespace logger {
namespace detail {

template<typename Stream>
inline void log_location(Stream &stream, const std::source_location &srcloc) {
    ::zpp::logger::detail::raw_log_location(stream, srcloc.file_name(), srcloc.function_name(), srcloc.line());
}

template<typename... Ts>
inline void raw_flog(const std::source_location &srcloc, Ts &&...ts) {
    ::zpp::logger::detail::log_location(::zpp::logger::detail::get_std_log_stream(), srcloc);
    ::zpp::logger::log(std::forward<Ts>(ts)...);
}

template<typename... Ts>
inline void raw_eflog(const std::source_location &srcloc, Ts &&...ts) {
    ::zpp::logger::detail::log_location(::zpp::logger::detail::get_std_elog_stream(), srcloc);
    ::zpp::logger::elog(std::forward<Ts>(ts)...);
}

template<typename... Ts>
inline void raw_ffail(const std::source_location &srcloc, Ts &&...ts) {
    ::zpp::logger::detail::log_location(::zpp::logger::detail::get_std_fail_stream(), srcloc);
    ::zpp::logger::fail(std::forward<Ts>(ts)...);
}

} // namespace detail
} // namespace logger
} // namespace zpp

/** Log a message and the location of the logging. */
#define  flog(...)  detail::raw_flog(std::source_location::current(), __VA_ARGS__)
/** Log an error message and the location of the logging. */
#define eflog(...) detail::raw_eflog(std::source_location::current(), __VA_ARGS__)
/** Log an error message and the location of the logging. After that, terminate the program. */
#define ffail(...) detail::raw_ffail(std::source_location::current(), __VA_ARGS__)

#else

#include <cstddef>  // std::size_t

#if not defined(PROJECT_ROOT_PATH)
#define PROJECT_ROOT_PATH ""
#endif

namespace zpp {
namespace logger {
namespace detail {

consteval bool is_prefix(const char *const prefix, const char *const string) {
    std::size_t idx = 0;
    while (prefix[idx] != '\0') {
        if (string[idx] == '\0' || prefix[idx] != string[idx]) {
            return false;
        }
        ++idx;
    }
    return true;
}

consteval const char *discard_prefix(const char *const prefix, const char *const string) {
    std::size_t idx = 0;
    while (prefix[idx] != '\0') {
        ++idx;
    }
    return &string[idx];
}

consteval const char *get_filepath(const char *const filepath) {
    return is_prefix(PROJECT_ROOT_PATH, filepath)
        ? discard_prefix(PROJECT_ROOT_PATH, filepath)
        : filepath;
}

template<typename... Ts>
inline void raw_flog(const auto &filename, const auto &function, const auto &line, Ts &&...ts) {
    ::zpp::logger::detail::raw_log_location(::zpp::logger::detail::get_std_log_stream(), filename, function, line);
    ::zpp::logger::log(std::forward<Ts>(ts)...);
}

template<typename... Ts>
inline void raw_eflog(const auto &filename, const auto &function, const auto &line, Ts &&...ts) {
    ::zpp::logger::detail::raw_log_location(::zpp::logger::detail::get_std_elog_stream(), filename, function, line);
    ::zpp::logger::elog(std::forward<Ts>(ts)...);
}

template<typename... Ts>
inline void raw_ffail(const auto &filename, const auto &function, const auto &line, Ts &&...ts) {
    ::zpp::logger::detail::raw_log_location(::zpp::logger::detail::get_std_fail_stream(), filename, function, line);
    ::zpp::logger::fail(std::forward<Ts>(ts)...);
}

} // namespace detail
} // namespace logger
} // namespace zpp

/** Log a message and the location of the logging. */
#define flog(...)                                       \
    detail::raw_flog(                                   \
        ::zpp::logger::detail::get_filepath(__FILE__),  \
        __func__,                                       \
        __LINE__,                                       \
        __VA_ARGS__                                     \
    )

/** Log an error message and the location of the logging. */
#define eflog(...)                                      \
    detail::raw_eflog(                                  \
        ::zpp::logger::detail::get_filepath(__FILE__),  \
        __func__,                                       \
        __LINE__,                                       \
        __VA_ARGS__                                     \
    )

/** Log an error message and the location of the logging. After that, terminate the program. */
#define ffail(...)                                      \
    detail::raw_ffail(                                  \
        ::zpp::logger::detail::get_filepath(__FILE__),  \
        __func__,                                       \
        __LINE__,                                       \
        __VA_ARGS__                                     \
    )

#endif // if __cpp_lib_source_location >= 201907L

#endif // __QUIC_FILEHOST_UTILS_HH__
