#ifndef __QUIC_FILEHOST_QUIC_QUIC_STREAM_HH__
#define __QUIC_FILEHOST_QUIC_QUIC_STREAM_HH__

#include <memory>
#include <quic/common.hh>

#include <quic/detail/callbacks.hh>

#include <cstddef>
#include <cstring>  // std::memcpy
#include <vector>

namespace zpp {
namespace quic {
namespace detail {

template<typename ByteType>
    requires (sizeof(ByteType) == 1)
class one_directionial_quic_stream {
public:
    using value_type = ByteType;

private:
    std::vector<ByteType>   m_stream{};
    std::size_t             m_begin     = 0;
    std::size_t             m_end       = 0;

public:
    auto size() const noexcept {
        return m_end - m_begin;
    }

    auto capacity() const noexcept {
        return m_stream.capacity() - m_begin;
    }

    void reserve(const std::size_t capacity) {
        m_stream.reserve(m_begin + capacity);
    }

    void drop(const std::size_t count) {
        if (count > size()) {
            throw 1;    // TODO
        }
        m_begin += count;
    }

    ByteType *data() noexcept {
        return &m_stream[m_begin];
    }

    const ByteType *data() const noexcept {
        return &m_stream[m_begin];
    }

    void write(const ByteType *buffer, const std::size_t count) {
        if (!count) {
            return;
        }

        if (m_end + count > m_stream.size()) {
            m_stream.resize(std::max(2 * m_stream.size(), m_stream.size() + 2 * count));
        }

        std::memcpy(&m_stream[m_end], buffer, count);
        m_end += count;
    }

    void read(ByteType *buffer, const std::size_t count) {
        if (count > m_end - m_begin) {
            throw 1;    // TODO
        }

        std::memcpy(buffer, &m_stream[m_begin], count);
        m_begin += count;
    }
};

template<typename ByteType>
    requires (sizeof(ByteType) == 1)
class base_quic_stream;

} // namespace detail

template<typename ByteType>
    requires (sizeof(ByteType) == 1)
class quic_stream;

template<typename ByteType>
    requires (sizeof(ByteType) == 1)
class quic_istream {
public:
    using value_type = ByteType;

private:
    detail::one_directionial_quic_stream<ByteType> *m_istream = nullptr;

private:
    friend class quic_stream<ByteType>;

public:
    void write(const ByteType *buffer, const std::size_t count) {
        m_istream->write(buffer, count);
    }

    quic_istream(const quic_istream<ByteType>&) = default;
    quic_istream(quic_istream<ByteType>&&) = default;
    quic_istream<ByteType> &operator=(const quic_istream<ByteType>&) = default;
    quic_istream<ByteType> &operator=(quic_istream<ByteType>&&) = default;

private:
    quic_istream() = default;
};

template<typename ByteType>
    requires (sizeof(ByteType) == 1)
class quic_ostream {
public:
    using value_type = ByteType;

private:
    detail::one_directionial_quic_stream<ByteType> *m_ostream = nullptr;

private:
    friend class quic_stream<ByteType>;

public:
    void read(ByteType *buffer, const std::size_t count) {
        m_ostream->read(buffer, count);
    }

private:
    quic_ostream() = default;
};

template<typename ByteType = quic_stream_value_t>
    requires (sizeof(ByteType) == 1)
class quic_stream {
public:
    using value_type = ByteType;

private:
    detail::one_directionial_quic_stream<ByteType> *m_istream = nullptr;
    detail::one_directionial_quic_stream<ByteType> *m_ostream = nullptr;

private:
    friend class detail::base_quic_stream<ByteType>;

public:
    void write(const ByteType *buffer, const std::size_t count) {
        m_istream->write(buffer, count);
    }

    void read(ByteType *buffer, const std::size_t count) {
        m_ostream->read(buffer, count);
    }

    quic_istream<ByteType> get_istream() noexcept {
        return quic_istream<ByteType> { .m_istream = m_istream };
    }

    quic_ostream<ByteType> get_ostream() noexcept {
        return quic_ostream<ByteType> { .m_ostream = m_ostream };
    }

private:
    quic_stream() = default;
};

namespace detail {

template<typename ByteType>
    requires (sizeof(ByteType) == 1)
class base_quic_stream {
public:
    using value_type = ByteType;

private:
    one_directionial_quic_stream<ByteType> m_istream{};
    one_directionial_quic_stream<ByteType> m_ostream{};

private:
    friend void ::zpp::quic::detail::on_read(lsquic_stream_t*, lsquic_stream_ctx_t*);
    friend void ::zpp::quic::detail::on_write(lsquic_stream_t*, lsquic_stream_ctx_t*);

public:
    void write(const ByteType *buffer, const std::size_t count) {
        m_istream.write(buffer, count);
    }

    void read(ByteType *buffer, const std::size_t count) {
        m_ostream.read(buffer, count);
    }

    quic_stream<ByteType> get_wrapper() noexcept {
        quic_stream<ByteType> result{};
        result.m_istream = std::addressof(m_istream);
        result.m_ostream = std::addressof(m_ostream);
        return result;
    }

    quic_stream<ByteType> get_reversed_wrapper() noexcept {
        quic_stream<ByteType> result{};
        result.m_istream = std::addressof(m_ostream);
        result.m_ostream = std::addressof(m_istream);
        return result;
    }
};

} // namespace detail
} // namespace quic
} // namespace zpp

#endif // __QUIC_FILEHOST_QUIC_QUIC_STREAM_HH__
