#include "gtest/gtest.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <poll.h>
#include <set>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "http_parse/hpack.h"
#include "smartdns/http2.h"

#define GET_HEADER(stream, name) ({ \
    char _buf[256]; \
    int _len = http2_stream_get_header((stream), (name), _buf, sizeof(_buf)); \
    (_len >= 0) ? _buf : nullptr; \
})

class LIBHTTP2 : public ::testing::Test
{
  protected:
    void SetUp() override {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) < 0) {
            perror("socketpair");
            FAIL() << "Failed to create socketpair";
        }
        client_sock = socks[0];
        server_sock = socks[1];

        int bufsize = 2 * 1024 * 1024;
        setsockopt(client_sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        setsockopt(client_sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
        setsockopt(server_sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        setsockopt(server_sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

        fcntl(client_sock, F_SETFL, O_NONBLOCK);
        fcntl(server_sock, F_SETFL, O_NONBLOCK);
    }

    void TearDown() override {
        if (client_sock != -1) close(client_sock);
        if (server_sock != -1) close(server_sock);
    }

    int socks[2];
    int client_sock = -1;
    int server_sock = -1;

    static int bio_read(void *private_data, uint8_t *buf, int len) {
        int fd = *(int *)private_data;
        int ret = read(fd, buf, len);
        if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            errno = EAGAIN;
            return -1;
        }
        return ret;
    }

    static int bio_write(void *private_data, const uint8_t *buf, int len) {
        int fd = *(int *)private_data;
        int ret = write(fd, buf, len);
        if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            errno = EAGAIN;
            return -1;
        }
        return ret;
    }

    void WriteServerFrame(uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len) {
        uint8_t frame[256] = {0};
        ASSERT_GE(len, 0);
        ASSERT_LE(len, (int)sizeof(frame) - 9);
        frame[0] = (len >> 16) & 0xff;
        frame[1] = (len >> 8) & 0xff;
        frame[2] = len & 0xff;
        frame[3] = type;
        frame[4] = flags;
        frame[5] = (stream_id >> 24) & 0x7f;
        frame[6] = (stream_id >> 16) & 0xff;
        frame[7] = (stream_id >> 8) & 0xff;
        frame[8] = stream_id & 0xff;
        if (len > 0) memcpy(frame + 9, payload, len);
        ASSERT_EQ(write(server_sock, frame, 9 + len), 9 + len);
    }

    void WriteClientFrame(uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len) {
        uint8_t frame[256] = {0};
        ASSERT_GE(len, 0);
        ASSERT_LE(len, (int)sizeof(frame) - 9);
        frame[0] = (len >> 16) & 0xff;
        frame[1] = (len >> 8) & 0xff;
        frame[2] = len & 0xff;
        frame[3] = type;
        frame[4] = flags;
        frame[5] = (stream_id >> 24) & 0x7f;
        frame[6] = (stream_id >> 16) & 0xff;
        frame[7] = (stream_id >> 8) & 0xff;
        frame[8] = stream_id & 0xff;
        if (len > 0) memcpy(frame + 9, payload, len);
        ASSERT_EQ(write(client_sock, frame, 9 + len), 9 + len);
    }

    void StartClientWithServerSettings(struct http2_ctx *ctx) {
        ASSERT_NE(ctx, nullptr);
        WriteServerFrame(0x04, 0, 0, NULL, 0);
        for (int i = 0; i < 20 && http2_ctx_handshake(ctx) != 1; i++) {
            usleep(1000);
        }
    }
};

static int HpackCountHeader(void *ctx, const char *name, const char *value) {
    int *count = (int *)ctx;
    (*count)++;
    return 0;
}

TEST_F(LIBHTTP2, HpackDynamicTableSizeUpdateMustPrecedeHeaders) {
    struct hpack_context hpack;
    hpack_init_context(&hpack);

    const uint8_t invalid_block[] = {
        0x40, 0x03, 'x', '-', 'a', 0x01, 'b', /* literal with incremental indexing */
        0x20                                      /* dynamic table size update to zero */
    };
    int count = 0;
    EXPECT_LT(hpack_decode_headers(&hpack, invalid_block, sizeof(invalid_block), HpackCountHeader, &count), 0);

    const uint8_t valid_block[] = {
        0x20,                                    /* dynamic table size update to zero */
        0x40, 0x03, 'x', '-', 'a', 0x01, 'b' /* literal with incremental indexing */
    };
    count = 0;
    EXPECT_EQ(hpack_decode_headers(&hpack, valid_block, sizeof(valid_block), HpackCountHeader, &count), 0);
    EXPECT_EQ(count, 1);

    hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackResizeEvictsDynamicEntriesBeforeReuse) {
    struct hpack_context hpack;
    uint8_t buf[128] = {0};
    hpack_init_context(&hpack);

    ASSERT_GT(hpack_encode_header(&hpack, "x-hpack-sync", "dynamic-value", buf, sizeof(buf)), 0);
    ASSERT_GT(hpack.entry_count, 0);
    ASSERT_GT(hpack.dynamic_table_size, 0U);

    hpack_resize_dynamic_table(&hpack, 0);
    EXPECT_EQ(hpack.entry_count, 0);
    EXPECT_EQ(hpack.dynamic_table_size, 0U);
    EXPECT_EQ(hpack.dynamic_table, nullptr);

    ASSERT_GT(hpack_encode_header(&hpack, "x-hpack-sync", "dynamic-value", buf, sizeof(buf)), 0);
    EXPECT_NE(buf[0], 0xbe);
    EXPECT_EQ(hpack.entry_count, 0);

    hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackMultipleInitialSizeUpdatesRefreshTable) {
    struct hpack_context hpack;
    hpack_init_context(&hpack);

    const uint8_t add_entry[] = {
        0x40, 0x03, 'x', '-', 'a', 0x01, 'b' /* x-a: b */
    };
    int count = 0;
    ASSERT_EQ(hpack_decode_headers(&hpack, add_entry, sizeof(add_entry), HpackCountHeader, &count), 0);
    ASSERT_GT(hpack.entry_count, 0);

    const uint8_t resize_block[] = {
        0x3f, 0xe1, 0x03, /* dynamic table size update to 512 */
        0x20,             /* dynamic table size update to zero */
        0x82              /* :method: GET */
    };
    count = 0;
    EXPECT_EQ(hpack_decode_headers(&hpack, resize_block, sizeof(resize_block), HpackCountHeader, &count), 0);
    EXPECT_EQ(count, 1);
    EXPECT_EQ(hpack.entry_count, 0);
    EXPECT_EQ(hpack.dynamic_table_size, 0U);

    hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackShrunkTableRejectsEvictedDynamicIndex) {
    struct hpack_context hpack;
    hpack_init_context(&hpack);

    const uint8_t add_entry[] = {
        0x40, 0x0c, 'x', '-', 'h', 'p', 'a', 'c', 'k', '-', 's', 'y', 'n', 'c',
        0x0d, 'd', 'y', 'n', 'a', 'm', 'i', 'c', '-', 'v', 'a', 'l', 'u', 'e'
    };
    int count = 0;
    ASSERT_EQ(hpack_decode_headers(&hpack, add_entry, sizeof(add_entry), HpackCountHeader, &count), 0);
    ASSERT_GT(hpack.entry_count, 0);

    hpack_resize_dynamic_table(&hpack, 0);

    const uint8_t indexed_old_dynamic_entry[] = {
        0xbe /* dynamic table index 62 */
    };
    count = 0;
    EXPECT_LT(hpack_decode_headers(&hpack, indexed_old_dynamic_entry, sizeof(indexed_old_dynamic_entry),
                                   HpackCountHeader, &count), 0);

    hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackDynamicTableSharedAcrossInterleavedStreams) {
    struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
    ASSERT_NE(ctx, nullptr);

    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
    WriteClientFrame(0x04, 0, 0, NULL, 0);
    for (int i = 0; i < 50 && http2_ctx_handshake(ctx) != 1; i++) {
        usleep(1000);
    }

    const uint8_t stream1_headers[] = {
        0x82, /* :method: GET */
        0x84, /* :path: / */
        0x86, /* :scheme: http */
        0x40, /* literal header with incremental indexing, new name */
        0x0c, 'x', '-', 'h', 'p', 'a', 'c', 'k', '-', 's', 'y', 'n', 'c',
        0x0d, 'd', 'y', 'n', 'a', 'm', 'i', 'c', '-', 'v', 'a', 'l', 'u', 'e'
    };
    WriteClientFrame(0x01, 0x04, 1, stream1_headers, sizeof(stream1_headers));

    const uint8_t stream3_headers[] = {
        0x82, /* :method: GET */
        0x84, /* :path: / */
        0x86, /* :scheme: http */
        0xbe  /* dynamic table index 62 from stream 1 */
    };
    WriteClientFrame(0x01, 0x05, 3, stream3_headers, sizeof(stream3_headers));

    struct http2_stream *stream1 = nullptr;
    struct http2_stream *stream3 = nullptr;
    for (int i = 0; i < 50 && (stream1 == nullptr || stream3 == nullptr); i++) {
        struct http2_poll_item items[8] = {};
        int count = 0;
        int poll_ret = http2_ctx_poll_readable(ctx, items, 8, &count);
        ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
        for (int j = 0; j < count; j++) {
            if (items[j].stream == nullptr && items[j].readable) {
                struct http2_stream *accepted = http2_ctx_accept_stream(ctx);
                if (accepted == nullptr) continue;
                if (http2_stream_get_id(accepted) == 1) stream1 = accepted;
                else if (http2_stream_get_id(accepted) == 3) stream3 = accepted;
                else http2_stream_close(accepted);
            }
            if (items[j].stream != nullptr) http2_stream_put(items[j].stream);
        }
        usleep(1000);
    }

    ASSERT_NE(stream1, nullptr);
    ASSERT_NE(stream3, nullptr);
    EXPECT_STREQ(GET_HEADER(stream1, "x-hpack-sync"), "dynamic-value");
    EXPECT_STREQ(GET_HEADER(stream3, "x-hpack-sync"), "dynamic-value");
    EXPECT_FALSE(http2_ctx_is_closed(ctx));

    http2_stream_close(stream3);
    http2_stream_close(stream1);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsHeaderTableSizeEvictsResponseEncoderEntries) {
    struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
    ASSERT_NE(ctx, nullptr);

    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
    WriteClientFrame(0x04, 0, 0, NULL, 0);
    for (int i = 0; i < 50 && http2_ctx_handshake(ctx) != 1; i++) usleep(1000);

    const uint8_t request_headers[] = {0x82, 0x84, 0x86};
    WriteClientFrame(0x01, 0x05, 1, request_headers, sizeof(request_headers));

    struct http2_stream *stream = nullptr;
    for (int i = 0; i < 50 && stream == nullptr; i++) {
        struct http2_poll_item items[4] = {};
        int count = 0;
        ASSERT_GE(http2_ctx_poll_readable(ctx, items, 4, &count), 0);
        for (int j = 0; j < count; j++) {
            if (items[j].stream == nullptr && items[j].readable)
                stream = http2_ctx_accept_stream(ctx);
            if (items[j].stream != nullptr) http2_stream_put(items[j].stream);
        }
        usleep(1000);
    }
    ASSERT_NE(stream, nullptr);

    struct http2_header_pair headers[] = {{"x-hpack-response", "dynamic-value"}};
    ASSERT_EQ(http2_stream_set_response(stream, 200, headers, 1), 0);
    uint8_t response_buf[512] = {0};
    ssize_t response_len = read(client_sock, response_buf, sizeof(response_buf));
    ASSERT_GT(response_len, 0);
    ASSERT_NE(memchr(response_buf, 0x40, response_len), nullptr);

    const uint8_t settings_zero[] = {
        0x00, 0x01,             /* SETTINGS_HEADER_TABLE_SIZE */
        0x00, 0x00, 0x00, 0x00  /* zero */
    };
    WriteClientFrame(0x04, 0, 0, settings_zero, sizeof(settings_zero));
    {
        int poll_ret = http2_ctx_poll(ctx, NULL, 0, NULL);
        ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
    }

    http2_stream_close(stream);

    const uint8_t request_headers2[] = {0x82, 0x84, 0x86};
    WriteClientFrame(0x01, 0x05, 3, request_headers2, sizeof(request_headers2));

    stream = nullptr;
    for (int i = 0; i < 50 && stream == nullptr; i++) {
        struct http2_poll_item items[4] = {};
        int count = 0;
        int poll_ret = http2_ctx_poll_readable(ctx, items, 4, &count);
        ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
        for (int j = 0; j < count; j++) {
            if (items[j].stream == nullptr && items[j].readable)
                stream = http2_ctx_accept_stream(ctx);
            if (items[j].stream != nullptr) http2_stream_put(items[j].stream);
        }
        usleep(1000);
    }
    ASSERT_NE(stream, nullptr);

    ASSERT_EQ(http2_stream_set_response(stream, 200, headers, 1), 0);
    memset(response_buf, 0, sizeof(response_buf));
    response_len = read(client_sock, response_buf, sizeof(response_buf));
    ASSERT_GT(response_len, 0);
    EXPECT_EQ(memchr(response_buf, 0xbe, response_len), nullptr);
    EXPECT_NE(memchr(response_buf, 0x40, response_len), nullptr);

    http2_stream_close(stream);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsOnNonZeroStreamFailsProtocol) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);
    WriteServerFrame(0x04, 0, 1, NULL, 0);
    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, ServerRejectsEnablePushSetting) {
    struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
    ASSERT_NE(ctx, nullptr);

    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
    const uint8_t settings_enable_push[] = {
        0x00, 0x02,             /* SETTINGS_ENABLE_PUSH */
        0x00, 0x00, 0x00, 0x01  /* enabled */
    };
    WriteClientFrame(0x04, 0, 0, settings_enable_push, sizeof(settings_enable_push));
    EXPECT_EQ(http2_ctx_handshake(ctx), HTTP2_ERR_PROTOCOL);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsMaxHeaderListSizeLimitsResponseHeaders) {
    struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
    ASSERT_NE(ctx, nullptr);

    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
    const uint8_t settings_header_list_size[] = {
        0x00, 0x06,             /* SETTINGS_MAX_HEADER_LIST_SIZE */
        0x00, 0x00, 0x00, 0x08  /* very small */
    };
    WriteClientFrame(0x04, 0, 0, settings_header_list_size, sizeof(settings_header_list_size));

    for (int i = 0; i < 50 && http2_ctx_handshake(ctx) != 1; i++) usleep(1000);

    const uint8_t request_headers[] = {0x82, 0x84, 0x86};
    WriteClientFrame(0x01, 0x05, 1, request_headers, sizeof(request_headers));

    struct http2_stream *stream = nullptr;
    for (int i = 0; i < 50 && stream == nullptr; i++) {
        struct http2_poll_item items[4] = {};
        int count = 0;
        int poll_ret = http2_ctx_poll_readable(ctx, items, 4, &count);
        ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
        for (int j = 0; j < count; j++) {
            if (items[j].stream == nullptr && items[j].readable)
                stream = http2_ctx_accept_stream(ctx);
            if (items[j].stream != nullptr) http2_stream_put(items[j].stream);
        }
        usleep(1000);
    }
    ASSERT_NE(stream, nullptr);

    struct http2_header_pair headers[] = {{"x-large-response-header", "too-large-for-peer"}};
    EXPECT_LT(http2_stream_set_response(stream, 200, headers, 1), 0);

    http2_stream_close(stream);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsAckWithPayloadFailsProtocol) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    const uint8_t settings_payload[] = {0x00, 0x03, 0x00, 0x00, 0x00, 0x64};
    WriteServerFrame(0x04, 0x01, 0, settings_payload, sizeof(settings_payload));
    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsEnablePushInvalidValueFailsProtocol) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    const uint8_t settings_payload[] = {0x00, 0x02, 0x00, 0x00, 0x00, 0x02};
    WriteServerFrame(0x04, 0, 0, settings_payload, sizeof(settings_payload));
    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, WindowUpdateZeroIncrementFailsProtocol) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    const uint8_t window_update_payload[] = {0x00, 0x00, 0x00, 0x00};
    WriteServerFrame(0x08, 0, 0, window_update_payload, sizeof(window_update_payload));
    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, RstStreamOnConnectionStreamFailsProtocol) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    const uint8_t rst_payload[] = {0x00, 0x00, 0x00, 0x00};
    WriteServerFrame(0x03, 0, 0, rst_payload, sizeof(rst_payload));
    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, DataAfterEndStreamFailsProtocol) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    struct http2_stream *stream = http2_stream_new(ctx);
    ASSERT_NE(stream, nullptr);

    const uint8_t headers_fragment[] = {0x08, 0x03, '2', '0', '0'};
    WriteServerFrame(0x01, 0x05, 1, headers_fragment, sizeof(headers_fragment));
    for (int i = 0; i < 20 && http2_stream_get_status(stream) != 200; i++) {
        http2_ctx_poll(ctx, NULL, 0, NULL);
        usleep(1000);
    }
    ASSERT_EQ(http2_stream_get_status(stream), 200);

    const uint8_t data_payload[] = {0x01};
    WriteServerFrame(0x00, 0, 1, data_payload, sizeof(data_payload));
    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);

    http2_stream_close(stream);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, DataAfterLocallyClosedStreamDoesNotFailConnection) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    struct http2_stream *stream = http2_stream_new(ctx);
    ASSERT_NE(stream, nullptr);

    const uint8_t headers_fragment[] = {0x08, 0x03, '2', '0', '0'};
    const uint8_t data_payload[] = {0x2a};
    WriteServerFrame(0x01, 0x04, 1, headers_fragment, sizeof(headers_fragment));
    WriteServerFrame(0x00, 0x01, 1, data_payload, sizeof(data_payload));

    uint8_t body[8] = {0};
    int body_len = -1;
    for (int i = 0; i < 20 && body_len <= 0; i++) {
        http2_ctx_poll(ctx, NULL, 0, NULL);
        body_len = http2_stream_read_body(stream, body, sizeof(body));
        if (body_len <= 0) usleep(1000);
    }
    ASSERT_EQ(body_len, 1);
    EXPECT_EQ(body[0], 0x2a);
    EXPECT_EQ(http2_stream_read_body(stream, body, sizeof(body)), 0);

    http2_stream_close(stream);

    const uint8_t late_data[] = {0x11};
    WriteServerFrame(0x00, 0, 1, late_data, sizeof(late_data));
    int late_poll_ret = http2_ctx_poll(ctx, NULL, 0, NULL);
    EXPECT_TRUE(late_poll_ret == 0 || late_poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(late_poll_ret);

    struct http2_stream *next_stream = http2_stream_new(ctx);
    ASSERT_NE(next_stream, nullptr);
    const uint8_t next_headers_fragment[] = {0x08, 0x03, '2', '0', '0'};
    WriteServerFrame(0x01, 0x05, 3, next_headers_fragment, sizeof(next_headers_fragment));
    for (int i = 0; i < 20 && http2_stream_get_status(next_stream) != 200; i++) {
        http2_ctx_poll(ctx, NULL, 0, NULL);
        usleep(1000);
    }
    EXPECT_EQ(http2_stream_get_status(next_stream), 200);

    http2_stream_close(next_stream);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, DataOnIdleStreamFailsProtocol) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    const uint8_t data_payload[] = {0x01};
    WriteServerFrame(0x00, 0, 1, data_payload, sizeof(data_payload));
    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, RefusedHeadersStillUpdateHpackDecoder) {
    struct http2_settings server_settings = {};
    server_settings.max_concurrent_streams = 1;
    struct http2_ctx *server_ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, &server_settings);
    ASSERT_NE(server_ctx, nullptr);

    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
    WriteClientFrame(0x04, 0, 0, NULL, 0);

    int server_ret = 0;
    for (int i = 0; i < 50; i++) {
        server_ret = http2_ctx_handshake(server_ctx);
        if (server_ret == 1) break;
        usleep(1000);
    }
    ASSERT_EQ(server_ret, 1);

    const uint8_t hold_headers[] = {0x82, 0x84, 0x86};
    WriteClientFrame(0x01, 0x05, 1, hold_headers, sizeof(hold_headers));

    struct http2_stream *hold_server_stream = nullptr;
    for (int i = 0; i < 50 && hold_server_stream == nullptr; i++) {
        struct http2_poll_item items[4] = {};
        int count = 0;
        ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
        for (int j = 0; j < count; j++) {
            if (items[j].stream == nullptr && items[j].readable) {
                hold_server_stream = http2_ctx_accept_stream(server_ctx);
            }
            if (items[j].stream != nullptr) http2_stream_put(items[j].stream);
        }
        usleep(1000);
    }
    ASSERT_NE(hold_server_stream, nullptr);

    const uint8_t refused_headers[] = {
        0x82, 0x84, 0x86,
        0x40, 0x0c, 'x', '-', 'h', 'p', 'a', 'c', 'k', '-', 's', 'y', 'n', 'c',
        0x0d, 'd', 'y', 'n', 'a', 'm', 'i', 'c', '-', 'v', 'a', 'l', 'u', 'e'
    };
    WriteClientFrame(0x01, 0x05, 3, refused_headers, sizeof(refused_headers));

    for (int i = 0; i < 50; i++) {
        int poll_ret = http2_ctx_poll_readable(server_ctx, NULL, 0, NULL);
        ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
        usleep(1000);
    }
    EXPECT_FALSE(http2_ctx_is_closed(server_ctx));

    http2_stream_close(hold_server_stream);

    const uint8_t accepted_headers[] = {
        0x82, 0x84, 0x86,
        0xbe  /* dynamic table index 62: x-hpack-sync: dynamic-value */
    };
    WriteClientFrame(0x01, 0x05, 5, accepted_headers, sizeof(accepted_headers));

    struct http2_stream *accepted_server_stream = nullptr;
    for (int i = 0; i < 50 && accepted_server_stream == nullptr; i++) {
        struct http2_poll_item items[4] = {};
        int count = 0;
        int poll_ret = http2_ctx_poll_readable(server_ctx, items, 4, &count);
        ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
        for (int j = 0; j < count; j++) {
            if (items[j].stream == nullptr && items[j].readable) {
                accepted_server_stream = http2_ctx_accept_stream(server_ctx);
            }
            if (items[j].stream != nullptr) http2_stream_put(items[j].stream);
        }
        usleep(1000);
    }

    ASSERT_NE(accepted_server_stream, nullptr);
    EXPECT_STREQ(GET_HEADER(accepted_server_stream, "x-hpack-sync"), "dynamic-value");
    EXPECT_FALSE(http2_ctx_is_closed(server_ctx));

    http2_stream_close(accepted_server_stream);
    http2_ctx_close(server_ctx);
}

TEST_F(LIBHTTP2, StreamNewAfterGoawayFails) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    const uint8_t goaway_payload[] = {0, 0, 0, 0, 0, 0, 0, 0};
    WriteServerFrame(0x07, 0, 0, goaway_payload, sizeof(goaway_payload));
    http2_ctx_poll(ctx, NULL, 0, NULL);

    struct http2_stream *stream = http2_stream_new(ctx);
    EXPECT_EQ(stream, nullptr);

    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, ResponseHeadersContinuation) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);

    struct http2_stream *stream = http2_stream_new(ctx);
    ASSERT_NE(stream, nullptr);

    StartClientWithServerSettings(ctx);

    const uint8_t headers_fragment[] = {0x08};
    const uint8_t continuation_fragment[] = {0x03, '2', '0', '0'};
    WriteServerFrame(0x01, 0x01, 1, headers_fragment, sizeof(headers_fragment));
    WriteServerFrame(0x09, 0x04, 1, continuation_fragment, sizeof(continuation_fragment));

    for (int i = 0; i < 20 && http2_stream_get_status(stream) != 200; i++) {
        http2_ctx_poll(ctx, NULL, 0, NULL);
        usleep(1000);
    }
    EXPECT_EQ(http2_stream_get_status(stream), 200);
    EXPECT_TRUE(http2_stream_is_end(stream));

    http2_stream_close(stream);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, ResponseDataFragmentsKeepStreamOpenUntilEndStream) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);

    struct http2_stream *stream = http2_stream_new(ctx);
    ASSERT_NE(stream, nullptr);

    StartClientWithServerSettings(ctx);

    const uint8_t headers[] = {
        0x08, 0x03, '2', '0', '0', /* :status: 200 */
        0x0f, 0x0d, 0x01, '4'     /* content-length: 4 */
    };
    WriteServerFrame(0x01, 0x04, 1, headers, sizeof(headers));

    const uint8_t first_fragment[] = {0xde, 0xad};
    WriteServerFrame(0x00, 0, 1, first_fragment, sizeof(first_fragment));

    struct http2_poll_item items[10] = {};
    int count = 0;
    ASSERT_EQ(http2_ctx_poll_readable(ctx, items, 10, &count), 0);
    ASSERT_GT(count, 0);

    bool found = false;
    for (int i = 0; i < count; i++) {
        if (items[i].stream == nullptr) continue;
        if (http2_stream_get_id(items[i].stream) == http2_stream_get_id(stream)) {
            found = true;
            uint8_t body[4] = {};
            EXPECT_EQ(http2_stream_get_status(items[i].stream), 200);
            ASSERT_EQ(http2_stream_read_body(items[i].stream, body, sizeof(body)), (int)sizeof(first_fragment));
            EXPECT_EQ(memcmp(body, first_fragment, sizeof(first_fragment)), 0);
            EXPECT_FALSE(http2_stream_is_end(items[i].stream));
        }
        http2_stream_put(items[i].stream);
    }
    ASSERT_TRUE(found);

    memset(items, 0, sizeof(items));
    count = 0;
    ASSERT_EQ(http2_ctx_poll_readable(ctx, items, 10, &count), 0);
    EXPECT_EQ(count, 0);

    const uint8_t second_fragment[] = {0xbe, 0xef};
    WriteServerFrame(0x00, 0x01, 1, second_fragment, sizeof(second_fragment));

    memset(items, 0, sizeof(items));
    count = 0;
    ASSERT_EQ(http2_ctx_poll_readable(ctx, items, 10, &count), 0);
    ASSERT_GT(count, 0);

    found = false;
    for (int i = 0; i < count; i++) {
        if (items[i].stream == nullptr) continue;
        if (http2_stream_get_id(items[i].stream) == http2_stream_get_id(stream)) {
            found = true;
            uint8_t body[4] = {};
            ASSERT_EQ(http2_stream_read_body(items[i].stream, body, sizeof(body)), (int)sizeof(second_fragment));
            EXPECT_EQ(memcmp(body, second_fragment, sizeof(second_fragment)), 0);
            EXPECT_TRUE(http2_stream_is_end(items[i].stream));
        }
        http2_stream_put(items[i].stream);
    }
    ASSERT_TRUE(found);

    http2_stream_close(stream);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, ResponseEndStreamBeforeContentLengthResetsStreamOnly) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);

    struct http2_stream *stream = http2_stream_new(ctx);
    ASSERT_NE(stream, nullptr);

    StartClientWithServerSettings(ctx);

    const uint8_t headers[] = {
        0x08, 0x03, '2', '0', '0', /* :status: 200 */
        0x0f, 0x0d, 0x01, '4'     /* content-length: 4 */
    };
    WriteServerFrame(0x01, 0x04, 1, headers, sizeof(headers));

    const uint8_t short_body[] = {0xde, 0xad};
    WriteServerFrame(0x00, 0x01, 1, short_body, sizeof(short_body));

    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_EAGAIN);

    struct http2_stream *next_stream = http2_stream_new(ctx);
    ASSERT_NE(next_stream, nullptr);

    http2_stream_close(next_stream);
    http2_stream_close(stream);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, FullyReadEndedRequestIsNotReportedReadableAgain) {
    struct http2_ctx *client_ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    struct http2_ctx *server_ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
    ASSERT_NE(client_ctx, nullptr);
    ASSERT_NE(server_ctx, nullptr);

    int client_ret = 0, server_ret = 0;
    for (int i = 0; i < 20; i++) {
        client_ret = http2_ctx_handshake(client_ctx);
        server_ret = http2_ctx_handshake(server_ctx);
        if (client_ret == 1 && server_ret == 1) break;
        usleep(1000);
    }
    ASSERT_EQ(client_ret, 1);
    ASSERT_EQ(server_ret, 1);

    const char body[] = "dns-query";
    char content_length[16];
    snprintf(content_length, sizeof(content_length), "%zu", sizeof(body) - 1);
    struct http2_header_pair headers[] = {
        {"content-type", "application/dns-message"}, {"content-length", content_length}, {NULL, NULL}};

    struct http2_stream *client_stream = http2_stream_new(client_ctx);
    ASSERT_NE(client_stream, nullptr);
    ASSERT_EQ(http2_stream_set_request(client_stream, "POST", "/dns-query", NULL, headers), 0);
    ASSERT_EQ(http2_stream_write_body(client_stream, (const uint8_t *)body, sizeof(body) - 1, 1), (int)sizeof(body) - 1);
    int poll_ret = http2_ctx_poll(client_ctx, NULL, 0, NULL);
    ASSERT_TRUE(poll_ret >= 0 || poll_ret == HTTP2_ERR_EAGAIN);

    struct http2_stream *server_stream = nullptr;
    for (int i = 0; i < 20 && server_stream == nullptr; i++) {
        struct http2_poll_item items[4];
        int count = 0;
        ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
        for (int j = 0; j < count; j++) {
            if (items[j].stream == nullptr && items[j].readable)
                server_stream = http2_ctx_accept_stream(server_ctx);
            if (items[j].stream != nullptr) http2_stream_put(items[j].stream);
        }
        usleep(1000);
    }
    ASSERT_NE(server_stream, nullptr);

    uint8_t buf[32];
    ASSERT_EQ(http2_stream_read_body(server_stream, buf, sizeof(buf)), (int)sizeof(body) - 1);
    EXPECT_TRUE(http2_stream_is_end(server_stream));

    struct http2_poll_item items[4];
    int count = 0;
    ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
    EXPECT_EQ(count, 0);
    for (int i = 0; i < count; i++) {
        if (items[i].stream != nullptr) http2_stream_put(items[i].stream);
    }

    http2_stream_close(server_stream);
    http2_stream_close(client_stream);
    http2_ctx_close(server_ctx);
    http2_ctx_close(client_ctx);
}

TEST_F(LIBHTTP2, InvalidCompressedEndedRequestIsNotReportedReadableAgain) {
    struct http2_ctx *client_ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    struct http2_ctx *server_ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
    ASSERT_NE(client_ctx, nullptr);
    ASSERT_NE(server_ctx, nullptr);

    int client_ret = 0, server_ret = 0;
    for (int i = 0; i < 20; i++) {
        client_ret = http2_ctx_handshake(client_ctx);
        server_ret = http2_ctx_handshake(server_ctx);
        if (client_ret == 1 && server_ret == 1) break;
        usleep(1000);
    }
    ASSERT_EQ(client_ret, 1);
    ASSERT_EQ(server_ret, 1);

    const char body[] = "not-a-gzip-body";
    char content_length[16];
    snprintf(content_length, sizeof(content_length), "%zu", sizeof(body) - 1);
    struct http2_header_pair headers[] = {
        {"content-type", "application/dns-message"},
        {"content-length", content_length},
        {"content-encoding", "gzip"},
        {NULL, NULL}
    };

    struct http2_stream *client_stream = http2_stream_new(client_ctx);
    ASSERT_NE(client_stream, nullptr);
    ASSERT_EQ(http2_stream_set_request(client_stream, "POST", "/dns-query", NULL, headers), 0);
    ASSERT_EQ(http2_stream_write_body(client_stream, (const uint8_t *)body, sizeof(body) - 1, 1), (int)sizeof(body) - 1);
    int poll_ret = http2_ctx_poll(client_ctx, NULL, 0, NULL);
    ASSERT_TRUE(poll_ret >= 0 || poll_ret == HTTP2_ERR_EAGAIN);

    struct http2_stream *server_stream = nullptr;
    for (int i = 0; i < 20 && server_stream == nullptr; i++) {
        struct http2_poll_item items[4];
        int count = 0;
        ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
        for (int j = 0; j < count; j++) {
            if (items[j].stream == nullptr && items[j].readable)
                server_stream = http2_ctx_accept_stream(server_ctx);
            if (items[j].stream != nullptr) http2_stream_put(items[j].stream);
        }
        usleep(1000);
    }
    ASSERT_NE(server_stream, nullptr);
    EXPECT_TRUE(http2_stream_is_remote_end(server_stream));

    uint8_t buf[32];
    errno = 0;
    ASSERT_LT(http2_stream_read_body(server_stream, buf, sizeof(buf)), 0);
    EXPECT_EQ(errno, EINVAL);

    struct http2_poll_item items[4];
    int count = 0;
    ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
    EXPECT_EQ(count, 0);
    for (int i = 0; i < count; i++) {
        if (items[i].stream != nullptr) http2_stream_put(items[i].stream);
    }

    http2_stream_close(server_stream);
    http2_stream_close(client_stream);
    http2_ctx_close(server_ctx);
    http2_ctx_close(client_ctx);
}

TEST_F(LIBHTTP2, PollReturnsResponseBeforeGoawayEof) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);

    struct http2_stream *stream = http2_stream_new(ctx);
    ASSERT_NE(stream, nullptr);

    StartClientWithServerSettings(ctx);

    const uint8_t headers_fragment[] = {0x08};
    const uint8_t continuation_fragment[] = {0x03, '2', '0', '0'};
    WriteServerFrame(0x01, 0x01, 1, headers_fragment, sizeof(headers_fragment));
    WriteServerFrame(0x09, 0x04, 1, continuation_fragment, sizeof(continuation_fragment));
    const uint8_t goaway_payload[] = {0, 0, 0, 1, 0, 0, 0, 0};
    WriteServerFrame(0x07, 0, 0, goaway_payload, sizeof(goaway_payload));
    ASSERT_EQ(shutdown(server_sock, SHUT_WR), 0);

    struct http2_poll_item items[10] = {};
    int count = 0;
    int ret = http2_ctx_poll_readable(ctx, items, 10, &count);
    EXPECT_EQ(ret, 0);
    ASSERT_GT(count, 0);

    bool found = false;
    for (int i = 0; i < count; i++) {
        if (items[i].stream == nullptr) continue;
        if (http2_stream_get_id(items[i].stream) == http2_stream_get_id(stream)) {
            found = true;
            EXPECT_TRUE(items[i].readable);
            EXPECT_EQ(http2_stream_get_status(items[i].stream), 200);
            EXPECT_TRUE(http2_stream_is_end(items[i].stream));
        }
        http2_stream_put(items[i].stream);
    }
    EXPECT_TRUE(found);

    http2_stream_close(stream);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, RequestHostHeaderOverridesAuthority) {
    struct http2_ctx *client_ctx = http2_ctx_client_new("1.1.1.1", bio_read, bio_write, &client_sock, NULL);
    struct http2_ctx *server_ctx = http2_ctx_server_new("local-server", bio_read, bio_write, &server_sock, NULL);
    ASSERT_NE(client_ctx, nullptr);
    ASSERT_NE(server_ctx, nullptr);

    int client_ret = 0, server_ret = 0;
    for (int i = 0; i < 50; i++) {
        server_ret = http2_ctx_handshake(server_ctx);
        client_ret = http2_ctx_handshake(client_ctx);
        if (client_ret == 1 && server_ret == 1) break;
        usleep(1000);
    }
    ASSERT_EQ(client_ret, 1);
    ASSERT_EQ(server_ret, 1);

    struct http2_stream *client_stream = http2_stream_new(client_ctx);
    ASSERT_NE(client_stream, nullptr);
    struct http2_header_pair headers[] = {{"host", "cloudflare-dns.com"}, {NULL, NULL}};
    ASSERT_EQ(http2_stream_set_request(client_stream, "GET", "/dns-query", NULL, headers), 0);

    struct http2_stream *server_stream = nullptr;
    for (int i = 0; i < 50 && server_stream == nullptr; i++) {
        struct http2_poll_item items[10] = {};
        int count = 0;
        http2_ctx_poll(server_ctx, items, 10, &count);
        for (int j = 0; j < count; j++) {
            if (items[j].stream == nullptr && items[j].readable)
                server_stream = http2_ctx_accept_stream(server_ctx);
            if (items[j].stream) http2_stream_put(items[j].stream);
        }
        usleep(1000);
    }

    ASSERT_NE(server_stream, nullptr);
    EXPECT_STREQ(GET_HEADER(server_stream, ":authority"), "cloudflare-dns.com");
    EXPECT_EQ(GET_HEADER(server_stream, "host"), nullptr);

    http2_stream_close(server_stream);
    http2_stream_close(client_stream);
    http2_ctx_close(server_ctx);
    http2_ctx_close(client_ctx);
}

TEST_F(LIBHTTP2, InvalidPingLengthFailsProtocol) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    const uint8_t ping_payload[] = {0};
    WriteServerFrame(0x06, 0, 0, ping_payload, sizeof(ping_payload));
    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, WriteBodyReturnsPayloadLengthForMultiFrameBody) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    struct http2_stream *stream = http2_stream_new(ctx);
    ASSERT_NE(stream, nullptr);
    struct http2_header_pair headers[] = {{"content-type", "application/dns-message"}, {NULL, NULL}};
    ASSERT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", NULL, headers), 0);

    std::vector<uint8_t> body(20000);
    for (size_t i = 0; i < body.size(); i++) body[i] = (uint8_t)(i & 0xff);

    EXPECT_EQ(http2_stream_write_body(stream, body.data(), body.size(), 1), (int)body.size());

    http2_stream_close(stream);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, ContinuationWithoutHeadersFailsProtocol) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    const uint8_t payload[] = {0x00};
    WriteServerFrame(0x09, 0x04, 1, payload, sizeof(payload));
    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, HeadersInterruptedByDataFailsProtocol) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    StartClientWithServerSettings(ctx);

    const uint8_t headers_fragment[] = {0x08};
    const uint8_t data_payload[] = {0x01};
    WriteServerFrame(0x01, 0, 1, headers_fragment, sizeof(headers_fragment));
    WriteServerFrame(0x00, 0, 1, data_payload, sizeof(data_payload));

    EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
    http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, Integrated) {
    std::thread server_thread([this]() {
        struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Server handshake failed";

        struct http2_stream *stream = nullptr;
        int max_attempts = 200;
        while (max_attempts-- > 0 && !stream) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 100);
            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);
            for (int i = 0; i < count; i++) {
                if (items[i].stream == nullptr && items[i].readable) {
                    stream = http2_ctx_accept_stream(ctx);
                    if (stream) break;
                }
            }
            usleep(20000);
        }
        ASSERT_NE(stream, nullptr) << "Server failed to accept stream";

        char method_buf[64] = {0};
        char path_buf[256] = {0};
        if (http2_stream_get_method(stream, method_buf, sizeof(method_buf)) >= 0 &&
            http2_stream_get_path(stream, path_buf, sizeof(path_buf)) >= 0) {
            EXPECT_STREQ(method_buf, "POST");
            EXPECT_STREQ(path_buf, "/echo");
        }

        uint8_t request_body[4096];
        int request_body_len = 0;
        while (!http2_stream_is_end(stream) && request_body_len < (int)sizeof(request_body)) {
            int read_len = http2_stream_read_body(stream, request_body + request_body_len,
                                                  sizeof(request_body) - request_body_len);
            if (read_len <= 0) {
                http2_ctx_poll(ctx, NULL, 0, NULL);
                usleep(1000);
                if (read_len < 0 && errno != EAGAIN) break;
                continue;
            }
            request_body_len += read_len;
        }

        char response[8192];
        int response_len = snprintf(response, sizeof(response), "Echo Response: %.*s", request_body_len, request_body);
        char content_length[32];
        snprintf(content_length, sizeof(content_length), "%d", response_len);
        struct http2_header_pair headers[] = {
            {"content-type", "text/plain"}, {"content-length", content_length}, {NULL, NULL}};
        http2_stream_set_response(stream, 200, headers, 2);
        int written = 0;
        while (written < response_len) {
            int w = http2_stream_write_body(stream, (const uint8_t *)response + written, response_len - written, 0);
            if (w < 0) {
                if (errno == EAGAIN) {
                    http2_ctx_poll(ctx, NULL, 0, NULL);
                    usleep(1000);
                    continue;
                }
                break;
            }
            written += w;
        }
        http2_stream_write_body(stream, NULL, 0, 1);

        int flush_retries = 100;
        while (http2_ctx_want_write(ctx) && flush_retries-- > 0) {
            if (http2_ctx_poll(ctx, NULL, 0, NULL) < 0) break;
            usleep(1000);
        }
        http2_stream_close(stream);
        http2_ctx_close(ctx);
    });

    std::thread client_thread([this]() {
        usleep(50000);
        struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Client handshake failed";

        struct http2_stream *stream = http2_stream_new(ctx);
        ASSERT_NE(stream, nullptr);

        struct http2_header_pair headers[] = {
            {"content-type", "application/json"}, {"content-length", "27"}, {NULL, NULL}};
        http2_stream_set_request(stream, "POST", "/echo", NULL, headers);
        const char *request_body = "{\"message\":\"Hello Echo!\"}";
        http2_stream_write_body(stream, (const uint8_t *)request_body, strlen(request_body), 1);

        int max_attempts = 200;
        while (max_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 100);
            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);
            if (http2_stream_get_status(stream) > 0) break;
            usleep(20000);
        }
        ASSERT_EQ(http2_stream_get_status(stream), 200);

        uint8_t response_body[4096];
        int response_body_len = 0;
        while (!http2_stream_is_end(stream) && response_body_len < (int)sizeof(response_body)) {
            int read_len = http2_stream_read_body(stream, response_body + response_body_len,
                                                  sizeof(response_body) - response_body_len);
            if (read_len > 0) {
                response_body_len += read_len;
            } else {
                usleep(10000);
            }
        }

        std::string resp((char *)response_body, response_body_len);
        EXPECT_NE(resp.find("Echo Response"), std::string::npos);
        EXPECT_NE(resp.find("Hello Echo"), std::string::npos);

        http2_stream_close(stream);
        http2_ctx_close(ctx);
    });

    server_thread.join();
    client_thread.join();
}

TEST_F(LIBHTTP2, MultiStream) {
    const int NUM_STREAMS = 3;
    std::thread server_thread([this, NUM_STREAMS]() {
        struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Server handshake failed";

        int streams_completed = 0;
        int max_iterations = 500;
        std::set<struct http2_stream *> processed_streams;
        while (streams_completed < NUM_STREAMS && max_iterations-- > 0) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 100);

            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);

            for (int i = 0; i < count; i++) {
                if (items[i].stream == nullptr && items[i].readable) {
                    http2_ctx_accept_stream(ctx);
                } else if (items[i].stream && items[i].readable) {
                    struct http2_stream *stream = items[i].stream;
                    uint8_t buf[1024];
                    http2_stream_read_body(stream, buf, sizeof(buf));

                    if (http2_stream_is_end(stream)) {
                        if (processed_streams.find(stream) == processed_streams.end()) {
                            char response[256];
                            int response_len = snprintf(response, sizeof(response), "Echo from stream %d",
                                                        http2_stream_get_id(stream));
                            char content_length[32];
                            snprintf(content_length, sizeof(content_length), "%d", response_len);
                            struct http2_header_pair headers[] = {{"content-type", "text/plain"},
                                                                  {"content-length", content_length}};
                            http2_stream_set_response(stream, 200, headers, 2);
                            int written = 0;
                            while (written < response_len) {
                                int w = http2_stream_write_body(stream, (const uint8_t *)response + written,
                                                                response_len - written, 0);
                                if (w < 0) {
                                    if (errno == EAGAIN) {
                                        http2_ctx_poll(ctx, NULL, 0, NULL);
                                        usleep(1000);
                                        continue;
                                    }
                                    break;
                                }
                                written += w;
                            }
                            http2_stream_write_body(stream, NULL, 0, 1);
                            streams_completed++;
                            processed_streams.insert(stream);
                        }
                    }
                }
            }
            usleep(2000);
        }

        for (auto stream : processed_streams) http2_stream_close(stream);
        http2_ctx_close(ctx);
    });

    std::thread client_thread([this, NUM_STREAMS]() {
        usleep(50000);
        struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Client handshake failed";

        struct http2_stream *streams[NUM_STREAMS];
        for (int i = 0; i < NUM_STREAMS; i++) {
            streams[i] = http2_stream_new(ctx);
            ASSERT_NE(streams[i], nullptr);

            char path[64];
            snprintf(path, sizeof(path), "/stream%d", i);
            char body[128];
            int body_len = snprintf(body, sizeof(body), "Request from stream %d", i);
            char content_length[32];
            snprintf(content_length, sizeof(content_length), "%d", body_len);

            struct http2_header_pair headers[] = {
                {"content-type", "text/plain"}, {"content-length", content_length}, {NULL, NULL}};
            http2_stream_set_request(streams[i], "POST", path, NULL, headers);
            http2_stream_write_body(streams[i], (const uint8_t *)body, body_len, 1);
        }

        int streams_completed = 0;
        int max_iterations = 500;
        std::set<int> completed_stream_ids;
        while (streams_completed < NUM_STREAMS && max_iterations-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 100);

            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);

            for (int i = 0; i < count; i++) {
                if (items[i].stream && items[i].readable) {
                    struct http2_stream *stream = items[i].stream;
                    uint8_t buf[1024];
                    int total = 0;
                    while (!http2_stream_is_end(stream)) {
                        int r = http2_stream_read_body(stream, buf + total, sizeof(buf) - total);
                        if (r < 0) {
                            if (errno == EAGAIN) break;
                            break;
                        }
                        if (r == 0) break;
                        total += r;
                    }
                    if (http2_stream_is_end(stream)) {
                        int stream_id = http2_stream_get_id(stream);
                        if (completed_stream_ids.find(stream_id) == completed_stream_ids.end()) {
                            completed_stream_ids.insert(stream_id);
                            streams_completed++;
                        }
                    }
                }
            }
            usleep(2000);
        }

        EXPECT_EQ(streams_completed, NUM_STREAMS);
        for (int i = 0; i < NUM_STREAMS; i++) http2_stream_close(streams[i]);
        http2_ctx_close(ctx);
    });

    server_thread.join();
    client_thread.join();
}

TEST_F(LIBHTTP2, EarlyStreamCreation) {
    std::thread server_thread([this]() {
        struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            int poll_ret = poll(&pfd, 1, 10);
            if (poll_ret == 0) continue;
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Server handshake failed";

        struct http2_stream *stream = nullptr;
        int max_attempts = 200;
        while (max_attempts-- > 0 && !stream) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 100);
            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);
            for (int i = 0; i < count; i++) {
                if (items[i].stream == nullptr && items[i].readable) {
                    stream = http2_ctx_accept_stream(ctx);
                    if (stream) break;
                }
            }
            usleep(20000);
        }
        ASSERT_NE(stream, nullptr) << "Server failed to accept stream";

        char method_buf[64] = {0};
        char path_buf[256] = {0};
        if (http2_stream_get_method(stream, method_buf, sizeof(method_buf)) >= 0 &&
            http2_stream_get_path(stream, path_buf, sizeof(path_buf)) >= 0) {
            EXPECT_STREQ(method_buf, "POST");
            EXPECT_STREQ(path_buf, "/early-test");
        } else {
            FAIL() << "Failed to get method or path";
        }

        uint8_t request_body[4096];
        int request_body_len = 0;
        while (!http2_stream_is_end(stream) && request_body_len < (int)sizeof(request_body)) {
            int read_len = http2_stream_read_body(stream, request_body + request_body_len,
                                                  sizeof(request_body) - request_body_len);
            if (read_len <= 0) {
                http2_ctx_poll(ctx, NULL, 0, NULL);
                usleep(1000);
                if (read_len < 0 && errno != EAGAIN) break;
                continue;
            }
            request_body_len += read_len;
        }

        char response[8192];
        int response_len = snprintf(response, sizeof(response), "Echo Response: %.*s", request_body_len, request_body);
        char content_length[32];
        snprintf(content_length, sizeof(content_length), "%d", response_len);
        struct http2_header_pair headers[] = {
            {"content-type", "text/plain"}, {"content-length", content_length}, {NULL, NULL}};
        http2_stream_set_response(stream, 200, headers, 2);
        int written = 0;
        while (written < response_len) {
            int w = http2_stream_write_body(stream, (const uint8_t *)response + written, response_len - written, 0);
            if (w < 0) {
                if (errno == EAGAIN) {
                    http2_ctx_poll(ctx, NULL, 0, NULL);
                    usleep(1000);
                    continue;
                }
                break;
            }
            written += w;
        }
        http2_stream_write_body(stream, NULL, 0, 1);

        int flush_retries = 100;
        while (http2_ctx_want_write(ctx) && flush_retries-- > 0) {
            if (http2_ctx_poll(ctx, NULL, 0, NULL) < 0) break;
            usleep(1000);
        }
        http2_stream_close(stream);
        http2_ctx_close(ctx);
    });

    std::thread client_thread([this]() {
        usleep(50000);
        struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        struct http2_stream *stream = http2_stream_new(ctx);
        ASSERT_NE(stream, nullptr);

        struct http2_header_pair headers[] = {{"user-agent", "test-client"}, {NULL, NULL}};
        int ret = http2_stream_set_request(stream, "POST", "/early-test", NULL, headers);
        EXPECT_EQ(ret, 0);
        const char *request_body = "test echo";
        http2_stream_write_body(stream, (const uint8_t *)request_body, strlen(request_body), 1);

        int handshake_attempts = 200;
        ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Client handshake failed";

        int max_attempts = 200;
        while (max_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 100);
            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);
            if (http2_stream_get_status(stream) > 0) break;
            usleep(20000);
        }
        EXPECT_EQ(http2_stream_get_status(stream), 200);

        uint8_t response_body[4096];
        int response_body_len = 0;
        while (!http2_stream_is_end(stream) && response_body_len < (int)sizeof(response_body)) {
            int read_len = http2_stream_read_body(stream, response_body + response_body_len,
                                                  sizeof(response_body) - response_body_len);
            if (read_len > 0) {
                response_body_len += read_len;
            } else {
                usleep(10000);
            }
        }

        std::string resp((char *)response_body, response_body_len);
        EXPECT_NE(resp.find("Echo Response"), std::string::npos);
        EXPECT_NE(resp.find("test echo"), std::string::npos);

        http2_stream_close(stream);
        http2_ctx_close(ctx);
    });

    server_thread.join();
    client_thread.join();
}

TEST_F(LIBHTTP2, ServerLoopTerminationOnDisconnect) {
    std::thread server_thread([this]() {
        struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            int poll_ret = poll(&pfd, 1, 10);
            if (poll_ret == 0) continue;
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Server handshake failed";

        struct http2_stream *stream = nullptr;
        int max_attempts = 200;
        while (max_attempts-- > 0 && !stream) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 100);
            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);
            for (int i = 0; i < count; i++) {
                if (items[i].stream == nullptr && items[i].readable) {
                    stream = http2_ctx_accept_stream(ctx);
                    if (stream) break;
                }
            }
            usleep(20000);
        }
        ASSERT_NE(stream, nullptr) << "Server failed to accept stream";

        uint8_t buf[1024];
        int loop_count = 0;
        while (loop_count++ < 100) {
            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);

            int data_read = 0;
            for (int i = 0; i < count; i++) {
                if (items[i].stream == stream && items[i].readable) {
                    int ret = http2_stream_read_body(stream, buf, sizeof(buf));
                    if (ret > 0) data_read = 1;
                    else if (ret == 0) data_read = 1;
                }
                if (items[i].stream) http2_stream_put(items[i].stream);
            }

            if (!data_read && http2_stream_is_end(stream)) break;
            usleep(10000);
        }
        EXPECT_LT(loop_count, 100) << "Server loop did not terminate";
        http2_ctx_close(ctx);
    });

    std::thread client_thread([this]() {
        usleep(50000);
        struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret != 0) break;
        }
        ASSERT_EQ(ret, 1);

        struct http2_stream *stream = http2_stream_new(ctx);
        ASSERT_NE(stream, nullptr);

        struct http2_header_pair headers[] = {{"content-type", "text/plain"}, {NULL, NULL}};
        http2_stream_set_request(stream, "POST", "/test", NULL, headers);
        http2_stream_write_body(stream, (const uint8_t *)"test", 4, 1);
        http2_stream_close(stream);
        http2_ctx_close(ctx);
    });

    server_thread.join();
    client_thread.join();
}

TEST_F(LIBHTTP2, StreamClose) {
    std::thread server_thread([this]() {
        struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            int poll_ret = poll(&pfd, 1, 10);
            if (poll_ret == 0) continue;
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Server handshake failed";

        struct http2_stream *stream = nullptr;
        int max_attempts = 200;
        while (max_attempts-- > 0 && !stream) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 100);
            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);
            for (int i = 0; i < count; i++) {
                if (items[i].stream == nullptr && items[i].readable) {
                    stream = http2_ctx_accept_stream(ctx);
                    if (stream) break;
                }
            }
            usleep(20000);
        }
        ASSERT_NE(stream, nullptr) << "Server failed to accept stream";

        uint8_t buf[1024];
        http2_stream_read_body(stream, buf, sizeof(buf));
        http2_stream_set_response(stream, 200, NULL, 0);
        http2_stream_write_body(stream, (const uint8_t *)"OK", 2, 1);

        int flush_retries = 100;
        while (http2_ctx_want_write(ctx) && flush_retries-- > 0) {
            if (http2_ctx_poll(ctx, NULL, 0, NULL) < 0) break;
            usleep(1000);
        }
        http2_stream_close(stream);
        http2_ctx_close(ctx);
    });

    std::thread client_thread([this]() {
        usleep(50000);
        struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Client handshake failed";

        struct http2_stream *stream = http2_stream_new(ctx);
        ASSERT_NE(stream, nullptr);

        http2_stream_set_request(stream, "GET", "/test", NULL, NULL);
        http2_stream_write_body(stream, NULL, 0, 1);

        int max_attempts = 200;
        while (max_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 100);
            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);
            if (http2_stream_get_status(stream) > 0) break;
            usleep(20000);
        }

        http2_stream_get(stream);
        http2_stream_close(stream);
        EXPECT_FALSE(http2_stream_is_end(stream));

        uint8_t buf[1024];
        int read_len = http2_stream_read_body(stream, buf, sizeof(buf));
        EXPECT_GE(read_len, 0);

        while (!http2_stream_is_end(stream)) {
            read_len = http2_stream_read_body(stream, buf, sizeof(buf));
            if (read_len <= 0) break;
        }
        EXPECT_TRUE(http2_stream_is_end(stream));

        http2_stream_put(stream);
        http2_ctx_put(ctx);
    });

    server_thread.join();
    client_thread.join();
}

TEST_F(LIBHTTP2, ReferenceCountingNormal) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    struct http2_stream *stream = http2_stream_new(ctx);
    ASSERT_NE(stream, nullptr);
    http2_ctx_close(ctx);
    http2_stream_close(stream);
}

TEST_F(LIBHTTP2, ReferenceCountingContextError) {
    struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
    ASSERT_NE(ctx, nullptr);
    struct http2_stream *stream = http2_stream_new(ctx);
    ASSERT_NE(stream, nullptr);
    close(client_sock);
    client_sock = -1;
    http2_ctx_close(ctx);
    http2_stream_close(stream);
}

TEST_F(LIBHTTP2, BasicPOSTEcho) {
    std::thread server_thread([this]() {
        struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Server handshake failed";

        struct http2_stream *stream = nullptr;
        int max_attempts = 200;
        while (max_attempts-- > 0 && !stream) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 100);
            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);
            for (int i = 0; i < count; i++) {
                if (items[i].stream == nullptr && items[i].readable) {
                    stream = http2_ctx_accept_stream(ctx);
                    if (stream) break;
                }
            }
            usleep(20000);
        }
        ASSERT_NE(stream, nullptr) << "Server failed to accept stream";

        uint8_t body[1024];
        int total_read = 0;
        while (!http2_stream_is_end(stream) && total_read < (int)sizeof(body)) {
            int read_len = http2_stream_read_body(stream, body + total_read, sizeof(body) - total_read);
            if (read_len < 0) {
                if (errno == EAGAIN) {
                    http2_ctx_poll(ctx, NULL, 0, NULL);
                    usleep(1000);
                    continue;
                }
                FAIL() << "Server read error";
            }
            if (read_len == 0) break;
            total_read += read_len;
        }

        char content_length[32];
        snprintf(content_length, sizeof(content_length), "%d", total_read);
        struct http2_header_pair headers[] = {
            {"content-type", "text/plain"},
            {"content-length", content_length},
            {NULL, NULL}
        };
        ASSERT_EQ(http2_stream_set_response(stream, 200, headers, 2), 0);

        int written = 0;
        while (written < total_read) {
            int w = http2_stream_write_body(stream, body + written, total_read - written, 0);
            if (w < 0) {
                if (errno == EAGAIN) {
                    http2_ctx_poll(ctx, NULL, 0, NULL);
                    usleep(1000);
                    continue;
                }
                FAIL() << "Server write error";
            }
            written += w;
        }
        http2_stream_write_body(stream, NULL, 0, 1);

        int flush_retries = 100;
        while (http2_ctx_want_write(ctx) && flush_retries-- > 0) {
            if (http2_ctx_poll(ctx, NULL, 0, NULL) < 0) break;
            usleep(1000);
        }
        http2_stream_close(stream);
        http2_ctx_close(ctx);
    });

    std::thread client_thread([this]() {
        usleep(50000);
        struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
        ASSERT_NE(ctx, nullptr);

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        ASSERT_EQ(ret, 1) << "Client handshake failed";

        struct http2_stream *stream = http2_stream_new(ctx);
        ASSERT_NE(stream, nullptr);

        const char *payload = "Hello, HTTP/2 Echo!";
        int payload_len = strlen(payload);
        char content_length[32];
        snprintf(content_length, sizeof(content_length), "%d", payload_len);
        struct http2_header_pair headers[] = {
            {"content-type", "text/plain"},
            {"content-length", content_length},
            {NULL, NULL}
        };
        ASSERT_EQ(http2_stream_set_request(stream, "POST", "/echo", NULL, headers), 0);
        ASSERT_GE(http2_stream_write_body(stream, (const uint8_t *)payload, payload_len, 1), 0);

        int max_attempts = 200;
        while (max_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 100);
            struct http2_poll_item items[10];
            int count = 0;
            http2_ctx_poll(ctx, items, 10, &count);
            if (http2_stream_get_status(stream) > 0) break;
            usleep(20000);
        }
        ASSERT_EQ(http2_stream_get_status(stream), 200);

        uint8_t resp[1024];
        int total_read = 0;
        while (!http2_stream_is_end(stream) && total_read < (int)sizeof(resp)) {
            int read_len = http2_stream_read_body(stream, resp + total_read, sizeof(resp) - total_read);
            if (read_len < 0) {
                if (errno == EAGAIN) {
                    http2_ctx_poll(ctx, NULL, 0, NULL);
                    usleep(1000);
                    continue;
                }
                FAIL() << "Client read error";
            }
            if (read_len == 0) break;
            total_read += read_len;
        }
        EXPECT_EQ(total_read, payload_len);
        EXPECT_EQ(memcmp(resp, payload, payload_len), 0);

        http2_stream_close(stream);
        http2_ctx_close(ctx);
    });

    server_thread.join();
    client_thread.join();
}

TEST_F(LIBHTTP2, HighConcurrencyPOSTEcho) {
    const int NUM_STREAMS = 256;
    const int BODY_SIZE = 64;
    const int MAX_ITERATIONS = 10000;
    const int POLL_ITEMS = 512;

    std::atomic<int> server_completed{0};
    std::atomic<int> client_completed{0};
    std::atomic<bool> server_error{false};
    std::atomic<bool> client_error{false};

    std::thread server_thread([&]() {
        struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
        if (!ctx) { server_error = true; return; }

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        if (ret != 1) { server_error = true; http2_ctx_close(ctx); return; }

        std::set<struct http2_stream *> processed;
        int iteration = 0;
        while (server_completed.load() < NUM_STREAMS && iteration++ < MAX_ITERATIONS) {
            struct pollfd pfd = {server_sock, POLLIN, 0};
            poll(&pfd, 1, 50);

            struct http2_poll_item items[POLL_ITEMS];
            int count = 0;
            int poll_ret = http2_ctx_poll(ctx, items, POLL_ITEMS, &count);
            if (poll_ret < 0 && poll_ret != HTTP2_ERR_EAGAIN) {
                server_error = true;
                break;
            }

            for (int i = 0; i < count; i++) {
                if (items[i].stream == nullptr && items[i].readable) {
                    struct http2_stream *s = http2_ctx_accept_stream(ctx);
                    (void)s;
                    continue;
                }
                if (items[i].stream && items[i].readable) {
                    struct http2_stream *stream = items[i].stream;
                    if (processed.find(stream) != processed.end()) continue;

                    uint8_t body[4096];
                    int total_read = 0;
                    while (!http2_stream_is_end(stream) && total_read < (int)sizeof(body)) {
                        int read_len = http2_stream_read_body(stream, body + total_read,
                                                               sizeof(body) - total_read);
                        if (read_len < 0) {
                            if (errno == EAGAIN) break;
                            server_error = true;
                            goto server_done;
                        }
                        if (read_len == 0) break;
                        total_read += read_len;
                    }

                    if (http2_stream_is_end(stream) && total_read > 0) {
                        char content_length[32];
                        snprintf(content_length, sizeof(content_length), "%d", total_read);
                        struct http2_header_pair headers[] = {
                            {"content-type", "text/plain"},
                            {"content-length", content_length},
                            {NULL, NULL}
                        };
                        if (http2_stream_set_response(stream, 200, headers, 2) == 0) {
                            int written = 0;
                            bool write_ok = true;
                            while (written < total_read) {
                                int w = http2_stream_write_body(stream, body + written,
                                                                total_read - written, 0);
                                if (w < 0) {
                                    if (errno == EAGAIN) {
                                        http2_ctx_poll(ctx, NULL, 0, NULL);
                                        usleep(1000);
                                        continue;
                                    }
                                    write_ok = false;
                                    break;
                                }
                                written += w;
                            }
                            if (write_ok) {
                                http2_stream_write_body(stream, NULL, 0, 1);
                                processed.insert(stream);
                                server_completed++;
                            } else {
                                server_error = true;
                            }
                        } else {
                            server_error = true;
                        }
                    }
                }
            }
            usleep(1000);
        }
    server_done:
        for (auto s : processed) http2_stream_close(s);
        http2_ctx_close(ctx);
    });

    std::thread client_thread([&]() {
        usleep(50000);

        struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
        if (!ctx) { client_error = true; return; }

        int handshake_attempts = 200;
        int ret = 0;
        while (handshake_attempts-- > 0) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 10);
            ret = http2_ctx_handshake(ctx);
            if (ret == 1) break;
            if (ret < 0) break;
        }
        if (ret != 1) { client_error = true; http2_ctx_close(ctx); return; }

        std::vector<struct http2_stream *> streams;
        streams.reserve(NUM_STREAMS);
        std::vector<std::string> sent_bodies;
        sent_bodies.reserve(NUM_STREAMS);

        for (int i = 0; i < NUM_STREAMS; i++) {
            struct http2_stream *stream = http2_stream_new(ctx);
            if (!stream) { client_error = true; break; }
            streams.push_back(stream);

            char path[32];
            snprintf(path, sizeof(path), "/echo/%d", i);
            char body[BODY_SIZE];
            int body_len = snprintf(body, sizeof(body), "Echo-%d-%08x", i, rand());
            sent_bodies.push_back(std::string(body, body_len));

            char content_length[16];
            snprintf(content_length, sizeof(content_length), "%d", body_len);
            struct http2_header_pair headers[] = {
                {"content-type", "text/plain"},
                {"content-length", content_length},
                {NULL, NULL}
            };
            if (http2_stream_set_request(stream, "POST", path, NULL, headers) != 0) {
                client_error = true;
                break;
            }
            if (http2_stream_write_body(stream, (const uint8_t *)body, body_len, 1) < 0) {
                client_error = true;
                break;
            }
        }

        if (client_error) {
            for (auto s : streams) http2_stream_close(s);
            http2_ctx_close(ctx);
            return;
        }

        std::map<int, std::string> received;
        int iteration = 0;
        while (client_completed.load() < NUM_STREAMS && iteration++ < MAX_ITERATIONS) {
            struct pollfd pfd = {client_sock, POLLIN, 0};
            poll(&pfd, 1, 50);

            struct http2_poll_item items[POLL_ITEMS];
            int count = 0;
            int poll_ret = http2_ctx_poll(ctx, items, POLL_ITEMS, &count);
            if (poll_ret < 0 && poll_ret != HTTP2_ERR_EAGAIN) {
                client_error = true;
                break;
            }

            for (int i = 0; i < count; i++) {
                if (items[i].stream && items[i].readable) {
                    struct http2_stream *stream = items[i].stream;
                    int sid = http2_stream_get_id(stream);
                    if (received.find(sid) != received.end()) continue;

                    uint8_t body[4096];
                    int total_read = 0;
                    while (!http2_stream_is_end(stream) && total_read < (int)sizeof(body)) {
                        int read_len = http2_stream_read_body(stream, body + total_read,
                                                               sizeof(body) - total_read);
                        if (read_len < 0) {
                            if (errno == EAGAIN) break;
                            client_error = true;
                            goto client_done;
                        }
                        if (read_len == 0) break;
                        total_read += read_len;
                    }
                    if (http2_stream_is_end(stream) && total_read > 0) {
                        received[sid] = std::string((char*)body, total_read);
                        client_completed++;
                    }
                }
            }
            usleep(1000);
        }
    client_done:
        bool all_match = true;
        for (size_t i = 0; i < streams.size() && !client_error; i++) {
            int sid = http2_stream_get_id(streams[i]);
            auto it = received.find(sid);
            if (it == received.end()) {
                all_match = false;
                break;
            }
            if (it->second != sent_bodies[i]) {
                all_match = false;
                break;
            }
        }
        EXPECT_TRUE(all_match) << "Some response bodies mismatch";
        EXPECT_EQ(client_completed.load(), NUM_STREAMS);

        for (auto s : streams) http2_stream_close(s);
        http2_ctx_close(ctx);
    });

    server_thread.join();
    client_thread.join();

    EXPECT_FALSE(server_error.load());
    EXPECT_FALSE(client_error.load());
    EXPECT_EQ(server_completed.load(), NUM_STREAMS);
    EXPECT_EQ(client_completed.load(), NUM_STREAMS);
}
