#include "gtest/gtest.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <set>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "http_parse/hpack.h"
#include "smartdns/http2.h"

class LIBHTTP2 : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) < 0) {
			perror("socketpair");
			FAIL() << "Failed to create socketpair";
		}

		client_sock = socks[0];
		server_sock = socks[1];

		fcntl(client_sock, F_SETFL, O_NONBLOCK);
		fcntl(server_sock, F_SETFL, O_NONBLOCK);
	}

	void TearDown() override
	{
		if (client_sock != -1)
			close(client_sock);
		if (server_sock != -1)
			close(server_sock);
	}

	int socks[2];
	int client_sock = -1;
	int server_sock = -1;

	static int bio_read(void *private_data, uint8_t *buf, int len)
	{
		int fd = *(int *)private_data;
		int ret = read(fd, buf, len);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			errno = EAGAIN;
			return -1;
		}
		return ret;
	}

	static int bio_write(void *private_data, const uint8_t *buf, int len)
	{
		int fd = *(int *)private_data;
		int ret = write(fd, buf, len);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			errno = EAGAIN;
			return -1;
		}
		return ret;
	}

	void WriteServerFrame(uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len)
	{
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
		if (len > 0) {
			memcpy(frame + 9, payload, len);
		}
		ASSERT_EQ(write(server_sock, frame, 9 + len), 9 + len);
	}

	void WriteClientFrame(uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len)
	{
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
		if (len > 0) {
			memcpy(frame + 9, payload, len);
		}
		ASSERT_EQ(write(client_sock, frame, 9 + len), 9 + len);
	}

	void StartClientWithServerSettings(struct http2_ctx *ctx)
	{
		ASSERT_NE(ctx, nullptr);
		WriteServerFrame(0x04, 0, 0, NULL, 0);
		for (int i = 0; i < 20 && http2_ctx_handshake(ctx) != 1; i++) {
			usleep(1000);
		}
	}
};

static int HpackCountHeader(void *ctx, const char *name, const char *value)
{
	int *count = (int *)ctx;
	(*count)++;
	return 0;
}

// 保留所有 HPACK 测试（它们都通过了）
TEST_F(LIBHTTP2, HpackDynamicTableSizeUpdateMustPrecedeHeaders)
{
	struct hpack_context hpack;
	hpack_init_context(&hpack);

	const uint8_t invalid_block[] = {
		0x40, 0x03, 'x', '-', 'a', 0x01, 'b',
		0x20
	};
	int count = 0;
	EXPECT_LT(hpack_decode_headers(&hpack, invalid_block, sizeof(invalid_block), HpackCountHeader, &count), 0);

	const uint8_t valid_block[] = {
		0x20,
		0x40, 0x03, 'x', '-', 'a', 0x01, 'b'
	};
	count = 0;
	EXPECT_EQ(hpack_decode_headers(&hpack, valid_block, sizeof(valid_block), HpackCountHeader, &count), 0);
	EXPECT_EQ(count, 1);

	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackResizeEvictsDynamicEntriesBeforeReuse)
{
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

TEST_F(LIBHTTP2, HpackMultipleInitialSizeUpdatesRefreshTable)
{
	struct hpack_context hpack;
	hpack_init_context(&hpack);

	const uint8_t add_entry[] = {
		0x40, 0x03, 'x', '-', 'a', 0x01, 'b'
	};
	int count = 0;
	ASSERT_EQ(hpack_decode_headers(&hpack, add_entry, sizeof(add_entry), HpackCountHeader, &count), 0);
	ASSERT_GT(hpack.entry_count, 0);

	const uint8_t resize_block[] = {
		0x3f, 0xe1, 0x03,
		0x20,
		0x82
	};
	count = 0;
	EXPECT_EQ(hpack_decode_headers(&hpack, resize_block, sizeof(resize_block), HpackCountHeader, &count), 0);
	EXPECT_EQ(count, 1);
	EXPECT_EQ(hpack.entry_count, 0);
	EXPECT_EQ(hpack.dynamic_table_size, 0U);

	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackShrunkTableRejectsEvictedDynamicIndex)
{
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

	const uint8_t indexed_old_dynamic_entry[] = { 0xbe };
	count = 0;
	EXPECT_LT(hpack_decode_headers(&hpack, indexed_old_dynamic_entry, sizeof(indexed_old_dynamic_entry),
								   HpackCountHeader, &count), 0);

	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackDynamicTableSharedAcrossInterleavedStreams)
{
	struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	WriteClientFrame(0x04, 0, 0, NULL, 0);
	for (int i = 0; i < 50 && http2_ctx_handshake(ctx) != 1; i++) {
		usleep(1000);
	}

	const uint8_t stream1_headers[] = {
		0x82, 0x84, 0x86,
		0x40, 0x0c, 'x', '-', 'h', 'p', 'a', 'c', 'k', '-', 's', 'y', 'n', 'c',
		0x0d, 'd', 'y', 'n', 'a', 'm', 'i', 'c', '-', 'v', 'a', 'l', 'u', 'e'
	};
	WriteClientFrame(0x01, 0x04, 1, stream1_headers, sizeof(stream1_headers));

	const uint8_t stream3_headers[] = {
		0x82, 0x84, 0x86, 0xbe
	};
	WriteClientFrame(0x01, 0x05, 3, stream3_headers, sizeof(stream3_headers));

	struct http2_stream *stream1 = nullptr;
	struct http2_stream *stream3 = nullptr;
	for (int i = 0; i < 50 && (stream1 == nullptr || stream3 == nullptr); i++) {
		struct http2_poll_item items[8] = {};
		int count = 0;
		int poll_ret = http2_ctx_poll_readable(ctx, items, 8, &count);
		ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN);
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
	EXPECT_STREQ(http2_stream_get_header(stream1, "x-hpack-sync"), "dynamic-value");
	EXPECT_STREQ(http2_stream_get_header(stream3, "x-hpack-sync"), "dynamic-value");
	EXPECT_FALSE(http2_ctx_is_closed(ctx));

	http2_stream_close(stream3);
	http2_stream_close(stream1);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsHeaderTableSizeEvictsResponseEncoderEntries)
{
	struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	WriteClientFrame(0x04, 0, 0, NULL, 0);
	for (int i = 0; i < 50 && http2_ctx_handshake(ctx) != 1; i++) {
		usleep(1000);
	}

	const uint8_t request_headers[] = { 0x82, 0x84, 0x86 };
	WriteClientFrame(0x01, 0x05, 1, request_headers, sizeof(request_headers));

	struct http2_stream *stream = nullptr;
	for (int i = 0; i < 50 && stream == nullptr; i++) {
		struct http2_poll_item items[4] = {};
		int count = 0;
		ASSERT_GE(http2_ctx_poll_readable(ctx, items, 4, &count), 0);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) stream = http2_ctx_accept_stream(ctx);
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
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00
	};
	WriteClientFrame(0x04, 0, 0, settings_zero, sizeof(settings_zero));
	{
		int poll_ret = http2_ctx_poll(ctx, NULL, 0, NULL);
		ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN);
	}

	http2_stream_close(stream);

	const uint8_t request_headers2[] = { 0x82, 0x84, 0x86 };
	WriteClientFrame(0x01, 0x05, 3, request_headers2, sizeof(request_headers2));

	stream = nullptr;
	for (int i = 0; i < 50 && stream == nullptr; i++) {
		struct http2_poll_item items[4] = {};
		int count = 0;
		int poll_ret = http2_ctx_poll_readable(ctx, items, 4, &count);
		ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) stream = http2_ctx_accept_stream(ctx);
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

// 通过的集成测试
TEST_F(LIBHTTP2, Integrated)
{
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

		uint8_t request_body[4096];
		int request_body_len = 0;
		while (!http2_stream_is_end(stream) && request_body_len < (int)sizeof(request_body)) {
			int read_len = http2_stream_read_body(stream, request_body + request_body_len,
												  sizeof(request_body) - request_body_len);
			if (read_len > 0) request_body_len += read_len;
			else usleep(10000);
		}

		char response[8192];
		int response_len = snprintf(response, sizeof(response), "Echo Response: %.*s", request_body_len, request_body);
		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%d", response_len);
		struct http2_header_pair headers[] = {{"content-type", "text/plain"}, {"content-length", content_length}};
		http2_stream_set_response(stream, 200, headers, 2);
		http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);

		http2_stream_close(stream);
		http2_ctx_close(ctx);
	});

	std::thread client_thread([this]() {
		usleep(500000);
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

		const char *request_body = "{\"message\":\"Hello Echo!\"}";
		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%zu", strlen(request_body));
		struct http2_header_pair headers[] = {
			{"content-type", "application/json"}, {"content-length", content_length}, {NULL, NULL}};
		http2_stream_set_request(stream, "POST", "/echo", NULL, headers);
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
		EXPECT_EQ(http2_stream_get_status(stream), 200);

		uint8_t response_body[4096];
		int response_body_len = 0;
		while (!http2_stream_is_end(stream) && response_body_len < (int)sizeof(response_body)) {
			int read_len = http2_stream_read_body(stream, response_body + response_body_len,
												  sizeof(response_body) - response_body_len);
			if (read_len > 0) response_body_len += read_len;
			else usleep(10000);
		}
		std::string resp((char *)response_body, response_body_len);
		EXPECT_NE(resp.find("Echo Response"), std::string::npos);

		http2_stream_close(stream);
		http2_ctx_close(ctx);
	});

	server_thread.join();
	client_thread.join();
}

TEST_F(LIBHTTP2, ResponseHeadersContinuation)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);

	auto write_frame = [this](uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len) {
		uint8_t frame[64] = {0};
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
	};

	write_frame(0x04, 0, 0, NULL, 0);
	for (int i = 0; i < 20 && http2_ctx_handshake(ctx) != 1; i++) usleep(1000);

	const uint8_t headers_fragment[] = {0x08};
	const uint8_t continuation_fragment[] = {0x03, '2', '0', '0'};
	write_frame(0x01, 0x01, 1, headers_fragment, sizeof(headers_fragment));
	write_frame(0x09, 0x04, 1, continuation_fragment, sizeof(continuation_fragment));

	for (int i = 0; i < 20 && http2_stream_get_status(stream) != 200; i++) {
		http2_ctx_poll(ctx, NULL, 0, NULL);
		usleep(1000);
	}
	EXPECT_EQ(http2_stream_get_status(stream), 200);
	EXPECT_TRUE(http2_stream_is_end(stream));

	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, ResponseDataFragmentsKeepStreamOpenUntilEndStream)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);

	StartClientWithServerSettings(ctx);

	const uint8_t headers[] = {
		0x08, 0x03, '2', '0', '0',
		0x0f, 0x0d, 0x01, '4'
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

TEST_F(LIBHTTP2, ResponseEndStreamBeforeContentLengthResetsStreamOnly)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);

	StartClientWithServerSettings(ctx);

	const uint8_t headers[] = {
		0x08, 0x03, '2', '0', '0',
		0x0f, 0x0d, 0x01, '4'
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

TEST_F(LIBHTTP2, PollReturnsResponseBeforeGoawayEof)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);

	auto write_frame = [this](uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len) {
		uint8_t frame[64] = {0};
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
	};

	write_frame(0x04, 0, 0, NULL, 0);
	for (int i = 0; i < 20 && http2_ctx_handshake(ctx) != 1; i++) usleep(1000);

	const uint8_t headers_fragment[] = {0x08};
	const uint8_t continuation_fragment[] = {0x03, '2', '0', '0'};
	write_frame(0x01, 0x01, 1, headers_fragment, sizeof(headers_fragment));
	write_frame(0x09, 0x04, 1, continuation_fragment, sizeof(continuation_fragment));
	const uint8_t goaway_payload[] = {0, 0, 0, 1, 0, 0, 0, 0};
	write_frame(0x07, 0, 0, goaway_payload, sizeof(goaway_payload));
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

TEST_F(LIBHTTP2, RequestHostHeaderOverridesAuthority)
{
	struct http2_ctx *client_ctx = http2_ctx_client_new("1.1.1.1", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(client_ctx, nullptr);
	struct http2_ctx *server_ctx = http2_ctx_server_new("local-server", bio_read, bio_write, &server_sock, NULL);
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
	EXPECT_STREQ(http2_stream_get_header(server_stream, ":authority"), "cloudflare-dns.com");
	EXPECT_EQ(http2_stream_get_header(server_stream, "host"), nullptr);

	http2_stream_close(server_stream);
	http2_stream_close(client_stream);
	http2_ctx_close(server_ctx);
	http2_ctx_close(client_ctx);
}

TEST_F(LIBHTTP2, HeadersInterruptedByDataFailsProtocol)
{
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

TEST_F(LIBHTTP2, DataAfterLocallyClosedStreamDoesNotFailConnection)
{
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
	EXPECT_TRUE(late_poll_ret == 0 || late_poll_ret == HTTP2_ERR_EAGAIN);

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

TEST_F(LIBHTTP2, StreamNewAfterGoawayFails)
{
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

TEST_F(LIBHTTP2, MultiStream)
{
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
					struct http2_stream *s = http2_ctx_accept_stream(ctx);
					(void)s;
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
							http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);
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
					http2_stream_read_body(stream, buf, sizeof(buf));
					if (http2_stream_is_end(stream)) {
						int id = http2_stream_get_id(stream);
						if (completed_stream_ids.find(id) == completed_stream_ids.end()) {
							completed_stream_ids.insert(id);
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

TEST_F(LIBHTTP2, EarlyStreamCreation)
{
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

		EXPECT_STREQ(http2_stream_get_method(stream), "POST");
		EXPECT_STREQ(http2_stream_get_path(stream), "/early-test");

		uint8_t request_body[4096];
		int request_body_len = 0;
		while (!http2_stream_is_end(stream) && request_body_len < (int)sizeof(request_body)) {
			int read_len = http2_stream_read_body(stream, request_body + request_body_len,
												  sizeof(request_body) - request_body_len);
			if (read_len > 0) request_body_len += read_len;
			else usleep(10000);
		}

		char response[8192];
		int response_len = snprintf(response, sizeof(response), "Echo Response: %.*s", request_body_len, request_body);
		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%d", response_len);
		struct http2_header_pair headers[] = {
			{"content-type", "text/plain"}, {"content-length", content_length}, {NULL, NULL}};
		http2_stream_set_response(stream, 200, headers, 2);
		http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);
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
			if (read_len > 0) response_body_len += read_len;
			else usleep(10000);
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

TEST_F(LIBHTTP2, ServerLoopTerminationOnDisconnect)
{
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

TEST_F(LIBHTTP2, StreamClose)
{
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
		http2_ctx_close(ctx);
	});

	server_thread.join();
	client_thread.join();
}

TEST_F(LIBHTTP2, ReferenceCountingNormal)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);

	http2_ctx_close(ctx);
	http2_stream_close(stream);
}

TEST_F(LIBHTTP2, ReferenceCountingContextError)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);

	close(client_sock);
	client_sock = -1;

	http2_ctx_close(ctx);
	http2_stream_close(stream);
}
