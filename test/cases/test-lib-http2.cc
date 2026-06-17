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

#include "smartdns/http2.h"

class LIBHTTP2 : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// Create socketpair for communication
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) < 0) {
			perror("socketpair");
			FAIL() << "Failed to create socketpair";
		}

		client_sock = socks[0];
		server_sock = socks[1];

		// Set non-blocking
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

	// BIO callbacks
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
};

// ========== 原有测试用例（保持不变） ==========

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
			if (ret == 1)
				break;
			if (ret < 0)
				break;
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
							// 循环发送数据确保完整
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
							http2_stream_write_body(stream, NULL, 0, 1); // END_STREAM
							streams_completed++;
							processed_streams.insert(stream);
						}
					}
				}
			}
			usleep(2000);
		}

		for (auto stream : processed_streams) {
			http2_stream_close(stream);
		}
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
			if (ret == 1)
				break;
			if (ret < 0)
				break;
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

		for (int i = 0; i < NUM_STREAMS; i++) {
			http2_stream_close(streams[i]);
		}
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
		// 循环发送数据
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
		http2_stream_write_body(stream, NULL, 0, 1); // END_STREAM

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
		EXPECT_EQ(ret, 0) << "Failed to set request";
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
		EXPECT_LT(loop_count, 100) << "Server loop did not terminate (infinite loop detected)";
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

// ========== 新增测试：基本 POST 回显 ==========
TEST_F(LIBHTTP2, BasicPOSTEcho)
{
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

		// 循环发送数据
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
		http2_stream_write_body(stream, NULL, 0, 1); // END_STREAM

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

// ========== 高并发测试：1024 个并发 POST 流 ==========
TEST_F(LIBHTTP2, HighConcurrencyPOSTEcho)
{
	const int NUM_STREAMS = 1024;
	const int BODY_SIZE = 64;
	const int MAX_ITERATIONS = 3000;  // 增加迭代次数确保完成
	const int POLL_ITEMS = 256;       // 增加每次 poll 返回的项数

	std::atomic<int> server_completed{0};
	std::atomic<int> client_completed{0};
	std::atomic<bool> server_error{false};
	std::atomic<bool> client_error{false};

	// ---- 服务器 ----
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
					// Accept new stream; will be handled later
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
							// 循环发送数据
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
								http2_stream_write_body(stream, NULL, 0, 1); // END_STREAM
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

	// ---- 客户端 ----
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
			// 发送请求体（一次性发送，小数据应该可以）
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
		// 验证所有响应匹配
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
