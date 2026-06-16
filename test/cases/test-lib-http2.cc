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

	// Helper to flush pending writes
	static void flush_http2_writes(struct http2_ctx *ctx, int max_retries = 100)
	{
		while (http2_ctx_want_write(ctx) && max_retries-- > 0) {
			if (http2_ctx_poll(ctx, NULL, 0, NULL) < 0) {
				break;
			}
			usleep(1000);
		}
	}
};

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
			if (poll_ret == 0) {
				continue;
			}
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
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
					if (stream)
						break;
				}
			}
			usleep(20000);
		}
		if (!stream) {
			std::cout << "Server failed to accept stream after timeout" << std::endl;
		}
		ASSERT_NE(stream, nullptr) << "Server failed to accept stream";

		uint8_t request_body[4096];
		int request_body_len = 0;
		while (!http2_stream_is_end(stream) && request_body_len < (int)sizeof(request_body)) {
			int read_len = http2_stream_read_body(stream, request_body + request_body_len,
												  sizeof(request_body) - request_body_len);
			if (read_len <= 0) {
				http2_ctx_poll(ctx, NULL, 0, NULL);
				if (read_len == 0 && http2_stream_is_remote_end(stream)) {
					break;
				}
				usleep(1000);
				continue;
			}
			request_body_len += read_len;
		}

		char response[8192];
		int response_len = snprintf(response, sizeof(response), "Echo Response: %.*s", request_body_len, request_body);
		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%d", response_len);
		struct http2_header_pair headers[] = {{"content-type", "text/plain"}, {"content-length", content_length}};
		http2_stream_set_response(stream, 200, headers, 2);
		http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);

		flush_http2_writes(ctx);
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
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Client handshake failed";

		struct http2_stream *stream = http2_stream_new(ctx);
		ASSERT_NE(stream, nullptr);

		struct http2_header_pair headers[] = {
			{"content-type", "application/json"}, {"content-length", "27"}, {NULL, NULL}};
		http2_stream_set_request(stream, "POST", "/echo", NULL, headers);
		const char *request_body = "{\"message\":\"Hello Echo!\"}";
		http2_stream_write_body(stream, (const uint8_t *)request_body, strlen(request_body), 1);

		// Flush request data to server
		flush_http2_writes(ctx);

		int max_attempts = 200;
		while (max_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 100);

			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
			if (http2_stream_get_status(stream) > 0)
				break;

			usleep(20000);
		}

		EXPECT_EQ(http2_stream_get_status(stream), 200);

		uint8_t response_body[4096];
		int response_body_len = 0;
		while (!http2_stream_is_end(stream) && response_body_len < (int)sizeof(response_body)) {
			int read_len = http2_stream_read_body(stream, response_body + response_body_len,
												  sizeof(response_body) - response_body_len);
			if (read_len <= 0) {
				http2_ctx_poll(ctx, NULL, 0, NULL);
				if (read_len == 0 && http2_stream_is_remote_end(stream)) {
					break;
				}
				usleep(1000);
				continue;
			}
			response_body_len += read_len;
		}

		std::string resp((char *)response_body, response_body_len);
		EXPECT_NE(resp.find("Echo Response"), std::string::npos);

		http2_stream_close(stream);
		http2_ctx_close(ctx);
	});

	server_thread.join();
	client_thread.join();
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
							http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);
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

		// Flush all pending writes
		flush_http2_writes(ctx);

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
			if (poll_ret == 0) {
				continue;
			}
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
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
					if (stream)
						break;
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
				if (read_len == 0 && http2_stream_is_remote_end(stream)) {
					break;
				}
				usleep(1000);
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
		http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);
		flush_http2_writes(ctx);
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
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Client handshake failed";

		// Flush the request data after handshake
		flush_http2_writes(ctx);

		int max_attempts = 200;
		while (max_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 100);

			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
			if (http2_stream_get_status(stream) > 0)
				break;

			usleep(20000);
		}

		EXPECT_EQ(http2_stream_get_status(stream), 200);

		uint8_t response_body[4096];
		int response_body_len = 0;
		while (!http2_stream_is_end(stream) && response_body_len < (int)sizeof(response_body)) {
			int read_len = http2_stream_read_body(stream, response_body + response_body_len,
												  sizeof(response_body) - response_body_len);
			if (read_len <= 0) {
				http2_ctx_poll(ctx, NULL, 0, NULL);
				if (read_len == 0 && http2_stream_is_remote_end(stream)) {
					break;
				}
				usleep(1000);
				continue;
			}
			response_body_len += read_len;
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
			if (poll_ret == 0) {
				continue;
			}
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
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
					if (stream)
						break;
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
					if (ret > 0) {
						data_read = 1;
					} else if (ret == 0) {
						data_read = 1;
					}
				}
				if (items[i].stream) {
					http2_stream_put(items[i].stream);
				}
			}

			if (!data_read && http2_stream_is_end(stream)) {
				break;
			}
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
			if (ret != 0) {
				break;
			}
		}
		ASSERT_EQ(ret, 1);

		struct http2_stream *stream = http2_stream_new(ctx);
		ASSERT_NE(stream, nullptr);

		struct http2_header_pair headers[] = {{"content-type", "text/plain"}, {NULL, NULL}};
		http2_stream_set_request(stream, "POST", "/test", NULL, headers);
		http2_stream_write_body(stream, (const uint8_t *)"test", 4, 1);
		flush_http2_writes(ctx);
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
			if (poll_ret == 0) {
				continue;
			}
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
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
					if (stream)
						break;
				}
			}
			usleep(20000);
		}
		ASSERT_NE(stream, nullptr) << "Server failed to accept stream";

		uint8_t buf[1024];
		http2_stream_read_body(stream, buf, sizeof(buf));
		http2_stream_set_response(stream, 200, NULL, 0);
		http2_stream_write_body(stream, (const uint8_t *)"OK", 2, 1);

		flush_http2_writes(ctx);
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
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Client handshake failed";

		struct http2_stream *stream = http2_stream_new(ctx);
		ASSERT_NE(stream, nullptr);

		http2_stream_set_request(stream, "GET", "/test", NULL, NULL);
		http2_stream_write_body(stream, NULL, 0, 1);

		flush_http2_writes(ctx);

		int max_attempts = 200;
		while (max_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 100);
			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
			if (http2_stream_get_status(stream) > 0)
				break;
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
			if (read_len <= 0) {
				break;
			}
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

TEST_F(LIBHTTP2, StressTest)
{
	const int NUM_STREAMS = 1024;
	std::atomic<int> server_processed(0);
	std::atomic<int> client_completed(0);
	std::atomic<bool> test_completed(false);

	std::thread server_thread([this, NUM_STREAMS, &server_processed, &test_completed]() {
		struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		auto start_time = std::chrono::steady_clock::now();
		int ret = 0;
		while (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			int poll_ret = poll(&pfd, 1, 10);
			if (poll_ret == 0) {
				continue;
			}
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Server handshake failed";

		std::vector<struct http2_stream *> streams;
		start_time = std::chrono::steady_clock::now();
		while (!test_completed && std::chrono::steady_clock::now() - start_time < std::chrono::seconds(30)) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			poll(&pfd, 1, 10);

			struct http2_poll_item items[64];
			int count = 0;
			http2_ctx_poll(ctx, items, 64, &count);

			for (int i = 0; i < count; i++) {
				if (items[i].stream == nullptr && items[i].readable) {
					struct http2_stream *stream = http2_ctx_accept_stream(ctx);
					if (stream) {
						streams.push_back(stream);
					}
				} else if (items[i].stream && items[i].readable) {
					struct http2_stream *stream = items[i].stream;
					uint8_t buf[1024];
					while (http2_stream_read_body(stream, buf, sizeof(buf)) > 0)
						;

					if (http2_stream_is_end(stream)) {
						char response[256];
						int response_len = snprintf(response, sizeof(response), "Echo %d", http2_stream_get_id(stream));
						char content_length[32];
						snprintf(content_length, sizeof(content_length), "%d", response_len);
						struct http2_header_pair headers[] = {{"content-type", "text/plain"},
															  {"content-length", content_length}};
						http2_stream_set_response(stream, 200, headers, 2);
						http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);
						server_processed++;
					}
				}
				if (items[i].stream) {
					http2_stream_put(items[i].stream);
				}
			}
		}

		for (auto stream : streams) {
			http2_stream_close(stream);
		}
		http2_ctx_close(ctx);
	});

	std::thread client_thread([this, NUM_STREAMS, &client_completed, &test_completed]() {
		usleep(50000);
		struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		auto start_time = std::chrono::steady_clock::now();
		int ret = 0;
		while (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 10);
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Client handshake failed";

		std::vector<struct http2_stream *> streams;
		streams.reserve(NUM_STREAMS);
		std::set<int> completed_ids;

		auto process_events = [&](int timeout_ms) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, timeout_ms);

			struct http2_poll_item items[64];
			int count = 0;
			http2_ctx_poll(ctx, items, 64, &count);

			for (int i = 0; i < count; i++) {
				if (items[i].stream && items[i].readable) {
					struct http2_stream *stream = items[i].stream;
					uint8_t buf[1024];
					while (http2_stream_read_body(stream, buf, sizeof(buf)) > 0)
						;

					if (http2_stream_is_end(stream)) {
						int id = http2_stream_get_id(stream);
						if (completed_ids.find(id) == completed_ids.end()) {
							completed_ids.insert(id);
							client_completed++;
						}
					}
				}
				if (items[i].stream) {
					http2_stream_put(items[i].stream);
				}
			}
		};

		for (int i = 0; i < NUM_STREAMS; i++) {
			struct http2_stream *stream = http2_stream_new(ctx);
			if (stream) {
				streams.push_back(stream);
				char path[64];
				snprintf(path, sizeof(path), "/stream%d", i);
				char body[64];
				int body_len = snprintf(body, sizeof(body), "Req %d", i);

				struct http2_header_pair headers[] = {{"content-type", "text/plain"}, {NULL, NULL}};
				http2_stream_set_request(stream, "POST", path, NULL, headers);
				http2_stream_write_body(stream, (const uint8_t *)body, body_len, 1);
			}

			if (i % 10 == 0) {
				process_events(0);
			}
		}
		ASSERT_EQ(streams.size(), NUM_STREAMS);

		// Flush all requests
		flush_http2_writes(ctx);

		start_time = std::chrono::steady_clock::now();
		while (client_completed < NUM_STREAMS &&
			   std::chrono::steady_clock::now() - start_time < std::chrono::seconds(30)) {
			process_events(10);
		}

		EXPECT_EQ(client_completed, NUM_STREAMS);

		for (auto stream : streams) {
			http2_stream_close(stream);
		}
		http2_ctx_close(ctx);
		test_completed = true;
	});

	server_thread.join();
	client_thread.join();
}
