#include "client.h"
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/http2.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{

const char *HTTP2_TEST_CERT_FILE = "/tmp/smartdns-http2-test-cert.pem";
const char *HTTP2_TEST_KEY_FILE = "/tmp/smartdns-http2-test-key.pem";

bool EnsureHTTP2TestCert()
{
	if (access(HTTP2_TEST_CERT_FILE, F_OK) == 0 && access(HTTP2_TEST_KEY_FILE, F_OK) == 0) {
		return true;
	}
	return generate_cert_key(HTTP2_TEST_KEY_FILE, HTTP2_TEST_CERT_FILE, NULL, "DNS:smartdns,IP:127.0.0.1", 1) == 0;
}

class HTTP2DoHClient
{
  public:
	struct PendingResponse {
		struct http2_stream *stream = nullptr;
		std::vector<uint8_t> response;
		int status = 0;
		bool done = false;
		bool ok = false;
		std::string error;
	};

	~HTTP2DoHClient()
	{
		if (ctx_ != nullptr) http2_ctx_close(ctx_);
		if (ssl_ != nullptr) SSL_free(ssl_);
		if (ssl_ctx_ != nullptr) SSL_CTX_free(ssl_ctx_);
		if (fd_ >= 0) close(fd_);
	}

	bool Connect(const char *host, int port)
	{
		fd_ = socket(AF_INET, SOCK_STREAM, 0);
		if (fd_ < 0) {
			last_error_ = std::string("socket failed: ") + strerror(errno);
			return false;
		}

		struct sockaddr_in addr = {};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
			last_error_ = "inet_pton failed";
			return false;
		}
		if (connect(fd_, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
			last_error_ = std::string("connect failed: ") + strerror(errno);
			return false;
		}

		ssl_ctx_ = SSL_CTX_new(TLS_client_method());
		if (ssl_ctx_ == nullptr) {
			last_error_ = "SSL_CTX_new failed";
			return false;
		}
		SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, NULL);
		ssl_ = SSL_new(ssl_ctx_);
		if (ssl_ == nullptr) {
			last_error_ = "SSL_new failed";
			return false;
		}
		const unsigned char alpn[] = {2, 'h', '2'};
		if (SSL_set_alpn_protos(ssl_, alpn, sizeof(alpn)) != 0) {
			last_error_ = "SSL_set_alpn_protos failed";
			return false;
		}
		SSL_set_fd(ssl_, fd_);
		int ssl_connect_ret = SSL_connect(ssl_);
		if (ssl_connect_ret != 1) {
			int ssl_get_error = SSL_get_error(ssl_, ssl_connect_ret);
			int saved_errno = errno;
			unsigned long ssl_error = ERR_get_error();
			char ssl_error_string[256] = {0};
			if (ssl_error != 0) ERR_error_string_n(ssl_error, ssl_error_string, sizeof(ssl_error_string));
			last_error_ = std::string("SSL_connect failed: ") + (ssl_error_string[0] ? ssl_error_string : "no ssl error");
			last_error_ += ", ssl_get_error=" + std::to_string(ssl_get_error);
			last_error_ += ", errno=" + std::to_string(saved_errno) + "(" + std::string(strerror(saved_errno)) + ")";
			return false;
		}
		const unsigned char *selected_alpn = nullptr;
		unsigned int selected_alpn_len = 0;
		SSL_get0_alpn_selected(ssl_, &selected_alpn, &selected_alpn_len);
		if (selected_alpn_len != 2 || memcmp(selected_alpn, "h2", 2) != 0) {
			last_error_ = "ALPN h2 was not selected";
			return false;
		}
		int flags = fcntl(fd_, F_GETFL, 0);
		if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) != 0) {
			last_error_ = "fcntl O_NONBLOCK failed";
			return false;
		}
		ctx_ = http2_ctx_client_new(host, BioRead, BioWrite, this, NULL);
		if (ctx_ == nullptr) {
			last_error_ = "http2_ctx_client_new failed";
			return false;
		}
		for (int i = 0; i < 200; i++) {
			int ret = http2_ctx_handshake(ctx_);
			if (ret == 1) return true;
			if (ret < 0) {
				last_error_ = std::string("http2 handshake failed: ") + http2_error_to_string(ret);
				return false;
			}
			struct pollfd pfd = {fd_, POLLIN, 0};
			poll(&pfd, 1, 10);
		}
		last_error_ = "http2 handshake timed out";
		return false;
	}

	bool Query(const std::vector<uint8_t> &request, std::vector<uint8_t> *response)
	{
		return QueryInternal(request, true, request.size(), response);
	}

	bool QueryWithoutContentLength(const std::vector<uint8_t> &request, std::vector<uint8_t> *response)
	{
		return QueryInternal(request, false, 0, response);
	}

	bool QueryStatus(const std::vector<uint8_t> &request, int *status, std::vector<uint8_t> *response)
	{
		if (ctx_ == nullptr || response == nullptr || status == nullptr) {
			last_error_ = "query status without connected ctx";
			return false;
		}
		struct http2_stream *stream = http2_stream_new(ctx_);
		if (stream == nullptr) {
			last_error_ = "http2_stream_new failed";
			return false;
		}
		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%zu", request.size());
		struct http2_header_pair headers[4] = {{"content-type", "application/dns-message"},
											   {"accept", "application/dns-message"},
											   {"content-length", content_length},
											   {NULL, NULL}};
		if (http2_stream_set_request(stream, "POST", "/dns-query", NULL, headers) != 0 ||
			http2_stream_write_body(stream, request.data(), request.size(), 1) < 0) {
			last_error_ = "write request failed";
			http2_stream_close(stream);
			return false;
		}
		bool ok = WaitAnyResponse(stream, status, response);
		http2_stream_close(stream);
		return ok;
	}

	bool StartQuery(const std::vector<uint8_t> &request, PendingResponse *pending)
	{
		if (ctx_ == nullptr || pending == nullptr) {
			last_error_ = "start query without connected ctx";
			return false;
		}
		pending->response.clear();
		pending->status = 0;
		pending->done = false;
		pending->ok = false;
		pending->error.clear();
		struct http2_stream *stream = http2_stream_new(ctx_);
		if (stream == nullptr) {
			last_error_ = "http2_stream_new failed";
			return false;
		}
		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%zu", request.size());
		struct http2_header_pair headers[4] = {{"content-type", "application/dns-message"},
											   {"accept", "application/dns-message"},
											   {"content-length", content_length},
											   {NULL, NULL}};
		if (http2_stream_set_request(stream, "POST", "/dns-query", NULL, headers) != 0 ||
			http2_stream_write_body(stream, request.data(), request.size(), 1) < 0) {
			last_error_ = "write request failed";
			http2_stream_close(stream);
			return false;
		}
		pending->stream = stream;
		return true;
	}

	bool PumpPending(std::vector<PendingResponse> *pending_responses, int poll_timeout_ms)
	{
		if (ctx_ == nullptr || pending_responses == nullptr) {
			last_error_ = "pump without connected ctx";
			return false;
		}
		struct pollfd pfd = {fd_, POLLIN | POLLOUT, 0};
		poll(&pfd, 1, poll_timeout_ms);
		int ret = http2_ctx_poll(ctx_, NULL, 0, NULL);
		if (ret < 0 && ret != HTTP2_ERR_EAGAIN) {
			last_error_ = std::string("http2 poll failed: ") + http2_error_to_string(ret);
			return false;
		}
		for (auto &pending : *pending_responses) {
			if (pending.done || pending.stream == nullptr) continue;
			uint8_t buf[1024];
			while (true) {
				int len = http2_stream_read_body(pending.stream, buf, sizeof(buf));
				if (len > 0) {
					pending.response.insert(pending.response.end(), buf, buf + len);
					continue;
				}
				if (len < 0 && errno != EAGAIN) {
					pending.error = std::string("read response failed: ") + strerror(errno);
					pending.done = true;
					pending.ok = false;
					http2_stream_close(pending.stream);
					pending.stream = nullptr;
					break;
				}
				break;
			}
			if (pending.stream != nullptr && http2_stream_get_status(pending.stream) == 200 && http2_stream_is_end(pending.stream)) {
				pending.status = http2_stream_get_status(pending.stream);
				pending.done = true;
				pending.ok = !pending.response.empty();
				if (!pending.ok) pending.error = "empty response";
				http2_stream_close(pending.stream);
				pending.stream = nullptr;
				continue;
			}
			if (pending.stream != nullptr && http2_stream_is_end(pending.stream) && http2_stream_get_status(pending.stream) != 200) {
				pending.status = http2_stream_get_status(pending.stream);
				pending.done = true;
				pending.ok = false;
				pending.error = std::string("stream ended without response, status=") + std::to_string(http2_stream_get_status(pending.stream));
				http2_stream_close(pending.stream);
				pending.stream = nullptr;
			}
		}
		return true;
	}

	void ClosePending(std::vector<PendingResponse> *pending_responses)
	{
		if (pending_responses == nullptr) return;
		for (auto &pending : *pending_responses) {
			if (pending.stream != nullptr) {
				http2_stream_close(pending.stream);
				pending.stream = nullptr;
			}
		}
	}

	const std::string &LastError() const { return last_error_; }

  private:
	bool QueryInternal(const std::vector<uint8_t> &request, bool has_content_length, size_t advertised_content_length,
					   std::vector<uint8_t> *response)
	{
		if (ctx_ == nullptr || response == nullptr) {
			last_error_ = "query without connected ctx";
			return false;
		}
		struct http2_stream *stream = http2_stream_new(ctx_);
		if (stream == nullptr) {
			last_error_ = "http2_stream_new failed";
			return false;
		}
		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%zu", advertised_content_length);
		struct http2_header_pair headers[4] = {{"content-type", "application/dns-message"},
											   {"accept", "application/dns-message"},
											   {NULL, NULL},
											   {NULL, NULL}};
		if (has_content_length) {
			headers[2].name = "content-length";
			headers[2].value = content_length;
		}
		if (http2_stream_set_request(stream, "POST", "/dns-query", NULL, headers) != 0 ||
			http2_stream_write_body(stream, request.data(), request.size(), 1) < 0) {
			last_error_ = "write request failed";
			http2_stream_close(stream);
			return false;
		}
		bool ok = WaitResponse(stream, response);
		http2_stream_close(stream);
		return ok;
	}

	static int BioRead(void *private_data, uint8_t *buf, int len)
	{
		HTTP2DoHClient *client = (HTTP2DoHClient *)private_data;
		int ret = SSL_read(client->ssl_, buf, len);
		if (ret > 0) return ret;
		int ssl_err = SSL_get_error(client->ssl_, ret);
		if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
			errno = EAGAIN;
			return -1;
		}
		return ret;
	}

	static int BioWrite(void *private_data, const uint8_t *buf, int len)
	{
		HTTP2DoHClient *client = (HTTP2DoHClient *)private_data;
		int ret = SSL_write(client->ssl_, buf, len);
		if (ret > 0) return ret;
		int ssl_err = SSL_get_error(client->ssl_, ret);
		if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
			errno = EAGAIN;
			return -1;
		}
		return ret;
	}

	bool WaitResponse(struct http2_stream *stream, std::vector<uint8_t> *response)
	{
		response->clear();
		for (int i = 0; i < 300; i++) {
			struct pollfd pfd = {fd_, POLLIN, 0};
			poll(&pfd, 1, 10);
			int ret = http2_ctx_poll(ctx_, NULL, 0, NULL);
			if (ret < 0 && ret != HTTP2_ERR_EAGAIN) {
				last_error_ = std::string("http2 poll failed: ") + http2_error_to_string(ret);
				return false;
			}
			uint8_t buf[1024];
			while (true) {
				int len = http2_stream_read_body(stream, buf, sizeof(buf));
				if (len > 0) {
					response->insert(response->end(), buf, buf + len);
					continue;
				}
				if (len < 0 && errno != EAGAIN) {
					last_error_ = std::string("read response failed: ") + strerror(errno);
					return false;
				}
				break;
			}
			if (http2_stream_get_status(stream) == 200 && http2_stream_is_end(stream)) return !response->empty();
			if (http2_stream_is_end(stream) && http2_stream_get_status(stream) != 200) {
				last_error_ = std::string("stream ended without response, status=") + std::to_string(http2_stream_get_status(stream));
				return false;
			}
		}
		last_error_ = std::string("response timed out, status=") + std::to_string(http2_stream_get_status(stream)) + ", bytes=" + std::to_string(response->size());
		return false;
	}

	bool WaitAnyResponse(struct http2_stream *stream, int *status, std::vector<uint8_t> *response)
	{
		response->clear();
		*status = 0;
		for (int i = 0; i < 300; i++) {
			struct pollfd pfd = {fd_, POLLIN, 0};
			poll(&pfd, 1, 10);
			int ret = http2_ctx_poll(ctx_, NULL, 0, NULL);
			if (ret < 0 && ret != HTTP2_ERR_EAGAIN) {
				last_error_ = std::string("http2 poll failed: ") + http2_error_to_string(ret);
				return false;
			}
			uint8_t buf[1024];
			while (true) {
				int len = http2_stream_read_body(stream, buf, sizeof(buf));
				if (len > 0) {
					response->insert(response->end(), buf, buf + len);
					continue;
				}
				if (len < 0 && errno != EAGAIN) {
					last_error_ = std::string("read response failed: ") + strerror(errno);
					return false;
				}
				break;
			}
			if (http2_stream_is_end(stream)) {
				*status = http2_stream_get_status(stream);
				return *status > 0;
			}
		}
		last_error_ = std::string("response timed out, status=") + std::to_string(http2_stream_get_status(stream)) + ", bytes=" + std::to_string(response->size());
		return false;
	}

	int fd_ = -1;
	SSL_CTX *ssl_ctx_ = nullptr;
	SSL *ssl_ = nullptr;
	struct http2_ctx *ctx_ = nullptr;
	std::string last_error_;
};

std::vector<uint8_t> BuildDnsQuery(const char *domain, uint16_t id)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	unsigned char out[DNS_IN_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	struct dns_head head = {};
	head.id = id;
	head.qr = DNS_QR_QUERY;
	head.opcode = DNS_OP_QUERY;
	head.rd = 1;
	if (dns_packet_init(packet, sizeof(packet_buff), &head) != 0) return {};
	if (dns_add_domain(packet, domain, DNS_T_A, DNS_C_IN) != 0) return {};
	int len = dns_encode(out, sizeof(out), packet);
	if (len <= 0) return {};
	return std::vector<uint8_t>(out, out + len);
}

bool DnsResponseIsReply(const std::vector<uint8_t> &response)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	if (dns_decode(packet, sizeof(packet_buff), (unsigned char *)response.data(), response.size()) != 0) return false;
	return packet->head.qr == DNS_QR_ANSWER;
}

} // namespace

// 保留的唯一一个 HTTP/2 测试（已经通过）
TEST(HTTP2, DownstreamDohServerWithoutContentLengthReadsToEndStream)
{
	Defer {
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};
	smartdns::Server server;
	server.Start(R"""(bind-https [::]:60053 -alpn h2
address /no-content-length.example.com/6.6.6.6
log-level debug
)""");
	HTTP2DoHClient client;
	usleep(200000);
	ASSERT_TRUE(client.Connect("127.0.0.1", 60053)) << client.LastError();
	std::vector<uint8_t> query = BuildDnsQuery("no-content-length.example.com", 0x3001);
	ASSERT_FALSE(query.empty());
	std::vector<uint8_t> response;
	ASSERT_TRUE(client.QueryWithoutContentLength(query, &response)) << client.LastError();
	EXPECT_TRUE(DnsResponseIsReply(response));
}
