/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qpack.h"
#include "hpack.h"

int qpack_huffman_decode(const uint8_t *bytes, const uint8_t *bytes_max, uint8_t *decoded, size_t max_decoded,
						 size_t *nb_decoded)
{
	size_t src_len = bytes_max - bytes;
	int ret = hpack_decode_huffman(bytes, src_len, decoded, max_decoded);
	if (ret < 0) {
		return -1;
	}
	*nb_decoded = ret;
	return 0;
}

/* clang-format off */
static struct qpack_header_field _http3_static_header_table[] = {
	{.name = ":authority", .value = ""},
	{.name = ":path", .value = "/"},
	{.name = "age", .value = "0"},
	{.name = "content-disposition", .value = ""},
	{.name = "content-length", .value = "0"},
	{.name = "cookie", .value = ""},
	{.name = "date", .value = ""},
	{.name = "etag", .value = ""},
	{.name = "if-modified-since", .value = ""},
	{.name = "if-none-match", .value = ""},
	{.name = "last-modified", .value = ""},
	{.name = "link", .value = ""},
	{.name = "location", .value = ""},
	{.name = "referer", .value = ""},
	{.name = "set-cookie", .value = ""},
	{.name = ":method", .value = "CONNECT"},
	{.name = ":method", .value = "DELETE"},
	{.name = ":method", .value = "GET"},
	{.name = ":method", .value = "HEAD"},
	{.name = ":method", .value = "OPTIONS"},
	{.name = ":method", .value = "POST"},
	{.name = ":method", .value = "PUT"},
	{.name = ":scheme", .value = "http"},
	{.name = ":scheme", .value = "https"},
	{.name = ":status", .value = "103"},
	{.name = ":status", .value = "200"},
	{.name = ":status", .value = "304"},
	{.name = ":status", .value = "404"},
	{.name = ":status", .value = "503"},
	{.name = "accept", .value = "*/*"},
	{.name = "accept", .value = "application/dns-message"},
	{.name = "accept-encoding", .value = "gzip, deflate, br"},
	{.name = "accept-ranges", .value = "bytes"},
	{.name = "access-control-allow-headers", .value = "cache-control"},
	{.name = "access-control-allow-headers", .value = "content-type"},
	{.name = "access-control-allow-origin", .value = "*"},
	{.name = "cache-control", .value = "max-age=0"},
	{.name = "cache-control", .value = "max-age=2592000"},
	{.name = "cache-control", .value = "max-age=604800"},
	{.name = "cache-control", .value = "no-cache"},
	{.name = "cache-control", .value = "no-store"},
	{.name = "cache-control", .value = "public, max-age=31536000"},
	{.name = "content-encoding", .value = "br"},
	{.name = "content-encoding", .value = "gzip"},
	{.name = "content-type", .value = "application/dns-message"},
	{.name = "content-type", .value = "application/javascript"},
	{.name = "content-type", .value = "application/json"},
	{.name = "content-type", .value = "application/x-www-form-urlencoded"},
	{.name = "content-type", .value = "image/gif"},
	{.name = "content-type", .value = "image/jpeg"},
	{.name = "content-type", .value = "image/png"},
	{.name = "content-type", .value = "text/css"},
	{.name = "content-type", .value = "text/html; charset=utf-8"},
	{.name = "content-type", .value = "text/plain"},
	{.name = "content-type", .value = "text/plain;charset=utf-8"},
	{.name = "range", .value = "bytes=0-"},
	{.name = "strict-transport-security", .value = "max-age=31536000"},
	{.name = "strict-transport-security", .value = "max-age=31536000; includesubdomains"},
	{.name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload"},
	{.name = "vary", .value = "accept-encoding"},
	{.name = "vary", .value = "origin"},
	{.name = "x-content-type-options", .value = "nosniff"},
	{.name = "x-xss-protection", .value = "1; mode=block"},
	{.name = ":status", .value = "100"},
	{.name = ":status", .value = "204"},
	{.name = ":status", .value = "206"},
	{.name = ":status", .value = "302"},
	{.name = ":status", .value = "400"},
	{.name = ":status", .value = "403"},
	{.name = ":status", .value = "421"},
	{.name = ":status", .value = "425"},
	{.name = ":status", .value = "500"},
	{.name = "accept-language", .value = ""},
	{.name = "access-control-allow-credentials", .value = "FALSE"},
	{.name = "access-control-allow-credentials", .value = "TRUE"},
	{.name = "access-control-allow-headers", .value = "*"},
	{.name = "access-control-allow-methods", .value = "get"},
	{.name = "access-control-allow-methods", .value = "get, post, options"},
	{.name = "access-control-allow-methods", .value = "options"},
	{.name = "access-control-expose-headers", .value = "content-length"},
	{.name = "access-control-request-headers", .value = "content-type"},
	{.name = "access-control-request-method", .value = "get"},
	{.name = "access-control-request-method", .value = "post"},
	{.name = "alt-svc", .value = "clear"},
	{.name = "authorization", .value = ""},
	{.name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{.name = "early-data", .value = "1"},
	{.name = "expect-ct", .value = ""},
	{.name = "forwarded", .value = ""},
	{.name = "if-range", .value = ""},
	{.name = "origin", .value = ""},
	{.name = "purpose", .value = "prefetch"},
	{.name = "server", .value = ""},
	{.name = "timing-allow-origin", .value = "*"},
	{.name = "upgrade-insecure-requests", .value = "1"},
	{.name = "user-agent", .value = ""},
	{.name = "x-forwarded-for", .value = ""},
	{.name = "x-frame-options", .value = "deny"},
	{.name = "x-frame-options", .value = "sameorigin"},
};

/* clang-format on */

struct qpack_header_field *qpack_get_static_header_field(int index)
{
	int len = sizeof(_http3_static_header_table) / sizeof(_http3_static_header_table[0]);
	if (index < 0 || index >= len) {
		return NULL;
	}
	return &_http3_static_header_table[index];
}
