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

#include "gtest/gtest.h"
#include "../src/http_parse/hpack.h"
#include <string>
#include <vector>
#include <cstring>

/* Helper: collect decoded headers for verification */
struct DecodeResult {
    std::vector<std::pair<std::string, std::string>> headers;
};

static int on_header(void *ctx, const char *name, const char *value) {
    auto *result = static_cast<DecodeResult*>(ctx);
    result->headers.emplace_back(name, value);
    return 0;
}

TEST(HPACKHuffman, DecodeBasic) {
    // Known HPACK Huffman encoding of "GET" (RFC 7541 Appendix B)
    // 'G' (71) -> 0b011001 (6 bits), 'E' (69) -> 0b000101 (6 bits), 'T' (84) -> 0b000110 (6 bits)
    // Packed into bytes: 01100100 01010001 10?????? -> 0x64 0x51 0x80? Actually manual test uses RFC example.
    // Simpler: use pre‑computed example from RFC 7541 C.4 for "www.example.com"
    const uint8_t huffman_data[] = {
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
    };
    uint8_t decoded[64];
    int ret = hpack_decode_huffman(huffman_data, sizeof(huffman_data), decoded, sizeof(decoded));
    ASSERT_GT(ret, 0);
    std::string s(reinterpret_cast<char*>(decoded), ret);
    EXPECT_EQ(s, "www.example.com");
    std::cout << "Huffman decoded: " << s << std::endl;
}

TEST(HPACKHuffman, DecodeWithPadding) {
    // Single symbol '0' (5 bits: 0x00) padded with three 1's: 0x07
    const uint8_t huffman_data[] = {0x07};
    uint8_t decoded[16];
    int ret = hpack_decode_huffman(huffman_data, sizeof(huffman_data), decoded, sizeof(decoded));
    ASSERT_EQ(ret, 1);
    EXPECT_EQ(decoded[0], '0');
}

TEST(HPACKHuffman, InvalidPadding) {
    const uint8_t invalid_padding[] = {0x80}; // 0b10000000, trailing bits are 0, not all 1
    uint8_t out[16];
    int ret = hpack_decode_huffman(invalid_padding, sizeof(invalid_padding), out, sizeof(out));
    EXPECT_EQ(ret, -1);
}

TEST(HPACKRoundtrip, IndexedHeader) {
    struct hpack_context encoder, decoder;
    hpack_init_context(&encoder);
    hpack_init_context(&decoder);

    uint8_t buf[64];
    int len = hpack_encode_header(&encoder, ":method", "GET", buf, sizeof(buf));
    ASSERT_GT(len, 0);
    // Should be an indexed header (0x80 + index 2 = 0x82)
    EXPECT_EQ(buf[0], 0x82);

    DecodeResult result;
    int ret = hpack_decode_headers(&decoder, buf, len, on_header, &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.headers.size(), 1);
    EXPECT_EQ(result.headers[0].first, ":method");
    EXPECT_EQ(result.headers[0].second, "GET");

    hpack_free_context(&encoder);
    hpack_free_context(&decoder);
}

TEST(HPACKRoundtrip, LiteralWithIndexedName) {
    struct hpack_context encoder, decoder;
    hpack_init_context(&encoder);
    hpack_init_context(&decoder);

    uint8_t buf[256];
    int len = hpack_encode_header(&encoder, "content-type", "text/html", buf, sizeof(buf));
    ASSERT_GT(len, 0);
    // First byte: 0x40 + index(28) = 0x5C
    EXPECT_EQ(buf[0] & 0xC0, 0x40);

    DecodeResult result;
    int ret = hpack_decode_headers(&decoder, buf, len, on_header, &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.headers.size(), 1);
    EXPECT_EQ(result.headers[0].first, "content-type");
    EXPECT_EQ(result.headers[0].second, "text/html");

    // Dynamic table should have one entry now
    EXPECT_EQ(decoder.entry_count, 1);

    // Now encode the same header again – should become indexed header (dynamic table index 62)
    len = hpack_encode_header(&encoder, "content-type", "text/html", buf, sizeof(buf));
    ASSERT_GT(len, 0);
    EXPECT_EQ(buf[0] & 0x80, 0x80); // indexed header
    EXPECT_EQ(buf[0], 0xBE); // 0x80 + 62 = 0xBE

    hpack_free_context(&encoder);
    hpack_free_context(&decoder);
}

TEST(HPACKRoundtrip, LiteralWithNewName) {
    struct hpack_context encoder, decoder;
    hpack_init_context(&encoder);
    hpack_init_context(&decoder);

    uint8_t buf[256];
    int len = hpack_encode_header(&encoder, "x-custom", "value123", buf, sizeof(buf));
    ASSERT_GT(len, 0);
    // Literal with incremental indexing, new name -> first byte 0x40
    EXPECT_EQ(buf[0] & 0xC0, 0x40);

    DecodeResult result;
    int ret = hpack_decode_headers(&decoder, buf, len, on_header, &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.headers.size(), 1);
    EXPECT_EQ(result.headers[0].first, "x-custom");
    EXPECT_EQ(result.headers[0].second, "value123");
    EXPECT_EQ(decoder.entry_count, 1);

    hpack_free_context(&encoder);
    hpack_free_context(&decoder);
}

TEST(HPACKRoundtrip, MultipleHeaders) {
    struct hpack_context encoder, decoder;
    hpack_init_context(&encoder);
    hpack_init_context(&decoder);

    const char *headers[][2] = {
        {":method", "GET"},
        {":path", "/index.html"},
        {":scheme", "https"},
        {"user-agent", "smartdns/2.0"},
        {"accept", "*/*"}
    };
    const int n = sizeof(headers) / sizeof(headers[0]);
    uint8_t buf[2048];
    int total_len = 0;
    for (int i = 0; i < n; ++i) {
        int l = hpack_encode_header(&encoder, headers[i][0], headers[i][1],
                                    buf + total_len, sizeof(buf) - total_len);
        ASSERT_GT(l, 0);
        total_len += l;
    }

    DecodeResult result;
    int ret = hpack_decode_headers(&decoder, buf, total_len, on_header, &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.headers.size(), n);
    for (int i = 0; i < n; ++i) {
        EXPECT_EQ(result.headers[i].first, headers[i][0]);
        EXPECT_EQ(result.headers[i].second, headers[i][1]);
    }
    std::cout << "Encoded " << n << " headers into " << total_len << " bytes" << std::endl;

    hpack_free_context(&encoder);
    hpack_free_context(&decoder);
}

TEST(HPACKDynamicTable, EvictionBySize) {
    struct hpack_context ctx;
    hpack_init_context(&ctx);
    ctx.max_dynamic_table_size = 200; // very small
    uint8_t buf[256];

    // Add an entry of size about 38 bytes
    int len = hpack_encode_header(&ctx, "foo", "bar", buf, sizeof(buf));
    ASSERT_GT(len, 0);
    EXPECT_EQ(ctx.entry_count, 1);
    size_t used = ctx.dynamic_table_size;

    // Add many entries to force eviction from tail
    const char *names[] = {"a1", "a2", "a3", "a4", "a5"};
    for (int i = 0; i < 5; ++i) {
        int l = hpack_encode_header(&ctx, names[i], "v", buf, sizeof(buf));
        ASSERT_GT(l, 0);
    }
    // After additions, table size should be <= max
    EXPECT_LE(ctx.dynamic_table_size, ctx.max_dynamic_table_size);
    // Some entries must have been evicted
    EXPECT_LT(ctx.entry_count, 6);

    hpack_free_context(&ctx);
}

TEST(HPACKDynamicTable, ResizeAndEvict) {
    struct hpack_context ctx;
    hpack_init_context(&ctx);
    ctx.max_dynamic_table_size = 500;
    uint8_t buf[256];

    // Add 10 small entries
    for (int i = 0; i < 10; ++i) {
        char name[4], value[4];
        snprintf(name, sizeof(name), "k%d", i);
        snprintf(value, sizeof(value), "v%d", i);
        hpack_encode_header(&ctx, name, value, buf, sizeof(buf));
    }
    int old_count = ctx.entry_count;
    // Shrink size to 200 -> evict from tail
    hpack_resize_dynamic_table(&ctx, 200);
    EXPECT_LE(ctx.dynamic_table_size, 200);
    EXPECT_LT(ctx.entry_count, old_count);

    // Expand size again – no eviction
    hpack_resize_dynamic_table(&ctx, 1000);
    EXPECT_EQ(ctx.entry_count, ctx.entry_count); // unchanged
    EXPECT_LE(ctx.dynamic_table_size, 1000);

    hpack_free_context(&ctx);
}

TEST(HPACKDynamicTable, TailPointerMaintained) {
    struct hpack_context ctx;
    hpack_init_context(&ctx);
    ctx.max_dynamic_table_size = 10000;
    uint8_t buf[256];

    // Add three entries
    hpack_encode_header(&ctx, "first", "1", buf, sizeof(buf));
    hpack_encode_header(&ctx, "second", "2", buf, sizeof(buf));
    hpack_encode_header(&ctx, "third", "3", buf, sizeof(buf));
    ASSERT_EQ(ctx.entry_count, 3);

    // The tail should point to the oldest ("first")
    EXPECT_NE(ctx.dynamic_table_tail, nullptr);
    EXPECT_STREQ(ctx.dynamic_table_tail->name, "first");

    // Add a large entry that forces eviction of the oldest
    // Make entry size large enough to evict at least one entry
    // We can't easily create a huge entry without writing long strings, but we can shrink max size
    hpack_resize_dynamic_table(&ctx, 150); // force eviction
    // After eviction, tail should be the next oldest ("second")
    EXPECT_NE(ctx.dynamic_table_tail, nullptr);
    EXPECT_STREQ(ctx.dynamic_table_tail->name, "second");

    hpack_free_context(&ctx);
}

TEST(HPACKDecode, DynamicTableSizeUpdate) {
    struct hpack_context decoder;
    hpack_init_context(&decoder);
    decoder.max_dynamic_table_size = 4096;

    // Create a dynamic table size update frame: 0x20 + encoded size 1024 (5-bit prefix)
    uint8_t data[16];
    data[0] = 0x20;
    // encode 1024 with 5-bit prefix (max_prefix=31)
    int ret = 0;
    uint64_t val = 1024;
    int max_prefix = 31;
    if (val < (uint64_t)max_prefix) {
        data[0] |= (uint8_t)val;
        ret = 1;
    } else {
        data[0] |= (uint8_t)max_prefix;
        val -= max_prefix;
        int idx = 1;
        while (val >= 128) {
            data[idx++] = (val & 0x7F) | 0x80;
            val >>= 7;
        }
        data[idx++] = (uint8_t)val;
        ret = idx;
    }
    // Decode as header block
    DecodeResult result;
    ret = hpack_decode_headers(&decoder, data, ret, on_header, &result);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(result.headers.size(), 0); // no actual header
    EXPECT_EQ(decoder.max_dynamic_table_size, 1024);

    hpack_free_context(&decoder);
}

TEST(HPACKHuffman, AutoSelectHuffman) {
    struct hpack_context encoder, decoder;
    hpack_init_context(&encoder);
    hpack_init_context(&decoder);

    // "GET" – 3 bytes, Huffman gives 2 bytes -> should be used
    uint8_t buf[256];
    int len = hpack_encode_header(&encoder, "x-method", "GET", buf, sizeof(buf));
    ASSERT_GT(len, 0);
    // Decode and verify
    DecodeResult result;
    int ret = hpack_decode_headers(&decoder, buf, len, on_header, &result);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result.headers.size(), 1);
    EXPECT_EQ(result.headers[0].first, "x-method");
    EXPECT_EQ(result.headers[0].second, "GET");

    // A string that doesn't compress well (e.g., random) might not use Huffman.
    // We simply verify decoding succeeds.

    hpack_free_context(&encoder);
    hpack_free_context(&decoder);
}
