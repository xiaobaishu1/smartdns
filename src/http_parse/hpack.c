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

#include "hpack.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* HPACK Huffman decoding table based on RFC 7541 Appendix B */
/* Each entry contains: symbol, code length in bits */
struct huffman_decode_entry {
	uint32_t bits;
	uint8_t nbits;
	uint16_t symbol;
};

/* HPACK static table (RFC 7541 Appendix A) */
struct hpack_static_entry {
	const char *name;
	const char *value;
};

/* Huffman encoding table: maps symbol (0-255) to {code, nbits} */
struct huffman_encoding_entry {
	uint32_t code;
	uint8_t nbits;
};

typedef struct {
	uint16_t symbol;
	uint8_t nbits;
	uint8_t need_more;
} huffman_fast_entry_t;

/* Build Huffman tree nodes for fallback decoding (long codes > 12 bits) */
typedef struct huffman_tree_node {
	uint16_t symbol;
	uint8_t nbits;      /* only valid for leaf nodes; otherwise 0 */
	struct huffman_tree_node *left;
	struct huffman_tree_node *right;
} huffman_tree_node_t;

/* clang-format off */

static const struct hpack_static_entry hpack_static_table[] = {
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""}
};

/* Complete Huffman decoding table for HPACK (RFC 7541 Appendix B) */

static const struct huffman_decode_entry huffman_table[] = {
	{0x00, 5, '0'},      /*  48 */
	{0x01, 5, '1'},      /*  49 */
	{0x02, 5, '2'},      /*  50 */
	{0x03, 5, 'a'},      /*  97 */
	{0x04, 5, 'c'},      /*  99 */
	{0x05, 5, 'e'},      /* 101 */
	{0x06, 5, 'i'},      /* 105 */
	{0x07, 5, 'o'},      /* 111 */
	{0x08, 5, 's'},      /* 115 */
	{0x09, 5, 't'},      /* 116 */
	{0x14, 6, ' '},      /*  32 */
	{0x15, 6, '%'},      /*  37 */
	{0x16, 6, '-'},      /*  45 */
	{0x17, 6, '.'},      /*  46 */
	{0x18, 6, '/'},      /*  47 */
	{0x19, 6, '3'},      /*  51 */
	{0x1a, 6, '4'},      /*  52 */
	{0x1b, 6, '5'},      /*  53 */
	{0x1c, 6, '6'},      /*  54 */
	{0x1d, 6, '7'},      /*  55 */
	{0x1e, 6, '8'},      /*  56 */
	{0x1f, 6, '9'},      /*  57 */
	{0x20, 6, '='},      /*  61 */
	{0x21, 6, 'A'},      /*  65 */
	{0x22, 6, '_'},      /*  95 */
	{0x23, 6, 'b'},      /*  98 */
	{0x24, 6, 'd'},      /* 100 */
	{0x25, 6, 'f'},      /* 102 */
	{0x26, 6, 'g'},      /* 103 */
	{0x27, 6, 'h'},      /* 104 */
	{0x28, 6, 'l'},      /* 108 */
	{0x29, 6, 'm'},      /* 109 */
	{0x2a, 6, 'n'},      /* 110 */
	{0x2b, 6, 'p'},      /* 112 */
	{0x2c, 6, 'r'},      /* 114 */
	{0x2d, 6, 'u'},      /* 117 */
	{0x5c, 7, ':'},      /*  58 */
	{0x5d, 7, 'B'},      /*  66 */
	{0x5e, 7, 'C'},      /*  67 */
	{0x5f, 7, 'D'},      /*  68 */
	{0x60, 7, 'E'},      /*  69 */
	{0x61, 7, 'F'},      /*  70 */
	{0x62, 7, 'G'},      /*  71 */
	{0x63, 7, 'H'},      /*  72 */
	{0x64, 7, 'I'},      /*  73 */
	{0x65, 7, 'J'},      /*  74 */
	{0x66, 7, 'K'},      /*  75 */
	{0x67, 7, 'L'},      /*  76 */
	{0x68, 7, 'M'},      /*  77 */
	{0x69, 7, 'N'},      /*  78 */
	{0x6a, 7, 'O'},      /*  79 */
	{0x6b, 7, 'P'},      /*  80 */
	{0x6c, 7, 'Q'},      /*  81 */
	{0x6d, 7, 'R'},      /*  82 */
	{0x6e, 7, 'S'},      /*  83 */
	{0x6f, 7, 'T'},      /*  84 */
	{0x70, 7, 'U'},      /*  85 */
	{0x71, 7, 'V'},      /*  86 */
	{0x72, 7, 'W'},      /*  87 */
	{0x73, 7, 'Y'},      /*  89 */
	{0x74, 7, 'j'},      /* 106 */
	{0x75, 7, 'k'},      /* 107 */
	{0x76, 7, 'q'},      /* 113 */
	{0x77, 7, 'v'},      /* 118 */
	{0x78, 7, 'w'},      /* 119 */
	{0x79, 7, 'x'},      /* 120 */
	{0x7a, 7, 'y'},      /* 121 */
	{0x7b, 7, 'z'},      /* 122 */
	{0xf8, 8, '&'},      /*  38 */
	{0xf9, 8, '*'},      /*  42 */
	{0xfa, 8, ','},      /*  44 */
	{0xfb, 8, ';'},      /*  59 */
	{0xfc, 8, 'X'},      /*  88 */
	{0xfd, 8, 'Z'},      /*  90 */
	{0x3f8, 10, '!'},    /*  33 */
	{0x3f9, 10, '"'},    /*  34 */
	{0x3fa, 10, '('},    /*  40 */
	{0x3fb, 10, ')'},    /*  41 */
	{0x3fc, 10, '?'},    /*  63 */
	{0x7fa, 11, '\''},   /*  39 */
	{0x7fb, 11, '+'},    /*  43 */
	{0x7fc, 11, '|'},    /* 124 */
	{0xffa, 12, '#'},    /*  35 */
	{0xffb, 12, '>'},    /*  62 */
	{0x1ff8, 13, 0x00},  /*   0 */
	{0x1ff9, 13, '$'},   /*  36 */
	{0x1ffa, 13, '@'},   /*  64 */
	{0x1ffb, 13, '['},   /*  91 */
	{0x1ffc, 13, ']'},   /*  93 */
	{0x1ffd, 13, '~'},   /* 126 */
	{0x3ffc, 14, '^'},   /*  94 */
	{0x3ffd, 14, '}'},   /* 125 */
	{0x7ffc, 15, '<'},   /*  60 */
	{0x7ffd, 15, '`'},   /*  96 */
	{0x7ffe, 15, '{'},   /* 123 */
	{0x7fff0, 19, '\\'}, /*  92 */
	{0x7fff1, 19, 0xc3}, /* 195 */
	{0x7fff2, 19, 0xd0}, /* 208 */
	{0xfffe6, 20, 0x80}, /* 128 */
	{0xfffe7, 20, 0x82}, /* 130 */
	{0xfffe8, 20, 0x83}, /* 131 */
	{0xfffe9, 20, 0xa2}, /* 162 */
	{0xfffea, 20, 0xb8}, /* 184 */
	{0xfffeb, 20, 0xc2}, /* 194 */
	{0xfffec, 20, 0xe0}, /* 224 */
	{0xfffed, 20, 0xe2}, /* 226 */
	{0x1fffdc, 21, 0x99}, /* 153 */
	{0x1fffdd, 21, 0xa1}, /* 161 */
	{0x1fffde, 21, 0xa7}, /* 167 */
	{0x1fffdf, 21, 0xac}, /* 172 */
	{0x1fffe0, 21, 0xb0}, /* 176 */
	{0x1fffe1, 21, 0xb1}, /* 177 */
	{0x1fffe2, 21, 0xb3}, /* 179 */
	{0x1fffe3, 21, 0xd1}, /* 209 */
	{0x1fffe4, 21, 0xd8}, /* 216 */
	{0x1fffe5, 21, 0xd9}, /* 217 */
	{0x1fffe6, 21, 0xe3}, /* 227 */
	{0x1fffe7, 21, 0xe5}, /* 229 */
	{0x1fffe8, 21, 0xe6}, /* 230 */
	{0x3fffd2, 22, 0x81}, /* 129 */
	{0x3fffd3, 22, 0x84}, /* 132 */
	{0x3fffd4, 22, 0x85}, /* 133 */
	{0x3fffd5, 22, 0x86}, /* 134 */
	{0x3fffd6, 22, 0x88}, /* 136 */
	{0x3fffd7, 22, 0x92}, /* 146 */
	{0x3fffd8, 22, 0x9a}, /* 154 */
	{0x3fffd9, 22, 0x9c}, /* 156 */
	{0x3fffda, 22, 0xa0}, /* 160 */
	{0x3fffdb, 22, 0xa3}, /* 163 */
	{0x3fffdc, 22, 0xa4}, /* 164 */
	{0x3fffdd, 22, 0xa9}, /* 169 */
	{0x3fffde, 22, 0xaa}, /* 170 */
	{0x3fffdf, 22, 0xad}, /* 173 */
	{0x3fffe0, 22, 0xb2}, /* 178 */
	{0x3fffe1, 22, 0xb5}, /* 181 */
	{0x3fffe2, 22, 0xb9}, /* 185 */
	{0x3fffe3, 22, 0xba}, /* 186 */
	{0x3fffe4, 22, 0xbb}, /* 187 */
	{0x3fffe5, 22, 0xbd}, /* 189 */
	{0x3fffe6, 22, 0xbe}, /* 190 */
	{0x3fffe7, 22, 0xc4}, /* 196 */
	{0x3fffe8, 22, 0xc6}, /* 198 */
	{0x3fffe9, 22, 0xe4}, /* 228 */
	{0x3fffea, 22, 0xe8}, /* 232 */
	{0x3fffeb, 22, 0xe9}, /* 233 */
	{0x7fffd8, 23, 0x01}, /*   1 */
	{0x7fffd9, 23, 0x87}, /* 135 */
	{0x7fffda, 23, 0x89}, /* 137 */
	{0x7fffdb, 23, 0x8a}, /* 138 */
	{0x7fffdc, 23, 0x8b}, /* 139 */
	{0x7fffdd, 23, 0x8c}, /* 140 */
	{0x7fffde, 23, 0x8d}, /* 141 */
	{0x7fffdf, 23, 0x8f}, /* 143 */
	{0x7fffe0, 23, 0x93}, /* 147 */
	{0x7fffe1, 23, 0x95}, /* 149 */
	{0x7fffe2, 23, 0x96}, /* 150 */
	{0x7fffe3, 23, 0x97}, /* 151 */
	{0x7fffe4, 23, 0x98}, /* 152 */
	{0x7fffe5, 23, 0x9b}, /* 155 */
	{0x7fffe6, 23, 0x9d}, /* 157 */
	{0x7fffe7, 23, 0x9e}, /* 158 */
	{0x7fffe8, 23, 0xa5}, /* 165 */
	{0x7fffe9, 23, 0xa6}, /* 166 */
	{0x7fffea, 23, 0xa8}, /* 168 */
	{0x7fffeb, 23, 0xae}, /* 174 */
	{0x7fffec, 23, 0xaf}, /* 175 */
	{0x7fffed, 23, 0xb4}, /* 180 */
	{0x7fffee, 23, 0xb6}, /* 182 */
	{0x7fffef, 23, 0xb7}, /* 183 */
	{0x7ffff0, 23, 0xbc}, /* 188 */
	{0x7ffff1, 23, 0xbf}, /* 191 */
	{0x7ffff2, 23, 0xc5}, /* 197 */
	{0x7ffff3, 23, 0xe7}, /* 231 */
	{0x7ffff4, 23, 0xef}, /* 239 */
	{0xffffea, 24, 0x09}, /*   9 */
	{0xffffeb, 24, 0x8e}, /* 142 */
	{0xffffec, 24, 0x90}, /* 144 */
	{0xffffed, 24, 0x91}, /* 145 */
	{0xffffee, 24, 0x94}, /* 148 */
	{0xffffef, 24, 0x9f}, /* 159 */
	{0xfffff0, 24, 0xab}, /* 171 */
	{0xfffff1, 24, 0xce}, /* 206 */
	{0xfffff2, 24, 0xd7}, /* 215 */
	{0xfffff3, 24, 0xe1}, /* 225 */
	{0xfffff4, 24, 0xec}, /* 236 */
	{0xfffff5, 24, 0xed}, /* 237 */
	{0x1ffffec, 25, 0xc7}, /* 199 */
	{0x1ffffed, 25, 0xcf}, /* 207 */
	{0x1ffffee, 25, 0xea}, /* 234 */
	{0x1ffffef, 25, 0xeb}, /* 235 */
	{0x3ffffe0, 26, 0xc0}, /* 192 */
	{0x3ffffe1, 26, 0xc1}, /* 193 */
	{0x3ffffe2, 26, 0xc8}, /* 200 */
	{0x3ffffe3, 26, 0xc9}, /* 201 */
	{0x3ffffe4, 26, 0xca}, /* 202 */
	{0x3ffffe5, 26, 0xcd}, /* 205 */
	{0x3ffffe6, 26, 0xd2}, /* 210 */
	{0x3ffffe7, 26, 0xd5}, /* 213 */
	{0x3ffffe8, 26, 0xda}, /* 218 */
	{0x3ffffe9, 26, 0xdb}, /* 219 */
	{0x3ffffea, 26, 0xee}, /* 238 */
	{0x3ffffeb, 26, 0xf0}, /* 240 */
	{0x3ffffec, 26, 0xf2}, /* 242 */
	{0x3ffffed, 26, 0xf3}, /* 243 */
	{0x3ffffee, 26, 0xff}, /* 255 */
	{0x7ffffde, 27, 0xcb}, /* 203 */
	{0x7ffffdf, 27, 0xcc}, /* 204 */
	{0x7ffffe0, 27, 0xd3}, /* 211 */
	{0x7ffffe1, 27, 0xd4}, /* 212 */
	{0x7ffffe2, 27, 0xd6}, /* 214 */
	{0x7ffffe3, 27, 0xdd}, /* 221 */
	{0x7ffffe4, 27, 0xde}, /* 222 */
	{0x7ffffe5, 27, 0xdf}, /* 223 */
	{0x7ffffe6, 27, 0xf1}, /* 241 */
	{0x7ffffe7, 27, 0xf4}, /* 244 */
	{0x7ffffe8, 27, 0xf5}, /* 245 */
	{0x7ffffe9, 27, 0xf6}, /* 246 */
	{0x7ffffea, 27, 0xf7}, /* 247 */
	{0x7ffffeb, 27, 0xf8}, /* 248 */
	{0x7ffffec, 27, 0xfa}, /* 250 */
	{0x7ffffed, 27, 0xfb}, /* 251 */
	{0x7ffffee, 27, 0xfc}, /* 252 */
	{0x7ffffef, 27, 0xfd}, /* 253 */
	{0x7fffff0, 27, 0xfe}, /* 254 */
	{0xfffffe2, 28, 0x02}, /*   2 */
	{0xfffffe3, 28, 0x03}, /*   3 */
	{0xfffffe4, 28, 0x04}, /*   4 */
	{0xfffffe5, 28, 0x05}, /*   5 */
	{0xfffffe6, 28, 0x06}, /*   6 */
	{0xfffffe7, 28, 0x07}, /*   7 */
	{0xfffffe8, 28, 0x08}, /*   8 */
	{0xfffffe9, 28, 0x0b}, /*  11 */
	{0xfffffea, 28, 0x0c}, /*  12 */
	{0xfffffeb, 28, 0x0e}, /*  14 */
	{0xfffffec, 28, 0x0f}, /*  15 */
	{0xfffffed, 28, 0x10}, /*  16 */
	{0xfffffee, 28, 0x11}, /*  17 */
	{0xfffffef, 28, 0x12}, /*  18 */
	{0xffffff0, 28, 0x13}, /*  19 */
	{0xffffff1, 28, 0x14}, /*  20 */
	{0xffffff2, 28, 0x15}, /*  21 */
	{0xffffff3, 28, 0x17}, /*  23 */
	{0xffffff4, 28, 0x18}, /*  24 */
	{0xffffff5, 28, 0x19}, /*  25 */
	{0xffffff6, 28, 0x1a}, /*  26 */
	{0xffffff7, 28, 0x1b}, /*  27 */
	{0xffffff8, 28, 0x1c}, /*  28 */
	{0xffffff9, 28, 0x1d}, /*  29 */
	{0xffffffa, 28, 0x1e}, /*  30 */
	{0xffffffb, 28, 0x1f}, /*  31 */
	{0xffffffc, 28, 0x7f}, /* 127 */
	{0xffffffd, 28, 0xdc}, /* 220 */
	{0xffffffe, 28, 0xf9}, /* 249 */
	{0x3ffffffc, 30, 0x0a}, /*  10 */
	{0x3ffffffd, 30, 0x0d}, /*  13 */
	{0x3ffffffe, 30, 0x16}, /*  22 */
	{0x3fffffff, 30, 0x100} /* 256 (EOS) */
};

/* HPACK integer encoding/decoding */

static int hpack_encode_integer(uint64_t value, int prefix_bits, uint8_t *buf, int buf_size)
{
	int max_prefix = (1 << prefix_bits) - 1;
	int offset = 0;

	if (value < (uint64_t)max_prefix) {
		if (buf_size < 1) {
			return -1;
		}
		buf[0] |= (uint8_t)value;
		return 1;
	}

	if (buf_size < 1) {
		return -1;
	}
	buf[offset++] |= (uint8_t)max_prefix;
	value -= max_prefix;

	while (value >= 128) {
		if (offset >= buf_size) {
			return -1;
		}
		buf[offset++] = (uint8_t)((value & 0x7F) | 0x80);
		value >>= 7;
	}

	if (offset >= buf_size) {
		return -1;
	}
	buf[offset++] = (uint8_t)value;
	return offset;
}

static int hpack_decode_integer(const uint8_t *data, int data_len, int prefix_bits, uint64_t *value)
{
	int max_prefix = (1 << prefix_bits) - 1;
	int offset = 0;
	uint64_t result;
	int shift = 0;

	if (data_len < 1) {
		return -1;
	}

	result = data[offset++] & max_prefix;
	if (result < (uint64_t)max_prefix) {
		*value = result;
		return offset;
	}

	while (offset < data_len) {
		uint8_t byte = data[offset++];
		/*
		 * RFC 7541 §5.1: integers are variable-length but must fit in
		 * the wire representation.  Guard against undefined behaviour
		 * from shifting a uint64_t by >= 64 positions: reject the
		 * integer if we have already consumed enough continuation bytes
		 * that the next shift would be >= 64.  Also reject when the
		 * byte contributes bits beyond bit 63 (i.e. shift == 63 but
		 * the 7-bit payload is > 1, which would require bits 64+).
		 */
		if (shift >= 64 || (shift == 63 && (byte & 0x7F) > 1)) {
			return -1;
		}
		result += (uint64_t)(byte & 0x7F) << shift;
		shift += 7;
		if ((byte & 0x80) == 0) {
			*value = result;
			return offset;
		}
	}

	return -1;
}

/* Get the fast Huffman decoding table (function‑local static) */

static const huffman_fast_entry_t* get_huffman_fast_table(void)
{
	static huffman_fast_entry_t table[4096]; /* 1 << 12 = 4096 */
	static int initialized = 0;
	int i;

	if (initialized)
		return table;

	memset(table, 0xff, sizeof(table));
	for (i = 0; i < (int)(sizeof(huffman_table) / sizeof(huffman_table[0])); i++) {
		uint32_t bits = huffman_table[i].bits;
		uint8_t nbits = huffman_table[i].nbits;
		uint16_t sym = huffman_table[i].symbol;
		if (sym == 256) continue; /* ignore EOS */

		if (nbits <= 12) {
			uint32_t base = bits << (12 - nbits);
			uint32_t count = 1 << (12 - nbits);
			for (uint32_t j = 0; j < count; j++) {
				uint32_t idx = base | j;
				table[idx].symbol = sym;
				table[idx].nbits = nbits;
				table[idx].need_more = 0;
			}
		} else {
			uint32_t top = bits >> (nbits - 12);
			if (top < 4096) {
				/* Only set if not already set to a shorter code (rare) */
				if (table[top].need_more == 0 && table[top].symbol != (uint16_t)-1)
					continue;
				table[top].symbol = sym;
				table[top].nbits = nbits;
				table[top].need_more = 1;
			}
		}
	}
	initialized = 1;
	return table;
}

static huffman_tree_node_t* huffman_build_tree(void)
{
	static huffman_tree_node_t root = {0};
	static int built = 0;
	if (built) return &root;

	/* Initialize root with dummy values */
	memset(&root, 0, sizeof(root));

	for (int i = 0; i < (int)(sizeof(huffman_table) / sizeof(huffman_table[0])); i++) {
		uint32_t bits = huffman_table[i].bits;
		uint8_t nbits = huffman_table[i].nbits;
		uint16_t sym = huffman_table[i].symbol;
		if (sym == 256) continue; /* EOS, ignore */

		huffman_tree_node_t *node = &root;
		for (int bit = nbits - 1; bit >= 0; bit--) {
			int b = (bits >> bit) & 1;
			if (b == 0) {
				if (!node->left) {
					node->left = calloc(1, sizeof(huffman_tree_node_t));
					if (!node->left) return NULL;
				}
				node = node->left;
			} else {
				if (!node->right) {
					node->right = calloc(1, sizeof(huffman_tree_node_t));
					if (!node->right) return NULL;
				}
				node = node->right;
			}
		}
		/* Leaf node */
		node->symbol = sym;
		node->nbits = nbits;
	}
	built = 1;
	return &root;
}

/* Fallback decoder using Huffman tree traversal */

static int hpack_decode_huffman_long(uint64_t bit_buffer, int bits_avail, uint8_t *dst,
                                     size_t dst_len, size_t *dst_pos)
{
	huffman_tree_node_t *root = huffman_build_tree();
	if (!root) return -1;

	int bit_pos = bits_avail - 1; /* current bit index (most significant) */
	huffman_tree_node_t *node = root;
	int consumed = 0;

	while (bit_pos >= 0) {
		int b = (bit_buffer >> bit_pos) & 1;
		if (b == 0)
			node = node->left;
		else
			node = node->right;
		consumed++;
		bit_pos--;

		if (!node) {
			/* Invalid code */
			return -1;
		}
		if (node->nbits > 0) {
			/* Leaf node found */
			if (node->symbol == 256) return -1; /* EOS unexpected */
			if (*dst_pos >= dst_len) return -1;
			dst[(*dst_pos)++] = (uint8_t)node->symbol;
			/* Return number of bits consumed */
			return consumed;
		}
		if (bit_pos < 0) {
			/* Need more bits */
			break;
		}
	}
	/* Incomplete code (need more bits) */
	return -1;
}

/* Huffman decoder using fast 12‑bit lookup table */

int hpack_decode_huffman(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len)
{
	const huffman_fast_entry_t *huffman_fast_table = get_huffman_fast_table();
	size_t dst_pos = 0;
	uint64_t bits = 0;
	int bits_avail = 0;
	size_t i = 0;

	while (i < src_len || bits_avail > 0) {
		/* Refill bit buffer */
		while (bits_avail <= 56 && i < src_len) {
			bits = (bits << 8) | src[i++];
			bits_avail += 8;
		}

		if (bits_avail < 12) {
			/* Not enough bits for the 12-bit fast lookup, but there may still be
			 * valid short symbols (minimum code length is 5 bits).  Try a linear
			 * scan over the table before giving up so that we don't misidentify
			 * trailing symbol bits as padding and return -1.
			 */
			int found = 0;
			int try_len;
			for (try_len = bits_avail; try_len >= 5; try_len--) {
				uint32_t code = (uint32_t)((bits >> (bits_avail - try_len)) &
				                           ((1ULL << try_len) - 1));
				size_t j;
				for (j = 0; j < (int)(sizeof(huffman_table) / sizeof(huffman_table[0])); j++) {
					if (huffman_table[j].nbits != (uint8_t)try_len ||
					    huffman_table[j].bits  != code)
						continue;
					if (huffman_table[j].symbol == 256) /* EOS – invalid mid-stream */
						return -1;
					if (dst_pos >= dst_len)
						return -1;
					dst[dst_pos++] = (uint8_t)huffman_table[j].symbol;
					bits_avail -= try_len;
					bits &= (bits_avail > 0) ? ((1ULL << bits_avail) - 1) : 0;
					found = 1;
					break;
				}
				if (found)
					break;
			}
			if (!found)
				break; /* Only padding bits remain */
			continue;
		}

		/* Extract top 12 bits */
		int shift = bits_avail - 12;
		uint32_t key = (bits >> shift) & (4096 - 1);
		const huffman_fast_entry_t *entry = &huffman_fast_table[key];

		if (entry->need_more == 0) {
			/* Normal symbol: decode in one shot */
			if (entry->nbits > bits_avail)
				return -1;
			if (dst_pos >= dst_len)
				return -1;
			dst[dst_pos++] = (uint8_t)entry->symbol;
			bits_avail -= entry->nbits;
			bits &= ((uint64_t)1 << bits_avail) - 1;
		} else {
			/* Long code (length > 12 bits) – fallback to linear scan */
			int consumed = hpack_decode_huffman_long(bits, bits_avail, dst, dst_len, &dst_pos);
			if (consumed < 0) {
				/* Check for valid padding at end */
				if (i == src_len && bits_avail > 0 && bits_avail <= 7) {
					uint32_t remaining = bits & ((1U << bits_avail) - 1);
					if (remaining == ((1U << bits_avail) - 1)) {
						/* Valid padding: end of stream */
						break;
					}
				}
				return -1;
			}
			bits_avail -= consumed;
			bits &= ((uint64_t)1 << bits_avail) - 1;
		}
	}

	/* After all bytes, ensure we have consumed all bits (padding already handled) */
	if (bits_avail > 0) {
		/* Only padding bits may remain, all must be 1's and no more than 7 bits */
		uint32_t remaining = bits & ((1U << bits_avail) - 1);
		if (remaining != ((1U << bits_avail) - 1))
			return -1;
	}

	return dst_pos;
}

/* Get Huffman encoding table (function‑local static) */
static const struct huffman_encoding_entry* get_huffman_encoding_table(void)
{
	static struct huffman_encoding_entry table[256];
	static int initialized = 0;
	if (initialized)
		return table;

	memset(table, 0, sizeof(table));
	for (int i = 0; i < (int)(sizeof(huffman_table) / sizeof(huffman_table[0])); i++) {
		uint16_t sym = huffman_table[i].symbol;
		if (sym < 256) {
			table[sym].code = huffman_table[i].bits;
			table[sym].nbits = huffman_table[i].nbits;
		}
	}
	initialized = 1;
	return table;
}

static int hpack_decode_string(const uint8_t *data, int data_len, char **str)
{
	uint64_t len;
	int huffman;
	int offset = 0;
	int ret;

	if (data_len < 1) {
		return -1;
	}

	huffman = (data[0] & 0x80) != 0;
	ret = hpack_decode_integer(data, data_len, 7, &len);
	if (ret < 0) {
		return -1;
	}
	offset += ret;

	if ((uint64_t)offset + len > (uint64_t)data_len) {
		return -1;
	}

	if (huffman) {
		/* Huffman decoding */

		/* Allocate buffer for decoded string (worst case: same size as encoded) */
		uint8_t *decoded = malloc(len * 2 + 1);
		if (!decoded) {
			return -1;
		}

		int decoded_len = hpack_decode_huffman(data + offset, len, decoded, len * 2);
		if (decoded_len < 0) {
			free(decoded);
			return -1;
		}

		*str = malloc(decoded_len + 1);
		if (!*str) {
			free(decoded);
			return -1;
		}

		memcpy(*str, decoded, decoded_len);
		(*str)[decoded_len] = '\0';
		free(decoded);
	} else {
		/* Literal string */
		*str = malloc(len + 1);
		if (*str == NULL) {
			return -1;
		}

		memcpy(*str, data + offset, len);
		(*str)[len] = '\0';
	}

	offset += len;

	return offset;
}

/* Huffman encode a byte array, return number of bytes written to dst, or -1 */

static int hpack_encode_huffman(const uint8_t *src, size_t src_len,
                                uint8_t *dst, size_t dst_capacity)
{
	const struct huffman_encoding_entry *huffman_encoding_table = get_huffman_encoding_table();
	uint64_t bits = 0;
	int nbits = 0;
	int max_bits = 64; /* bits is uint64_t, maximum bits we can hold */
	size_t dst_pos = 0;
	size_t i;

	for (i = 0; i < src_len; i++) {
		uint8_t sym = src[i];
		uint32_t code = huffman_encoding_table[sym].code;
		uint8_t code_nbits = huffman_encoding_table[sym].nbits;

		if (code_nbits == 0) {
			return -1;
		}

		/* Avoid overflow when adding new code bits */
		if (nbits + code_nbits > max_bits) {
			/* Flush as many bytes as possible to free space */
			while (nbits >= 8) {
				if (dst_pos >= dst_capacity)
					return -1;
				dst[dst_pos++] = (bits >> (nbits - 8)) & 0xFF;
				nbits -= 8;
			}
			/* After flushing, nbits < 8, so we can safely shift */
		}

		bits = (bits << code_nbits) | code;
		nbits += code_nbits;
		while (nbits >= 8) {
			if (dst_pos >= dst_capacity)
				return -1;
			dst[dst_pos++] = (bits >> (nbits - 8)) & 0xFF;
			nbits -= 8;
		}
	}

	/* Final padding: add 1 bits to reach byte boundary (RFC 7541 5.2) */
	if (nbits > 0) {
		bits = (bits << (8 - nbits)) | ((1U << (8 - nbits)) - 1);
		dst[dst_pos++] = bits & 0xFF;
	}

	return dst_pos;
}

/* HPACK string encoding/decoding */

static int hpack_encode_string(const char *str, uint8_t *buf, int buf_size)
{
	int len = strlen(str);
	int offset = 0;
	int ret;
	int use_huffman = 0;
	uint8_t *huffman_buf = NULL;
	int huffman_len = 0;

	/* Try Huffman encoding first (if it reduces size) */
	huffman_buf = malloc(len * 2 + 8);
	if (huffman_buf) {
		huffman_len = hpack_encode_huffman((const uint8_t *)str, len, huffman_buf, len * 2 + 8);
		if (huffman_len > 0 && huffman_len < len) {
			use_huffman = 1;
		} else {
			free(huffman_buf);
			huffman_buf = NULL;
		}
	}

	if (buf_size < 1) {
		free(huffman_buf);
		return -1;
	}

	/* Set Huffman flag */
	buf[offset] = use_huffman ? 0x80 : 0x00;
	int encode_len = use_huffman ? huffman_len : len;
	ret = hpack_encode_integer(encode_len, 7, buf + offset, buf_size - offset);
	if (ret < 0) {
		free(huffman_buf);
		return -1;
	}
	offset += ret;

	if (offset + encode_len > buf_size) {
		free(huffman_buf);
		return -1;
	}

	if (use_huffman) {
		memcpy(buf + offset, huffman_buf, huffman_len);
		offset += huffman_len;
		free(huffman_buf);
	} else {
		memcpy(buf + offset, str, len);
		offset += len;
	}

	return offset;
}

/* HPACK dynamic table management */

void hpack_init_context(struct hpack_context *hpack)
{
	hpack->dynamic_table = NULL;
	hpack->dynamic_table_tail = NULL;
	hpack->dynamic_table_size = 0;
	hpack->max_dynamic_table_size = 4096; /* RFC 7541 §6.5.2 Default size */
	hpack->entry_count = 0;
	hpack->last_sent_table_size = hpack->max_dynamic_table_size;
}

void hpack_free_context(struct hpack_context *hpack)
{
	struct hpack_dynamic_entry *entry = hpack->dynamic_table;
	while (entry) {
		struct hpack_dynamic_entry *next = entry->next;
		free(entry->name);
		free(entry->value);
		free(entry);
		entry = next;
	}
	hpack->dynamic_table_tail = NULL;
	hpack->dynamic_table = NULL;
	hpack->dynamic_table_size = 0;
	hpack->entry_count = 0;
}

static int hpack_add_dynamic_entry(struct hpack_context *hpack, const char *name, const char *value)
{
	struct hpack_dynamic_entry *entry;
	size_t entry_size = strlen(name) + strlen(value) + 32;

	if (entry_size > hpack->max_dynamic_table_size) {
		while (hpack->dynamic_table) {
			struct hpack_dynamic_entry *last = hpack->dynamic_table_tail;
			if (!last)
				break;
			if (last->prev) {
				last->prev->next = NULL;
				hpack->dynamic_table_tail = last->prev;
			} else {
				hpack->dynamic_table = NULL;
				hpack->dynamic_table_tail = NULL;
			}
			hpack->dynamic_table_size -= last->size;
			hpack->entry_count--;
			free(last->name);
			free(last->value);
			free(last);
		}
		return 0;
	}

	/* Evict entries if necessary */
	while (hpack->dynamic_table_size + entry_size > hpack->max_dynamic_table_size && hpack->dynamic_table) {
		struct hpack_dynamic_entry *last = hpack->dynamic_table_tail;
		if (!last) {
			break;
		}

		if (last->prev) {
			last->prev->next = NULL;
			hpack->dynamic_table_tail = last->prev;
		} else {
			hpack->dynamic_table = NULL;
			hpack->dynamic_table_tail = NULL;
		}

		hpack->dynamic_table_size -= last->size;
		hpack->entry_count--;
		free(last->name);
		free(last->value);
		free(last);
	}

	entry = malloc(sizeof(*entry));
	if (!entry) {
		return -1;
	}

	entry->name = strdup(name);
	entry->value = strdup(value);
	if (!entry->name || !entry->value) {
		free(entry->name);
		free(entry->value);
		free(entry);
		return -1;
	}

	entry->size = entry_size;
	entry->prev = NULL;
	entry->next = hpack->dynamic_table;

	if (hpack->dynamic_table) {
		hpack->dynamic_table->prev = entry;
	} else {
		hpack->dynamic_table_tail = entry;
	}

	hpack->dynamic_table = entry;
	hpack->dynamic_table_size += entry_size;
	hpack->entry_count++;

	return 0;
}

static int hpack_get_entry(struct hpack_context *hpack, uint64_t index, const char **name, const char **value)
{
	const size_t static_table_size = sizeof(hpack_static_table) / sizeof(hpack_static_table[0]);

	if (index == 0) {
		return -1;
	}

	if (index <= static_table_size) {
		*name = hpack_static_table[index - 1].name;
		*value = hpack_static_table[index - 1].value;
		return 0;
	}

	/* Dynamic table */
	uint64_t dynamic_index = index - static_table_size - 1;
	struct hpack_dynamic_entry *entry = hpack->dynamic_table;
	uint64_t i = 0;

	while (entry && i < dynamic_index) {
		entry = entry->next;
		i++;
	}

	if (!entry) {
		return -1;
	}

	*name = entry->name;
	*value = entry->value;
	return 0;
}

static int hpack_find_index(struct hpack_context *hpack, const char *name, const char *value, int *index,
							int *name_only_index)
{
	const size_t static_table_size = sizeof(hpack_static_table) / sizeof(hpack_static_table[0]);
	int i;

	*index = 0;
	*name_only_index = 0;

	/* Search static table */
	for (i = 0; i < (int)static_table_size; i++) {
		if (strcmp(hpack_static_table[i].name, name) == 0) {
			if (*name_only_index == 0) {
				*name_only_index = i + 1;
			}
			if (strcmp(hpack_static_table[i].value, value) == 0) {
				*index = i + 1;
				return 0;
			}
		}
	}

	/* Search dynamic table */
	struct hpack_dynamic_entry *entry = hpack->dynamic_table;
	i = 0;
	while (entry) {
		if (strcmp(entry->name, name) == 0) {
			if (*name_only_index == 0) {
				*name_only_index = static_table_size + 1 + i;
			}
			if (strcmp(entry->value, value) == 0) {
				*index = static_table_size + 1 + i;
				return 0;
			}
		}
		entry = entry->next;
		i++;
	}

	return 0;
}

/* HPACK encoding */

int hpack_encode_header(struct hpack_context *hpack, const char *name, const char *value, uint8_t *buf, int buf_size)
{
	int index, name_only_index;
	int offset = 0;
	int ret;
	uint8_t size_update_buf[8];

	if (hpack->max_dynamic_table_size != hpack->last_sent_table_size) {
		/* Size update: prefix 5 bits with value 0x20 (00100000) */
		size_update_buf[0] = 0x20;
		ret = hpack_encode_integer(hpack->max_dynamic_table_size, 5,
					   size_update_buf, sizeof(size_update_buf));
		if (ret < 0) {
			return -1;
		}
		if (offset + ret > buf_size) {
			return -1;
		}
		memcpy(buf + offset, size_update_buf, ret);
		offset += ret;
		/* Remember the size we just advertised */
		hpack->last_sent_table_size = hpack->max_dynamic_table_size;
	}

	hpack_find_index(hpack, name, value, &index, &name_only_index);

	if (index > 0) {
		/* Indexed header field (RFC 7541 §6.1) */
		if (buf_size - offset < 1) {
			return -1;
		}
		buf[offset] = 0x80;
		ret = hpack_encode_integer(index, 7, buf + offset, buf_size - offset);
		if (ret < 0) {
			return -1;
		}
		return offset + ret;
	}

	if (name_only_index > 0) {
		/* Literal with incremental indexing - indexed name */
		if (buf_size < 1) {
			return -1;
		}
		buf[offset] = 0x40;
		ret = hpack_encode_integer(name_only_index, 6, buf + offset, buf_size - offset);
		if (ret < 0) {
			return -1;
		}
		offset += ret;

		ret = hpack_encode_string(value, buf + offset, buf_size - offset);
		if (ret < 0) {
			return -1;
		}
		offset += ret;

		hpack_add_dynamic_entry(hpack, name, value);
		return offset;
	}

	/* Literal with incremental indexing - new name */
	if (buf_size < 1) {
		return -1;
	}
	buf[offset++] = 0x40;

	ret = hpack_encode_string(name, buf + offset, buf_size - offset);
	if (ret < 0) {
		return -1;
	}
	offset += ret;

	ret = hpack_encode_string(value, buf + offset, buf_size - offset);
	if (ret < 0) {
		return -1;
	}
	offset += ret;

	hpack_add_dynamic_entry(hpack, name, value);
	return offset;
}

/* HPACK decoding */

void hpack_resize_dynamic_table(struct hpack_context *hpack, size_t new_size)
{
	hpack->max_dynamic_table_size = new_size;

	/* Evict entries if necessary */
	while (hpack->dynamic_table_size > hpack->max_dynamic_table_size && hpack->dynamic_table) {
		struct hpack_dynamic_entry *last = hpack->dynamic_table_tail;
		if (!last) {
			break;
		}

		if (last->prev) {
			last->prev->next = NULL;
			hpack->dynamic_table_tail = last->prev;
		} else {
			hpack->dynamic_table = NULL;
			hpack->dynamic_table_tail = NULL;
		}

		hpack->dynamic_table_size -= last->size;
		hpack->entry_count--;
		free(last->name);
		free(last->value);
		free(last);
	}
}

int hpack_decode_headers(struct hpack_context *hpack, const uint8_t *data, int data_len, hpack_on_header_fn on_header,
						 void *ctx)
{
	int offset = 0;
	int past_size_updates = 0;

	while (offset < data_len) {
		const char *name = NULL;
		const char *value = NULL;
		char *allocated_name = NULL;
		char *allocated_value = NULL;

		if ((data[offset] & 0x80) != 0) {
			uint64_t index;
			const char *static_name, *static_value;
			int ret = hpack_decode_integer(data + offset, data_len - offset, 7, &index);
			if (ret < 0) {
				return -1;
			}
			if (hpack_get_entry(hpack, index, &static_name, &static_value) < 0) {
				return -1;
			}
			offset += ret;

			name = static_name;
			value = static_value;
			past_size_updates = 1;
		} else if ((data[offset] & 0x40) != 0) {
			uint64_t index;
			int ret = hpack_decode_integer(data + offset, data_len - offset, 6, &index);
			if (ret < 0) {
				return -1;
			}
			offset += ret;

			if (index > 0) {
				const char *static_name, *static_value;
				if (hpack_get_entry(hpack, index, &static_name, &static_value) < 0) {
					return -1;
				}
				name = static_name;
			} else {
				ret = hpack_decode_string(data + offset, data_len - offset, &allocated_name);
				if (ret < 0) {
					return -1;
				}
				offset += ret;
				name = allocated_name;
			}

			ret = hpack_decode_string(data + offset, data_len - offset, &allocated_value);
			if (ret < 0) {
				free(allocated_name);
				return -1;
			}
			offset += ret;
			value = allocated_value;

			if (name && value) {
				hpack_add_dynamic_entry(hpack, name, value);
			}
			past_size_updates = 1;
		} else if ((data[offset] & 0x20) != 0) {
			uint64_t new_size;
			int ret;

			if (past_size_updates) {
				return -1;
			}

			ret = hpack_decode_integer(data + offset, data_len - offset, 5, &new_size);
			if (ret < 0) {
				return -1;
			}
			offset += ret;
			hpack_resize_dynamic_table(hpack, new_size);
			continue;
		} else {
			uint64_t index;
			int prefix = 4;
			int ret = hpack_decode_integer(data + offset, data_len - offset, prefix, &index);
			if (ret < 0) {
				return -1;
			}
			offset += ret;

			if (index > 0) {
				const char *static_name, *static_value;
				if (hpack_get_entry(hpack, index, &static_name, &static_value) < 0) {
					return -1;
				}
				name = static_name;
			} else {
				ret = hpack_decode_string(data + offset, data_len - offset, &allocated_name);
				if (ret < 0) {
					return -1;
				}
				offset += ret;
				name = allocated_name;
			}

			ret = hpack_decode_string(data + offset, data_len - offset, &allocated_value);
			if (ret < 0) {
				free(allocated_name);
				return -1;
			}
			offset += ret;
			value = allocated_value;
			past_size_updates = 1;
		}

		/* Add header to stream */
		if (on_header(ctx, name, value) < 0) {
			free(allocated_name);
			free(allocated_value);
			return -1;
		}

		/* Free allocated strings if they were copied */
		if (allocated_name) {
			free(allocated_name);
		}
		if (allocated_value) {
			free(allocated_value);
		}
	}

	return 0;
}
