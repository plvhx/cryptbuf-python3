#include "./base64.h"

#include <string.h>
#include <stdlib.h>

static const char charlist[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
};

static const char reverse_index[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

char *base64_encode(const char *buf, size_t len)
{
	char *obuf, *ptobuf;
	const char *ptbuf = (const char *)(buf);
	size_t i, q, r;
	int c;

	if (!len) {
		return NULL;
	}

	{ q = len / 3; r = len % 3; }

	obuf = calloc((q + (r ? 1 : 0)) * 4 + 1, sizeof(char));

	if (obuf == NULL) {
		return NULL;
	}

	ptobuf = obuf;

	for (i = 0; i < q; i++) {
		{ c = (0xff & *ptbuf++) << 16; c |= (0xff & *ptbuf++) << 8; c |= (0xff & *ptbuf++); }
		{ *ptobuf++ = charlist[c >> 18]; *ptobuf++ = charlist[(c >> 12) & 0x3f]; }
		{ *ptobuf++ = charlist[(c >> 6) & 0x3f]; *ptobuf++ = charlist[c & 0x3f]; }
	}

	if (r == 1) {
		c = 0xff & *ptbuf++;
		{ *ptobuf++ = charlist[c >> 2]; *ptobuf++ = charlist[(c & 0x03) << 4]; }
		{ *ptobuf++ = '='; *ptobuf++ = '='; }
	} else if (r == 2) {
		{ c = (0xff & *ptbuf++) << 8; c |= 0xff & *ptbuf++; }
		{ *ptobuf++ = charlist[c >> 10]; *ptobuf++ = charlist[(c >> 4) & 0x3f]; }
		{ *ptobuf++ = charlist[(c & 0x0f) << 2]; *ptobuf++ = '='; }
	}

	return obuf;
}

char *base64_decode(const char *buf, size_t len, size_t *olen)
{
	char *obuf, *ptobuf;
	const char *ptbuf = (const char *)buf;
	size_t i, q, r, pad = 0;
	int c;

	if (!len) {
		return NULL;
	}

	r = len % 4;
	if (r) {
		return NULL;
	}

	q = len / 4;
	pad = buf[len - 2] == '='
		? 2
		: buf[len - 1] == '='
			? 1
			: 0;

	obuf = calloc(q * 3 - pad + 1, sizeof(char));

	if (obuf == NULL) {
		return NULL;
	}

	ptobuf = obuf;

	for (i = 0; i < q; i++) {
		{ c = reverse_index[(int)*ptbuf++] << 18; c += reverse_index[(int)*ptbuf++] << 12; }
		*ptobuf++ = (c & 0x00ff0000) >> 16;

		if (*ptbuf != '=') {
			c += reverse_index[(int)*ptbuf++] << 6;
			*ptobuf++ = (c & 0x0000ff00) >> 8;

			if (*ptbuf != '=') {
				c += reverse_index[(int)*ptbuf++];
				*ptobuf++ = c & 0xff;
			}
		}
	}

	*olen = ptobuf - obuf;
	
	return obuf;
}