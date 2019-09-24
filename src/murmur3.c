#include "./murmur3.h"

#define ROL(x, i)	(((x) << (i)) | ((x) >> (32 - (i))))

uint32_t murmur3_x86_32(const char *buf, size_t len, uint32_t seed)
{
	uint32_t hash = seed;
	const int32_t qlen = (int32_t)(len) >> 2;
	uint32_t k;
	const uint8_t *cbuf = (const uint8_t *)buf;
	const uint32_t v0 = 0xcc9e2d51;
	const uint32_t v1 = 0x1b873593;
	int i;

	const uint32_t *mbuf = (const uint32_t *)(cbuf + (qlen * 4));

	for (i = -qlen; i; i++) {
		{ k = mbuf[i]; k *= v0; k = ROL(k, 15); k *= v1; }
		{ hash ^= k; hash = ROL(hash, 13); hash = (hash * 5) + 0xe6546b64; }
	}

	const uint8_t *rem = (const uint8_t *)(cbuf + (qlen * 4));

	k = 0;

	switch (len & 3) {
	case 3: k ^= (uint8_t)rem[2] << 16;
	case 2: k ^= (uint8_t)rem[1] <<  8;
	case 1: k ^= (uint8_t)rem[0] <<  0;
			{ k *= v0; k = ROL(k, 15); k *= v1; hash ^= k; }
	}

	{ hash ^= len; hash ^= hash >> 16; hash *= 0x85ebca6b; }
	{ hash ^= hash >> 13; hash *= 0xc2b2ae35; hash ^= hash >> 16; }

	return hash;
}