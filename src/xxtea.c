#include "./xxtea.h"

#include <string.h>
#include <stdlib.h>

#ifndef XXTEA_MX
# define XXTEA_MX	(((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (ctx->kvec[(p & 3) ^ e] ^ z))
#endif

#ifndef XXTEA_DELTA_VAL
# define XXTEA_DELTA_VAL	0x9e3779b9
#endif

#define XXTEA_FIXED_KEY \
    size_t i;\
    uint8_t fixed_key[16];\
    memcpy(fixed_key, kbuf, 16);\
    for (i = 0; (i < 16) && (fixed_key[i] != 0); ++i);\
    for (++i; i < 16; ++i) fixed_key[i] = 0;\

static xxtea_ctx_t root = {
	.dvec = NULL,
	.kvec = NULL,
	.dvec_len = 0,
	.kvec_len = 0,
	.rbuf_len = 0
};

static xxtea_ctx_state_t root_state = { .state = XXTEA_CTX_STATE_UNDEFINED };

void __xxtea_context_init(xxtea_ctx_t *ctx)
{
	{ ctx->dvec = NULL; ctx->kvec = NULL; }
	{ ctx->dvec_len = 0; ctx->kvec_len = 0; }
	root_state.state = XXTEA_CTX_STATE_NULL_INIT;
}

void __xxtea_context_destruct(xxtea_ctx_t *ctx)
{
	{ free(ctx->kvec); free(ctx->dvec); }
	{ ctx->kvec = NULL; ctx->dvec = NULL; }
	{ ctx->dvec_len = 0; ctx->kvec_len = 0; }
	root_state.state = XXTEA_CTX_STATE_UNDEFINED;
}

static int __xxtea_block_encrypt(xxtea_ctx_t *ctx)
{
	uint32_t n = (uint32_t)ctx->dvec_len - 1;
	uint32_t z = ctx->dvec[n], y, p, q = 6 + 52 / (n + 1);
	uint32_t sum = 0, e;

	if (n < 1) {
		return -1;
	}

	while (0 < q--) {
		sum += XXTEA_DELTA_VAL;
		e = sum >> 2 & 3;

		for (p = 0; p < n; p++) {
			y = ctx->dvec[p + 1];
			z = ctx->dvec[p] += XXTEA_MX;
		}

		y = ctx->dvec[0];
		z = ctx->dvec[n] += XXTEA_MX;
	}

	return 0;
}

static int __xxtea_block_decrypt(xxtea_ctx_t *ctx)
{
	uint32_t n = (uint32_t)ctx->dvec_len - 1;
	uint32_t z, y = ctx->dvec[0], p, q = 6 + 52 / (n + 1);
	uint32_t sum = q * XXTEA_DELTA_VAL, e;

	if (n < 1) {
		return -1;
	}

	while (sum != 0) {
		e = sum >> 2 & 3;

		for (p = n; p > 0; p--) {
			z = ctx->dvec[p - 1];
			y = ctx->dvec[p] -= XXTEA_MX;
		}

		z = ctx->dvec[n];
		y = ctx->dvec[0] -= XXTEA_MX;
		sum -= XXTEA_DELTA_VAL;
	}

	return 0;
}

static int __xxtea_dvec_deserialize(xxtea_ctx_t *ctx, const uint8_t *buf, size_t len, int nonce)
{
#if !(defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN))
	size_t i;
#endif
	size_t n;

	n = (((len & 3) == 0) ? (len >> 2) : ((len >> 2) + 1));

	ctx->dvec = calloc((uint32_t)(nonce ? n + 1 : n), sizeof(uint32_t));

	if (ctx->dvec == NULL) {
		return -1;
	}

	if (nonce) {
		ctx->dvec[n] = (uint32_t)(len);
	}

	ctx->dvec_len = nonce ? n + 1 : n;

#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
	memcpy(ctx->dvec, buf, len);
#else
	for (i = 0; i < len; ++i) {
		ctx->dvec[i >> 2] |= (uint32_t)(buf[i]) << ((i & 3) << 3);
	}
#endif

	root_state.state = ((ctx->dvec != NULL && ctx->kvec == NULL) || (ctx->dvec == NULL && ctx->kvec != NULL))
		? XXTEA_CTX_STATE_PARTIAL
		: XXTEA_CTX_STATE_READY;

	return 0;
}

static int __xxtea_kvec_deserialize(xxtea_ctx_t *ctx, const uint8_t *buf, int nonce)
{
#if !(defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN))
	size_t i;
#endif
	size_t n;

	n = (((16 & 3) == 0) ? (16 >> 2) : ((16 >> 2) + 1));

	ctx->kvec = calloc(nonce ? n + 1 : n, sizeof(uint32_t));

	if (ctx->kvec == NULL) {
		return -1;
	}

	if (nonce) {
		ctx->kvec[n] = (uint32_t)(16);
	}

	ctx->kvec_len = nonce ? n + 1 : n;

#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
	memcpy(ctx->kvec, buf, 16);
#else
	for (i = 0; i < 16; ++i) {
		ctx->kvec[i >> 2] |= (uint32_t)(buf[i]) << ((i & 3) << 3);
	}
#endif

	root_state.state = ((ctx->dvec != NULL && ctx->kvec == NULL) || (ctx->dvec == NULL && ctx->kvec != NULL))
		? XXTEA_CTX_STATE_PARTIAL
		: XXTEA_CTX_STATE_READY;

	return 0;
}

uint8_t *__xxtea_rbuf_serialize(xxtea_ctx_t *ctx, int nonce, size_t *olen)
{
	uint8_t *rbuf;
#if !(defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN))
    size_t i;
#endif
    size_t m, n;

    n = ctx->dvec_len << 2;

    if (nonce) {
    	m = ctx->dvec[ctx->dvec_len - 1];
    	n -= 4;

    	if ((m < n - 3) || (m > n))
    		return NULL;

    	n = m;
    }

    rbuf = calloc(n + 1, sizeof(char));

    if (rbuf == NULL)
    	return NULL;

#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
    memcpy(rbuf, ctx->dvec, n);
#else
    for (i = 0; i < n; ++i) {
        rbuf[i] = (uint8_t)(ctx->dvec[i >> 2] >> ((i & 3) << 3));
    }
#endif

    *olen = n;

    return rbuf;
}

uint8_t *xxtea_encrypt(const uint8_t *buf, size_t blen, const uint8_t *kbuf, size_t *olen)
{
	uint8_t *rbuf;
	XXTEA_FIXED_KEY

	if (!blen)
		return NULL;

	__xxtea_context_init(&root);
	__xxtea_dvec_deserialize(&root, (const uint8_t *)buf, blen, 1);
	__xxtea_kvec_deserialize(&root, (const uint8_t *)fixed_key, 0);
	__xxtea_block_encrypt(&root);

	rbuf = __xxtea_rbuf_serialize(&root, 0, olen);
	__xxtea_context_destruct(&root);

	return rbuf;
}

uint8_t *xxtea_decrypt(const uint8_t *buf, size_t blen, const uint8_t *kbuf, size_t *olen)
{
	uint8_t *rbuf;
	XXTEA_FIXED_KEY;

	if (!blen)
		return NULL;
	
	__xxtea_context_init(&root);
	__xxtea_dvec_deserialize(&root, (const uint8_t *)buf, blen, 0);
	__xxtea_kvec_deserialize(&root, (const uint8_t *)fixed_key, 0);
	__xxtea_block_decrypt(&root);

	rbuf = __xxtea_rbuf_serialize(&root, 1, olen);
	__xxtea_context_destruct(&root);

	return rbuf;
}