#ifndef _XXTEA_H_
#define _XXTEA_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef XXTEA_CTX_STATE_UNDEFINED
#define XXTEA_CTX_STATE_UNDEFINED	1
#endif

#ifndef XXTEA_CTX_STATE_NULL_INIT
#define XXTEA_CTX_STATE_NULL_INIT	2
#endif

#ifndef XXTEA_CTX_STATE_PARTIAL
#define XXTEA_CTX_STATE_PARTIAL	4
#endif

#ifndef XXTEA_CTX_STATE_READY
#define XXTEA_CTX_STATE_READY	8
#endif

typedef struct xxtea_context {
	uint32_t *dvec;
	uint32_t *kvec;
	uint32_t dvec_len;
	uint32_t kvec_len;
	uint32_t rbuf_len;
} xxtea_ctx_t;

typedef struct xxtea_context_state {
	uint32_t state;
} xxtea_ctx_state_t;

uint8_t *xxtea_encrypt(const uint8_t *buf, size_t blen, const uint8_t *kbuf, size_t *olen);
uint8_t *xxtea_decrypt(const uint8_t *buf, size_t blen, const uint8_t *kbuf, size_t *olen);

#ifdef __cplusplus
}
#endif

#endif /* _XXTEA_H_ */