#ifndef _MURMUR3_H_
#define _MURMUR3_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t murmur3_x86_32(const char *buf, size_t len, uint32_t seed);

#ifdef __cplusplus
}
#endif

#endif /* _MURMUR3_H_ */