#ifndef _BASE64_H_
#define _BASE64_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char *base64_encode(const char *buf, size_t len);
char *base64_decode(const char *buf, size_t len, size_t *olen);

#ifdef __cplusplus
}
#endif

#endif /* _BASE64_H_ */