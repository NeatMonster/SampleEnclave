#ifndef _UTILS_H_
#define _UTILS_H_

#define TOKEN_FILENAME "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"

#if defined(__cplusplus)
extern "C" {
#endif

int initialize_enclave(void);

#if defined(__cplusplus)
}
#endif

#endif /* _UTILS_H_ */