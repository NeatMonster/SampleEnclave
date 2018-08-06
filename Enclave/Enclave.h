#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#if defined(__cplusplus)
extern "C" {
#endif

sgx_status_t new_vault(char *passphrase);

sgx_status_t vault_size(uint32_t *vault_size);

sgx_status_t save_vault(uint8_t *vault_data, uint32_t vault_size);

sgx_status_t load_vault(uint8_t *vault_data, uint32_t vault_size,
                        char *passphrase);

sgx_status_t create_account(char *name, char *user, char *pass);

sgx_status_t remove_account(char *name);

sgx_status_t has_account(char *name);

sgx_status_t get_username(char *name, char *user, uint32_t size);

sgx_status_t get_password(char *name, char *pass, uint32_t size);

#if defined(__cplusplus)
}
#endif

#endif /* _ENCLAVE_H_ */
