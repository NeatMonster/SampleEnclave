#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "Enclave.h"
#include "Enclave_t.h"

typedef struct account {
  struct account *next;

  char *name; /* site URL */
  char *user; /* username */
  char *pass; /* password */
} account_t;

typedef account_t *vault_t;

vault_t vault = NULL;
char *vault_pass = NULL;

uint32_t calc_vault_size() {
  uint32_t size = strlen(vault_pass) + 1;

  /* Calculate the accounts size */
  account_t *account = vault;
  while (account != NULL) {
    size += strlen(account->name) + 1;
    size += strlen(account->user) + 1;
    size += strlen(account->pass) + 1;
    account = account->next;
  }

  return size;
}

account_t *get_account(char *name) {
  account_t *account = vault;
  while (account != NULL) {
    if (!strcmp(account->name, name)) return account;
    account = account->next;
  }
  return NULL;
}

void add_account(account_t *account) {
  if (vault == NULL) {
    vault = account;
  } else {
    account_t *prev = vault;
    while (prev->next != NULL) prev = prev->next;
    prev->next = account;
  }
}

void del_account(account_t *account) {
  if (vault == account) {
    vault = account->next;
  } else {
    account_t *prev = vault;
    while (prev->next != account) prev = prev->next;
    prev->next = account->next;
  }

  /* Free the account */
  free(account->name);
  free(account->user);
  free(account->pass);
  free(account);
}

sgx_status_t new_vault(char *passphrase) {
  /* Passphrase cannot be null */
  if (passphrase == NULL) return SGX_ERROR_UNEXPECTED;
  /* Vault already initialized */
  if (vault_pass != NULL) return SGX_ERROR_UNEXPECTED;

  vault_pass = (char *)malloc(strlen(passphrase) + 1);
  if (vault_pass == NULL) return SGX_ERROR_UNEXPECTED;
  memcpy(vault_pass, passphrase, strlen(passphrase) + 1);
  return SGX_SUCCESS;
}

sgx_status_t vault_size(uint32_t *vault_size) {
  /* Vault not initialized */
  if (vault_pass == NULL) return SGX_ERROR_UNEXPECTED;

  /* Calculate sealed data size */
  uint32_t size = sgx_calc_sealed_data_size(0, calc_vault_size());
  if (size == 0xFFFFFFFF) return SGX_ERROR_UNEXPECTED;
  *vault_size = size;
  return SGX_SUCCESS;
}

sgx_status_t save_vault(uint8_t *vault_data, uint32_t vault_size) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  /* Vault not initialized */
  if (vault_pass == NULL) return ret;

  /* Allocate the input buffer */
  uint32_t buf_size = calc_vault_size();
  uint8_t *buf = (uint8_t *)malloc(buf_size), *ptr = buf;
  if (buf == NULL) return ret;

  /* Write the passphrase */
  memcpy(ptr, vault_pass, strlen(vault_pass) + 1);
  ptr += strlen(vault_pass) + 1;

  /* Write the vault accounts */
  account_t *account = vault;
  while (account != NULL) {
    /* Write the account name */
    memcpy(ptr, account->name, strlen(account->name) + 1);
    ptr += strlen(account->name) + 1;

    /* Write the account user */
    memcpy(ptr, account->user, strlen(account->user) + 1);
    ptr += strlen(account->user) + 1;

    /* Write the account pass */
    memcpy(ptr, account->pass, strlen(account->pass) + 1);
    ptr += strlen(account->pass) + 1;

    account = account->next;
  }

  /* Seal the vault data */
  ret = sgx_seal_data(0, NULL, buf_size, buf, vault_size,
                      (sgx_sealed_data_t *)vault_data);

  /* Free the buffer */
  free(buf);
  return ret;
}

sgx_status_t load_vault(uint8_t *vault_data, uint32_t vault_size,
                        char *passphrase) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  /* Passphrase cannot be null */
  if (passphrase == NULL) return ret;
  /* Vault already initialized */
  if (vault_pass != NULL) return ret;

  /* Allocate the output buffer */
  uint32_t buf_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)vault_data);
  if (buf_size == 0xFFFFFFFF) return ret;
  uint8_t *buf = (uint8_t *)malloc(buf_size), *ptr = buf;
  if (buf == NULL) return ret;

  /* Unseal the vault data */
  account_t *account = NULL;
  uint32_t len = 0;
  ret =
      sgx_unseal_data((sgx_sealed_data_t *)vault_data, NULL, 0, buf, &buf_size);
  if (ret != SGX_SUCCESS) goto cleanup;
  if (strcmp(passphrase, (const char *)ptr)) goto cleanup;

  /* Save the passphrase */
  len = strlen((const char *)ptr) + 1;
  vault_pass = (char *)malloc(len);
  if (vault_pass == NULL) goto cleanup;
  memcpy(vault_pass, ptr, len);
  ptr += len;

  /* Read the vault accounts */
  while (ptr < buf + buf_size) {
    /* Allocate a new account */
    account = (account_t *)malloc(sizeof(account_t));
    if (account == NULL) goto cleanup;
    account->next = NULL;

    /* Read the account name */
    len = strlen((const char *)ptr) + 1;
    account->name = (char *)malloc(len);
    if (account->name == NULL) goto cleanup;
    memcpy(account->name, ptr, len);
    ptr += len;

    /* Read the account user */
    len = strlen((const char *)ptr) + 1;
    account->user = (char *)malloc(len);
    if (account->user == NULL) goto cleanup;
    memcpy(account->user, ptr, len);
    ptr += len;

    /* Read the account pass */
    len = strlen((const char *)ptr) + 1;
    account->pass = (char *)malloc(len);
    if (account->pass == NULL) goto cleanup;
    memcpy(account->pass, ptr, len);
    ptr += len;

    add_account(account);
    account = NULL;
  }

  /* Free the buffers */
  free(buf);
  return ret;

cleanup:
  /* Free everything */
  while (vault != NULL) del_account(vault);
  if (vault_pass != NULL) free(vault_pass);
  if (account != NULL) {
    if (account->name != NULL) free(account->name);
    if (account->user != NULL) free(account->user);
    if (account->pass != NULL) free(account->pass);
    free(account);
  }
  free(buf);
  return SGX_ERROR_UNEXPECTED;
}

sgx_status_t create_account(char *name, char *user, char *pass) {
  /* Name, user or pass cannot be null */
  if (name == NULL || user == NULL || pass == NULL) return SGX_ERROR_UNEXPECTED;
  /* Vault not initialized */
  if (vault_pass == NULL) return SGX_ERROR_UNEXPECTED;

  /* Ensure the account doesn't exist */
  account_t *account = get_account(name);
  if (account != NULL) return SGX_ERROR_UNEXPECTED;

  /* Allocate a new account */
  account = (account_t *)malloc(sizeof(account_t));
  if (account == NULL) return SGX_ERROR_UNEXPECTED;

  /* Copy the name */
  account->name = (char *)malloc(strlen(name));
  if (account->name == NULL) goto cleanup;
  memcpy(account->name, name, strlen(name));

  /* Copy the user */
  account->user = (char *)malloc(strlen(user));
  if (account->user == NULL) goto cleanup;
  memcpy(account->user, user, strlen(user));

  /* Copy the pass */
  account->pass = (char *)malloc(strlen(pass));
  if (account->pass == NULL) goto cleanup;
  memcpy(account->pass, pass, strlen(pass));

  add_account(account);
  return SGX_SUCCESS;

cleanup:
  if (account->name) free(account->name);
  if (account->user) free(account->user);
  if (account->pass) free(account->pass);
  free(account);
  return SGX_ERROR_UNEXPECTED;
}

sgx_status_t remove_account(char *name) {
  /* Name cannot be null */
  if (name == NULL) return SGX_ERROR_UNEXPECTED;
  /* Vault not initialized */
  if (vault_pass == NULL) return SGX_ERROR_UNEXPECTED;

  /* Ensure the account does exist */
  account_t *account = get_account(name);
  if (account == NULL) return SGX_ERROR_UNEXPECTED;

  del_account(account);
  return SGX_SUCCESS;
}

sgx_status_t has_account(char *name) {
  /* Name cannot be null */
  if (name == NULL) return SGX_ERROR_UNEXPECTED;
  /* Vault not initialized */
  if (vault_pass == NULL) return SGX_ERROR_UNEXPECTED;

  /* Get the matching account */
  account_t *account = get_account(name);
  if (account == NULL) return SGX_ERROR_UNEXPECTED;
  return SGX_SUCCESS;
}

sgx_status_t get_username(char *name, char *user, uint32_t size) {
  /* Name, user or size cannot be null */
  if (name == NULL || user == NULL || size < 2) return SGX_ERROR_UNEXPECTED;
  /* Vault not initialized */
  if (vault_pass == NULL) return SGX_ERROR_UNEXPECTED;

  /* Get the matching account */
  account_t *account = get_account(name);
  if (account == NULL || size < strlen(account->user) + 1)
    return SGX_ERROR_UNEXPECTED;

  memcpy(user, account->user, strlen(account->user) + 1);
  return SGX_SUCCESS;
}

sgx_status_t get_password(char *name, char *pass, uint32_t size) {
  /* Name, pass or size cannot be null */
  if (name == NULL || pass == NULL || size < 2) return SGX_ERROR_UNEXPECTED;
  /* Vault not initialized */
  if (vault_pass == NULL) return SGX_ERROR_UNEXPECTED;

  /* Get the matching account */
  account_t *account = get_account(name);
  if (account == NULL || size < strlen(account->pass) + 1)
    return SGX_ERROR_UNEXPECTED;

  memcpy(pass, account->pass, strlen(account->pass) + 1);
  return SGX_SUCCESS;
}
