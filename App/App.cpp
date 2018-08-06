#include <fstream>
#include <iostream>

using namespace std;

#include "sgx_urts.h"

#include "Enclave_u.h"
#include "Utils.h"

sgx_enclave_id_t enclave_id = 0;

#define VAULT_FILE "vault.dat"

int main(int argc, char *argv[]) {
  int retcode = 0;
  sgx_status_t ret, status;
  uint8_t *vault_data = NULL;
  int option = -1;

  /* Initialize the enclave */
  cout << ". Initializing enclave..." << endl;
  if (initialize_enclave() < 0) {
    cout << "! Failed to initialize enclave" << endl;
    return -1;
  }

  {
    /* Initialize the vault */
    ifstream infile(VAULT_FILE);
    if (infile.good()) {
      cout << ". Loading vault data..." << endl;

      /* Get the passphrase */
      string passphrase;
      cout << "? Enter the passphrase: ";
      cin >> passphrase;

      /* Get vault size */
      infile.seekg(0, infile.end);
      uint32_t vault_size = infile.tellg();
      infile.seekg(0, infile.beg);

      /* Allocate buffer */
      vault_data = (uint8_t *)malloc(vault_size);

      /* Read vault file */
      infile.read((char *)vault_data, vault_size);

      /* Close vault file */
      infile.close();

      /* Call the enclave */
      cout << ". Sending vault data..." << endl;
      ret = load_vault(enclave_id, &status, vault_data, vault_size,
                       (char *)passphrase.c_str());
      fill_n(&passphrase[0], passphrase.capacity() - 1, 0xff);
      if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        free(vault_data);
        cout << "! Couldn't load vault into the enclave" << endl;
        cout << "! Maybe you entered a wrong passphrase" << endl;
        retcode = -1;
        goto destroy_enclave;
      }

      /* Free buffer */
      free(vault_data);
      vault_data = NULL;
      cout << ". Vault successfully loaded" << endl;
    } else {
      cout << ". Creating a vault..." << endl;

      /* Get a passphrase */
      string passphrase;
      cout << "? Enter a passphrase: ";
      cin >> passphrase;

      /* Create a vault */
      ret = new_vault(enclave_id, &status, (char *)passphrase.c_str());
      fill_n(&passphrase[0], passphrase.capacity() - 1, 0xff);
      if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        cout << "! Couldn't create a new vault" << endl;
        retcode = -1;
        goto destroy_enclave;
      }

      cout << ". Vault successfully created" << endl;
    }
  }

  /* Display the main menu */
  while (option != 0) {
    cout << ". MAIN MENU" << endl;
    cout << ". 1 - View an account" << endl;
    cout << ". 2 - Create an account" << endl;
    cout << ". 3 - Remove an account" << endl;
    cout << ". 0 - Exit the program" << endl;
    cout << "? What do you want to do: ";

    cin >> option;
    switch (option) {
      case 1: {
        /* Get the account name */
        string name;
        cout << "? What is the account name: ";
        cin >> name;

        /* Check if it exists */
        ret = has_account(enclave_id, &status, (char *)name.c_str());
        if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
          cout << "! This account doesn't exist!" << endl;
          continue;
        }

        /* Get the account user */
        string user;
        user.resize(256);
        ret = get_username(enclave_id, &status, (char *)name.c_str(),
                           (char *)user.c_str(), 256);
        if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
          cout << "! Couldn't get the username" << endl;
          continue;
        }
        user.resize(strlen(user.c_str()));
        cout << ". Username: " << user << endl;
        fill_n(&user[0], user.capacity() - 1, 0xff);

        /* Get the account pass */
        string pass;
        pass.resize(256);
        ret = get_password(enclave_id, &status, (char *)name.c_str(),
                           (char *)pass.c_str(), 256);
        if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
          cout << "! Couldn't get the password" << endl;
          continue;
        }
        pass.resize(strlen(pass.c_str()));
        cout << ". Password: " << string(pass) << endl;
        fill_n(&pass[0], pass.capacity() - 1, 0xff);
        break;
      }

      case 2: {
        /* Get the account name */
        string name;
        cout << "? What is the account name: ";
        cin >> name;

        /* Get the account user */
        string user;
        cout << "? What is the account username: ";
        cin >> user;

        /* Get the account pass */
        string pass;
        cout << "? What is the account password: ";
        cin >> pass;

        /* Create the account */
        ret = create_account(enclave_id, &status, (char *)name.c_str(),
                             (char *)user.c_str(), (char *)pass.c_str());
        fill_n(&user[0], user.capacity() - 1, 0xff);
        fill_n(&pass[0], pass.capacity() - 1, 0xff);
        if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
          cout << "! Couldn't create the account" << endl;
          continue;
        }
        cout << ". Account successfully created" << endl;
        break;
      }

      case 3: {
        /* Get the account name */
        string name;
        cout << "? What is the account name: ";
        cin >> name;

        /* Remove the account */
        ret = remove_account(enclave_id, &status, (char *)name.c_str());
        if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
          cout << "! Couldn't remove the account" << endl;
          continue;
        }
        cout << ". Account successfully removed" << endl;
        break;
      }
    }
  }

  {
    /* Vault destruction */
    cout << ". Saving vault data..." << endl;
    ofstream outfile(VAULT_FILE);

    /* Get vault size */
    uint32_t vault_sz;
    ret = vault_size(enclave_id, &status, &vault_sz);
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
      cout << "! Couldn't get the vault size" << endl;
      retcode = -1;
      goto destroy_enclave;
    }

    /* Allocate buffer */
    vault_data = (uint8_t *)malloc(vault_sz);

    /* Call the enclave */
    ret = save_vault(enclave_id, &status, vault_data, vault_sz);
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
      free(vault_data);
      cout << "! Couldn't save vault from the enclave" << endl;
      cout << "ret " << ret << " status " << status << endl;
      retcode = -1;
      goto destroy_enclave;
    }

    /* Write vault file */
    outfile.write((char *)vault_data, vault_sz);

    /* Close vault file */
    outfile.close();

    /* Free buffer */
    free(vault_data);
    vault_data = NULL;
  }

destroy_enclave:
  /* Destroy the enclave */
  sgx_destroy_enclave(enclave_id);
  printf(". Enclave successfully destroyed.\n");
  return retcode;
}
