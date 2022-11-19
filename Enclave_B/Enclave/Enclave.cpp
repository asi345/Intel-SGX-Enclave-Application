#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "sgx_tcrypto.h"


int enclave_secret = 42;

sgx_status_t ret;

sgx_ecc_state_handle_t *p_ecc_handle;
sgx_ec256_private_t *p_private;
sgx_ec256_public_t *p_public;

sgx_ec256_dh_shared_t *p_shared_key;
sgx_aes_ctr_128bit_key_t *p_key;


/*****
BEGIN 2. E_B GENERATE KEY PAIR
*****/
sgx_status_t eccKeyPair(sgx_ec256_public_t *p_public_key) {
  ret = sgx_ecc256_open_context(p_ecc_handle);
  if (ret != SGX_SUCCESS)
    return ret;

  ret = sgx_ecc256_create_key_pair(p_private, p_public, *p_ecc_handle);
  if (ret != SGX_SUCCESS)
    return ret;
  
  // ecc key size = 256 bits = 32 bytes
  for (int i = 0; i < 32; i++) {
    p_public_key->gx[i] = p_public->gx[i];
    p_public_key->gy[i] = p_public->gy[i];
  }

  return SGX_SUCCESS;
}
/*****
END 2. E_B GENERATE KEY PAIR
*****/

/*****
BEGIN 3. E_B CALCULATE SHARED SECRET
*****/
sgx_status_t sharedSecret(sgx_ec256_public_t *p_pubKey) {
  ret = sgx_ecc256_compute_shared_dhkey(p_private, p_pubKey, p_shared_key, *p_ecc_handle);
  if (ret != SGX_SUCCESS)
    return ret;

  // AESCTR key will be 128-bit = 16 bytes length
  for (int i = 0; i < 16; i++) {
    *(p_key + i) = p_shared_key->s[i];
  }

  return SGX_SUCCESS;
}
/*****
END 3. E_B CALCULATE SHARED SECRET
*****/

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

sgx_status_t printSecret()
{
  char buf[BUFSIZ] = {"From Enclave: Hello from the enclave.\n"};
  ocall_print_string(buf);
  printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
  return SGX_SUCCESS;
}
