#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "sgx_tcrypto.h"


int enclave_secret = 42;

sgx_status_t ret;

sgx_ecc_state_handle_t ecc_handle;
sgx_ec256_private_t private;
sgx_ec256_public_t public;

sgx_ec256_dh_shared_t shared_key;
sgx_aes_ctr_128bit_key_t key;


/*****
BEGIN 2. E_B GENERATE KEY PAIR
*****/
sgx_status_t eccKeyPair(sgx_ec256_public_t *p_public_key) {
  ret = sgx_ecc256_open_context(&ecc_handle);
  if (ret != SGX_SUCCESS)
    return ret;

  ret = sgx_ecc256_create_key_pair(&private, &public, ecc_handle);
  if (ret != SGX_SUCCESS)
    return ret;
  
  // ecc key size = 256 bits = 32 bytes
  for (int i = 0; i < 32; i++) {
    p_public_key->gx[i] = public.gx[i];
    p_public_key->gy[i] = public.gy[i];
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
  printf("startingB");
  ret = sgx_ecc256_compute_shared_dhkey(&private, p_pubKey, &shared_key, ecc_handle);
  if (ret != SGX_SUCCESS)
    return ret;

  printf("compute babyB");
  // AESCTR key will be 128-bit = 16 bytes length
  for (int i = 0; i < 16; i++) {
    key[i] = shared_key.s[i];
  }
  printf("are we good??B");
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
  char buf[BUFSIZ] = {"From Enclave: Hello from the enclave B.\n"};
  ocall_print_string(buf);
  printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
  return SGX_SUCCESS;
}
