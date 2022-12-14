#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"


int enclave_secret = 42;

sgx_status_t ret;

sgx_ecc_state_handle_t ecc_handle;
sgx_ec256_private_t private_key;
sgx_ec256_public_t public_key;

sgx_ec256_dh_shared_t shared_key;
sgx_aes_ctr_128bit_key_t key;

// initialization vector should be ctr key size = 128 bits
uint8_t IV_zero[16];
const char PSK_B[] = "I AM BOBOB";

// the challenge numbers to be added
uint8_t a;
uint8_t b;

uint8_t sum;

/*****
BEGIN 2. E_B GENERATE KEY PAIR
*****/
sgx_status_t eccKeyPair(sgx_ec256_public_t *p_public_key) {
  ret = sgx_ecc256_open_context(&ecc_handle);
  if (ret != SGX_SUCCESS)
    return ret;

  ret = sgx_ecc256_create_key_pair(&private_key, &public_key, ecc_handle);
  if (ret != SGX_SUCCESS)
    return ret;
  
  // ecc key size = 256 bits = 32 bytes
  for (int i = 0; i < 32; i++) {
    p_public_key->gx[i] = public_key.gx[i];
    p_public_key->gy[i] = public_key.gy[i];
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
  ret = sgx_ecc256_compute_shared_dhkey(&private_key, p_pubKey, &shared_key, ecc_handle);
  if (ret != SGX_SUCCESS)
    return ret;

  // AESCTR key will be 128-bit = 16 bytes length
  for (int i = 0; i < 16; i++) {
    key[i] = shared_key.s[i];
  }
  
  return SGX_SUCCESS;
}
/*****
END 3. E_B CALCULATE SHARED SECRET
*****/

/*****
BEGIN 1. E_B ENCRYPTED PSK
*****/
sgx_status_t encPsk(uint8_t *c) {

  for (int i = 0; i < 16; i ++) {
    IV_zero[i] = 0;
  }

  // length of PSK is 11 bytes
  ret = sgx_aes_ctr_encrypt(&key, (const uint8_t*) PSK_B, 11, IV_zero, 1, c);
  if (ret != SGX_SUCCESS)
    return ret;
  
  return SGX_SUCCESS;
}
/*****
END 1. E_B ENCRYPTED PSK
*****/

/*****
BEGIN 1. E_B DECRYPTED PSK
*****/
sgx_status_t decPsk(uint8_t *c) {
  uint8_t m[11];
  ret = sgx_aes_ctr_decrypt(&key, c, 11, IV_zero, 1, m);
  if (ret != SGX_SUCCESS)
    return ret;

  const char PSK_A[] = "I AM ALICE";
  for (int i = 0; i < 11; i++) {
    uint8_t ch = (uint8_t) PSK_A[i];
    if (ch != m[i + 11]) {
      printf("B could not verify identity of A\n");
      return SGX_ERROR_UNEXPECTED;
    }
  }

  return SGX_SUCCESS;
}
/*****
END 1. E_B DECRYPTED PSK
*****/

/*****
BEGIN 6. E_B DECRYPTED CHALLENGE
*****/
sgx_status_t decChal(uint8_t *cA, uint8_t *cB) {
  ret = sgx_aes_ctr_decrypt(&key, cA, 1, IV_zero, 1, &a);
  if (ret != SGX_SUCCESS)
    return ret;

  ret = sgx_aes_ctr_decrypt(&key, cB, 1, IV_zero, 1, &b);
  if (ret != SGX_SUCCESS)
    return ret;
  
  return SGX_SUCCESS;
}
/*****
END 6. E_B DECRYPTED CHALLENGE
*****/

/*****
BEGIN 7. E_B ENCRYPTED RESPONSE
*****/
sgx_status_t encResp(uint8_t *c) {
  sum = a + b;

  ret = sgx_aes_ctr_encrypt(&key, &sum, 1, IV_zero, 1, c);
  if (ret != SGX_SUCCESS)
    return ret;
  
  return SGX_SUCCESS;
}
/*****
END 7. E_B ENCRYPTED RESPONSE
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
