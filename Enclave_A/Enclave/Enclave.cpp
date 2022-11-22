#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

int enclave_secret = 1337;

sgx_status_t ret;

sgx_ecc_state_handle_t ecc_handle;
sgx_ec256_private_t private_key;
sgx_ec256_public_t public_key;

sgx_ec256_dh_shared_t shared_key;
sgx_aes_ctr_128bit_key_t key;

// initialization vector should be ctr key size = 128 bits
unsigned char IV[16];
const char PSK_A[] = "I AM ALICE";

// the challenge numbers to be added
uint8_t a;
uint8_t b;

/*****
BEGIN 2. E_A GENERATE KEY PAIR
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
END 2. E_A GENERATE KEY PAIR
*****/

/*****
BEGIN 3. E_A CALCULATE SHARED SECRET
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
END 3. E_A CALCULATE SHARED SECRET
*****/

/*****
BEGIN 1. E_A ENCRYPTED PSK
*****/
sgx_status_t encPsk(uint8_t *c, unsigned char *p_IV) {
  ret = sgx_read_rand(IV, 16);
  if (ret != SGX_SUCCESS)
    return ret;

  for (int i = 0; i < 16; i++) {
    p_IV[i] = IV[i];
  }

  // length of PSK is 11 bytes
  ret = sgx_aes_ctr_encrypt(&key, (const uint8_t*) PSK_A, 11, IV, 1, c);
  if (ret != SGX_SUCCESS)
    return ret;
  
  return SGX_SUCCESS;
}
/*****
END 1. E_A ENCRYPTED PSK
*****/

/*****
BEGIN 1. E_A DECRYPTED PSK
*****/
sgx_status_t decPsk(uint8_t *c, unsigned char *p_IV) {
  uint8_t m[11];
  ret = sgx_aes_ctr_decrypt(&key, c, 11, p_IV, 1, m);
  if (ret != SGX_SUCCESS)
    return ret;

  const char PSK_B[] = "I AM BOBOB";
  for (int i = 0; i < 11; i++) {
    uint8_t ch = (uint8_t) PSK_B[i];
    if (ch != m[i + 11]) {
      printf("A could not verify identity of B\n");
      return SGX_ERROR_UNEXPECTED;
    }
  }

  return SGX_SUCCESS;
}
/*****
END 1. E_A DECRYPTED PSK
*****/

/*****
BEGIN 4. E_A GENERATE AND ENCRYPT CHALLENGE
*****/
sgx_status_t genChal(uint8_t *cA, uint8_t *cB) {
  ret = sgx_read_rand(&a, 1);
  if (ret != SGX_SUCCESS)
    return ret;

  ret = sgx_read_rand(&b, 1);
  if (ret != SGX_SUCCESS)
    return ret;

  uint8_t IV_zero[16];
  for (int i = 0; i < 16; i ++) {
    IV_zero[i] = 0;
  }

  printf("numbers %d-%d", a, b);

  // length of numbers is 2 bytes
  ret = sgx_aes_ctr_encrypt(&key, &a, 1, IV_zero, 1, cA);
  if (ret != SGX_SUCCESS)
    return ret;
  
  ret = sgx_aes_ctr_encrypt(&key, &b, 1, IV_zero, 1, cB);
  if (ret != SGX_SUCCESS)
    return ret;

  printf("c enc %d-%d-%d-%d", IV_zero[14], IV_zero[15], *cA, *cB);
  
  return SGX_SUCCESS;
}
/*****
END 4. E_A GENERATE AND ENCRYPT CHALLENGE
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
  char buf[BUFSIZ] = {"From Enclave: Hello from the enclave A.\n"};
  ocall_print_string(buf);
  printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
  return SGX_SUCCESS;
}
