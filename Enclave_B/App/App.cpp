#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include "sgx_tcrypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cstdio>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

/*****
BEGIN 1. A_B SEND PUBLIC KEY
*****/
void sendPubKey(sgx_ec256_public_t pubKey) {
    mkfifo("/tmp/fifoB", 0666);
    int pipe = open("/tmp/fifoB", O_WRONLY);
    // public key is 256 bits
    write(pipe, pubKey.gx, 32);
    write(pipe, pubKey.gy, 32);
    close(pipe);
}
/*****
END 1. A_B SEND PUBLIC KEY
*****/

/*****
BEGIN 1. A_B RECEIVE PUBLIC KEY
*****/
sgx_ec256_public_t receivePubKey() {
    mkfifo("/tmp/fifoA", 0666);
    int pipe = open("/tmp/fifoA", O_RDONLY);
    // public key is 256 bits
    sgx_ec256_public_t pubKey;
    read(pipe, pubKey.gx, 32);
    read(pipe, pubKey.gy, 32);
    close(pipe);
    return pubKey;
}
/*****
END 1. A_B RECEIVE PUBLIC KEY
*****/

/*****
BEGIN 1. A_B SEND ENCRYPTED PSK
*****/
void sendEncPSK(uint8_t *c, unsigned char *IV) {
    mkfifo("/tmp/fifoB2", 0666);
    int pipe = open("/tmp/fifoB2", O_WRONLY);
    // psk is 11 bytes
    write(pipe, IV, 16);
    write(pipe, c, 11);
    close(pipe);
}
/*****
END 1. A_B SEND ENCRYPTED PSK
*****/

/*****
BEGIN 1. A_B RECEIVE ENCRYPTED PSK
*****/
void receiveEncPSK(uint8_t *c, unsigned char *IV) {
    mkfifo("/tmp/fifoA2", 0666);
    int pipe = open("/tmp/fifoA2", O_RDONLY);
    read(pipe, IV, 16);
    read(pipe, c, 11);
    close(pipe);
}
/*****
END 1. A_B RECEIVE ENCRYPTED PSK
*****/

/*****
BEGIN 1. A_B RECEIVE ENCRYPTED CHALLENGE
*****/
void receiveEncChal(uint8_t *c, unsigned char *IV) {
    mkfifo("/tmp/fifoA3", 0666);
    int pipe = open("/tmp/fifoA3", O_RDONLY);
    read(pipe, IV, 16);
    read(pipe, c, 2);
    printf("rec %d, %d", (uint8_t) IV[0], c[0]);
    close(pipe);
}
/*****
END 1. A_B RECEIVE ENCRYPTED CHALLENGE
*****/

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enclave initialization failed.\n");
        return -1;
    }
    printf("From App: Enclave creation success. \n");  
    printf("From App: Write your protocol here ... \n");


    sgx_status_t sgx_status;
    sgx_status_t ret;

    sgx_ec256_public_t pubKeyB;

    ret = eccKeyPair(global_eid, &sgx_status, &pubKeyB);
    if (ret == SGX_SUCCESS) {
        printf("Enclave_B created\n");
    } else {
        printf("Enclave_B not created\n");
        print_error_message(ret);
    }

    /*****
    BEGIN 1. A_B SEND PUBLIC KEY
    *****/
    sendPubKey(pubKeyB);
    printf("B has sended public key\n");
    /*****
    END 1. A_B SEND PUBLIC KEY
    *****/

   /*****
    BEGIN 1. A_B RECEIVE PUBLIC KEY
    *****/
    sgx_ec256_public_t pubKeyA = receivePubKey();
    printf("B has received public key\n");
    /*****
    END 1. A_B RECEIVE PUBLIC KEY
    *****/

   /*****
    BEGIN 3. A_B CALCULATE SHARED SECRET
    *****/
    ret = sharedSecret(global_eid, &sgx_status, &pubKeyA);
    if (ret == SGX_SUCCESS) {
        printf("Enclave_B calculated shared key\n");
    } else {
        printf("Enclave_B could not calculate shared key\n");
        print_error_message(ret);
    }
   /*****
    END 3. A_B CALCULATE SHARED SECRET
    *****/

   uint8_t c[11];
   unsigned char IV[16];
   /*****
    BEGIN 1. A_B SEND ENCRYPTED PSK
    *****/
   encPsk(global_eid, &sgx_status, c, IV);
   if (sgx_status == SGX_SUCCESS) {
        printf("Enclave_B has sent encrypted PSK\n");
    } else {
        printf("Enclave_B could not send encrypted PSK\n");
        print_error_message(sgx_status);
    }
    sendEncPSK(c, IV);
    printf("B has sent encrypted PSK\n");
   /*****
    END 1. A_B SEND ENCRYPTED PSK
    *****/

   uint8_t c2[11];
   unsigned char IV2[16];

   /*****
    BEGIN 1. A_B RECEIVE ENCRYPTED PSK
    *****/
   receiveEncPSK(c2, IV2);
   printf("B has received encrypted PSK\n");
   decPsk(global_eid, &sgx_status, c2, IV2);
   if (sgx_status == SGX_SUCCESS) {
        printf("Enclave_B has decrypted PSK and verified A\n");
    } else {
        printf("Enclave_B could not decrypt PSK\n");
        print_error_message(sgx_status);
    }
   /*****
    END 1. A_B RECEIVE ENCRYPTED PSK
    *****/

   uint8_t c3[2];
   unsigned char IV3[16];

   /*****
    BEGIN 1. A_B RECEIVE ENCRYPTED CHALLENGE
    *****/
    receiveEncChal(c3, IV3);
    printf("B has received the challenge from A\n");
    decChal(global_eid, &sgx_status, c3, IV3);
    if (sgx_status == SGX_SUCCESS) {
        printf("Enclave_B has decrypted the challenge\n");
    } else {
        printf("Enclave_B could not decrypt the challenge\n");
        print_error_message(sgx_status);
    }
   /*****
    END 1. A_B RECEIVE ENCRYPTED CHALLENGE
    *****/

    printSecret(global_eid, &sgx_status);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("From App: Enclave destroyed.\n");
    return 0;
}

