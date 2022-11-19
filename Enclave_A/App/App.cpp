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

char *fifoSend = "/tmp/fifoA";
char *fifoReceive = "/tmp/fifoB";

/*****
BEGIN 1. A_A SEND PUBLIC KEY
*****/
void sendPubKey(sgx_ec256_public_t pubKey) {
    mkfifo("/tmp/fifoA", 0666);
    int pipe = open("/tmp/fifoA", O_WRONLY);
    char* buf = new char[32];
    for (int i = 0; i < 32; i ++) {
        buf[i] = (char) pubKey.gx[i];
    }
    // public key is 256 bits
    write(pipe, buf, 32);
    for (int i = 0; i < 32; i ++) {
        buf[i] = (char) pubKey.gy[i];
    }
    write(pipe, buf, 32);
    close(pipe);
}
/*****
END 1. A_A SEND PUBLIC KEY
*****/

/*****
BEGIN 1. A_A RECEIVE PUBLIC KEY
*****/
sgx_ec256_public_t receivePubKey() {
    mkfifo("/tmp/fifoB", 0666);
    int pipe = open("/tmp/fifoB", O_RDONLY);
    // public key is 256 bits
    sgx_ec256_public_t pubKey;
    read(pipe, pubKey.gx, 32);
    read(pipe, pubKey.gy, 32);
    close(pipe);
    return pubKey;
}
/*****
END 1. A_A RECEIVE PUBLIC KEY
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

    sgx_status_t sgx_status;

    sgx_status_t ret;
    sgx_ec256_public_t pubKeyA;

    ret = eccKeyPair(global_eid, &sgx_status, &pubKeyA);
    if (ret == SGX_SUCCESS) {
        printf("Enclave_A created\n");
    } else {
        printf("Enclave_A not created\n");
        print_error_message(ret);
    }

    /*****
    BEGIN 1. A_A SEND PUBLIC KEY
    *****/
    sendPubKey(pubKeyA);
    printf("A has sended public key\n");
    /*****
    END 1. A_A SEND PUBLIC KEY
    *****/

   /*****
    BEGIN 1. A_A RECEIVE PUBLIC KEY
    *****/
    sgx_ec256_public_t pubKeyB = receivePubKey();
    printf("A has received public key\n");
    printf(pubKeyB.gx);
    /*****
    END 1. A_A RECEIVE PUBLIC KEY
    *****/

   /*****
    BEGIN 3. A_A CALCULATE SHARED SECRET
    *****/
    ret = sharedSecret(global_eid, &sgx_status, &pubKeyB);
    if (ret == SGX_SUCCESS) {
        printf("Enclave_A calculated shared key\n");
    } else {
        printf("Enclave_A could not calculate shared key\n");
        print_error_message(ret);
    }
   /*****
    END 3. A_A CALCULATE SHARED SECRET
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
