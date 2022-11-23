------------------------------
How to Run and See the Outputs
------------------------------
Clean the environment from earlier compilations
$ ./cleaner.sh

Run the project
$ ./run.sh

See the outputs from App A
$ cat App_A_output.txt

See the outputs from App B
$ cat App_B_output.txt

The output files shows an execution flow and confirms the tasks that were done.
One could check if the challenge was successful by checking if the outpus are
positive. If in the output of App A, 'A HAS VERIFIED THE RESPONSE FROM B AS TRUE'
is written, then it means that the challenge is solved successfully. If in the
output of A, 'A HAS VERIFIED THE RESPONSE FROM B AS FALSE' is written, then it
means that the challenge has failed because of an error in some part of the
program.


------------------------
Purpose of SampleEnclave
------------------------
The project demonstrates several fundamental usages of Intel(R) Software Guard 
Extensions (Intel(R) SGX) SDK:
- Initializing and destroying an enclave
- Creating ECALLs or OCALLs
- Calling trusted libraries inside the enclave

------------------------------------
How to Build/Execute the Sample Code
------------------------------------
1. Install Intel(R) SGX SDK for Linux* OS
2. Make sure your environment is set:
    $ source ${sgx-sdk-install-path}/environment
3. Build the project with the prepared Makefile:
    a. Hardware Mode, Debug build:
        1) Enclave with no mitigation:
            $ make
        2) Enclave with mitigations for indirects and returns only:
            $ make MITIGATION-CVE-2020-0551=CF
        3) Enclave with full mitigation:
            $ make MITIGATION-CVE-2020-0551=LOAD
    b. Hardware Mode, Pre-release build:
        1) Enclave with no mitigation:
            $ make SGX_PRERELEASE=1 SGX_DEBUG=0
        2) Enclave with mitigations for indirects and returns only:
            $ make SGX_PRERELEASE=1 SGX_DEBUG=0 MITIGATION-CVE-2020-0551=CF
        3) Enclave with full mitigation:
            $ make SGX_PRERELEASE=1 SGX_DEBUG=0 MITIGATION-CVE-2020-0551=LOAD
    c. Hardware Mode, Release build:
        1) Enclave with no mitigation:
            $ make SGX_DEBUG=0
        2) Enclave with mitigations for indirects and returns only:
            $ make SGX_DEBUG=0 MITIGATION-CVE-2020-0551=CF
        3) Enclave with full mitigation:
            $ make SGX_DEBUG=0 MITIGATION-CVE-2020-0551=LOAD
    d. Simulation Mode, Debug build:
        $ make SGX_MODE=SIM
    e. Simulation Mode, Pre-release build:
        $ make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
    f. Simulation Mode, Release build:
        $ make SGX_MODE=SIM SGX_DEBUG=0
4. Execute the binary directly:
    $ ./app
5. Remember to "make clean" before switching build mode

------------------------------------------
Explanation about Configuration Parameters
------------------------------------------
TCSMaxNum, TCSNum, TCSMinPool

    These three parameters will determine whether a thread will be created
    dynamically  when there is no available thread to do the work.


StackMaxSize, StackMinSize

    For a dynamically created thread, StackMinSize is the amount of stack available
    once the thread is created and StackMaxSize is the total amount of stack that
    thread can use. The gap between StackMinSize and StackMaxSize is the stack
    dynamically expanded as necessary at runtime.

    For a static thread, only StackMaxSize is relevant which specifies the total
    amount of stack available to the thread.


HeapMaxSize, HeapInitSize, HeapMinSize

    HeapMinSize is the amount of heap available once the enclave is initialized.

    HeapMaxSize is the total amount of heap an enclave can use. The gap between
    HeapMinSize and HeapMaxSize is the heap dynamically expanded as necessary
    at runtime.

    HeapInitSize is here for compatibility.

-------------------------------------------------    
Sample configuration files for the Sample Enclave
-------------------------------------------------
config.01.xml: There is no dynamic thread, no dynamic heap expansion.
config.02.xml: There is no dynamic thread. But dynamic heap expansion can happen.
config.03.xml: There are dynamic threads. For a dynamic thread, there's no stack expansion.
config.04.xml: There are dynamic threads. For a dynamic thread, stack will expanded as necessary.

-------------------------------------------------
Launch token initialization
-------------------------------------------------
If using libsgx-enclave-common or sgxpsw under version 2.4, an initialized variable launch_token needs to be passed as the 3rd parameter of API sgx_create_enclave. For example,

sgx_launch_token_t launch_token = {0};
sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, launch_token, NULL, &global_eid, NULL);
