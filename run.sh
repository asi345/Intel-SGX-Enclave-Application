touch /tmp/fifoA /tmp/fifoB /tmp/fifoA2 /tmp/fifoB2 /tmp/fifoA3 /tmp/fifoB3

cd Enclave_A
make clean
make SGX_MODE=SIM
./app > App_A_output.txt &

cd ../Enclave_B
make clean
make SGX_MODE=SIM
./app > App_B_output.txt &