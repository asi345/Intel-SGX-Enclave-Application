### Steps to compile and run your project here ###
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
One could check if the challenge was successful by checking if the outputs are
positive. If in the output of App A, 'A HAS VERIFIED THE RESPONSE FROM B AS TRUE'
is written, then it means that the challenge is solved successfully. If in the
output of A, 'A HAS VERIFIED THE RESPONSE FROM B AS FALSE' is written, then it
means that the challenge has failed because of an error in some part of the
program.