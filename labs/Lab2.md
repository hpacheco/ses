
# Lab 2 - Testing for security

In the previous lab we have looked into dynamic and static analyses techniques to find vulnerabilities in the internal behavior of programs.
Another essential process of secure software design is that of software testing, i.e., providing inputs for the programs and checking the outputs of programs against such inputs.
On top of classical software testing techniques, such as unit testing, various automated testing approaches propose to complement existing software testing efforts by facilitating the writing of tests and improving test coverage.

In this lab we will look at two techniques that, both separately and combined, have proven to be valuable additions for finding serious bugs that have been lying in software for a long time (see [these](https://github.com/google/fuzzer-test-suite) examples):
* **fuzzing**, a black-box testing technique that consists in *blindly* generating a wide set of random program-independent inputs according to some genetic algorithm;
* **symbolic execution**, a white-box testing technique that consists in substituting program inputs by symbolic (undefined) values and partially evaluating the program; an outcome of the program exploration is to generate program-dependent tests for symbolic inputs.
* **concolic execution** is a software testing technique that combines symbolic execution with concrete execution of particular inputs, e.g. generated using fuzzing.
Fuzzing, symbolic execution and concolic execution are a currently hot research topic, and there are many experimental academic tools being proposed recently. The [FuzzBench](https://google.github.io/fuzzbench/) project is an effort to standardize benchmarks of such tools.

## [Radamsa](https://gitlab.com/akihe/radamsa)

Radamsa is a black-box fuzzing tool that generates random program inputs by mutating some given input. Radamsa is fully scriptable, and so far has been successful in finding vulnerabilities in various real-world applications.

Radamsa is simply a command-line tool that receives a file with some data to mutate and returns various possible mutations. We can control command-line parameters such as the number of mutations or the *seeds* (randomness) used for generation of mutations, as in the following example:
<details>
<summary>Result</summary>

```ShellSession
$ cd c/misc/wisdom            
1aaaaaaaa
$ radamsa inputs/1 -n 3 -s 564
4294967295aaaaaaaa
-42949672964294967295aaaaaaaa
170141183460469231731687303715884105727aaaaaaaa
```
</details>

Radamsa by itself is not a testing framework. Therefore, in order to run generated test cases against an application, we have to script the testing logic ourselves. We will use a simple example borrowed from this [course](https://www.coursera.org/learn/software-security). Consider an interactive C program [wisdom-alt.c](../c/misc/wisdom/wisdom-alt.c) that has two modes: storing a secret string or displaying a stored secret string. We have written a a Python script [fuzz.py](../c/misc/wisdom/fuzz.py) that connects the output from radamsa to the input of the wisdom program and reads the initial data from the [inputs/1](../c/misc/wisdom/inputs/1) file; it will mutate the input data using different seeds and, in each run, send the mutated data line by line to the interactive wisdom program. You may run this example as follows:
<details>
<summary>Result</summary>

```ShellSession
$ gcc wisdom-alt.c -o wisdom-alt
$ python3 fuzz.py ./wisdom-alt 
```
</details>

The fuzzer will quickly find a bug, i.e., record a crash. Why did the program crash? You can replicate the same behavior by running the program manually. You can also edit [fuzz.py](../c/misc/wisdom/fuzz.py) to change the input data, the seed or have radamsa generate different inputs.

As you may perceive, it turns out that the bug occurs an invalid menu option (that is not 1 or 2) is passed to the interactive program.
The file [wisdom-alt2.c](../c/misc/wisdom/wisdom-alt2.c) contains an additional guard to ignore invalid options; this change fixis the previous bug. You may run the second wisdom program as before:
<details>
<summary>Result</summary>

```ShellSession
$ gcc wisdom-alt2.c -o wisdom-alt2
$ python3 fuzz.py ./wisdom-alt2
```
</details>

This time, the fuzzer will not find a sequence of interactive inputs that crashes the program.
But how certain can we be about the effectiveness of the fuzzer? Since it is essentially generating random inputs, hoping to find a crashing execution may come down to mere chance. As an experiment, [fuzz2.py](../c/misc/wisdom/fuzz.py) changes the input fuzzing file from [inputs/1](../c/misc/wisdom/inputs/1) to [inputs/2](../c/misc/wisdom/inputs/2). Re-run the fuzzer; it will now find a crashing execution, why? You will notice that finding a crash depends on the input length.

## [KLEE](https://klee.github.io/)

KLEE is a symbolic execution tool which can significantly beat the coverage of developer’s own hand-written test suites.
KLEE is able to automatically generated high-coverage test inputs that perform better than the poor performance of manual and random testing approaches. It does so by forking symbolic variables on program branches, to make sure that if generates inputs to check every possible program path. In practice, KLEE will not have 100% program coverage: evaluating all program executions is a computationally expensive and undecidable problem, and hence, like all symbolic execution techniques, KLEE needs to compromise on a maximum path depth.

The KLEE tool is a white-box testing instrument that runs on LLVM bitcode.
To try symbolic on the wisdom program, we have to modify it to identify which variables KLEE should treat as symbolic.

### Wisdom example

Borrowing again from this [course](https://www.coursera.org/learn/software-security), the changes in [wisdom-alt-klee.c](../c/misc/wisdom/wisdom-alt-klee.c) are the following:
* we replace the external call to `gets` for a function `sym_gets` with an infinite loop that simulates the generation of a varying-size sequence of symbolic characters determined by their ASCII code;
* we remove the loop that repeatedly requests user input; this is just a simplification that speeds up our testing because we only need one input to find the bug, and KLEE will repeatedly explore different inputs;
* we replace the command that `read`s the initial input to use the KLEE-specific `klee_make_symbolic` function, which returns a fixed-size symbolic array.

We will use a pre-configured docker container. Inside the [vm](../vm) folder, open a bash inside the KLEE container, compile the instrumented wisdom program to LLVM bytecode, and run KLEE:

<details>
<summary>Result</summary>

```ShellSession
$ make run-klee
klee@container# cd path/to/c/misc/wisdom/
klee@container# clang -I /home/klee/klee_src/include/ -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone wisdom-alt-klee.c
klee@container# klee wisdom-alt-klee.bc
Hello there                               
1. Receive wisdom
2. Add wisdom
Selection >KLEE: WARNING ONCE: resolved symbolic function pointer to: get_wisdom
KLEE: WARNING ONCE: resolved symbolic function pointer to: put_wisdom                                    
no wisdom                                                                                                
Enter some wisdom
KLEE: ERROR: wisdom-alt-klee.c:60: memory error: out of bound pointer
KLEE: NOTE: now ignoring this error at this location                                                     
KLEE: done: total instructions = 10428                                                                   
KLEE: done: completed paths = 132                                                                        
KLEE: done: generated tests = 132   
```
</details>

It should exit shortly and discover the error (an overflow related to the size of the array read from `gets`), printing a stack trace and some information about the current state. It will have created a directory `klee-last` in the current directory that contains further information about the symbolic execution. If you look in there, you will see that it generated some tests, error reports and some statistics.
The (binary) files ending in `.ktest` in this directory can be formatted intelligibly by using `ktest-tool`. Use the following commands to inspect the symbolic state that the error occurred in:

<details>
<summary>Result</summary>

```ShellSession
klee@container# ls klee-last | grep err
klee@container# ktest-tool klee-last/test000132.ktest
ktest file : 'klee-last/test000132.ktest'
args       : ['wisdom-alt-klee.bc']
num objects: 132
object   0: name: 'buf'
object   0: size: 20
object   0: data: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
object   0: hex : 0x0000000000000000000000000000000000000000
object   0: text: ....................
object   1: name: 'r'
object   1: size: 4
object   1: data: b'\x01\x00\x00\x00'
object   1: hex : 0x01000000
object   1: int : 1
object   1: uint: 1
object   1: text: ....
object   2: name: 'v'
object   2: size: 4
object   2: data: b'\x01\x00\x00\x00'
object   2: hex : 0x01000000
object   2: int : 1
object   2: uint: 1
object   2: text: ....
object   3: name: 'input'
object   3: size: 4
object   3: data: b'\x01\x00\x00\x00'
object   3: hex : 0x01000000
object   3: int : 1
object   3: uint: 1
object   3: text: ....
...
```
</details>

You may also simulate a run of the 

While we can run the test cases generated by KLEE on our program by hand, KLEE provides a convenient replay library, which simply replaces the calls to symbolic functions to assignments of the inputs stored in a `.ktest` file.
To run our erroneous test, you can recompile it with the `lkleeRuntest` library:

<details>
<summary>Result</summary>

```ShellSession
klee@container# export LD_LIBRARY_PATH=/home/klee/klee_build/lib/:$LD_LIBRARY_PATH
klee@container# gcc -I /home/klee/klee_src/include/ -L /home/klee/klee_build/lib/ wisdom-alt-klee.c -lkleeRuntest
klee@container# KTEST_FILE=klee-last/test000132.ktest ./a.out
$ echo $?
```
 </details>
 
The last command prints the test's output: it shall be 0 for successful tests and non-0 for failing tests.
For our erroneous tests, it shall fail. You can also confirm the error.

### Maze example

In a sense, a symbolic executor is exploring a maze defined by the program's execution space. We can make this analogy a reality by using KLEE to symbolically execute a program that asks its user to solve a maze. Check the [maze.c](../c/misc/maze/maze.c), taken from this blog [post](https://feliam.wordpress.com/2010/10/07/the-symbolic-maze/), that defines a maze-solving procedure.

Compile and run the program. We can solve the maze with the following input:
<details>
<summary>Result</summary>

```ShellSession
klee@container# cd path/to/c/misc/maze/
klee@container# gcc maze.c -o maze
klee@container# echo 'ssssddddwwaawwddddssssddwwww' | ./maze
...
Player pos: 9x2
Iteration no. 26. Action: w.
+-+---+---+
|X|XXXXX|#|
|X|X--+X|X|
|X|XXX|X|X|
|X+--X|X|X|
|XXXXX|XXX|
+-----+---+

You win!
Your solution <             ssssddddwwaawwddddssssddwwww>
```
</details>

The file [maze-klee.c](../c/misc/maze/maze-klee.c) is a slightly modified version of it with symbolic inputs. We also introduce a KLEE-specific assertion when the maze is solved, to make it easier to distinguish when KLEE finds a solution.
Compile the symbolic program for KLEE and run it.

<details>
<summary>Result</summary>

```ShellSession
$ make run-klee
klee@container# cd path/to/c/misc/maze/
klee@container# clang -I /home/klee/klee_src/include/ -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone maze-klee.c
klee@container# klee maze-klee.bc
```
</details>

KLEE will work for a while and then end. The maze program will generate an assertion failure when a path through the maze has been identified, so the test that is a winning path through the maze is identified as an error. Look for the path that solved the maze looking for a file that ends in `.err` inside the `klee-last` folder.

It turns out there are multiple "solutions" to the maze; you can see them all by passing the argument `--emit-all-errors` to KLEE.
As it turns out, something funny is going on: the found path is not even the length of the maze and somehow the solution is allowed to walk through walls. Look through the code, and find the condition that allows this to happen. What line is it on? Comment it out and try again: KLEE shall now find the only correct solution.

## [Blab](https://code.google.com/archive/p/ouspg/wikis/Blab.wiki)

Blab is a small tool for generating data according to grammars. It is intended to be used to generate data which has a known context-free structure, usually in order to be able to test programs or produce interesting sample data for fuzzers.

If we try to use a fuzzer like radamsa to solve our maze, it will unlikely succeed since since it does not know that only sequences of `wsad` characters are valid inputs. We can however improve by encoding such an input grammar using blab; check the [fuzz.py](../c/misc/maze/fuzz.py) which automates the search for a maze solution, you can run it as follows.

```ShellSession
$ cd path/to/c/misc/maze/
$ python3 fuzz.py ./maze 
```

Did it find a solution? You may try to improve the grammar, the seed or the number of attempts to make it so.

## [American Fuzzy Lopp (AFL)](https://github.com/google/AFL)

AFL is a white-box fuzzing tool which symbolically executes programs and takes the constraints of inputs into account to create dynamic tests. The tested program should first be compiled with a utility program to enable control flow tracking. Any behavioural changes as a response to the input can then be detected by the fuzzer. If there is no access to the source code, then blackbox testing is supported as well.

We will try a few examples from this AFL [tutorial](https://github.com/mykter/afl-training).

### Quickstart example

Consider the [vulnerable.c](../c/misc/quickstart/vulnerable.c) program, which simply reads a string from `stdin` and prints it to `stdout`.
Compile it for AFL and test it for some input:

```ShellSession
$ AFL_HARDEN=1 afl-clang-fast vulnerable.c -o vulnerable
$ ./vulnerable # Press enter to get usage instructions
$ ./vulnerable < inputs/u
```

Now fuzz it with AFL. The following command receives a folder `inputs` with input files that will serve as a base for mutations, and produces reports in folder `out`:
```ShellSession
$ afl-fuzz -i inputs -o out ./vulnerable
```
You will see an AFL menu with progress statistics, that will run indefinitely. Waait a few minutes until you see a few reported crashes, and stop the process with `CTRL+C`. You will then find the inputs that provoked crashes in the folder `out/default/crashes`. Try them out, and trace the bug back to the code.

### Heartbleed example

We can also see how to detect a real-world bug such as [Heartbleed](https://heartbleed.com/) in a complex library such as [OpenSSL](https://www.openssl.org/).
Heartbleed is a heap buffer overflow bug in the TLS handshake phase, that is triggered if a Heartbeat message is longer than its expected length. You may read more about the bug in resources such as [this](https://www.synopsys.com/blogs/software-security/heartbleed-bug/)

Start by pulling a buggy version of OpenSSL 1.0.1f from the official OpenSSL GitHub repository, and compiling it with AFL support; we also compile with Address Sanitizer support to detect memory errors [^1]. Building will take a while:
```ShellSession
$ cd c/misc/heartbleed/
$ git submodule --init --recursive
$ cd openssl
$ CC=afl-clang-fast CXX=afl-clang-fast++ ./config -d
$ AFL_USE_ASAN=1 make
```
The next step is to compile the [handshake.cc](../c/misc/heartbleed/handshake.cc) C++ program which performs a TLS handshake.
```ShellSession
$ cd ..
AFL_USE_ASAN=1 afl-clang-fast++ -g handshake.cc openssl/libssl.a openssl/libcrypto.a -o handshake -I openssl/include -ldl
```
We can now run the program with AFL to find the bug (note that this is not a working exploit, what would require a cleverly formed, malicious heartbeat message):
```ShellSession
$ afl-fuzz -i inputs -o out ./handshake
```
You may stop as soon as AFL finds a crash. Inspect the produced crash log.

[^1]: Address Sanitizer needs a lot of virtual memory, and by default AFL will limit the amount of memory a fuzzed software gets.
This may make your VM allocate a lot of memory and lead to random crashes; make sure that you are not running anything else important on the system.

## [Driller](https://github.com/shellphish/driller)

Driller is a concolic execution tool that explores only the paths that are found interesting by the fuzzer and uses symbolic execution to generate inputs for path branches that a fuzzer cannot satisfy. It uses AFL as a fuzzer and angr, a binary analysis framework, as a symbolic tracer over the executable's control flow graph.

Consider an example [buggy.c](../c/misc/buggy.c) program taken from this [article](https://blog.grimm-co.com/2020/05/guided-fuzzing-with-driller.html) that simply reads 6 bytes of input, checks them one by one against a sequence of characters, and crashes if all 6 of them match.
This is a typically hard program for a fuzzer to check without insight on the internal program behavior.
You may compile and test this program:
```ShellSession
$ gcc -o buggy buggy.c
$ echo 123456 | ./buggy
No problem
$ echo 7/42a8 | ./buggy
Segmentation fault (core dumped)
```

Let's now run a pre-packaged docker container, which contains a script, `shellphuzz`, that combines the AFL and Driller runs into a single command:
```ShellSession
$ echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first
$ make run-driller
driller@container# shellphuzz -d 1 -c 1 -w out -C --length-extension 4 ./buggy
```
This script will run until AFL finds the first crash. When it does, check the `out/buggy/sync/fuzzer-master/crashes` folder for the crash report.

## [Fuzzolic](https://github.com/season-lab/fuzzolic)

Fuzzolic is a concolic execution fuzzer with an approach similar to driller. It uses QEmu to analyze binaries and generate symbolic queries whose result may help in finding new test cases; such queries are discarded by a fuzzy (approximate) SAT solver.
Consider an [example.c](https://github.com/season-lab/fuzzolic/blob/master/tests/example/example.c) program which performs a conditional on a particular value. You may easily test this program using a pre-bundled docker container; change into the [vm](../vm) folder:
```ShellSessions
$ make run-fuzzolic
fuzzolic@container# gcc tests/example/example.c -o tests/example/example
fuzzolic@container# ./fuzzolic/fuzzolic.py -o ./workdir -i tests/example/inputs -- ./tests/example/example [args]
```
You may find more details about this example in the [documentation](https://season-lab.github.io/fuzzolic/usage.html#example). You may find more running examples in the [GitHub](https://github.com/season-lab/fuzzolic) repository.

Fuzzolic also provides automated support for alternating between fuzzolic and AFL, by feeding the generated fuzzolic test cases fo AFl and vice-versa. For the example program, you may try:
```ShellSession
fuzzolic@container# ./fuzzolic/run_afl_fuzzolic.py --address-reasoning --optimistic-solving --fuzzy -o workdir/ -i tests/example/inputs -- ./tests/example/example
```
**Remark:** Fuzzolic, and in particular its novel SAT solver, are experimental tools. It may be hard to understand why they fail for non-tested programs.

## [SymCC](https://github.com/eurecom-s3/symcc)

SymCC is a compiler wrapper which embeds symbolic execution into the program during compilation, and an associated run-time support library. In essence, the compiler inserts code that computes symbolic expressions for each value in the program. The actual computation happens through calls to the support library at run time.

You may build a docker container to try SymCC and AFL. Inside the [vm](../vm) folder, just try compiling the [buggy.c](../c/misc/buggy.c) example with SymCC, and running it: 
```ShellSession
$ make build-symcc
$ make run-symcc
symcc@container# ./symcc /path/to/ses/c/misc/buggy.c -o /path/to/ses/c/misc/buggy
symcc@container# mkdir results
symcc@container# export SYMCC_OUTPUT_DIR=`pwd`/results
symcc@container# echo 'aaaaaa' | ./path/to/ses/c/misc/buggy
```
SymCC will only perform one mutation: in the `results` folder, you will find a slightly mutated input, such as `7aaaaa`, that is informed by the conditional performed by the program and is closer to the bug.
You may automate fuzzing by providing a folder with initial inputs and using the following script:
```ShellSession
symcc@container# mkdir inputs #fill this folder with input files
symcc@container# ./util/pure_concolic_execution.sh -i inputs -o results /path/to/ses/c/misc/buggy
```
It will run indefinitely; stop it after a while and inspect the `results` folder. Can you find an input that causes the bug?

Even though it does not offer an not automated script, SymCC may also be combined with AFL similarly to fuzzolic; check the [documentation](https://github.com/eurecom-s3/symcc/blob/master/docs/Fuzzing.txt). 

## Tasks

The goal of this lab is to experiment with the testing tools described above. We will detect and fix the vulnerabilities found in example C programs from the [c/SARD-testsuite-100](../c/SARD-testsuite-100) testsuite. 
1. Study and try out the tools described above.
2. Choose one vulnerable programs from [c/SARD-testsuite-100](../c/SARD-testsuite-100) to analyse. It is not mandatory to choose examples from this dataset; you may also choose examples of vulnerable C programs from other resources such as, e.g., another [SARD dataset](https://samate.nist.gov/SARD/testsuite.php) or the [US-CERT dataset](https://www.cisa.gov/uscert/bsi/articles/tools/source-code-analysis/source-code-analysis-tools---example-programs).
4. Test your program with some of the above tools.
5. **In your group's GitHub repository, write a small report to the markdown file `Lab2.md`.**
6. The report shall discuss:
   * were you able to find the vulnerability? with which tools? why do you think that is the case?
   * how did you adapt the example code and/or the tool parameters?






