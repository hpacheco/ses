
# Lab 2 - Testing for security

In the previous lab we have looked into dynamic and static analyses techniques to find vulnerabilities in the internal behavior of programs.
Another essential process of secure software design is that of software testing, i.e., providing inputs for the programs and checking the outputs of programs against such inputs.
On top of classical software testing techniques, such as unit testing, various automated testing approaches propose to complement existing software testing efforts by facilitating the writing of tests and improving test coverage.

In this lab we will look at two techniques that, both separately and combined, have proven to be valuable additions for finding serious bugs that have been lying in software for a long time (see [these](https://github.com/google/fuzzer-test-suite) examples):
* **fuzzing**, a black-box testing technique that consists in generating a large number of random program-independent inputs according to some input-generation algorithm;
* **symbolic execution**, a white-box testing technique that consists in substituting program inputs by symbolic (undefined) values and partially evaluating the program; an outcome of the program exploration is to generate program-dependent tests for symbolic inputs.
* **concolic execution** is a software testing technique that combines symbolic execution with concrete execution of particular inputs, e.g. generated using fuzzing.

Fuzzing, symbolic execution and concolic execution are a currently hot research topic, and there are many recently proposed tools that combine these techniques (to the point that the nomenclature is often "fuzzy"). The [FuzzBench](https://google.github.io/fuzzbench/) project is an effort to standardize benchmarks of such tools. You may get a visual picture of the ever-growing list of available techniques and tools in this [survey](https://github.com/SoftSec-KAIST/Fuzzing-Survey).

## Lab install

To install the specific tools that will be used in this lab, run:
```
cd ses/vm
git pull
sh install-fuzz.sh
```

## Topics & Additional References

Before we start, this lab will cover, by example, a series of testing techniques and tools. These topics are only introduced in the theoretical lectures in a broad sense and shortly introduced in this lab, which together should be sufficient for our experimentation. For a more in-depth contextualization or more technical detail, you may ask the instructors or check the following references:

* [Finding vulnerabilities by fuzzing, dynamic and static analysis](https://cs155.stanford.edu/lectures/06-testing.pdf) from [Computer and Network Security @ Stanford](https://cs155.stanford.edu/)
* [Fuzz Testing](https://cmu-program-analysis.github.io/2021/lecture-slides/17-fuzzing.pdf) from [Program Analysis @ CMU](https://cmu-program-analysis.github.io/2021/)
* [Symbolic and Concolic Execution](https://www.software-lab.org/teaching/winter2021/pa/lecture_symbolic_execution.pdf) from [Program Analysis @ Stuttgart](https://www.software-lab.org/teaching/winter2021/pa/)
* [Awesome Fuzzing](https://github.com/secfigo/Awesome-Fuzzing), a compilation of various books and tools.
* [Awesome Symbolic Execution](https://github.com/ksluckow/awesome-symbolic-execution), a compilation of various lectures and tools.


## [Radamsa](https://gitlab.com/akihe/radamsa)

Radamsa is a mutation-based fuzzing tool that generates random program inputs by mutating some given input. Radamsa is fully scriptable, and so far has been successful in finding vulnerabilities in various real-world applications.

Radamsa is simply a command-line tool that receives a file with some data to mutate and returns various possible mutations. We can control command-line parameters such as the number of mutations or the *seeds* (randomness) used for generation of mutations, as in the following example:
<details>
<summary>Result</summary>

```ShellSession
$ cd c/misc/wisdom   
$ cat inputs/1         
1aaaaaaaa
$ radamsa inputs/1 -n 3 -s 564
4294967295aaaaaaaa
-42949672964294967295aaaaaaaa
170141183460469231731687303715884105727aaaaaaaa
```
</details>

Radamsa by itself is not a testing framework. Therefore, in order to run generated test cases against an application, we have to script the testing logic ourselves. We will use a simple example borrowed from this [course](https://www.coursera.org/learn/software-security). Consider an interactive C program [wisdom-alt.c](../c/misc/wisdom/wisdom-alt.c) that has two modes: storing a secret string or displaying a stored secret string. We have written a Python script [fuzz.py](../c/misc/wisdom/fuzz.py) that connects the output from radamsa to the input of the wisdom program and reads the initial data from the [inputs/1](../c/misc/wisdom/inputs/1) file; it will mutate the input data using different seeds and, in each run, send the mutated data line by line to the interactive wisdom program. You may run this example as follows:
<details>
<summary>Result</summary>

```ShellSession
$ gcc wisdom-alt.c -o wisdom-alt
$ python3 fuzz.py ./wisdom-alt 
```
</details>

The fuzzer will quickly find a bug, i.e., record a crash. Why did the program crash? You can replicate the same behavior by running the program manually. You can also edit [fuzz.py](../c/misc/wisdom/fuzz.py) to change the input data, the seed or have radamsa generate different inputs.

As you may perceive, it turns out that the bug occurs when an invalid menu option (that is not 1 or 2) is passed to the interactive program.
The file [wisdom-alt2.c](../c/misc/wisdom/wisdom-alt2.c) contains an additional guard to ignore invalid options; this change fixes the previous bug. You may run the second wisdom program as before:
<details>
<summary>Result</summary>

```ShellSession
$ gcc wisdom-alt2.c -o wisdom-alt2
$ python3 fuzz.py ./wisdom-alt2
```
</details>

This time, the fuzzer will not find a sequence of interactive inputs that crashes the program.
But how certain can we be about the effectiveness of the fuzzer? Since it is essentially generating random inputs, hoping to find a crashing execution may come down to mere chance. As an experiment, [fuzz2.py](../c/misc/wisdom/fuzz2.py) changes the input fuzzing file from [inputs/1](../c/misc/wisdom/inputs/1) to [inputs/2](../c/misc/wisdom/inputs/2). Re-run the fuzzer; it will now find a crashing execution, why? You will notice that finding a crash depends on the input length.

## [KLEE](https://klee.github.io/)

KLEE is a symbolic execution tool which can significantly beat the coverage of developer’s own hand-written test suites.
KLEE is able to automatically generate high-coverage test inputs that perform better than the poor performance of manual and random testing approaches. It does so by forking symbolic variables on program branches, to make sure that if generates concrete inputs to check every possible program path. In practice, KLEE will not have 100% program coverage: evaluating all program executions is a computationally expensive and undecidable problem, and hence, like all symbolic execution techniques, KLEE needs to compromise on a maximum path depth.

The KLEE tool runs on LLVM bitcode.
Many other symbolic execution tools exist for non-LLVM languages. A few examples for reference:
* [Java Pathfinder](https://github.com/javapathfinder) is a highly extensible system to verify executable Java bytecode programs that can serve as a Java alternative to KLEE. It features extensions for symbolic execution of Java bytecode such as [SymbolicPathFinder](https://github.com/SymbolicPathFinder/jpf-symbc).
* [angr](https://docs.angr.io/) is a binary analysis platform that supports dynamic symbolic execution of both Java programs and Android applications.

To try KLEE on the wisdom program, we have to modify it to identify which variables KLEE should treat as symbolic.

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
klee@container# klee --libc=uclibc wisdom-alt-klee.bc
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

The `--libc` flag tells KLEE to replace standard `libc` functions by a symbolically-compiled `uclibc` implementation; it is natural to get some warning related to this.
KLEE shall run shortly and discover the error (an overflow related to the size of the array read from `gets`), printing a stack trace and some information about the current state. It will have created a directory `klee-last` in the current directory that contains further information about the symbolic execution. If you look in there, you will see that it generated some tests, error reports and some statistics.
The (binary) files ending in `.ktest` in this directory can be formatted intelligibly by using `ktest-tool`. Use the following commands to inspect the concrete state that the error occurred in:

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

In a sense, a symbolic execution tool is exploring a maze defined by the program's execution space. We can make this analogy a reality by using KLEE to symbolically execute a program that asks its user to solve a maze. Check the [maze.c](../c/misc/maze/maze.c), taken from this blog [post](https://feliam.wordpress.com/2010/10/07/the-symbolic-maze/), that defines a maze-solving procedure.

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

The file [maze-klee.c](../c/misc/maze/maze-klee.c) is a slightly modified version: we introduce a KLEE-specific assertion when the maze is solved, to make it easier to distinguish when KLEE finds a solution.
Compile the symbolic program for KLEE and run it. This time, we make the input a symbolic string with size 30 using command-line arguments.

<details>
<summary>Result</summary>

```ShellSession
$ make run-klee
klee@container# cd path/to/c/misc/maze/
klee@container# clang -I /home/klee/klee_src/include/ -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone maze-klee.c
klee@container# klee -posix-runtime maze-klee.bc -sym-stdin 30
```
</details>

KLEE will work for a while and then end. The maze program will generate an assertion failure when a path through the maze has been identified, so the test that is a winning path through the maze is identified as an error. Look for the path that solved the maze looking for a file that ends in `.err` inside the `klee-last` folder.

It turns out there are multiple "solutions" to the maze; you can see them all by passing the argument `--emit-all-errors` to KLEE.
As it turns out, something funny is going on: the found path is not even the length of the maze and somehow the solution is allowed to walk through walls. Look through the code, and find the condition that allows this to happen. What line is it on? Comment it out and try again: KLEE shall now find the single correct solution.

## [Blab](https://code.google.com/archive/p/ouspg/wikis/Blab.wiki)

Blab is a small tool for generating data according to grammars, and can be seen as a minimal for a generation-based fuzzer. It is intended to be used to generate data which has a known context-free structure, usually in order to be able to test programs or produce interesting sample data for fuzzers. Fuzzers that rely on a specification for the input format to generate test cases are often called generation-based fuzzers.

If we try to use a fuzzer like radamsa to solve our maze, it will unlikely succeed since since it does not know that only sequences of `wsad` characters are valid inputs. We can however improve by encoding such an input grammar using blab; check the [fuzz.py](../c/misc/maze/fuzz.py) which automates the search for a maze solution, you can run it as follows.

```ShellSession
$ cd path/to/c/misc/maze/
$ python3 fuzz.py ./maze 
```

Did it find a solution? You may try to improve the grammar, the seed or the number of attempts to make it so.

## [American Fuzzy Lopp (AFL)](https://github.com/google/AFL)

AFL is a coverage-guided fuzzing tool, often called a grey-box fuzzer, which takes into account the code coverage of tested inputs to understand if it is making progress and to make informed decisions about which inputs to mutate to maximize coverage. In a sense, it is a lightweight form of symbolic execution. The tested program should first be compiled with a utility program to enable control flow tracking. Any behavioural changes as a response to the input can then be detected by the fuzzer. If there is no access to the source code, then blackbox testing is supported as well.

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
Heartbleed is a heap buffer overflow bug in the TLS handshake phase, that is triggered if a Heartbeat message is longer than its expected length. You may read more about the bug in resources such as [this one](https://www.synopsys.com/blogs/software-security/heartbleed-bug/).

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

### libxml2 example

As another example, start by pulling libxml2 version 2.9.2 (with a few known fuzzable vulnerabilities, see [here](https://github.com/google/fuzzer-test-suite/tree/master/libxml2-v2.9.2)) and compile it with ALF support. Building will take a while:
```ShellSession
$ cd c/misc/libxml2/
$ git submodule --init --recursive
$ cd libxml2
$ CC=afl-clang-fast ./autogen.sh --disable-shared --without-debug --without-ftp --without-http --without-legacy --without-python
$ AFL_USE_ASAN=1 make -j 4
```

To fuzz XML files, we define a program that reads a XML file and use the [W3C XML test suite](https://www.w3.org/XML/Test/) a base corpus of inputs. AFL also supports a dictionary with the vocabulary for aiding in generating mutations of the original inputs; we will use [AFL's XML dictionary](https://github.com/google/AFL/blob/master/dictionaries/xml.dict).

```ShellSession
$ AFL_USE_ASAN=1 afl-clang-fast ./xmlreadAFL.cc -I libxml2/include libxml2/.libs/libxml2.a -lz -lm -o fuzzer
$ wget https://www.w3.org/XML/Test/xmlts20130923.tar.gz -O - | tar -xz
$ mkdir output
$ afl-fuzz -i xmlconf -o output -x xml.dict ./fuzzer @@
```

AFL will soon find a crash (see [here](https://github.com/google/fuzzer-test-suite/tree/master/libxml2-v2.9.2)).

## [libFuzzer](https://llvm.org/docs/LibFuzzer.html)

LLVM's libFuzzer is a coverage-guided fuzzing engine that ships with Clang.
Contrarily fo AFL, that is targeted for fuzzing executables via I/O, libFuzzer is designed for fuzzing libraries via in-memory handlers; a few more technical differences can be consulted [in this article](https://www.moritz.systems/blog/an-introduction-to-llvm-libfuzzer/).

We can recompile our libxml2 example with libFuzzer support as follows:

```ShellSession
$ cd c/misc/libxml2/
$ git submodule --init --recursive
$ cd libxml2
$ FUZZ_CXXFLAGS="-g -O2 -fsanitize=fuzzer-no-link,address,undefined"
$ CXX="clang++ $FUZZ_CXXFLAGS" CC="clang $FUZZ_CXXFLAGS" CCLD="clang++ $FUZZ_CXXFLAGS" ./autogen.sh --disable-shared --without-debug --without-ftp --without-http --without-legacy --without-python
$ make -j 4
```

To fuzz XML files, we use the same XML dictionary and input corpus as we did for AFL:

```ShellSession
$ clang -g -O2 -fsanitize=fuzzer,address,undefined xmlreadLibFuzzer.cc -I libxml2/include libxml2/.libs/libxml2.a -lz -o fuzzer
$ ./fuzzer xmlconf -dict=xml.dict -max_len=64
```

The fuzzer will soon find a crash (see [here](https://github.com/google/fuzzer-test-suite/tree/master/libxml2-v2.9.2)), and exit when it finds the first crash.
Note that libFuzzer will add its generated inputs to the `xmlconf` directory.

## Other tools :warning: :construction:

There are many other modern fuzzing techniques that can achieve better results for custom programs, often by combining some form of symbolic execution. Many of the associated tools are experimental, possibly quite complex to configure and use, and can become out-of-date quickly.

**Remark:** For the sake of demonstration, we will look at a few, but be advised that it may be hard to understand their behavior outside of the example programs that we provide. 

The list of fuzzers presented here is merely demonstrative. For a slightly more complete picture, from 2021, the [UNIFUZZ](https://github.com/unifuzz/overview) project has made an effort to real world examples that you may alternatively explore.


### [Driller](https://github.com/shellphish/driller)

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

### [Fuzzolic](https://github.com/season-lab/fuzzolic)

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

### [SymCC](https://github.com/eurecom-s3/symcc)

SymCC is a compiler wrapper which embeds symbolic execution into the program during compilation, and an associated run-time support library. In essence, the compiler inserts code that computes symbolic expressions for each value in the program. The actual computation happens through calls to the support library at run time.

You may build a docker container to try SymCC and AFL. Inside the [vm](../vm) folder, just try compiling the [buggy.c](../c/misc/buggy.c) example with SymCC, and running it: 
```ShellSession
$ git pull
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

### [Angora](https://angorafuzzer.github.io/)

Angora is a mutation-based fuzzer that seeks to improve AFL's branch coverage without resorting to symbolic execution. Instead, it relies on dynamic byte-level taint tracking to try to understand how inputs affect branch constraints, and therefore how to mutate inputs to improve branch coverage. 

You may build a docker container to try Angora. Inside the [vm](../vm) folder, just try running:
```ShellSession
$ echo core | sudo tee /proc/sys/kernel/core_pattern
$ make run-angora
angora@container# cd tests
angora@container# ./test.sh mini
```
This will compile and run the [mini.c](https://github.com/AngoraFuzzer/Angora/blob/master/tests/mini/mini.c) example that you may find in `tests/mini/mini.c` inside the container; this example is very similar to the [buggy.c](../c/misc/buggy.c) example that we have seen before. You may inspect the output, including the found errors, in the folder `tests/output`. To fuzz your own program, the simplest way is to place it in a new subfolder under `tests` and running it as above; since Angora is a mutation-based fuzzer, the above test script will look for input seed files in folder `tests/input`.

### [KLEE-taint](https://github.com/feliam/klee-taint)

The testing methodologies that we have seen so far focus on traditional safety properties such as undefined behavior or memory errors.
These do not permit to directly capture security properties such as information leakage, as we have seen before in Lab 1.

Even if less usual when it comes to existing tools, we can naturally combine automated testing with security analysis techniques such as taint analysis [^3].
One such example is KLEE-taint, a (slightly outdated [^2]) fork of KLEE that dynamically propagates taint annotations alongside symbolic variables during symbolic execution. You can find more information in the [GitHub repository](https://github.com/feliam/klee-taint) and in the original [paper](https://cs.famaf.unc.edu.ar/~rcorin/kleecrypto/). 

[^2]: KLEE-taint appears to be a no longer supported extension to an older version of KLEE; the changes are minimal so, in principle, it would be easily portable to recent versions. More modern similar tools exist, e.g. [Jaint](https://tillschallau.de/wp-content/uploads/2021/05/jaint.pdf) for dynamic taint analysis and symbolic execution of Java programs; we could not however find its source code.

[^3]: Symbolic execution can also be extended for testing that a program satisfies a general security property. [ENCoVer](http://www.cse.chalmers.se/~musard/files/encover.html) is an example of such an academic prototype, developed as an extension to Java Pathfinder.

Consider the command injection example from before, minimally adapted to run with KLEE-taint in [os_cmd_injection_basic-bad-klee.c](../c/SARD-testsuite-100/000/149/241/os_cmd_injection_basic-bad-klee.c).
The most relevant are the two following annotations:
```C
klee_set_taint(1,arg,strlen(arg))
...
klee_assert(klee_get_taint(command,commandLength) != 1)
```
KLEE-taint taints memory bytes much like we have seen before for Taintgrind.
For an address `arg` containing a symbolic string, the first instruction taints a memory block if `strlen(arg)` bytes with taint tag `1`. 
The second instruction reads the taint `commandLength` bytes starting at address `command`, and checks if any of those bytes has a taint tag different than `1`.
Internally, KLEE-taint keeps a per-byte set of taint tags. By default, non-tainted data has taint tag `0`.

Inside the [vm](../vm) folder, we can run the command injection example as follows:
```ShellSession
$ git pull
$ make run-klee-taint
klee-taint@container# cd /path/to/ses/c/SARD-testsuite-100/000/149/241/
klee-taint@container# clang -I /home/klee/klee_src/include/ -emit-llvm -c -g -O0 -disable-O0-optnone os_cmd_injection_basic-bad-klee.c
klee-taint@container# klee --libc=uclibc --posix-runtime -taint=direct os_cmd_injection_basic-bad-klee.bc
```

KLEE-taint allows to choose from 3 growingly precise taint propagation modes: direct (taint is only propagated through assignments), indirect (when the condition of a conditional statement is dependent on a tainted value, the control flow is tainted) or region-based (when two branches of a conditional statement converge to instructions that are executed independently of the condition, the control flow is untainted); for this example, direct tainting suffices.
The result of running KLEE-taint shall be an assertion violation: if you remember the example, the content of `arg` will indeed flow into some bytes of the `command` string.

To be sure that taint is being correctly propagated, we can test if the fixed `command` header is also tainted. 
Program [os_cmd_injection_basic-bad2-klee.c](../c/SARD-testsuite-100/000/149/241/os_cmd_injection_basic-bad2-klee.c) only checks if the first `catLength` bytes of the `command` string are tainted.
If you run this program in the same way, KLEE-taint will not find an assertion violation as expected; indeed, taint is propagated at the byte-level as expected.


### [KLEE-taint-ct](https://github.com/rishabh246/klee-taint)

Similarly to how TIMECOP operates, KLEE-taint can be easily extended to automatically verify constant-time security properties: if the user marks secret symbolic inputs as tainted, (the symbolic execution of) a program is constant-time if no branch condition is symbolically tainted.
KLEE-taint-ct, a [simple fork](https://github.com/rishabh246/klee-taint) of KLEE-taint, automates the taint checking of all program branch conditions.

Remember the password checking example from before, adapted for KLEE in program [pass-loop-bad-klee.c](../c/misc/pass-loop-bad-klee.c).
Inside the [vm](../vm) folder, we can run it as follows:
```ShellSession
$ git pull
$ make run-klee-taint-ct
klee-taint-ct@container# cd /path/to/ses/c/misc/
klee-taint-ct@container# clang -I /home/klee/klee_src/include/ -emit-llvm -c -g -O0 pass-loop-bad-klee.c
klee-taint-ct@container# klee -taint=controlflow pass-loop-bad-klee.bc
```
The `controlflow` options corresponds to the `indirect` option of KLEE-taint. The fact that the control flow of the `for` loop depends on the secret arguments will be quickly detected by KLEE-taint-ct.
Then try the constant-time program [pass-loop-good-klee.c](../c/misc/pass-loop-good-klee.c); this time, KLEE-taint-ct shall not find any constant-time violation.

You may try other constant-time security analysis examples using KLEE-taint-ct in the [examples/taint](https://github.com/rishabh246/klee-taint/tree/master/examples/taint) folder of the GitHub repository.
Inside the [vm](../vm) folder, you may just run:
```ShellSession
$ git clone https://github.com/hpacheco/klee-taint-ct
$ cd examples/taint/path/to/the/folder/of/the/example/
$ make verify
```

### [dudect](https://www.reparaz.net/oscar/misc/dudect)

It is possible to reduce the analysis of some security properties to the comparison of two program executions (for slightly different inputs). One simple example is [dudect](https://www.reparaz.net/oscar/misc/dudect), a minimal C library that tests cryptographic functions with multiple inputs to find timing variations.

### [ct-fuzz](https://github.com/michael-emmi/ct-fuzz)

Constant-time static analysis tools such as ct-verif consider a *self-composed* program that simulates two parallel executions of the original program.
Using the same rationale, it is possible to use traditional fuzzers to support the automated testing of security properties by comparing the outputs of multiple fuzzed inputs; one such example is ct-fuzz, tailored for automated testing of constant-time security for cryptographic implementations. You may read the ct-fuzz [paper](http://www.cs.utah.edu/~shaobo/ct-fuzz.pdf) and the [GitHub repository](https://github.com/michael-emmi/ct-fuzz).

### [BinSec/Rel](https://github.com/binsec/rel)

We have seen extensions of KLEE (a symbolic execution tool) that combine dynamic taint analysis to support the analysis of security properties, including general information flow and constant-time security.
Nonetheless, symbolic execution by itself can be generalized to verify security properties, such as constant-time, that fall under the class of _relational properties_, that is, properties that can be expressed over multiple executions of the same program. This multiplication of the symbolic state is often more expensive, but also more precise than performing symbolic taint analysis.

[BinSec](https://binsec.github.io/) is a binary-level security analysis tool that employs symbolic execution among other techniques. [BinSec/Rel](https://github.com/binsec/rel) is a [plugin](https://github.com/binsec/binsec/blob/master/doc/sse/relse.md) that provides support checking for constant-time security using relational symbolic execution, that is, symbolically executing two executions of the same program such that their results must be the same for different secret symbolic inputs.

Remember the password checking example from before, adapted in program [pass-loop-bad-binsec.c](../c/misc/pass-loop-bad-binsec.c). 
Inside the [vm](../vm) folder, we can compile our program to a binary and run it inside a BinSec docker container as follows:

<details>
<summary>Result</summary>

```ShellSession
$ make run-binsec
binsec@container# cd /path/to/ses/c/misc/
binsec@container# sudo apt update && sudo apt install gcc gcc-multilib
binsec@container# gcc -g -m32 -static pass-loop-bad-binsec.c -o pass-loop-bad-binsec
binsec@container# binsec -sse -checkct -sse-script pass-loop-binsec.cfg -checkct-stats-file pass-loop-bad-binsec.toml pass-loop-bad-binsec
[sse:info] TTY: press [space] to switch between log and monitor modes.
[checkct:result] Instruction 0x08049d2a has control flow leak (0.093s)
[sse:info] Empty path worklist: halting ...
[sse:info] SMT queries
             Preprocessing simplifications
               total          379
               sat            0
               unsat          359
               constant enum  20
             
             Satisfiability queries
               total          20
               sat            18
               unsat          2
               unknown        0
               time           0.04
               average        0.00
             
           Exploration
             total paths                      18
             completed/cut paths              18
             pending paths                    0
             stale paths                      0
             failed assertions                0
             branching points                 39
             max path depth                   169
             visited instructions (unrolled)  373
             visited instructions (static)    54
             
           
[checkct:result] Program status is : insecure (0.119)
[checkct:info] 18 visited paths covering 54 instructions
[checkct:info] 30 / 31 control flow checks pass
[checkct:info] 383 / 383 memory access checks pass
```
</details>

Note that the [pass-loop-binsec.cfg](../c/misc/pass-loop-binsec.cfg) file includes a configuration which declares global C variables to be treated as secret or public symbolic inputs. In this example, BinSec will report that the program is insecure, and present symbolic inputs that testify that the program is not constant-time, i.e., different secret inputs may yield different public outputs.
The found counter-example will be detailed in file `pass-loop-bad-binsec.toml`, which will include sample instantiations for symbolic variables similar to the ones below:

<details>
<summary>Result</summary>

```ShellSession
n = ["0x00000009"]
["CT report"."Insecurity models".0x08049d2a.secret1]
arg = ["0x0000000000000000000000003a70c9ef"]
pass = ["0x00000000000000000000000007c5275b"]
["CT report"."Insecurity models".0x08049d2a.secret2]
arg = ["0xffffffffffffffffffffffffffffffff"]
pass = ["0xffffffffffffffffffffffffffffffff"]
```
</details>

Then try the constant-time program [pass-loop-good-binsec.c](../c/misc/pass-loop-good-binsec.c); this time, BinSec shall report that the program is secure:

<details>
<summary>Result</summary>

```ShellSession
binsec@container# gcc -g -m32 -static pass-loop-good-binsec.c -o pass-loop-good-binsec
binsec@container# binsec -sse -checkct -sse-script pass-loop-binsec.cfg -checkct-stats-file pass-loop-good-binsec.toml pass-loop-good-binsec
[sse:info] TTY: press [space] to switch between log and monitor modes.
[sse:info] Empty path worklist: halting ...
[sse:info] SMT queries
             Preprocessing simplifications
               total          244
               sat            0
               unsat          233
               constant enum  11
             
             Satisfiability queries
               total          11
               sat            9
               unsat          2
               unknown        0
               time           0.03
               average        0.00
             
           Exploration
             total paths                      9
             completed/cut paths              9
             pending paths                    0
             stale paths                      0
             failed assertions                0
             branching points                 21
             max path depth                   185
             visited instructions (unrolled)  257
             visited instructions (static)    54
             
           
[checkct:result] Program status is : secure (0.112)
[checkct:info] 9 visited paths covering 54 instructions
[checkct:info] 21 / 21 control flow checks pass
[checkct:info] 258 / 258 memory access checks pass
```
</details>

### [DifFuzz](https://github.com/isstac/diffuzz)

The approaches behind dudect and ct-fuzz have been developed specifically for cryptographic code. A more recent research direction, called _differential fuzzing_, considers the adaptation of general-purpose fuzzers for side-channel analysis. One such example is DifFuzz, from Java programs, which is built on top of AFL and employs resource-guided heuristics to automatically find inputs that attempt to maximize the difference in time/resource consumption between different program executions.

## Tasks

The goal of this lab is to experiment with the automated testing tools described above. We will detect and fix the vulnerabilities found in example C programs from the [c/SARD-testsuite-100](../c/SARD-testsuite-100) testsuite. 
1. Study and try out the tools described above.
2. Choose one vulnerable program from [c/SARD-testsuite-100](../c/SARD-testsuite-100) to analyse. To make it interesting, your chosen vulnerable program should only crash or lead to a security vulnerability for some inputs, but not for all inputs. It is not mandatory to choose examples from this dataset; you may also choose examples of vulnerable C programs from other resources such as the datasets illustrated in [Lab 1](Lab1.md). You may also wish to try out a more realistic example from, e.g., Google's FuzzBench [benchmarks](https://github.com/google/fuzzbench/tree/master/benchmarks).
4. Test your program with some of the above tools. You should try at least one basic black-box fuzzing tool (Radamsa or Blab) and one symbolic execution tool (KLEE); or make sure to explore other grey-box fuzzing tools (AFL and onwards).
5. **In your group's GitHub repository, write a small report to the markdown file `Lab2.md`.**
6. The report shall discuss:
   * were you able to find the vulnerability? with which tools? why do you think that is the case?
   * how did you adapt the example code and/or the tool parameters?
   * what have you experimentally learned about the tradeoffs between fuzzing and symbolic execution?






