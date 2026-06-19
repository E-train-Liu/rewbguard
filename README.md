# REwBGuard

## Introduction

REwBGuard is a Regular Expression Denial of Service (REDoS) detector.
It detects Regular Expressions with Backreferences (REwBs) with super-linear
runtime through static analysis.

This is one of the codebases for our USENIX Security 2026 paper:

> Yichen Liu, Berk Çakar, Aman Agrawal, Minseok Seo, James C Davis, 
> Dongyoon Lee. \
> "Regular Expression Denial of Service Induced by Backreferences". \
> In *Proceedings of the 35th USENIX Security Symposium* 
> *(USENIX Security 2026)*. August 2026.

This project is based on
[dk.brics.automaton](https://github.com/cs-au-dk/dk.brics.automaton).
We heavily extended code files under [src/](src/).

Now the regular expression part supports following features:
+ Capture groups,
+ Backreferences,
+ More escapes and character classes.

The automaton part now supports the following features:
+ The construction of Two-Phase Memory Automaton (2PMFA). Now the following 
  transition types are added:
    - Real epsilon transitions,
    - Capture-open and capture-close,
    - Backreference.
+ Extended basic operations which supports some 2PMFAs:
    - Backtracking run,
    - Union, intersection, complement, minimization, etc.,
    - Deciding emptyness.

We also created simple detectors for the 3 REDoS patterns in our paper 
and the IDA pattern. Code can be found in [exp/](exp/).

## Quick Start

### Using Maven

First, compile the codebase 

```sh
mvn compile
```

The run

```sh
mvn exec:java \
  -Dexec.mainClass="dk.brics.automaton.Main" \
  -Dexec.args="-i data/exp/snort2-register-regexes.toml -o data/out/detect_snort2-register.toml -a data/out/atkre_snort2-register.toml --vultypes 123 --timeout 60"
```

You can modify the arguments passed by `-Dexec.args`. See "Usage".

### Using Ant

First, download these `jar` files and put them under the [lib/](lib/) folder:
+ [net.sourceforge.argparse4j/argparse4j](https://mvnrepository.com/artifact/net.sourceforge.argparse4j/argparse4j)
+ [org.json/json](https://mvnrepository.com/artifact/org.json/json)
+ [org.xerial/sqlite-jdbc](https://mvnrepository.com/artifact/org.xerial/sqlite-jdbc)
+ [org.tomlj/tomlj](https://mvnrepository.com/artifact/org.tomlj/tomlj)
+ [org.antlr/antlr4-runtime](https://mvnrepository.com/artifact/org.antlr/antlr4-runtime)

Then, simply compile and run the detector on Snort dataset

```sh
ant execQuick
```

If you want to have more controls, you can compile by

```sh
ant transpile
```

Then run by

```sh
ant exec \
  -Dexec.args="-i data/exp/snort2-register-regexes.toml -o data/out/detect_snort2-register.toml -a data/out/atkre_snort2-register.toml --vultypes 123 --timeout 60"
```

Or muanually run java by

```sh
java -classpath "antbuild:lib/*" dk.brics.automaton.Main -i data/exp/snort2-register-regexes.toml -o data/out/detect_snort2-register.toml -a data/out/atkre_snort2-register.toml --vultypes 123 --timeout 60
```

You can modify the arguments. See "See "Usage".

where possible input arguments include

## Usage

```sh
java ... dk.brics.automaton.Main   \
  -i <input_file>                  \
  -o <output_detect_file>          \
  [-a <output_attack_string_file>] \
  [-f <input_format>]              \
  [-v <vulnerability_types>]       \
  [-t <timeout_sec>]               \
  [-m]
```

+ `-i`, `--input`: path to input file, see `-f` for format.
+ `-o`, `--output`: path to detection output file, contains info of each regex,
  and simplied report on whether the regex contains vulnerabilities of certain
  types.
+ `-a`, `--atkre`: path to attack string output file. After some modification,
  this file can be used by `atkre` for dynamic validation.
+ `-f`, `--format`: input format, current support:
    - `toml`: a TOML file, format 
        ```toml
        [[data]]
        pattern = '...'   # string
        flags = '...'     # string, optional
        sources = ['...'] # array of strings, optional
        ```
    - `json`: a JSON file, format
      ```json
      [
        {
          "pattern": "...",
          "flags": "...",    // optional
          "sources": ["..."] // optional
        }
      ]
      ```
      - `snort`: a single Snort 2 or Snort 3 `.rules` file.
      - `snortdir`: a directory. It and its child directories contains Snort
        `.rules` files.
+ `-v`, `--vultypes`: the vulnerability types to be detected in order.
    - Here, `0` means IDA, `1`-`3` means backref vulnerable patterns 1-3.
    - The order of chars matter. E.g. `1230` means detect pattern 1 first, then
      pattern 2, then pattern 3, finally pattern IDA. `0123` will make IDA 
      patterns to be detected first.
    - **Warning**: detecting IDA can be slow. Be careful when using `0`. Also,
      we suggest you to put `0` at the end so backref vulnerabilities can be
      detected before timeout.
+ `-t`, `--timeout`: the maximum time for each regex.
  - After such time, the detection Java `Thread` will be interrupted.
  - However, that does not means that the task will terminate immediately. See
    https://docs.oracle.com/javase/tutorial/essential/concurrency/interrupt.html
+ `-m`, `--multiple`: whether try to detect all vulnerabilities. Without this
  flag, the detector will detect at most one vulnerabilities for each type.
  - **Warning**: since IDA detection is very slow, be careful to use this 
    when you have `0` in `--vultypes`.


## Copyright

This project is forked from
[dk.brics.automaton](https://github.com/cs-au-dk/dk.brics.automaton).
We appreciate the work by previous developers.

The dk.brics.automaton use BSD lisence. Check [COPYING](COPYING) and the 
original repository for more information.
See original "README" file of dk.brics.automaton at 
[README.old.md](README.old.md).

This project is also under BSD license.
