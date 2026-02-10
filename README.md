# SLMAD

## Introduction

SLMAD stands for "Super-linear Memory Automaton Detector". 

This is one of the codebases for our USENIX Security 2026 paper:
"Regular Expression Denial of Service Induced by Backreferences".

This project is based on
[dk.brics.automaton](https://github.com/cs-au-dk/dk.brics.automaton).
We heavily extended code files under [src/](src/).

Now the regular expression part supports following features:
+ Capture groups,
+ Backreferences,
+ More escape and character classes.

The automaton part now supports the following features:
+ The construction of Two-Phase Memory Automaton (2PMFA). Now the following 
  transition types are added:
    - Real epsilon transitions,
    - Capture-open and capture-close,
    - Backreference.
+ Extended basic operations which supports part of 2PMFAs
    - Backtracking run,
    - Union, intersection, complement, minimization, etc.,
    - Deciding emptyness.

We also created simple detectors for the 3 REDoS patterns in our paper 
and the IDA pattern. Code can be found in [exp/](exp/).

## Quick Start

### Using Ant

First, download the `jar` file of
[org.json](https://mvnrepository.com/artifact/org.json/json/20140107) and
[org.xerial.sqlite-jdbc](https://mvnrepository.com/artifact/org.xerial/sqlite-jdbc)
under the [lib/](lib/) folder.

Then, simply compile and run the detector on Snort dataset

```sh
ant exp
```

If you want to run the detector on other datasets, please first compile the whole
codebase by

```sh
ant compileExp
```

Then,

```sh
java -classpath "antbuild:lib/*" dk.brics.automaton.AnalyzeRegExp <input_arguments> -r <detect_file_path> -a <atkre_file_path>
```
where possible input arguments include

+ `-j <path_to_json>`
+ `-q sqlite:<path_to_sqlite_db>:<table_name>.<column_name>`
+ `-s <path_to_snort_rule_file>`
+ `-S <path_to_snort_rule_dir>`

### Using Maven (Experimental)

The building routines using Maven may be instable.

To simply compile and run the detector on Snort dataset

```sh
mvn generate-test-resources
```

To only compile the codebase

```sh
mvn compile
```

## Copyright

This project is forked from
[dk.brics.automaton](https://github.com/cs-au-dk/dk.brics.automaton).
The original repository use BSD lisence. Check [COPYING](COPYING) and the 
original repository for more information.

See original "README" file of dk.brics.automaton at
[README.old.md](README.old.md).

This project is also under BSD license.
