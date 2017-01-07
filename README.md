Super Vanitygen
===============

Fast Vanity Bitcoin address generator for Linux using the
[secp256k1](https://github.com/sipa/secp256k1) library.

Features:
* Runs under the x86, x86\_64, arm, and arm64 (aarch64) architectures.
* Includes fast assembly versions of SHA-256 for Intel CPUs with SSSE3, AVX,
  AVX2, and SHA extensions.

Limitations:
* Currently only supports Bitcoin compressed public keys.
* Does not support combining private keys via addition/multiplication methods.

Example
-------
Example program execution:
(Note: Do _not_ send coins to this address!)

    $ vanitygen 1Vanity
    Difficulty: 888446610539
    [5003 Kkey/s][Total 31878804156][Prob 3.5%][50% in 1.4d]
    Private Key:   L3jTmJvNtjNrUw5SJJGFfGTog46fLutsQJ4XG66YWHMV5UmgFWqZ
    Address:       1Vanity8HEFQDR7ZFsAUFeRR67AG38PcR

Build Prerequisites
-------------------
Successful compilation depends on installing these additional programs:

* GCC
* Make
* Libtool
* Autotools
* GMP

Installing prerequisites on RedHat or Fedora Core:

    $ yum -y install gcc make automake autoconf libtool gmp-devel

Installing prerequisites on Ubuntu:

    $ sudo apt-get install build-essential automake autoconf libtool libgmp3-dev

Build Instructions
------------------
Simply run make:

    $ make

This will automatically configure the secp256k1 library and compile the
project using default options. To change compile options in secp256k1, cd to
secp256k1 and run configure with your new options, and then rerun make in the
top level directory.

If the gmp development library is not installed on your system, you may remove
-lgmp from the LDLIBS line in the Makefile. See below for other prerequisites.

For slow CPUs, you might get a better hash rate by lowering the "#define STEP"
value in vanitygen.c. Similarly, server CPUs with large amounts of fast memory
might benefit by increasing the STEP value.

Warning
-------
**Please verify all generated addresses before use!**

This software is beta and may contain bugs. Do not send coins to an address
without first checking that the generated private/public keys are correct.
Here are examples of other programs you can use to verify keys:

* [bitaddress.org](https://www.bitaddress.org)
* [bitcoin.sh](https://github.com/grondilu/bitcoin-bash-tools/blob/master/bitcoin.sh)
* or any common wallet software.

Do not run this program on a computer where others have the ability to strace
your program's execution.

License
-------
This software is distributed under the GPLv2 license. Most individual portions
are placed under compatible MIT or BSD licenses. See each respective file for
details.

Donations
---------
If you've found this program useful, please consider sending me a few bits:

`gandalf@winds.org` (via OpenAlias) or `1Ganda1fU65mNxGoXomdtReN3ejkcMHGEL`
