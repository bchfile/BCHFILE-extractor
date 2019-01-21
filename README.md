BCHFILE-extractor
===============

This is a tool for extract arbitrary file from the BitcoinCash blockchain.

Preparation
---------------

Install and Run Bitcoin-ABC node in daemon mode.

txindex is not needed, that means the Extractor support Prune mode node.

How to Run
---------------

Download the code:

$ git clone https://github.com/bchfile/BCHFILE-extractor.git

$ cd BCHFILE-extractor

Compile it:

$ g++ bchfile_extractor.cpp sha256.c -o bchfile

Run it:

$ ./bchfile

Waiting for a while, the program will extract all BCHFILEs from height 561352 to now.

For testnet:

Uncomment '#define TESTNET' and recompile.

Hints: Run 'ulimit -n' to check the most open files limit on your system and change it to 65536 if the limit cause any problem.
