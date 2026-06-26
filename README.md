# CUDA Blockchain Miner

A CUDA/C++ project that accelerates two core parts of a simplified Bitcoin-style mining flow: Merkle root computation and Proof of Work nonce search. The original workflow is based on a serial CPU miner, while this version moves the expensive hashing work to the GPU.

The project is not a full Bitcoin implementation. It focuses on the computational side of mining: grouping transactions into blocks, building a Merkle root for each block, and searching for a nonce that makes the block hash satisfy a given difficulty.

## Overview

The input contains a list of transactions, the previous block hash, a difficulty level, a maximum nonce value, and the maximum number of transactions allowed in one block.

Transactions are processed in groups. For each group, the miner:

1. computes the SHA-256 hash of every transaction;
2. builds the Merkle tree until a single Merkle root remains;
3. concatenates the previous block hash with the Merkle root;
4. searches for a valid nonce;
5. uses the resulting block hash as the previous hash for the next block.

## CUDA Implementation

The GPU implementation targets the two most expensive operations:

* **Merkle root generation** - transaction hashes and intermediate tree levels are computed in parallel where possible;
* **Proof of Work** - many nonce candidates are tested in parallel until a hash matching the required difficulty is found.

This fits well on the GPU because both parts involve a large number of independent SHA-256 computations.

## Proof of Work

For each block, the miner tries nonce values starting from `0` up to the provided maximum. A nonce is valid when the SHA-256 hash of the block data starts with the required number of zero characters.

The valid nonce is not necessarily unique, but any nonce that satisfies the difficulty condition is acceptable.

## Output

For every mined block, the program records:

* block ID;
* resulting block hash;
* Merkle root;
* nonce;
* time spent computing the Merkle root;
* time spent searching for the nonce;
* total time for the block.

At the end, the output also includes the total execution time spent in the Merkle and nonce stages.

## Project Structure

The main implementation work is concentrated in:

* `utils.cu` - CUDA logic for Merkle root computation and nonce search;
* `miner.cpp` - block processing flow and input/output handling;
* `cpu_miner/` - reference serial version used to understand the original algorithm;
* `gpu_miner/` - CUDA-based implementation.

## Notes

The main challenge is balancing correctness with performance. The Merkle tree must preserve the same hashing order as the serial version, including the case where the last hash of an odd level is duplicated. The nonce search also has to stop correctly once a valid candidate is found, while avoiding unnecessary synchronization overhead.

The result is a compact GPU mining simulation that shows how parallel hardware can speed up hashing-heavy blockchain computations.
