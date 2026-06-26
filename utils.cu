#include <stdio.h>
#include <stdint.h>
#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <cuda_runtime.h>
#include <utility>

// CUDA sprintf alternative for nonce finding. Converts integer to its string representation. Returns string's length.
__device__ int intToString(uint32_t num, char* out) {
    if (num == 0) {
        out[0] = '0';
        out[1] = '\0';
        return 1;
    }

    int i = 0;
    while (num != 0) {
        int digit = num % 10;
        num /= 10;
        out[i++] = '0' + digit;
    }

    // Reverse the string
    for (int j = 0; j < i / 2; j++) {
        char temp = out[j];
        out[j] = out[i - j - 1];
        out[i - j - 1] = temp;
    }
    out[i] = '\0';
    return i;
}

// CUDA strlen implementation.
__host__ __device__ size_t d_strlen(const char *str) {
    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// CUDA strcpy implementation.
__device__ void d_strcpy(char *dest, const char *src){
    int i = 0;
    while ((dest[i] = src[i]) != '\0') {
        i++;
    }
}

// CUDA strcat implementation.
__device__ void d_strcat(char *dest, const char *src){
    while (*dest != '\0') {
        dest++;
    }
    while (*src != '\0') {
        *dest = *src;
        dest++;
        src++;
    }
    *dest = '\0';
}

// Compute SHA256 and convert to hex
__host__ __device__ void apply_sha256(const BYTE *input, BYTE *output) {
    size_t input_length = d_strlen((const char *)input);
    SHA256_CTX ctx;
    BYTE buf[SHA256_BLOCK_SIZE];
    const char hex_chars[] = "0123456789abcdef";

    sha256_init(&ctx);
    sha256_update(&ctx, input, input_length);
    sha256_final(&ctx, buf);

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        output[i << 1]     = hex_chars[(buf[i] >> 4) & 0x0F];  // High nibble
        output[(i << 1) + 1] = hex_chars[buf[i] & 0x0F];         // Low nibble
    }
    output[SHA256_BLOCK_SIZE << 1] = '\0'; // Null-terminate
}

// Compare two hashes
__host__ __device__ int compare_hashes(BYTE* hash1, BYTE* hash2) {
    int len_bytes = SHA256_HASH_SIZE >> 1;
    for (int i = 0; i < len_bytes; i++) {
        if (hash1[i] < hash2[i]) {
            return -1; // hash1 is lower
        } else if (hash1[i] > hash2[i]) {
            return 1; // hash2 is lower
        }
    }
    return 0; // hashes are equal
}



__global__  void construct_merkle_root_cuda_hash(int transaction_size, BYTE *transactions, int n, BYTE (*hashes)[SHA256_HASH_SIZE]) {
    // Compute the SHA256 hash for each transaction
    unsigned int i = threadIdx.x + blockDim.x * blockIdx.x;
    if (i >= n)
        return;
    apply_sha256(transactions + i * transaction_size, hashes[i]);
}

__global__  void construct_merkle_root_cuda_tree(int n, BYTE (*in_hashes)[SHA256_HASH_SIZE], BYTE (*hashes)[SHA256_HASH_SIZE]) {
    unsigned int i = (threadIdx.x + blockDim.x * blockIdx.x) << 1;
    if (i >= n)
        return;
    BYTE combined[SHA256_HASH_SIZE << 1];
    for (int j = 0; j < SHA256_HASH_SIZE; j++){
        combined[j] = in_hashes[i][j];
    }
    if (i + 1 < n) {
        for (int j = 0; j < SHA256_HASH_SIZE; j++){
            combined[j+SHA256_HASH_SIZE-1] = in_hashes[i+1][j];
        }
    } else {
        // If odd number of hashes, duplicate the last one
        for (int j = 0; j < SHA256_HASH_SIZE; j++){
            combined[j+SHA256_HASH_SIZE-1] = in_hashes[i][j];
        }
    }

    apply_sha256(combined, hashes[i >> 1]);

}



// TODO 1: Implement this function in CUDA
void construct_merkle_root(int transaction_size, BYTE *transactions, int max_transactions_in_a_block, int n, BYTE merkle_root[SHA256_HASH_SIZE]) {
    BYTE (*hashes)[SHA256_HASH_SIZE] = (BYTE (*)[SHA256_HASH_SIZE])malloc(max_transactions_in_a_block * SHA256_HASH_SIZE);
    BYTE *device_transactions;
    BYTE (*device_hashes)[SHA256_HASH_SIZE];
    BYTE (*in_device_hashes)[SHA256_HASH_SIZE];
    cudaMalloc(&device_transactions, max_transactions_in_a_block * transaction_size);
    cudaMalloc(&device_hashes, max_transactions_in_a_block * SHA256_HASH_SIZE);
    cudaMalloc(&in_device_hashes, max_transactions_in_a_block * SHA256_HASH_SIZE);

    cudaMemcpy(device_transactions, transactions, max_transactions_in_a_block * transaction_size, cudaMemcpyHostToDevice);

    const size_t block_size = 64;
    size_t blocks_no = n / block_size;
    if (n % block_size) 
        ++blocks_no;

    // pentru ca am bariera doar la un singur bloc (n-am globala), trebuie sa sparg in mai multe kernel-uri
    construct_merkle_root_cuda_hash<<<blocks_no, block_size>>>(transaction_size, device_transactions, n, device_hashes);
    cudaDeviceSynchronize();

    cudaMemcpy(hashes, device_hashes, max_transactions_in_a_block * SHA256_HASH_SIZE, cudaMemcpyDeviceToHost);
    while (n > 1) {
        // apelez noua functie
        std::swap(in_device_hashes, device_hashes);
        construct_merkle_root_cuda_tree<<<blocks_no, block_size>>>(n, in_device_hashes, device_hashes);
        cudaDeviceSynchronize();
        n = (n + 1) >> 1;
    }
    cudaMemcpy(merkle_root, device_hashes, SHA256_HASH_SIZE, cudaMemcpyDeviceToHost);

    free(hashes);
    cudaFree(device_transactions);
    cudaFree(device_hashes);
    cudaFree(in_device_hashes);
}

// declar constant sa fac acces rapid
__constant__ BYTE device_difficulty[SHA256_HASH_SIZE >> 1];

__global__ void find_nonce_cuda(uint32_t start, uint32_t end, BYTE *block_hash, uint32_t *valid_nonce, SHA256_CTX ctx) {
    BYTE thread_block_hash[SHA256_HASH_SIZE >> 1];

    unsigned int nonce = start + threadIdx.x + blockDim.x * blockIdx.x;
    if (nonce >= end) 
        return;
    char nonce_string[NONCE_SIZE];
    int nonce_len = intToString(nonce, nonce_string);
    if (*(volatile uint32_t*) valid_nonce < UINT32_MAX)
         return;
    SHA256_CTX thread_ctx = ctx;
    sha256_update(&thread_ctx, (BYTE*)nonce_string, nonce_len);
    sha256_final(&thread_ctx, thread_block_hash);

    if (compare_hashes(thread_block_hash, device_difficulty) <= 0) {
        uint32_t last = atomicCAS(valid_nonce, UINT32_MAX, nonce);
        if (last == UINT32_MAX) {
            int len_bytes = SHA256_HASH_SIZE >> 1;
            for (int j = 0; j < len_bytes; j++){
                block_hash[j] = thread_block_hash[j];
            }
        }
        return;
    }
}

char hex_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}


// TODO 2: Implement this function in CUDA
int find_nonce(BYTE *difficulty, uint32_t max_nonce, BYTE *block_content, size_t current_length, BYTE *block_hash, uint32_t *valid_nonce) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, block_content, current_length);

    uint32_t last_nonce = *valid_nonce;
    BYTE *device_block_hash;
    uint32_t *device_valid_nonce;
    
    cudaMalloc(&device_block_hash, SHA256_HASH_SIZE);
    cudaMalloc(&device_valid_nonce, sizeof(uint32_t));

    BYTE out_difficulty[SHA256_HASH_SIZE >> 1];
    int len_bytes = SHA256_HASH_SIZE >> 1;
    for (int i = 0; i < len_bytes; i++) {
        out_difficulty[i] = (hex_to_byte(difficulty[i << 1]) << 4) | hex_to_byte(difficulty[(i << 1) + 1]);
    }
    cudaMemcpyToSymbol(device_difficulty, out_difficulty, SHA256_HASH_SIZE >> 1);
    uint32_t invalid_nonce = UINT32_MAX;
    cudaMemcpy(device_valid_nonce, &invalid_nonce, sizeof(uint32_t), cudaMemcpyHostToDevice);

    const size_t block_size = 256;
    // sparg pe chunk-uri
    const size_t chunk_size = 262144;
    size_t blocks_no = chunk_size / block_size;
    size_t start = 0;
    size_t end = start + chunk_size;
    while(start < max_nonce){
        if (end > max_nonce)
            end = max_nonce;
        find_nonce_cuda<<<blocks_no, block_size>>>(start, end, device_block_hash, device_valid_nonce, ctx);
        cudaDeviceSynchronize();
        cudaMemcpy(valid_nonce, device_valid_nonce, sizeof(uint32_t), cudaMemcpyDeviceToHost);
        if (*valid_nonce != UINT32_MAX)
            break;
        start += chunk_size;
        end += chunk_size;
    }

    cudaFree(device_valid_nonce);
    if (*valid_nonce != UINT32_MAX){
        BYTE output[SHA256_HASH_SIZE];
        cudaMemcpy(output, device_block_hash, SHA256_HASH_SIZE, cudaMemcpyDeviceToHost);
        const char hex_chars[] = "0123456789abcdef";
        for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
            block_hash[i << 1]     = hex_chars[(output[i] >> 4) & 0x0F];
            block_hash[(i << 1) + 1] = hex_chars[output[i] & 0x0F];
        }
        block_hash[SHA256_BLOCK_SIZE << 1] = '\0'; // Null-terminate
        cudaFree(device_block_hash);
        return 0;
    }
    else{
        *valid_nonce = last_nonce;
        cudaFree(device_block_hash); 
        return 1;
    }
}

__global__ void dummy_kernel() {}

// Warm-up function
void warm_up_gpu() {
    BYTE *dummy_data;
    cudaMalloc((void **)&dummy_data, 256);
    dummy_kernel<<<1, 1>>>();
    cudaDeviceSynchronize();
    cudaFree(dummy_data);
}
