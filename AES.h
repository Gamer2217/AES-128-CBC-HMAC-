#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/random.h>
#include <openssl/ssl.h>


/*
It makes first XOR between key and plaintext before whole encryption
*/
void add_round_key(uint8_t input1[4][4], uint8_t input2[4][4], uint8_t result[4][4]);


/*
A simple multiplication in Galious Field(GF^8). It uses polynom x^8+x^4+x^3+x+1 as basis for multiplication
*/
uint8_t gf8_multiply(uint8_t input1 , uint8_t input2);


/*
A simple inverse in Galious Field. If multiplication between two numbers(like 2 and 1/2) is equal to 1, then we use its value for affine transformation
*/
uint8_t gf8_inverse(uint8_t input);


/*
Uses some linear algebra to transform data
*/
uint8_t affine(uint8_t b);


/*
It combines GF8 functions and affine transformation to make sbox for sbytes method
*/
void s_box_maker(uint8_t sbox[16][16]);


/*
Basically replaces bytes from plaintext to bytes from sbox
*/
void s_box_encryption(uint8_t input_text[4][4] , uint8_t sbox[16][16], uint8_t result[4][4]);


/*
Replace bytes in left. If we have first row we don't do anything. If we have second-fourth row then we replace bytes to left by value from 1 to 3
*/
void shift_rows(uint8_t input[4][4],uint8_t output[4][4]);


/*
Uses GF8 multiplication and XOR between our text and mixcolumns matrix
*/
void mix_columns(uint8_t input[4][4], uint8_t matrix[4][4], uint8_t result[4][4]);


/*
It expands our key to 10 keys for each round of encryption
*/
void key_expansion(uint8_t input_key[4][4], uint8_t round_keys[11][4][4], uint8_t sbox[16][16]);


/*
It generates IV(Initialization Vector) to encrypt plaintext blocks(CBC method). Basically use getrandom() function in C that takes random bytes from Memory.
*/
void iv_generator(uint8_t result[4][4]);


/*
It's just AddRoundKey but I decided to make a whole function to make code a bit understandable
*/
void XOR_with_iv(uint8_t text[4][4], uint8_t iv[4][4] , uint8_t result[4][4]);


/*
Uses SHA-256 method to generate HMAC for authentification and for preventing some attacks like padding oracle(if we know padding we could decrypt message and even encrypt it again)
*/
void generate_HMAC(const uint8_t hmac_key[32],const uint8_t *data,size_t data_len,uint8_t hmac_result[32]);


/*
Simply creates inverse-sbox for decryption by using our sbox
*/
void inv_s_box_maker(uint8_t sbox[16][16], uint8_t inv_sbox[16][16]);


/*
Same as sbytes but in reverse form
*/
void s_box_decryption(uint8_t input_text[4][4] , uint8_t inv_sbox[16][16], uint8_t result[4][4]);


/*
Same as shift_rows but in reverse form
*/
void inv_shift_rows(uint8_t input[4][4],uint8_t output[4][4]);


/*
Same as mix_columns but we use another matrix for XOR and GF8 operations
*/
void inv_mix_columns(uint8_t input[4][4], uint8_t matrix[4][4], uint8_t result[4][4]);
