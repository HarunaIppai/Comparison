/************************************************************************
Lab 9 Nios Software

Dong Kai Wang, Fall 2017
Christine Chen, Fall 2013

For use with ECE 385 Experiment 9
University of Illinois ECE Department
************************************************************************/

#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "aes.h"
#include "system.h"

// TODO: check c0 ~ 3 corresponds to correct position in i
// (i = [c0, c1, c2, c3])
union word_32 {
	unsigned int i;
	struct {
		unsigned char c3;
		unsigned char c2;
		unsigned char c1;
		unsigned char c0;
	}chars;
};

// Pointer to base address of AES module, make sure it matches Qsys
volatile unsigned int* AES_PTR = AES_BASE;

// Execution mode: 0 for testing, 1 for benchmarking
int run_mode = 0;

/** charToHex
 *  Convert a single character to the 4-bit value it represents.
 *
 *  Input: a character c (e.g. 'A')
 *  Output: converted 4-bit value (e.g. 0xA)
 */
char charToHex(char c)
{
	char hex = c;

	if (hex >= '0' && hex <= '9')
		hex -= '0';
	else if (hex >= 'A' && hex <= 'F')
	{
		hex -= 'A';
		hex += 10;
	}
	else if (hex >= 'a' && hex <= 'f')
	{
		hex -= 'a';
		hex += 10;
	}
	return hex;
}

/** charsToHex
 *  Convert two characters to byte value it represents.
 *  Inputs must be 0-9, A-F, or a-f.
 *
 *  Input: two characters c1 and c2 (e.g. 'A' and '7')
 *  Output: converted byte value (e.g. 0xA7)
 */
char charsToHex(char c1, char c2)
{
	char hex1 = charToHex(c1);
	char hex2 = charToHex(c2);
	return (hex1 << 4) + hex2;
}

// (4x 32-bit int array) <- (32x 8-bit char array (ASCII format))
void asciiToUint(unsigned char* input, unsigned int* output) {
	int i;
	for (i = 0; i < 4; i++) {
		int j;
		union word_32 word;
		for (j = 0; j < 4; j++) {
			int offset = (4 * i + j) * 2;
			char currChar = charsToHex(input[offset], input[offset + 1]);
			switch (j) {
			case 0:
				word.chars.c0 = currChar;
				break;
			case 1:
				word.chars.c1 = currChar;
				break;
			case 2:
				word.chars.c2 = currChar;
				break;
			default:
				word.chars.c3 = currChar;
			}
		}
		output[i] = word.i;
	}
}

// a, b 4x 32-bit int array
// a <- a (bitwise XOR) b
void aesXor(unsigned int* a, const unsigned int* b) {
	int i;
	for (i = 0; i < 4; i++) {
		a[i] = a[i] ^ b[i];
	}
}

// perform subWord on inout (32-bit int)
void subWord(unsigned int* inout) {
	union word_32 word;
	word.i = *inout;
	word.chars.c0 = aes_sbox[word.chars.c0];
	word.chars.c1 = aes_sbox[word.chars.c1];
	word.chars.c2 = aes_sbox[word.chars.c2];
	word.chars.c3 = aes_sbox[word.chars.c3];
	*inout = word.i;
}

// perform subBytes on inout (4x 32-bit int array)
void subBytes(unsigned int* inout) {
	int i;
	for (i = 0; i < 4; i++) {
		subWord(inout + i);
	}
}

// perform shiftRows on inout (4x 32-bit int array)
void shiftRows(unsigned int* inout) {
	int i;
	union word_32 word[4];
	for (i = 0; i < 4; i++) {
		word[i].i = inout[i];
	}
	char temp;
	// row 1 - cyclical left-shift 1
	temp = word[0].chars.c1;
	word[0].chars.c1 = word[1].chars.c1;
	word[1].chars.c1 = word[2].chars.c1;
	word[2].chars.c1 = word[3].chars.c1;
	word[3].chars.c1 = temp;

	// row 2 - cyclical left-shift 2
	temp = word[0].chars.c2;
	word[0].chars.c2 = word[2].chars.c2;
	word[2].chars.c2 = temp;
	temp = word[1].chars.c2;
	word[1].chars.c2 = word[3].chars.c2;
	word[3].chars.c2 = temp;

	// row 3 - cyclical left-shift 3 (same as right-shift 1)
	temp = word[0].chars.c3;
	word[0].chars.c3 = word[3].chars.c3;
	word[3].chars.c3 = word[2].chars.c3;
	word[2].chars.c3 = word[1].chars.c3;
	word[1].chars.c3 = temp;

	for (i = 0; i < 4; i++) {
		inout[i] = word[i].i;
	}
}

// perform mixColumns on inout (4x 32-bit int array)
void mixColumns(unsigned int* inout) {
	int i;
	union word_32 newWord[4], oldWord[4];
	for (i = 0; i < 4; i++) {
		oldWord[i].i = inout[i];
	}

	for (i = 0; i < 4; i++) { // iterate through each col (word)
		newWord[i].chars.c0 = gf_mul[oldWord[i].chars.c0][0] ^ gf_mul[oldWord[i].chars.c1][1] ^ oldWord[i].chars.c2 ^ oldWord[i].chars.c3;
		newWord[i].chars.c1 = oldWord[i].chars.c0 ^ gf_mul[oldWord[i].chars.c1][0] ^ gf_mul[oldWord[i].chars.c2][1] ^ oldWord[i].chars.c3;
		newWord[i].chars.c2 = oldWord[i].chars.c0 ^ oldWord[i].chars.c1 ^ gf_mul[oldWord[i].chars.c2][0] ^ gf_mul[oldWord[i].chars.c3][1];
		newWord[i].chars.c3 = gf_mul[oldWord[i].chars.c0][1] ^ oldWord[i].chars.c1 ^ oldWord[i].chars.c2 ^ gf_mul[oldWord[i].chars.c3][0];
	}

	for (i = 0; i < 4; i++) {
		inout[i] = newWord[i].i;
	}
}

// perform keyExpansion on inout (4x 32-bit int array)
// Idx is the Rcon idx (current iteration count)
void keyExpansion(unsigned int* inout, int Idx) {
	int i;
	union word_32 oldWord[4], newWord[4];
	for (i = 0; i < 4; i++) {
		oldWord[i].i = inout[i];
	}
	for (i = 0; i < 4; i++) {
		if (i) {
			newWord[i].i = oldWord[i].i ^ newWord[i - 1].i;
		}
		else {
			newWord[i].i = oldWord[3].i;
			// rotWord
			unsigned char temp = newWord[i].chars.c0;
			newWord[i].chars.c0 = newWord[i].chars.c1;
			newWord[i].chars.c1 = newWord[i].chars.c2;
			newWord[i].chars.c2 = newWord[i].chars.c3;
			newWord[i].chars.c3 = temp;

			//printf("%08x\n", newWord[i].i);

			subWord(&(newWord[i].i));
			newWord[i].i ^= Rcon[Idx];
			newWord[i].i ^= oldWord[i].i;
		}
	}
	for (i = 0; i < 4; i++) {
		inout[i] = newWord[i].i;
	}
}

/** encrypt
 *  Perform AES encryption in software.
 *
 *  Input: msg_ascii - Pointer to 32x 8-bit char array that contains the input message in ASCII format
 *         key_ascii - Pointer to 32x 8-bit char array that contains the input key in ASCII format
 *  Output:  msg_enc - Pointer to 4x 32-bit int array that contains the encrypted message
 *               key - Pointer to 4x 32-bit int array that contains the input key
 */
void encrypt(unsigned char* msg_ascii, unsigned char* key_ascii, unsigned int* msg_enc, unsigned int* key)
{
	// Implement this function
	int i;
	unsigned int aes_state[4], round_key[4];
	asciiToUint(key_ascii, key);
	asciiToUint(msg_ascii, aes_state);

	// first add round key (cipher key itself)
	aesXor(aes_state, key);
	for (i = 0; i < 4; i++) {
		round_key[i] = key[i];
	}

	// iteration starts
	for (i = 1; i < 10; i++) {
		subBytes(aes_state);
		shiftRows(aes_state);
		mixColumns(aes_state);
//		for (int j = 0; j < 4; j++) {
//			printf("%08x ", aes_state[j]);
//		}
//		printf("\n");
		keyExpansion(round_key, i);
		aesXor(aes_state, round_key);
	}

	subBytes(aes_state);
	shiftRows(aes_state);
	keyExpansion(round_key, i);
	aesXor(aes_state, round_key);

	for (i = 0; i < 4; i++) {
		msg_enc[i] = aes_state[i];
	}
}

/** decrypt
 *  Perform AES decryption in hardware.
 *
 *  Input:  msg_enc - Pointer to 4x 32-bit int array that contains the encrypted message
 *              key - Pointer to 4x 32-bit int array that contains the input key
 *  Output: msg_dec - Pointer to 4x 32-bit int array that contains the decrypted message
 */
void decrypt(unsigned int* msg_enc, unsigned int* msg_dec, unsigned int* key)
{
	// Implement this function
	for (int i = 0; i < 4; i++){
		AES_PTR[i] = key[i];
	}
	for (int i = 0; i < 4; i++){
		AES_PTR[i+4] = msg_enc[i];
	}
	AES_PTR[14] = 1;
	while(!AES_PTR[15]){}
	for (int i = 0; i < 4; i++){
		msg_dec[i] = AES_PTR[i+8];
	}
	AES_PTR[14] = 0;
}

/** main
 *  Allows the user to enter the message, key, and select execution mode
 *
 */
int main()
{
	// Input Message and Key as 32x 8-bit ASCII Characters ([33] is for NULL terminator)
	unsigned char msg_ascii[33];
	unsigned char key_ascii[33];
	// Key, Encrypted Message, and Decrypted Message in 4x 32-bit Format to facilitate Read/Write to Hardware
	unsigned int key[4];
	unsigned int msg_enc[4];
	unsigned int msg_dec[4];

	printf("Select execution mode: 0 for testing, 1 for benchmarking: ");
	scanf("%d", &run_mode);

	if (run_mode == 0) {
		// Continuously Perform Encryption and Decryption
		while (1) {
			int i = 0;
			printf("\nEnter Message:\n");
			scanf("%s", msg_ascii);
			printf("\n");
			printf("\nEnter Key:\n");
			scanf("%s", key_ascii);
			printf("\n");
			encrypt(msg_ascii, key_ascii, msg_enc, key);
			printf("\nEncrpted message is: \n");
			for (i = 0; i < 4; i++) {
				printf("%08x", msg_enc[i]);
			}
			printf("\n");
			decrypt(msg_enc, msg_dec, key);
			printf("\nDecrypted message is: \n");
			for (i = 0; i < 4; i++) {
				printf("%08x", msg_dec[i]);
			}
			printf("\n");
		}
	}
	else {
		// Run the Benchmark
		int i = 0;
		int size_KB = 2;
		// Choose a random Plaintext and Key
		for (i = 0; i < 32; i++) {
			msg_ascii[i] = 'a';
			key_ascii[i] = 'b';
		}
		// Run Encryption
		clock_t begin = clock();
		for (i = 0; i < size_KB * 64; i++)
			encrypt(msg_ascii, key_ascii, msg_enc, key);
		clock_t end = clock();
		double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		double speed = size_KB / time_spent;
		printf("Software Encryption Speed: %f KB/s \n", speed);
		// Run Decryption
		begin = clock();
		for (i = 0; i < size_KB * 64; i++)
			decrypt(msg_enc, msg_dec, key);
		end = clock();
		time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		speed = size_KB / time_spent;
		printf("Hardware Encryption Speed: %f KB/s \n", speed);
	}
	return 0;
}
