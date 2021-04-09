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

struct chars {
	unsigned char c0;
	unsigned char c1;
	unsigned char c2;
	unsigned char c3;
};

union word_32 {
	unsigned int i;
	struct chars charf;
};

// Pointer to base address of AES module, make sure it matches Qsys
volatile unsigned int* AES_PTR = (unsigned int *)0xc0;

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

//Convert ASCII array to int array
void intConversion(unsigned char* in, unsigned int* out) {

	for (int i = 0; i < 4; i++) {

		int j;
		union word_32 currWord;

		for (int j = 0; j < 4; j++) {

			char currChar = charsToHex(in[(4*i+j)*2], in[(4*i+j)*2+1]);
			if (j == 0)
				currWord.charf.c0 = currChar;
			else if (j==1)
				currWord.charf.c1 = currChar;
			else if (j==2)
				currWord.charf.c2 = currChar;
			else if (j==3)
				currWord.charf.c3 = currChar;

		}

		out[i] = currWord.i;

	}

}

// a, b bitwise xor
void aesXor(unsigned int* a, const unsigned int* b) {

	for (int i = 0; i < 4; i++)
		a[i] ^= b[i];

}

void subWord(unsigned int* index) {

	union word_32 currWord;
	currWord.i = *index;
	currWord.charf.c0 = aes_sbox[currWord.charf.c0];
	currWord.charf.c1 = aes_sbox[currWord.charf.c1];
	currWord.charf.c2 = aes_sbox[currWord.charf.c2];
	currWord.charf.c3 = aes_sbox[currWord.charf.c3];
	*index = currWord.i;

}

void subBytes(unsigned int* index) {

	for (int i = 0; i < 4; i++)
		subWord(index + i);

}

void Rotation(union word_32 *roword, int shift) {

	char temp;
	temp = roword[0].charf.c1;
	if (shift == 2) {
		roword[0].charf.c2 = roword[2].charf.c2;
		roword[2].charf.c2 = temp;
		temp = roword[1].charf.c2;
		roword[1].charf.c2 = roword[3].charf.c2;
		roword[3].charf.c2 = temp;
	} else{
		roword[0].charf.c1 = roword[shift].charf.c1;
		roword[shift].charf.c1 = roword[shift*2%4].charf.c1;
		roword[shift*2%4].charf.c1 = roword[shift*3%4].charf.c1;
		roword[shift*3%4].charf.c1 = temp;
	}

}

void shiftRows(unsigned int* index) {

	union word_32 roword[4];
	for (int i = 0; i < 4; i++)
		roword[i].i = index[i];

	// row1
	Rotation(roword, 1);
	// row2
	Rotation(roword, 2);
	// row3
	Rotation(roword, 3);

	for (int i = 0; i < 4; i++)
		index[i] = roword[i].i;

}

// mixcolumns
void mixColumns(unsigned int* index) {

	union word_32 newWord[4], currWord[4];

	for (int i = 0; i < 4; i++)
		currWord[i].i = index[i];

	for (int i = 0; i < 4; i++) { // iterate

		newWord[i].charf.c0 = gf_mul[currWord[i].charf.c0][0] ^ gf_mul[currWord[i].charf.c1][1] ^ currWord[i].charf.c2 ^ currWord[i].charf.c3;
		newWord[i].charf.c1 = currWord[i].charf.c0 ^ gf_mul[currWord[i].charf.c1][0] ^ gf_mul[currWord[i].charf.c2][1] ^ currWord[i].charf.c3;
		newWord[i].charf.c2 = currWord[i].charf.c0 ^ currWord[i].charf.c1 ^ gf_mul[currWord[i].charf.c2][0] ^ gf_mul[currWord[i].charf.c3][1];
		newWord[i].charf.c3 = gf_mul[currWord[i].charf.c0][1] ^ currWord[i].charf.c1 ^ currWord[i].charf.c2 ^ gf_mul[currWord[i].charf.c3][0];

	}

	for (int i = 0; i < 4; i++)
		index[i] = newWord[i].i;
}

// perform keyExpansion on index
void keyExpansion(unsigned int* index, int Idx) {

	union word_32 currWord[4], newWord[4];
	for (int i = 0; i < 4; i++)
		currWord[i].i = index[i];

	newWord[0].i = currWord[3].i;
	unsigned char temp = newWord[0].charf.c0;
	newWord[0].charf.c0 = newWord[0].charf.c1;
	newWord[0].charf.c1 = newWord[0].charf.c2;
	newWord[0].charf.c2 = newWord[0].charf.c3;
	newWord[0].charf.c3 = temp;

	subWord(&(newWord[0].i));
	newWord[0].i ^= Rcon[Idx];
	newWord[0].i ^= currWord[0].i;

	for (int i = 1; i < 4; i++)
		newWord[i].i = currWord[i].i ^ newWord[i - 1].i;

	for (int i = 0; i < 4; i++)
		index[i] = newWord[i].i;

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

	unsigned int aes_msg[4], round_key[4];
	intConversion(key_ascii, key);
	intConversion(msg_ascii, aes_msg);

	aesXor(aes_msg, key);
	for (int i = 0; i < 4; i++)
		round_key[i] = key[i];

	for (int i = 1; i < 10; i++) {
		subBytes(aes_msg);
		shiftRows(aes_msg);
		mixColumns(aes_msg);
		keyExpansion(round_key, i);
		aesXor(aes_msg, round_key);
	}

	subBytes(aes_msg);
	shiftRows(aes_msg);
	keyExpansion(round_key, 10);
	aesXor(aes_msg, round_key);

	for (int i = 0; i < 4; i++)
		msg_enc[i] = aes_msg[i];

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
