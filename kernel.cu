// josecarlos.garciaortega@alum.uca.es
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
	invalid_plaintext,
	invalid_key,
	cuda_fail,
	successful
} cipher_status;

__global__ void internal_vigenere(char * dev_text, const char * dev_key, int keyLen, int len) {
	unsigned int i;
	char c;
	i = threadIdx.x + blockIdx.x * blockDim.x;
	
	c = dev_text[i];
	if (c >= 'a' && c <= 'z')
		c += 'A' - 'a';
	else if (c < 'A' || c > 'Z')
		return;

	dev_text[i] = (c - dev_key[i % keyLen] + 26) % 26 + 'A';
}
cipher_status generate_vigenere(const char * plainText, char * key, char * cipherText) {
	int blockSize, minGridSize, gridSize, i, keyLen, len;
	char * dev_text, *dev_key;
	cudaError_t cudaStatus;

	keyLen = strlen(key);
	len = strlen(plainText);

	for (i = 0; i < keyLen; ++i)
	{
		if (key[i] >= 'A' && key[i] <= 'Z')
			key[i] = key[i];
		else if (key[i] >= 'a' && key[i] <= 'z')
			key[i] = key[i] + 'A' - 'a';
	}
	
	// Start cuda interface
	cudaStatus = cudaSetDevice(0);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaSetDevice failed!  Do you have a CUDA-capable GPU installed?");
		return cuda_fail;
	}

	cudaStatus = cudaMalloc((void**)&dev_text, (len+1)*sizeof(char));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		return cuda_fail;
	}

	cudaStatus = cudaMalloc((void**)&dev_key, (keyLen + 1)*sizeof(char));
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMalloc failed!");
		return cuda_fail;
	}

	cudaStatus = cudaMemcpy(dev_text, plainText, (len+1)* sizeof(char), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy failed!");
		return cuda_fail;
	}

	cudaStatus = cudaMemcpy(dev_key, key, (keyLen + 1)* sizeof(char), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy failed!");
		return cuda_fail;
	}

	cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, internal_vigenere, 0, len);
	gridSize = (len + blockSize - 1) / blockSize;

	internal_vigenere << <gridSize, blockSize >> >(dev_text, dev_key, keyLen, len);



	// Check for any errors launching the kernel
	cudaStatus = cudaGetLastError();
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "vigenere launch failed: %s\n", cudaGetErrorString(cudaStatus));
		return cuda_fail;
	}

	// cudaDeviceSynchronize waits for the kernel to finish, and returns
	// any errors encountered during the launch.
	cudaStatus = cudaDeviceSynchronize();
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaDeviceSynchronize returned error code %d after launching jacobi!\n", cudaStatus);
		return cuda_fail;
	}

	cudaStatus = cudaMemcpy(cipherText, dev_text, (len+1)* sizeof(char), cudaMemcpyDeviceToHost);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy failed!");
		return cuda_fail;
	}

	return successful;
}


cipher_status cipher_vigenere (const char * plainText,  char * key, char * cipherText) {
	return generate_vigenere(plainText, key, cipherText);
}

cipher_status decipher_vigenere(const char * plainText, char * key, char * cipherText) {
	char * newKey;
	int keyLen, i;

	keyLen = strlen(key);

	newKey = (char*)malloc(sizeof(char)*(keyLen + 1));

	for (i = 0; i < keyLen; i++) newKey[i] = -key[i];
	newKey[i] = 0;

	return generate_vigenere(plainText, newKey, cipherText);
}

void cipherfile(char * key, const char * src, const char * dst) {
	FILE *f;
	long fsize;
	char * plainText, *cipherText;
	// http://stackoverflow.com/questions/14002954/c-programming-how-to-read-the-whole-file-contents-into-a-buffer
	f = fopen(src, "rb");
	fseek(f, 0, SEEK_END);
	fsize = ftell(f);
	fseek(f, 0, SEEK_SET); 

    plainText = (char*)malloc(fsize + 1);
	cipherText = (char*)malloc(fsize + 1);
	fread(plainText, fsize, 1, f);
	fclose(f);
	plainText[fsize] = 0;

	cipher_vigenere(plainText, key, cipherText);

	f = fopen(dst, "w");
	fwrite(cipherText, sizeof(char), fsize + 1, f);
	fclose(f);
}


void decipherfile(char * key, const char * src, const char * dst) {
	FILE *f;
	long fsize;
	char * plainText, *cipherText;
	// http://stackoverflow.com/questions/14002954/c-programming-how-to-read-the-whole-file-contents-into-a-buffer
	f = fopen(src, "rb");
	fseek(f, 0, SEEK_END);
	fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	plainText = (char*)malloc(fsize + 1);
	cipherText = (char*)malloc(fsize + 1);
	fread(plainText, fsize, 1, f);
	fclose(f);
	plainText[fsize] = 0;

	decipher_vigenere(plainText, key, cipherText);

	f = fopen(dst, "w");
	fwrite(cipherText, sizeof(char), fsize + 1, f);
	fclose(f);
}

int main(int argc, char ** args)
{
	puts("Jose Carlos Garcia - josecarlos.garciaortega@alum.uca.es - 2016");

	if (!strcmp(args[1], "cf") && argc == 5)
		cipherfile(args[2], args[3], args[4]);
	if (!strcmp(args[1], "df") && argc == 5)
		decipherfile(args[2], args[3], args[4]);


	return 0;
}