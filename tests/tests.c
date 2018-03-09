/*
 * tests.c
 *
 *  Created on: Jan 18, 2018
 *      Author: reza.zaba
 */



#include <stdio.h>
#include <tomcrypt.h>

#define PRINT
#define PRINTHASH
#define PRINTHMAC

int run_testvectors_ctr(char *cipher_name) {
	unsigned char key[3][32] = {
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
		{ 0xd7, 0x61, 0xf3, 0x99, 0x71, 0x38, 0xc1, 0xb9,
		  0xe7, 0x58, 0x26, 0xdb, 0x65, 0x80, 0x61, 0x53,
		  0x34, 0x49, 0x75, 0x14, 0x80, 0xf9, 0x88, 0x61,
		  0xaa, 0x4a, 0xff, 0xcb, 0x15, 0xcd, 0xac, 0x92 }
	};

	unsigned char pt[48] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x12, 0xf1, 0xe7, 0xf9, 0x12, 0xb8, 0x29, 0xf9,
		0xab, 0x31, 0x99, 0x01, 0xfc, 0xf9, 0xcd, 0x91
	};

	unsigned char iv[16] = {
		0x51, 0x0f, 0xe2, 0x08, 0xef, 0x75, 0x52, 0x66,
		0x66, 0x49, 0xf6, 0xfe, 0x16, 0xff, 0x8e, 0x25
	};

//	aes = AES

	unsigned char ct_aes[9][48] = {
		{ 0xa3, 0xb4, 0x2d, 0x78, 0x2d, 0x6b, 0xbe, 0xee,
		  0xdd, 0x77, 0x21, 0x12, 0xad, 0x22, 0x6a, 0x06,
		  0xa1, 0xea, 0x53, 0x8e, 0x1c, 0xad, 0x6f, 0xc1,
		  0x50, 0x83, 0x76, 0x3d, 0x13, 0xa6, 0x08, 0x4d,
		  0x2d, 0xfb, 0xe8, 0x66, 0x66, 0x80, 0xa4, 0xb0,
		  0x0e, 0x9a, 0xdc, 0xc8, 0x53, 0x80, 0x1c, 0x6c },

		{ 0xc3, 0x52, 0xeb, 0x6f, 0xc5, 0x03, 0x3d, 0x4f,
		  0xf1, 0x07, 0xc5, 0x3c, 0xf7, 0xda, 0x05, 0xa5,
		  0x1c, 0x48, 0x52, 0x1c, 0x8c, 0xc2, 0x79, 0xc0,
		  0x41, 0xdf, 0x0f, 0x0b, 0xf7, 0x3b, 0x4d, 0xa0,
		  0x0f, 0x06, 0xe3, 0x7a, 0x80, 0x11, 0x60, 0x6f,
		  0x8f, 0x16, 0xbd, 0x54, 0x44, 0x8f, 0x93, 0xab },

		{ 0xde, 0x5d, 0x86, 0x57, 0x24, 0xdf, 0x32, 0x04,
		  0xac, 0x00, 0x2d, 0x62, 0x1d, 0x28, 0xf3, 0xe9,
		  0x55, 0xe0, 0xff, 0xb5, 0x4d, 0x06, 0x12, 0xe3,
		  0x43, 0x48, 0xde, 0xb2, 0xc4, 0x1c, 0x96, 0xde,
		  0xdd, 0xb2, 0xbd, 0x79, 0xac, 0x0e, 0x3b, 0xd2,
		  0x4c, 0x73, 0x2e, 0x27, 0x57, 0x49, 0x4d, 0x67 },

		{ 0xfd, 0x59, 0x24, 0xf6, 0x7e, 0xbf, 0xdc, 0xe6,
		  0x01, 0xe0, 0x89, 0xe2, 0x3f, 0x9c, 0xd6, 0xfe,
		  0xb6, 0xc0, 0x64, 0x83, 0x95, 0xbc, 0x55, 0x55,
		  0xfd, 0x40, 0x22, 0x74, 0x18, 0xf2, 0xef, 0xdc,
		  0x5f, 0x3f, 0x60, 0x10, 0x4c, 0xef, 0x04, 0xf5,
		  0x2a, 0x23, 0x98, 0x86, 0xc1, 0x98, 0x17, 0x27 },

		{ 0xbe, 0xb2, 0xad, 0xa1, 0x82, 0xed, 0x7a, 0x9a,
		  0x22, 0x79, 0x92, 0xd9, 0x6a, 0x22, 0x1d, 0x5d,
		  0x7e, 0xf0, 0xf6, 0x28, 0x8d, 0xe3, 0xb0, 0x46,
		  0xbd, 0xc6, 0x34, 0x38, 0x39, 0x23, 0xe4, 0x78,
		  0x24, 0x6a, 0x3c, 0x4e, 0xa4, 0x78, 0x83, 0x16,
		  0xe3, 0x7d, 0xdb, 0x73, 0xb5, 0x37, 0x75, 0x5e },

		{ 0xf0, 0x20, 0x72, 0x16, 0xc0, 0x29, 0xd8, 0x53,
		  0x03, 0x99, 0xf2, 0xf7, 0x61, 0x55, 0x7f, 0x64,
		  0x98, 0x99, 0x2a, 0xc1, 0xe1, 0xa6, 0x01, 0xdd,
		  0x78, 0xd4, 0xf8, 0x46, 0x36, 0x8f, 0x6b, 0x4b,
		  0x7d, 0xd9, 0x12, 0x1b, 0x24, 0x4c, 0xb9, 0xcd,
		  0xac, 0xba, 0x6f, 0x53, 0x40, 0xfe, 0x22, 0xec },

		{ 0x36, 0x3a, 0xa8, 0x33, 0xa2, 0xfd, 0x26, 0x3f,
		  0xbb, 0x6c, 0x59, 0x91, 0x1d, 0xc2, 0x2e, 0x01,
		  0x25, 0x08, 0xf0, 0x47, 0x5b, 0x92, 0x47, 0xca,
		  0x22, 0xb9, 0x9e, 0xc3, 0x12, 0x23, 0xc0, 0x1b,
		  0x36, 0xa4, 0x26, 0x2e, 0xb7, 0xe8, 0x6a, 0x7e,
		  0x2f, 0x1c, 0xc6, 0x04, 0x04, 0xd9, 0xfd, 0xac },

		{ 0x6b, 0x0d, 0x49, 0xfe, 0xac, 0x34, 0xc3, 0xc5,
		  0x17, 0xe1, 0x3b, 0x62, 0x8c, 0x12, 0x6c, 0x0b,
		  0x03, 0x4f, 0x38, 0x1a, 0x95, 0x82, 0x97, 0xe3,
		  0x08, 0x9d, 0xec, 0x94, 0x3c, 0x76, 0xe1, 0xde,
		  0x58, 0xe6, 0x28, 0x9e, 0x0b, 0xa7, 0x2c, 0x09,
		  0xe7, 0xe1, 0x96, 0xd6, 0x38, 0x43, 0x3e, 0xe2 },

		{ 0xaa, 0xa9, 0x13, 0x82, 0x55, 0x77, 0x64, 0x49,
		  0x5f, 0xe1, 0x70, 0xa5, 0xb7, 0xb1, 0x62, 0x0d,
		  0xd2, 0xab, 0x96, 0xbb, 0x6c, 0x8a, 0x9a, 0xd9,
		  0x02, 0x62, 0x50, 0x88, 0xc4, 0x7f, 0x88, 0x73,
		  0xb7, 0xbe, 0x0b, 0xcb, 0x9a, 0xc6, 0x33, 0x03,
		  0x49, 0x2a, 0x98, 0x6b, 0xf1, 0x3e, 0x13, 0xd3 },
	};

	symmetric_CTR ctr;

	unsigned char pt0[80];
	unsigned char pt1[80];
	unsigned char ct[80];
	unsigned char curr_key[32];
	unsigned char *test_vec;

	int cipher_idx, err;
	int i, j, l;
	int keylen[] = { 16, 24, 32 };
	int countWord = 0;
	int offset_for_3des = 0;
	int ivlen = 0;

	// register the cipher
	if (!memcmp(cipher_name, "aes", 3)) {
		test_vec = ct_aes[0];
		if (register_cipher(&aes_desc) == -1) {
			printf("Error registering cipher\n");
			return -1;
		}
	}
	else {
		printf("Unknown cipher: %s\n", cipher_name);
		return -1;
	}

	// obtain the cipher ID
	cipher_idx = find_cipher(cipher_name);
	if (cipher_idx == -1) {
		printf("Invalid cipher\n");
		return -1;
	}

	ivlen = cipher_descriptor[cipher_idx].block_length;

	// three different key sizes (128, 192, 256 bits)
	for (i=0; i<3; i++) {
		// Triple-DES only supports 24 byte key. So skip the rest.
		if (!memcmp(cipher_name, "3des", 4) && (keylen[i] != 24))
			continue;

		// three different key values (all zeros, all ones, random)
		for (j=0; j<3; j++) {

			// load the current key value
			for (l=0; l<32; l++) {
				curr_key[l] = key[j][l];
			}

			// one 48-byte plaintext block
			if ((err = ctr_start(cipher_idx, iv, curr_key, keylen[i], 0,
								 CTR_COUNTER_BIG_ENDIAN, &ctr)) != CRYPT_OK) {
				printf("ctr_start error: %s\n", error_to_string(err));
				return -1;
			}
			else {
#ifdef PRINT
				printf("\nTEST VECTOR #%d (%s-%d)\n", i*3+j+1, cipher_name, keylen[i]*8);
				printf("Key                   = ");
				for (l=0; l<keylen[i]; l++) printf("%02x ", key[j][l]);
				printf("\n");

				printf("Plaintext             = ");
				for (l=0; l<48; l++) {
					printf("%02x ", pt[l]);
				}
				printf("\n");
#endif
				for (l=0; l<48; l++) {
					pt0[l] = pt[l];
				}

				if ((err = ctr_encrypt(pt0, ct, 48, &ctr)) != CRYPT_OK) {
					printf("ctr_encrypt error: %s\n", error_to_string(err));
					return -1;
				}

#ifdef PRINT
				printf("Ciphertext            = ");
				for (l=0; l<48; l++) printf("%02x ", ct[l]);
				printf("\n");
#endif

				if ((err = ctr_setiv(iv, ivlen, &ctr)) != CRYPT_OK) {
					printf("ctr_setiv error: %s\n", error_to_string(err));
					return -1;
				}

				if ((err = ctr_decrypt(ct, pt1, 48, &ctr)) != CRYPT_OK) {
					printf("ctr_decrypt error: %s\n", error_to_string(err));
					return -1;
				}

#ifdef PRINT
				printf("Decrypted Ciphertext  = ");
				for (l=0; l<48; l++) printf("%02x ", pt1[l]);
				printf("\n");
#endif

				if (!memcmp(cipher_name, "3des", 4)) {
					// 3*48 = 144
					offset_for_3des = 144;
				}

				for (l=0; l<48; l++) {
					// 3*48 = 144
//					printf("%d [%02x], ", i*144 + j*48 + l - offset_for_3des, test_vec[i*432 + j*3*48 + l - offset_for_3des]);
					if ((pt0[l] == pt1[l]) && (ct[l] == test_vec[i*144 + j*48 + l - offset_for_3des]))
						countWord++;
				}
//				printf("\n");

#ifdef PRINTOKSTATUS
				if (countWord == 48) {
						printf("%3d << OK >>\n", i*3+j+1);
				}
				else {
					printf("%3d << --- NOT OK [%2d] --- >>\n", i*3+j+1, countWord);
				}
#endif
				countWord = 0;
			}
		}
	}
//	printf("\n");

	// unregister the cipher
	if (!memcmp(cipher_name, "aes", 3)) {
		if ((err = unregister_cipher(&aes_desc)) != CRYPT_OK) {
			printf("Error removing cipher: %s\n", error_to_string(err));
			return -1;
		}
	}
	else {
		printf("Unknown cipher: %s\n", cipher_name);
		return -1;
	}

	return CRYPT_OK;
}



int run_testvectors_hash_function() {
	typedef struct AlgoName {
		char name[16];
	} algoName;

	algoName hash_name[2] = {
		{ "sha256" },
		{ "sha512" }
	};

	char print_name[10];

	int i, j, k, hash_idx, err, countWord, digest_size;
	hash_state hs;
	unsigned char pt[48] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				 	 	 	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
							 0x12, 0xf1, 0xe7, 0xf9, 0x12, 0xb8, 0x29, 0xf9, 0xab, 0x31, 0x99, 0x01, 0xfc, 0xf9, 0xcd, 0x91 };
	unsigned char digest[64];
	unsigned char *test_vec;
	int test_count = 0;
	int no_of_tests = 3;

	unsigned char dig_sha256[3][32] = {
		// sha256
		{ 0x37, 0x47, 0x08, 0xff, 0xf7, 0x71, 0x9d, 0xd5, 0x97, 0x9e, 0xc8, 0x75, 0xd5, 0x6c, 0xd2, 0x28, 0x6f, 0x6d, 0x3c, 0xf7, 0xec, 0x31, 0x7a, 0x3b, 0x25, 0x63, 0x2a, 0xab, 0x28, 0xec, 0x37, 0xbb },
		{ 0xa3, 0x86, 0xa1, 0x1d, 0x53, 0x5d, 0x60, 0x47, 0xc3, 0x0e, 0xcd, 0xd1, 0x13, 0x5c, 0x50, 0x8b, 0x28, 0x12, 0x37, 0x8b, 0x25, 0x54, 0xee, 0xab, 0x24, 0x7b, 0x48, 0xe7, 0x12, 0xdc, 0xe0, 0x09 },
		{ 0x2d, 0xa7, 0xf9, 0xff, 0xaa, 0xbe, 0x32, 0x66, 0x49, 0x06, 0x06, 0x51, 0x9d, 0xb5, 0x49, 0x54, 0x63, 0xa9, 0xb6, 0xe0, 0x9d, 0xb6, 0x16, 0xf6, 0x82, 0x3b, 0x61, 0x44, 0x2d, 0x25, 0xdc, 0x47 }};

	unsigned char dig_sha512[3][64] = {
		// sha512
		{ 0x0b, 0x6c, 0xba, 0xc8, 0x38, 0xdf, 0xe7, 0xf4, 0x7e, 0xa1, 0xbd, 0x0d, 0xf0, 0x0e, 0xc2, 0x82, 0xfd, 0xf4, 0x55, 0x10, 0xc9, 0x21, 0x61, 0x07, 0x2c, 0xcf, 0xb8, 0x40, 0x35, 0x39, 0x0c, 0x4d, 0xa7, 0x43, 0xd9, 0xc3, 0xb9, 0x54, 0xea, 0xa1, 0xb0, 0xf8, 0x6f, 0xc9, 0x86, 0x1b, 0x23, 0xcc, 0x6c, 0x86, 0x67, 0xab, 0x23, 0x2c, 0x11, 0xc6, 0x86, 0x43, 0x2e, 0xbb, 0x5c, 0x8c, 0x3f, 0x27 },
		{ 0xd2, 0x07, 0xa3, 0x8a, 0x8a, 0xf4, 0x75, 0x80, 0xca, 0x09, 0x19, 0x05, 0x0e, 0xa0, 0x95, 0x72, 0xd9, 0x50, 0x26, 0xaa, 0x9c, 0x42, 0xbc, 0x3a, 0xea, 0xb4, 0x52, 0xeb, 0x5d, 0xff, 0x66, 0x35, 0xaa, 0x94, 0x05, 0x6d, 0xf5, 0xf4, 0xc2, 0x48, 0xa7, 0xdc, 0x12, 0x26, 0x3c, 0x8b, 0x68, 0xae, 0x45, 0xcb, 0x9a, 0x79, 0x03, 0x73, 0xe2, 0xcb, 0x70, 0x3c, 0x4f, 0xe5, 0xca, 0x20, 0xff, 0xcb },
		{ 0x56, 0x29, 0xa6, 0x92, 0x29, 0xfc, 0xc8, 0x38, 0xe4, 0xf9, 0x8c, 0xd4, 0xf5, 0xa9, 0x14, 0x30, 0x53, 0x36, 0x4b, 0x6a, 0xfd, 0x57, 0x4e, 0x74, 0x89, 0x06, 0x26, 0xd8, 0xf3, 0x96, 0xa1, 0x85, 0xca, 0xa6, 0x3e, 0x02, 0x02, 0xe1, 0x9d, 0x36, 0x26, 0x62, 0x82, 0x03, 0x4a, 0x38, 0x77, 0x78, 0x0f, 0x59, 0x68, 0xf4, 0x75, 0xce, 0x3b, 0x71, 0x2a, 0x06, 0xf8, 0x71, 0x08, 0xba, 0x4c, 0x73 }};

	printf("\n");

	for (i = 0; i < 2; i++) {
		test_count = 0;

		if (!memcmp(hash_name[i].name, "sha256", 6)) {
			if (register_hash(&sha256_desc) == -1) {
				printf("Error registering hash\n");
				return -1;
			}
			test_vec = dig_sha256[0];
		}
		else if (!memcmp(hash_name[i].name, "sha512", 6)) {
			if (register_hash(&sha512_desc) == -1) {
				printf("Error registering hash\n");
				return -1;
			}
			test_vec = dig_sha512[0];
		}
		else {
			printf("Unknown hash\n");
			return -1;
		}

		// obtain the hash function index number
		hash_idx = find_hash(hash_name[i].name);
		if (hash_idx == -1) {
			printf("Invalid hash function: %s\n", hash_name[i].name);
			return -1;
		}

		digest_size = hash_descriptor[hash_idx].hashsize;

		// set the print name
		if (!memcmp(hash_name[i].name, "sha256", 6)) {
			strcpy(print_name, "SHA-256");
		}
		else if (!memcmp(hash_name[i].name, "sha512", 6)) {
			strcpy(print_name, "SHA-512");
		}

		printf("%s... \n", print_name);


		// cycle through different message lengths
		for (j = 0; j < 3; j++) {

			// initialize the hash
			hash_descriptor[hash_idx].init(&hs);

			// hash the data
			if ((err = hash_descriptor[hash_idx].process(&hs, pt, (j+1)*16)) != CRYPT_OK) {
				printf("Error when hashing data: %s\n", error_to_string(err));
			}

			// store the hash digest
			hash_descriptor[hash_idx].done(&hs, digest);

#ifdef PRINTHASH
			printf("Text    = ");
			for (k = 0; k < (j+1)*16; ++k) {
				printf("%02x", pt[k]);
			}
			printf("\n");
			printf("Digest  = ");
			for (k = 0; k < digest_size; ++k) {
				printf("%02x", digest[k]);
			}
			printf("\n");
#endif

			// compare with the test vectors
			countWord = 0;
			for (k = 0; k < digest_size; ++k) {
				if (digest[k] == test_vec[j*digest_size + k]) {
					countWord++;
				}
			}

			if (countWord == digest_size) {
				test_count++;
			}
			else {
			}
		}


		if (test_count == no_of_tests) {
			printf("OK!\n");
		}
		else {
			printf("ERROR!\n");
		}
	}

	return CRYPT_OK;
}



int run_testvectors_hmac() {
	typedef struct AlgoName {
		char name[16];
	} algoName;

	algoName hash_name[2] = {
		{ "sha256" },
		{ "sha512" }
	};

	char print_name[10];

	int i, j, k, l, hash_idx, err, countWord;
	unsigned long tag_len;
	hmac_state hms;
	unsigned char pt[48] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				 	 	 	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
							 0x12, 0xf1, 0xe7, 0xf9, 0x12, 0xb8, 0x29, 0xf9, 0xab, 0x31, 0x99, 0x01, 0xfc, 0xf9, 0xcd, 0x91 };
	unsigned char tag[64];
	unsigned char *test_vec;
	int test_count = 0;
	int no_of_tests = 9;

	unsigned char key[48] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xd7, 0x61, 0xf3, 0x99, 0x71, 0x38, 0xc1, 0xb9, 0xe7, 0x58, 0x26, 0xdb, 0x65, 0x80, 0x61, 0x53
	};

	unsigned char tag_sha256[9][32] = {
		// sha256
		{ 0x85, 0x3c, 0x74, 0x03, 0x93, 0x7d, 0x8b, 0x62, 0x39, 0x56, 0x9b, 0x18, 0x4e, 0xb7, 0x99, 0x3f, 0xc5, 0xf7, 0x51, 0xae, 0xfc, 0xea, 0x28, 0xf2, 0xc8, 0x63, 0x85, 0x8e, 0x2d, 0x29, 0xc5, 0x0b },
		{ 0x9b, 0x07, 0x04, 0x8c, 0x94, 0xaa, 0x81, 0xeb, 0x98, 0x3c, 0x7b, 0x5c, 0xe9, 0x46, 0x6e, 0xda, 0x39, 0xfa, 0x48, 0x71, 0xbc, 0x6b, 0x6d, 0x67, 0xd1, 0x4f, 0x95, 0x46, 0x74, 0x1e, 0x5b, 0xd6 },
		{ 0xa1, 0x41, 0xbc, 0x94, 0x2c, 0xd5, 0x5d, 0x92, 0x3d, 0x5d, 0x9e, 0x6c, 0xb2, 0xb0, 0xaf, 0x06, 0xd4, 0x0a, 0x0f, 0x61, 0x91, 0x42, 0x27, 0x79, 0xfd, 0x5b, 0x11, 0xb7, 0x3d, 0xb2, 0x7d, 0xd5 },
		{ 0x6c, 0x7b, 0xa3, 0xab, 0x82, 0xd6, 0x4a, 0x5c, 0x9f, 0xb1, 0x99, 0xe7, 0x35, 0x54, 0xfb, 0xbe, 0x40, 0xac, 0x65, 0xef, 0xb1, 0xe5, 0xd4, 0x05, 0xa3, 0x62, 0x82, 0xd3, 0xd7, 0x32, 0xb7, 0x42 },
		{ 0xde, 0xd2, 0x89, 0xda, 0x86, 0x24, 0xe5, 0x03, 0xa5, 0xf2, 0x3b, 0x7d, 0x92, 0x50, 0x42, 0x94, 0x74, 0x05, 0x8d, 0x92, 0x7c, 0x79, 0x57, 0x41, 0x12, 0xf1, 0x88, 0x66, 0xac, 0x78, 0x12, 0x02 },
		{ 0x94, 0x23, 0x2d, 0x26, 0x72, 0x08, 0xb8, 0x23, 0x35, 0x5c, 0xb8, 0x0d, 0x10, 0xe8, 0x96, 0xd2, 0x07, 0xbe, 0xf2, 0xcb, 0x67, 0xaa, 0xe3, 0x40, 0x0f, 0xce, 0xa9, 0x2a, 0x63, 0x0a, 0xf5, 0xd9 },
		{ 0xe9, 0xdd, 0xd5, 0x4e, 0xd8, 0x2c, 0x97, 0xeb, 0x0c, 0x45, 0xea, 0xb7, 0x8b, 0xbb, 0x95, 0xd2, 0xbf, 0xac, 0xf6, 0x63, 0xa8, 0xa7, 0x85, 0x22, 0xa8, 0xdc, 0x7c, 0x42, 0xfd, 0xc2, 0xad, 0xcd },
		{ 0x27, 0x17, 0x49, 0xe6, 0xad, 0xec, 0x8c, 0x29, 0x57, 0xb7, 0xdf, 0xd6, 0xad, 0x90, 0x55, 0x01, 0x4b, 0x0e, 0xa0, 0xd3, 0xb0, 0x95, 0x44, 0xda, 0x45, 0x10, 0x46, 0x8b, 0x10, 0xee, 0x0a, 0x6a },
		{ 0xb2, 0x8a, 0x23, 0xef, 0xcf, 0x26, 0x77, 0x11, 0xeb, 0xe5, 0x04, 0xaf, 0x77, 0x17, 0xfa, 0x84, 0xfd, 0x89, 0x70, 0x38, 0x2a, 0xa3, 0x2f, 0xaa, 0xf8, 0xbf, 0x46, 0x7d, 0x74, 0xc3, 0x45, 0x3b }};

	unsigned char tag_sha512[9][64] = {
		// sha512
		{ 0x65, 0xe8, 0x79, 0xd4, 0x7d, 0xf1, 0xde, 0xf0, 0xaf, 0x37, 0x8d, 0x32, 0xe9, 0xf4, 0xfe, 0x3a, 0x82, 0x4f, 0xb5, 0x1e, 0x21, 0x43, 0xc0, 0x33, 0x22, 0xde, 0xf2, 0x29, 0x36, 0x1a, 0xf3, 0xb1, 0x7a, 0x72, 0x4a, 0x3d, 0x65, 0x3d, 0x05, 0xcb, 0x9f, 0x41, 0xf4, 0xb9, 0x0d, 0x09, 0xe8, 0xe2, 0x88, 0x6a, 0x78, 0xda, 0x48, 0x53, 0x7d, 0x1c, 0xfa, 0x62, 0x97, 0x7a, 0x82, 0xe7, 0x37, 0x4e },
		{ 0x4f, 0xe2, 0x46, 0x9c, 0x71, 0x02, 0x72, 0x14, 0x3b, 0x34, 0x39, 0x9f, 0x45, 0xb5, 0x5b, 0x75, 0x9d, 0x96, 0x63, 0x54, 0x84, 0xeb, 0x83, 0x57, 0xb1, 0x9d, 0x83, 0x88, 0xe2, 0xcb, 0x37, 0xe1, 0xc5, 0xf9, 0xc1, 0x46, 0x3d, 0xde, 0xd5, 0xe3, 0xa6, 0x1d, 0xd1, 0x8d, 0x39, 0x3f, 0x63, 0x51, 0xb1, 0x07, 0x6f, 0xb2, 0xaf, 0x02, 0x4b, 0xbf, 0xd3, 0x0e, 0x52, 0x0d, 0x1f, 0x02, 0x41, 0xc9 },
		{ 0xfd, 0x1d, 0x07, 0x8b, 0xa1, 0xf0, 0x74, 0xa3, 0x53, 0x2c, 0xa4, 0x07, 0x4d, 0xbb, 0x25, 0x76, 0x45, 0x0b, 0xa5, 0x68, 0x7a, 0xad, 0x8f, 0x86, 0x99, 0xc0, 0x6c, 0x75, 0xb7, 0x7e, 0x95, 0xc2, 0xf8, 0xac, 0xc7, 0x8b, 0xfa, 0xb1, 0x44, 0x15, 0x1e, 0x6c, 0x96, 0x8e, 0x11, 0x5a, 0xd7, 0xdc, 0xa6, 0x31, 0x95, 0xfb, 0xb1, 0x9d, 0x78, 0x8c, 0x3d, 0x9a, 0x3b, 0x90, 0x50, 0x2a, 0x09, 0x26 },
		{ 0x6d, 0x64, 0x7c, 0x4b, 0xd1, 0x32, 0x4d, 0x26, 0xe9, 0xa0, 0x1d, 0xe5, 0x84, 0x13, 0xa1, 0x62, 0xb3, 0xa5, 0x47, 0x80, 0xcb, 0xd6, 0xae, 0xd7, 0xc4, 0x59, 0x87, 0x08, 0x77, 0x20, 0x41, 0x2b, 0xbe, 0xa2, 0x0e, 0x2f, 0xb9, 0xc5, 0xfa, 0x79, 0xe6, 0x1e, 0x61, 0xc8, 0x69, 0xc9, 0x24, 0x8c, 0x9d, 0xbe, 0x30, 0x36, 0x10, 0x6a, 0x69, 0xd0, 0xc2, 0xe0, 0x6d, 0x26, 0x48, 0x6c, 0x8e, 0x96 },
		{ 0x0c, 0x71, 0x60, 0x12, 0x89, 0x69, 0x8c, 0x27, 0x69, 0x23, 0x0b, 0x43, 0x8a, 0x33, 0x30, 0x89, 0x22, 0x76, 0x82, 0x95, 0x71, 0xbb, 0x2a, 0xd5, 0x7d, 0x85, 0x67, 0x38, 0xe4, 0x44, 0x4f, 0x41, 0x8b, 0x68, 0xaa, 0x12, 0x66, 0xad, 0xfd, 0x91, 0x7c, 0xba, 0x59, 0x42, 0x57, 0x6c, 0x85, 0xa3, 0x66, 0xd4, 0x88, 0xa3, 0x9c, 0xd4, 0x17, 0x88, 0x01, 0x55, 0xf3, 0xcf, 0x48, 0x8b, 0x33, 0xc5 },
		{ 0x3d, 0x57, 0x29, 0x1a, 0xb1, 0xc7, 0x5c, 0x42, 0x65, 0x68, 0xc3, 0x39, 0xe7, 0xd9, 0xdd, 0x08, 0xd2, 0x35, 0x25, 0x2d, 0x9c, 0x32, 0x31, 0xf9, 0x4c, 0x7a, 0x62, 0x2b, 0x61, 0x95, 0x19, 0x42, 0x69, 0xfb, 0xca, 0x40, 0xe2, 0xf6, 0x75, 0x2d, 0x7d, 0xa7, 0xea, 0xa7, 0xc4, 0x1e, 0x7d, 0x41, 0x68, 0xca, 0x36, 0x6a, 0xc3, 0x67, 0x4d, 0xc1, 0x0b, 0xae, 0x0b, 0x65, 0xe9, 0xe4, 0x89, 0x46 },
		{ 0x4a, 0x38, 0x6c, 0x94, 0xf8, 0x82, 0xfc, 0x33, 0x5c, 0x03, 0x41, 0xf8, 0x09, 0x40, 0x68, 0x11, 0x96, 0x8a, 0x0e, 0xd0, 0xcb, 0x1a, 0xcd, 0x08, 0x0c, 0x89, 0xcc, 0x5e, 0x25, 0x4f, 0xbf, 0x06, 0x57, 0xdb, 0xb1, 0xe3, 0x65, 0x9f, 0x91, 0x69, 0x62, 0x58, 0xcd, 0x99, 0x75, 0xdb, 0x63, 0x77, 0x93, 0xcb, 0x10, 0x46, 0x21, 0x5a, 0x7a, 0x6c, 0x16, 0xd2, 0x7d, 0xd1, 0xf3, 0x46, 0x70, 0xbe },
		{ 0x29, 0x88, 0x3e, 0x90, 0xe2, 0x14, 0x78, 0x5d, 0x31, 0x94, 0xc6, 0x3b, 0x8f, 0xfb, 0xdb, 0x8c, 0x55, 0x5b, 0x11, 0x28, 0x9b, 0xb1, 0xae, 0x73, 0xee, 0x28, 0x99, 0xea, 0x20, 0x81, 0x6e, 0x14, 0xd8, 0x12, 0x6e, 0x8a, 0x7c, 0xac, 0xac, 0x52, 0xa5, 0x0f, 0x55, 0xd2, 0xee, 0x8a, 0x35, 0xc0, 0x36, 0x13, 0xa3, 0x76, 0x10, 0x55, 0x30, 0x41, 0x9c, 0x71, 0x0a, 0x6b, 0x87, 0xca, 0xc9, 0x8c },
		{ 0xdf, 0xb2, 0xc5, 0x11, 0xea, 0xf6, 0x73, 0xd3, 0x0e, 0xa5, 0x5b, 0xaa, 0xde, 0x5e, 0xab, 0x26, 0x66, 0x40, 0x87, 0x50, 0xd5, 0x85, 0x08, 0x62, 0x4b, 0x96, 0xce, 0x43, 0xa4, 0x2a, 0x9f, 0x85, 0x09, 0xb4, 0x57, 0x39, 0xa5, 0x04, 0x18, 0x66, 0xb1, 0x42, 0xcf, 0x34, 0x75, 0xa5, 0x9c, 0x64, 0x6c, 0x78, 0xfe, 0x85, 0x47, 0x1d, 0xba, 0xab, 0xe4, 0x72, 0xb2, 0x3a, 0xce, 0x07, 0x94, 0x15 }};

	printf("\n");
	for (i = 0; i < 2; i++) {
		test_count = 0;

		if (!memcmp(hash_name[i].name, "sha256", 6)) {
			if (register_hash(&sha256_desc) == -1) {
				printf("Error registering hash\n");
				return -1;
			}
			test_vec = tag_sha256[0];
		}
		else if (!memcmp(hash_name[i].name, "sha512", 6)) {
			if (register_hash(&sha512_desc) == -1) {
				printf("Error registering hash\n");
				return -1;
			}
			test_vec = tag_sha512[0];
		}
		else {
			printf("Unknown hash\n");
			return -1;
		}

		// obtain the hash function index number
		hash_idx = find_hash(hash_name[i].name);
		if (hash_idx == -1) {
			printf("Invalid hash function: %s\n", hash_name[i].name);
			return -1;
		}

		tag_len = hash_descriptor[hash_idx].hashsize;

		// set the print name
		if (!memcmp(hash_name[i].name, "sha256", 6)) {
			strcpy(print_name, "SHA256");
		}
		else if (!memcmp(hash_name[i].name, "sha512", 6)) {
			strcpy(print_name, "SHA512");
		}

		printf("HMAC-%s... \n", print_name);


		// cycle through different key lengths
		for (j = 0; j < 3; j++) {

			// cycle through different message lengths
			for (k = 0; k < 3; k++) {

				// initialize the hash
				if ((err = hmac_init(&hms, hash_idx, key, (j+1)*16)) != CRYPT_OK) {
					printf("Error initializing HMAC: %s\n", error_to_string(err));
					return -1;
				}

				// MAC the data
				if ((err = hmac_process(&hms, pt, (k+1)*16)) != CRYPT_OK) {
					printf("Error when hashing data: %s\n", error_to_string(err));
				}

				// store the MAC tag
				hmac_done(&hms, tag, &tag_len);

#ifdef PRINTHMAC
				printf("Text    = ");
				for (l = 0; l < (k+1)*16; l++) {
					printf("%02x", pt[l]);
				}
				printf("\n");
				printf("MAC tag = ");
				for (l = 0; l < tag_len; l++) {
					printf("%02x", tag[l]);
				}
				printf("\n");
#endif

				// compare with the test vectors
				countWord = 0;
				for (l = 0; l < tag_len; l++) {
					if (tag[l] == test_vec[j*3*tag_len + k*tag_len + l]) {
						countWord++;
					}
				}

				if (countWord == tag_len) {
					test_count++;

				}
				else {

				}

			}
		}


		if (test_count == no_of_tests) {
			printf("OK!\n");
		}
		else {
			printf("ERROR!\n");
		}
	}

	return CRYPT_OK;
}


int test_prng() {
	prng_state prng;
	int err, i;
	unsigned long x;
	unsigned char prng_bits[256];

	printf("\n");

	/* register chacha20 */
	if (register_prng(&chacha20_prng_desc) == -1) {
		printf("Error registering ChaCha20\n");
		return -1;
	}

	/* setup the PRNG */
	if ((err = rng_make_prng(128, find_prng("chacha20"), &prng, NULL)) != CRYPT_OK) {
		printf("Error setting up PRNG, %s\n", error_to_string(err));
	}

	x = chacha20_prng_read(prng_bits, 32, &prng);

	printf("ChaCha20: ");
	for (i = 0; i < 32; ++i) {
		printf("%02x ", prng_bits[i]);
	}
	printf("\n");

	return 0;
}

int run_present() {
	symmetric_key skey;
	unsigned char key0[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char key1[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	unsigned char key3[16] = { 0x5B, 0x91, 0xCA, 0xDF, 0xF9, 0x30, 0x12, 0xDC,
			        0xEC, 0x87, 0x9D, 0x5A, 0x79, 0x0E, 0x13, 0x92 };
	unsigned char key4[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
					0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

	unsigned char pt0[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pt1[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	unsigned char pt2[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

	unsigned char iv[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	unsigned char *pt, *key;
	unsigned char ct[8];
	int keylen = 16, i;
	int cipher_idx, err, ivlen = 0;

	symmetric_ECB ecb;
	symmetric_CTR ctr;

	if (register_cipher(&present_desc) == -1) {
		printf("Error registering cipher\n");
		return -1;
	}

	// obtain the cipher ID
	cipher_idx = find_cipher("present");
	if (cipher_idx == -1) {
		printf("Invalid cipher\n");
		return -1;
	}

	ivlen = cipher_descriptor[cipher_idx].block_length;

	pt = pt2;
	key = key4;

	// ECB Mode
	if ((err = ecb_start(cipher_idx, key, keylen, 0, &ecb)) != CRYPT_OK) {
		printf("ecb_start error: %s\n", error_to_string(err));
		return -1;
	}

	printf("Key                   = ");
	for (i=0; i<keylen; i++) printf("%02x ", key[i]);
	printf("\n");

	printf("Plaintext             = ");
	for (i=0; i<8; i++) {
		printf("%02x ", pt[i]);
	}
	printf("\n");

	if ((err = ecb_encrypt(pt, ct, 8, &ecb)) != CRYPT_OK) {
		printf("ecb_encrypt error: %s\n", error_to_string(err));
		return -1;
	}

	printf("Ciphertext            = ");
	for (i=0; i<8; i++) printf("%02x ", ct[i]);
	printf("\n");

	if ((err = ecb_decrypt(ct, pt, 8, &ecb)) != CRYPT_OK) {
		printf("ecb_decrypt error: %s\n", error_to_string(err));
		return -1;
	}

	printf("Plaintext             = ");
	for (i=0; i<8; i++) {
		printf("%02x ", pt[i]);
	}
	printf("\n");


	// CTR Mode
	if ((err = ctr_start(cipher_idx, iv, key, keylen, 0,
						 CTR_COUNTER_BIG_ENDIAN, &ctr)) != CRYPT_OK) {
		printf("ctr_start error: %s\n", error_to_string(err));
		return -1;
	}
	else {
#ifdef PRINT
		printf("\n\nKey                   = ");
		for (i=0; i<keylen; i++) printf("%02x ", key[i]);
		printf("\n");

		printf("Plaintext             = ");
		for (i=0; i<8; i++) {
			printf("%02x ", pt[i]);
		}
		printf("\n");
#endif

		if ((err = ctr_encrypt(pt, ct, 8, &ctr)) != CRYPT_OK) {
			printf("ctr_encrypt error: %s\n", error_to_string(err));
			return -1;
		}

#ifdef PRINT
		printf("Ciphertext            = ");
		for (i=0; i<8; i++) printf("%02x ", ct[i]);
		printf("\n");
#endif

		if ((err = ctr_setiv(iv, ivlen, &ctr)) != CRYPT_OK) {
			printf("ctr_setiv error: %s\n", error_to_string(err));
			return -1;
		}

		if ((err = ctr_decrypt(ct, pt, 8, &ctr)) != CRYPT_OK) {
			printf("ctr_decrypt error: %s\n", error_to_string(err));
			return -1;
		}

		if ((err = ctr_done(&ctr)) != CRYPT_OK) {
			printf("ctr_done error: %s\n", error_to_string(err));
			return -1;
		}

#ifdef PRINT
		printf("Decrypted Ciphertext  = ");
		for (i=0; i<8; i++) printf("%02x ", pt[i]);
		printf("\n");
#endif
	}

	if (unregister_cipher(&present_desc) == -1) {
		printf("Error removing cipher\n");
		return -1;
	}



	return CRYPT_OK;
}


int main() {
//	run_testvectors_ctr("aes");
//	run_testvectors_hash_function();
//	run_testvectors_hmac();
//	test_prng();
	run_present();

	return 0;
}
