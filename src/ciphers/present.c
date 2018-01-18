/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* 
 * PRESENT implementation by MRZ
 *
 */

#include "tomcrypt.h"

#ifdef LTC_PRESENT

const struct ltc_cipher_descriptor present_desc =
{
    "present",
    100, // internal ID
    10, 16, 8, 31, // min key size, max key size, block size, default number of rounds
	&present_setup,
	&present_ecb_encrypt,
	&present_ecb_decrypt,
	&present_test,
	&present_done,
	&present_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

unsigned char S[16] = { 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
						0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2 };

unsigned char S8[256] = {
	0xcc, 0xc5, 0xc6, 0xcb, 0xc9, 0xc0, 0xca, 0xcd,
	0xc3, 0xce, 0xcf, 0xc8, 0xc4, 0xc7, 0xc1, 0xc2,
	0x5c, 0x55, 0x56, 0x5b, 0x59, 0x50, 0x5a, 0x5d,
	0x53, 0x5e, 0x5f, 0x58, 0x54, 0x57, 0x51, 0x52,
	0x6c, 0x65, 0x66, 0x6b, 0x69, 0x60, 0x6a, 0x6d,
	0x63, 0x6e, 0x6f, 0x68, 0x64, 0x67, 0x61, 0x62,
	0xbc, 0xb5, 0xb6, 0xbb, 0xb9, 0xb0, 0xba, 0xbd,
	0xb3, 0xbe, 0xbf, 0xb8, 0xb4, 0xb7, 0xb1, 0xb2,
	0x9c, 0x95, 0x96, 0x9b, 0x99, 0x90, 0x9a, 0x9d,
	0x93, 0x9e, 0x9f, 0x98, 0x94, 0x97, 0x91, 0x92,
	0x0c, 0x05, 0x06, 0x0b, 0x09, 0x00, 0x0a, 0x0d,
	0x03, 0x0e, 0x0f, 0x08, 0x04, 0x07, 0x01, 0x02,
	0xac, 0xa5, 0xa6, 0xab, 0xa9, 0xa0, 0xaa, 0xad,
	0xa3, 0xae, 0xaf, 0xa8, 0xa4, 0xa7, 0xa1, 0xa2,
	0xdc, 0xd5, 0xd6, 0xdb, 0xd9, 0xd0, 0xda, 0xdd,
	0xd3, 0xde, 0xdf, 0xd8, 0xd4, 0xd7, 0xd1, 0xd2,
	0x3c, 0x35, 0x36, 0x3b, 0x39, 0x30, 0x3a, 0x3d,
	0x33, 0x3e, 0x3f, 0x38, 0x34, 0x37, 0x31, 0x32,
	0xec, 0xe5, 0xe6, 0xeb, 0xe9, 0xe0, 0xea, 0xed,
	0xe3, 0xee, 0xef, 0xe8, 0xe4, 0xe7, 0xe1, 0xe2,
	0xfc, 0xf5, 0xf6, 0xfb, 0xf9, 0xf0, 0xfa, 0xfd,
	0xf3, 0xfe, 0xff, 0xf8, 0xf4, 0xf7, 0xf1, 0xf2,
	0x8c, 0x85, 0x86, 0x8b, 0x89, 0x80, 0x8a, 0x8d,
	0x83, 0x8e, 0x8f, 0x88, 0x84, 0x87, 0x81, 0x82,
	0x4c, 0x45, 0x46, 0x4b, 0x49, 0x40, 0x4a, 0x4d,
	0x43, 0x4e, 0x4f, 0x48, 0x44, 0x47, 0x41, 0x42,
	0x7c, 0x75, 0x76, 0x7b, 0x79, 0x70, 0x7a, 0x7d,
	0x73, 0x7e, 0x7f, 0x78, 0x74, 0x77, 0x71, 0x72,
	0x1c, 0x15, 0x16, 0x1b, 0x19, 0x10, 0x1a, 0x1d,
	0x13, 0x1e, 0x1f, 0x18, 0x14, 0x17, 0x11, 0x12,
	0x2c, 0x25, 0x26, 0x2b, 0x29, 0x20, 0x2a, 0x2d,
	0x23, 0x2e, 0x2f, 0x28, 0x24, 0x27, 0x21, 0x22
};

// Inverse S-box
unsigned char SI8[256] = {
	0x55, 0x5e, 0x5f, 0x58, 0x5c, 0x51, 0x52, 0x5d,
	0x5b, 0x54, 0x56, 0x53, 0x50, 0x57, 0x59, 0x5a,
	0xe5, 0xee, 0xef, 0xe8, 0xec, 0xe1, 0xe2, 0xed,
	0xeb, 0xe4, 0xe6, 0xe3, 0xe0, 0xe7, 0xe9, 0xea,
	0xf5, 0xfe, 0xff, 0xf8, 0xfc, 0xf1, 0xf2, 0xfd,
	0xfb, 0xf4, 0xf6, 0xf3, 0xf0, 0xf7, 0xf9, 0xfa,
	0x85, 0x8e, 0x8f, 0x88, 0x8c, 0x81, 0x82, 0x8d,
	0x8b, 0x84, 0x86, 0x83, 0x80, 0x87, 0x89, 0x8a,
	0xc5, 0xce, 0xcf, 0xc8, 0xcc, 0xc1, 0xc2, 0xcd,
	0xcb, 0xc4, 0xc6, 0xc3, 0xc0, 0xc7, 0xc9, 0xca,
	0x15, 0x1e, 0x1f, 0x18, 0x1c, 0x11, 0x12, 0x1d,
	0x1b, 0x14, 0x16, 0x13, 0x10, 0x17, 0x19, 0x1a,
	0x25, 0x2e, 0x2f, 0x28, 0x2c, 0x21, 0x22, 0x2d,
	0x2b, 0x24, 0x26, 0x23, 0x20, 0x27, 0x29, 0x2a,
	0xd5, 0xde, 0xdf, 0xd8, 0xdc, 0xd1, 0xd2, 0xdd,
	0xdb, 0xd4, 0xd6, 0xd3, 0xd0, 0xd7, 0xd9, 0xda,
	0xb5, 0xbe, 0xbf, 0xb8, 0xbc, 0xb1, 0xb2, 0xbd,
	0xbb, 0xb4, 0xb6, 0xb3, 0xb0, 0xb7, 0xb9, 0xba,
	0x45, 0x4e, 0x4f, 0x48, 0x4c, 0x41, 0x42, 0x4d,
	0x4b, 0x44, 0x46, 0x43, 0x40, 0x47, 0x49, 0x4a,
	0x65, 0x6e, 0x6f, 0x68, 0x6c, 0x61, 0x62, 0x6d,
	0x6b, 0x64, 0x66, 0x63, 0x60, 0x67, 0x69, 0x6a,
	0x35, 0x3e, 0x3f, 0x38, 0x3c, 0x31, 0x32, 0x3d,
	0x3b, 0x34, 0x36, 0x33, 0x30, 0x37, 0x39, 0x3a,
	0x05, 0x0e, 0x0f, 0x08, 0x0c, 0x01, 0x02, 0x0d,
	0x0b, 0x04, 0x06, 0x03, 0x00, 0x07, 0x09, 0x0a,
	0x75, 0x7e, 0x7f, 0x78, 0x7c, 0x71, 0x72, 0x7d,
	0x7b, 0x74, 0x76, 0x73, 0x70, 0x77, 0x79, 0x7a,
	0x95, 0x9e, 0x9f, 0x98, 0x9c, 0x91, 0x92, 0x9d,
	0x9b, 0x94, 0x96, 0x93, 0x90, 0x97, 0x99, 0x9a,
	0xa5, 0xae, 0xaf, 0xa8, 0xac, 0xa1, 0xa2, 0xad,
	0xab, 0xa4, 0xa6, 0xa3, 0xa0, 0xa7, 0xa9, 0xaa,
};


 /**
    Initialize the PRESENT block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
int present_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
    int i;
	ulong64 K_hi = 0;
	ulong64 K_lo = 0;
	ulong64 temp;
	
    LTC_ARGCHK(key  != NULL);
    LTC_ARGCHK(skey != NULL);

    if (keylen != 10 && keylen != 16) {
       return CRYPT_INVALID_KEYSIZE;
    }

    if (num_rounds != 0 && num_rounds != 31) {
       return CRYPT_INVALID_ROUNDS;
    }

    skey->present.Nr = 31;

	// load the first 64 bits of the key
	K_hi =
      ((ulong64)key[ 0] << 56) ^
      ((ulong64)key[ 1] << 48) ^
      ((ulong64)key[ 2] << 40) ^
      ((ulong64)key[ 3] << 32) ^
      ((ulong64)key[ 4] << 24) ^
      ((ulong64)key[ 5] << 16) ^
      ((ulong64)key[ 6] <<  8) ^
      ((ulong64)key[ 7]      );

	// load the second 64 bits of the key
	K_lo =
      ((ulong64)key[ 8] << 56) ^
      ((ulong64)key[ 9] << 48);

	// for 128-bit key
	if (keylen == 16) {
		K_lo ^=
		  ((ulong64)key[10] << 40) ^
		  ((ulong64)key[11] << 32) ^
		  ((ulong64)key[12] << 24) ^
		  ((ulong64)key[13] << 16) ^
		  ((ulong64)key[14] <<  8) ^
		  ((ulong64)key[15]      );

		// the first encryption key = the last decryption key
		skey->present.dK[31] = skey->present.eK[0] = K_hi;

		for (i = 1; i <= 31; ++i) {
			// rotate 61 bits to the left
			// | 127 126 125 ... 64 | 63 ... 0 | -> | 66 65 64 ... 3 | 2 1 0 127 ... 67 |
			temp = ((K_hi & 0x7) << 61) ^ (K_lo >> 3);
			K_lo = ((K_lo & 0x7) << 61) ^ (K_hi >> 3);
			
			K_hi = ((ulong64)S8[(temp & 0xFF00000000000000) >> 56] << 56)  ^ (temp & 0x00FFFFFFFFFFFFFF) ^ (i >> 2);
			K_lo ^= (ulong64)(i & 0x3) << 62;

			skey->present.dK[31-i] = skey->present.eK[i] = K_hi;
		}

		return CRYPT_OK;
	}

	// the first encryption key = the last decryption key
	skey->present.dK[31] = skey->present.eK[0] = K_hi;

	for (i = 1; i <= 31; ++i) {
		// rotate 61 bits to the left
		// | 79 78 77 ... 16 | 15 ... 0 | -> | 18 17 16 ... 35 | 34 ... 19 |
		temp = ((K_hi & 0x7) << 61) ^ (K_lo >> 3) ^ (K_hi >> 19);
		K_lo = (K_hi << 45) & (ulong64)0xFFFF000000000000;
		
		K_hi = ((ulong64)S[(temp & 0xF000000000000000) >> 60] << 60)  ^ (temp & 0x0FFFFFFFFFFFFFFF) ^ (i >> 1);
		K_lo ^= (ulong64)(i & 0x1) << 63;

		skey->present.dK[31-i] = skey->present.eK[i] = K_hi;
	}

    return CRYPT_OK;
}

/**
  Encrypts a block of text with PRESENT
  @param pt The input plaintext (8 bytes)
  @param ct The output ciphertext (8 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/

int present_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
	ulong64 state, temp, *rk;
	int Nr, i;

    LTC_ARGCHK(pt != NULL);
    LTC_ARGCHK(ct != NULL);
    LTC_ARGCHK(skey != NULL);

	Nr = skey->present.Nr;
	rk = skey->present.eK;

	// put the plaintext into a 64-bit variable
	state =
		((ulong64)pt[0] << 56) ^
		((ulong64)pt[1] << 48) ^
		((ulong64)pt[2] << 40) ^
		((ulong64)pt[3] << 32) ^
		((ulong64)pt[4] << 24) ^
		((ulong64)pt[5] << 16) ^
		((ulong64)pt[6] <<  8) ^
		((ulong64)pt[7]      );

	// do 31 rounds of PRESENT
	for (i = 0; i < Nr; ++i) {

		// XOR with round subkey
		state ^= rk[i];

		// sBoxLayer
		state =
			((ulong64)S8[(unsigned char)(state >> 56)       ] << 56) ^
			((ulong64)S8[(unsigned char)(state >> 48) & 0xff] << 48) ^
			((ulong64)S8[(unsigned char)(state >> 40) & 0xff] << 40) ^
			((ulong64)S8[(unsigned char)(state >> 32) & 0xff] << 32) ^
			((ulong64)S8[(unsigned char)(state >> 24) & 0xff] << 24) ^
			((ulong64)S8[(unsigned char)(state >> 16) & 0xff] << 16) ^
			((ulong64)S8[(unsigned char)(state >>  8) & 0xff] <<  8) ^
			((ulong64)S8[(unsigned char)(state      ) & 0xff]);

		// pLayer
		temp = 0;
		temp ^=
				 (state & 0x8000000000000000)       ^
				((state & 0x0800000000000000) <<  3) ^
				((state & 0x0080000000000000) <<  6) ^
				((state & 0x0008000000000000) <<  9) ^
				((state & 0x0000800000000000) << 12) ^
				((state & 0x0000080000000000) << 15) ^
				((state & 0x0000008000000000) << 18) ^
				((state & 0x0000000800000000) << 21) ^
				((state & 0x0000000080000000) << 24) ^
				((state & 0x0000000008000000) << 27) ^
				((state & 0x0000000000800000) << 30) ^
				((state & 0x0000000000080000) << 33) ^
				((state & 0x0000000000008000) << 36) ^
				((state & 0x0000000000000800) << 39) ^
				((state & 0x0000000000000080) << 42) ^
				((state & 0x0000000000000008) << 45);

		temp ^=
				((state & 0x4000000000000000) >> 15) ^
				((state & 0x0400000000000000) >> 12) ^
				((state & 0x0040000000000000) >>  9) ^
				((state & 0x0004000000000000) >>  6) ^
				((state & 0x0000400000000000) >>  3) ^
				 (state & 0x0000040000000000)        ^
				((state & 0x0000004000000000) <<  3) ^
				((state & 0x0000000400000000) <<  6) ^
				((state & 0x0000000040000000) <<  9) ^
				((state & 0x0000000004000000) << 12) ^
				((state & 0x0000000000400000) << 15) ^
				((state & 0x0000000000040000) << 18) ^
				((state & 0x0000000000004000) << 21) ^
				((state & 0x0000000000000400) << 24) ^
				((state & 0x0000000000000040) << 27) ^
				((state & 0x0000000000000004) << 30);

		temp ^=
				((state & 0x2000000000000000) >> 30) ^
				((state & 0x0200000000000000) >> 27) ^
				((state & 0x0020000000000000) >> 24) ^
				((state & 0x0002000000000000) >> 21) ^
				((state & 0x0000200000000000) >> 18) ^
				((state & 0x0000020000000000) >> 15) ^
				((state & 0x0000002000000000) >> 12) ^
				((state & 0x0000000200000000) >>  9) ^
				((state & 0x0000000020000000) >>  6) ^
				((state & 0x0000000002000000) >>  3) ^
				 (state & 0x0000000000200000)        ^
				((state & 0x0000000000020000) <<  3) ^
				((state & 0x0000000000002000) <<  6) ^
				((state & 0x0000000000000200) <<  9) ^
				((state & 0x0000000000000020) << 12) ^
				((state & 0x0000000000000002) << 15);

		temp ^=
				((state & 0x1000000000000000) >> 45) ^
				((state & 0x0100000000000000) >> 42) ^
				((state & 0x0010000000000000) >> 39) ^
				((state & 0x0001000000000000) >> 36) ^
				((state & 0x0000100000000000) >> 33) ^
				((state & 0x0000010000000000) >> 30) ^
				((state & 0x0000001000000000) >> 27) ^
				((state & 0x0000000100000000) >> 24) ^
				((state & 0x0000000010000000) >> 21) ^
				((state & 0x0000000001000000) >> 18) ^
				((state & 0x0000000000100000) >> 15) ^
				((state & 0x0000000000010000) >> 12) ^
				((state & 0x0000000000001000) >>  9) ^
				((state & 0x0000000000000100) >>  6) ^
				((state & 0x0000000000000010) >>  3) ^
				 (state & 0x0000000000000001)       ;

		state = temp;

	}

	// XOR with last round subkey
	state ^= rk[31];

	ct[0] = (unsigned char)(state >> 56);
	ct[1] = (unsigned char)(state >> 48);
	ct[2] = (unsigned char)(state >> 40);
	ct[3] = (unsigned char)(state >> 32);
	ct[4] = (unsigned char)(state >> 24);
	ct[5] = (unsigned char)(state >> 16);
	ct[6] = (unsigned char)(state >>  8);
	ct[7] = (unsigned char)(state      );

	return CRYPT_OK;
}


/**
  Decrypts a block of text with PRESENT
  @param ct The input ciphertext (8 bytes)
  @param pt The output plaintext (8 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/

int present_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey)
{
	ulong64 state, temp, *rk;
	int Nr, i;

    LTC_ARGCHK(pt != NULL);
    LTC_ARGCHK(ct != NULL);
    LTC_ARGCHK(skey != NULL);

	Nr = skey->present.Nr;
	rk = skey->present.dK;

	// put the ciphertext into a 64-bit variable
	state =
		((ulong64)ct[0] << 56) ^
		((ulong64)ct[1] << 48) ^
		((ulong64)ct[2] << 40) ^
		((ulong64)ct[3] << 32) ^
		((ulong64)ct[4] << 24) ^
		((ulong64)ct[5] << 16) ^
		((ulong64)ct[6] <<  8) ^
		((ulong64)ct[7]      );

	// do 31 rounds of PRESENT
	for (i = 0; i < Nr; ++i) {

		// XOR with round subkey
		state ^= rk[i];

		// Inverse pLayer
		temp = 0;
		temp ^=
				//          a---b---c---d---
				 (state & 0x8000000000000000)       ^
				((state & 0x0000800000000000) << 15) ^
				((state & 0x0000000080000000) << 30) ^
				((state & 0x0000000000008000) << 45) ^
				((state & 0x4000000000000000) >>  3) ^
				((state & 0x0000400000000000) << 12) ^
				((state & 0x0000000040000000) << 27) ^
				((state & 0x0000000000004000) << 42) ^
				((state & 0x2000000000000000) >>  6) ^
				((state & 0x0000200000000000) <<  9) ^
				((state & 0x0000000020000000) << 24) ^
				((state & 0x0000000000002000) << 39) ^
				((state & 0x1000000000000000) >>  9) ^
				((state & 0x0000100000000000) <<  6) ^
				((state & 0x0000000010000000) << 21) ^
				((state & 0x0000000000001000) << 36);

		temp ^=
				//          -a---b---c---d--
				((state & 0x0800000000000000) >> 12) ^
				((state & 0x0000080000000000) <<  3) ^
				((state & 0x0000000008000000) << 18) ^
				((state & 0x0000000000000800) << 33) ^
				((state & 0x0400000000000000) >> 15) ^
				 (state & 0x0000040000000000)        ^
				((state & 0x0000000004000000) << 15) ^
				((state & 0x0000000000000400) << 30) ^
				((state & 0x0200000000000000) >> 18) ^
				((state & 0x0000020000000000) >>  3) ^
				((state & 0x0000000002000000) << 12) ^
				((state & 0x0000000000000200) << 27) ^
				((state & 0x0100000000000000) >> 21) ^
				((state & 0x0000010000000000) >>  6) ^
				((state & 0x0000000001000000) <<  9) ^
				((state & 0x0000000000000100) << 24);

		temp ^=
				//          --a---b---c---d-
				((state & 0x0080000000000000) >> 24) ^
				((state & 0x0000008000000000) >>  9) ^
				((state & 0x0000000000800000) <<  6) ^
				((state & 0x0000000000000080) << 21) ^
				((state & 0x0040000000000000) >> 27) ^
				((state & 0x0000004000000000) >> 12) ^
				((state & 0x0000000000400000) <<  3) ^
				((state & 0x0000000000000040) << 18) ^
				((state & 0x0020000000000000) >> 30) ^
				((state & 0x0000002000000000) >> 15) ^
				 (state & 0x0000000000200000)        ^
				((state & 0x0000000000000020) << 15) ^
				((state & 0x0010000000000000) >> 33) ^
				((state & 0x0000001000000000) >> 18) ^
				((state & 0x0000000000100000) >>  3) ^
				((state & 0x0000000000000010) << 12);

		temp ^=
				//          ---a---b---c---d
				((state & 0x0008000000000000) >> 36) ^
				((state & 0x0000000800000000) >> 21) ^
				((state & 0x0000000000080000) >>  6) ^
				((state & 0x0000000000000008) <<  9) ^
				((state & 0x0004000000000000) >> 39) ^
				((state & 0x0000000400000000) >> 24) ^
				((state & 0x0000000000040000) >>  9) ^
				((state & 0x0000000000000004) <<  6) ^
				((state & 0x0002000000000000) >> 42) ^
				((state & 0x0000000200000000) >> 27) ^
				((state & 0x0000000000020000) >> 12) ^
				((state & 0x0000000000000002) <<  3) ^
				((state & 0x0001000000000000) >> 45) ^
				((state & 0x0000000100000000) >> 30) ^
				((state & 0x0000000000010000) >> 15) ^
				 (state & 0x0000000000000001)       ;

		state = temp;

		// inverse sBoxLayer
		state =
			((ulong64)SI8[(unsigned char)(state >> 56)       ] << 56) ^
			((ulong64)SI8[(unsigned char)(state >> 48) & 0xff] << 48) ^
			((ulong64)SI8[(unsigned char)(state >> 40) & 0xff] << 40) ^
			((ulong64)SI8[(unsigned char)(state >> 32) & 0xff] << 32) ^
			((ulong64)SI8[(unsigned char)(state >> 24) & 0xff] << 24) ^
			((ulong64)SI8[(unsigned char)(state >> 16) & 0xff] << 16) ^
			((ulong64)SI8[(unsigned char)(state >>  8) & 0xff] <<  8) ^
			((ulong64)SI8[(unsigned char)(state      ) & 0xff]);

	}

	// XOR with the last round subkey
	state ^= rk[31];

	pt[0] = (unsigned char)(state >> 56);
	pt[1] = (unsigned char)(state >> 48);
	pt[2] = (unsigned char)(state >> 40);
	pt[3] = (unsigned char)(state >> 32);
	pt[4] = (unsigned char)(state >> 24);
	pt[5] = (unsigned char)(state >> 16);
	pt[6] = (unsigned char)(state >>  8);
	pt[7] = (unsigned char)(state      );

	return CRYPT_OK;
}



/**
  Performs a self-test of the PRESENT block cipher
  @return CRYPT_OK if functional, CRYPT_NOP if self-test has been disabled
*/
int present_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
	symmetric_key skey;

	unsigned char key0[10] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							   0x00, 0x00 };
	unsigned char key1[10] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
							   0xff, 0xff };
	unsigned char key2[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
							   0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

	unsigned char pt0[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char pt1[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	unsigned char pt2[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

	unsigned char ct0[8] = { 0x55, 0x79, 0xC1, 0x38, 0x7B, 0x22, 0x84, 0x45 };
	unsigned char ct1[8] = { 0xE7, 0x2C, 0x46, 0xC0, 0xF5, 0x94, 0x50, 0x49 };
	unsigned char ct2[8] = { 0xA1, 0x12, 0xFF, 0xC7, 0x2F, 0x68, 0x41, 0x7B };
	unsigned char ct3[8] = { 0x33, 0x33, 0xDC, 0xD3, 0x21, 0x32, 0x10, 0xD2 };
	unsigned char ct4[8] = { 0x0e, 0x9d, 0x28, 0x68, 0x5e, 0x67, 0x1d, 0xd6 };

	unsigned char *pt, *key, ptx[8];
	unsigned char ct[8];
	int keylen, err, count, i;
	
	keylen = 10;
	key = key0;
    if ((err = present_setup(key, keylen, 0, &skey)) != CRYPT_OK) {
       return err;
    }
	
	pt = pt0;
	present_ecb_encrypt(pt, ct, &skey);
	present_ecb_decrypt(ct, ptx, &skey);
	
	count = 0;
	for (i=0; i<8; i++) {
		if ((ct[i] == ct0[i]) && (ptx[i] == pt[i])) count++;
	}
	if (count != 8) {
		return CRYPT_FAIL_TESTVECTOR;
	}
	
	pt = pt1;
	present_ecb_encrypt(pt, ct, &skey);
	present_ecb_decrypt(ct, ptx, &skey);
	
	count = 0;
	for (i=0; i<8; i++) {
		if ((ct[i] == ct2[i]) && (ptx[i] == pt[i])) count++;
	}
	if (count != 8) {
		return CRYPT_FAIL_TESTVECTOR;
	}
	
	
	key = key1;
    if ((err = present_setup(key, keylen, 0, &skey)) != CRYPT_OK) {
       return err;
    }
	
	pt = pt0;
	present_ecb_encrypt(pt, ct, &skey);
	present_ecb_decrypt(ct, ptx, &skey);
	
	count = 0;
	for (i=0; i<8; i++) {
		if ((ct[i] == ct1[i]) && (ptx[i] == pt[i])) count++;
	}
	if (count != 8) {
		return CRYPT_FAIL_TESTVECTOR;
	}
	
	pt = pt1;
	present_ecb_encrypt(pt, ct, &skey);
	present_ecb_decrypt(ct, ptx, &skey);
	
	count = 0;
	for (i=0; i<8; i++) {
		if ((ct[i] == ct3[i]) && (ptx[i] == pt[i])) count++;
	}
	if (count != 8) {
		return CRYPT_FAIL_TESTVECTOR;
	}
	
	// 128-bit key
	keylen = 16;
	
	key = key2;
    if ((err = present_setup(key, keylen, 0, &skey)) != CRYPT_OK) {
       return err;
    }
	
	pt = pt2;
	present_ecb_encrypt(pt, ct, &skey);
	present_ecb_decrypt(ct, ptx, &skey);
	
	count = 0;
	for (i=0; i<8; i++) {
		if ((ct[i] == ct4[i]) && (ptx[i] == pt[i])) count++;
	}
	if (count != 8) {
		return CRYPT_FAIL_TESTVECTOR;
	}
	
	return CRYPT_OK;
 #endif
}


/** Terminate the context
   @param skey    The scheduled key
*/
void present_done(symmetric_key *skey)
{
  LTC_UNUSED_PARAM(skey);
}


/**
  Gets suitable key size
  @param keysize [in/out] The length of the recommended key (in bytes).  This function will store the suitable size back in this variable.
  @return CRYPT_OK if the input key size is acceptable.
*/
int present_keysize(int *keysize)
{
   LTC_ARGCHK(keysize != NULL);

   if (*keysize < 10)
      return CRYPT_INVALID_KEYSIZE;
   
   if (*keysize > 10) {
      *keysize = 16;
      return CRYPT_OK;
   }
   return CRYPT_OK;
}

#endif