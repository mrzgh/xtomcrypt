/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/*
 * Implementation of PHOTON by MRZ
 *
 *
 *  PHOTON-n/r/r' variants:
 *  VARIANT           STATE SIZE   CELL SIZE (s)  NUMBER OF  BITS PER  BITRATE (r)
 *                    (bits/bytes)   (bits)       CELLS (d)     ROW    (bits/byte)
 *  ------------------------------------------------------------------------------
 *  PHOTON-80/20/16    100 / 12.5      4              5         20       20 / 2.5
 *  PHOTON-128/16/16   144 / 18        4              6         24       16 / 2
 *  PHOTON-160/36/36   196 / 24.5      4              7         28       36 / 4.5
 *  PHOTON-224/32/32   256 / 32        4              8         32       32 / 4
 *  PHOTON-256/32/32   288 / 36        8              6         48       32 / 4
 *
 *  r is the size of input block
 */

#include "tomcrypt.h"

#ifdef LTC_PHOTON

const struct ltc_hash_descriptor photon80_desc =
{
   "photon-80",                  /* name of hash */
   200,                          /* internal ID */
   10,                           /* Size of digest in octets */
   3,                            /* Input block size in octets */
   { 0 },  						/* ASN.1 OID */
   1,                            /* Length OID */
   &photon80_init,
   &photon80_process,
   &photon80_done,
   NULL,
   NULL
};

const struct ltc_hash_descriptor photon128_desc =
{
   "photon-128",                 /* name of hash */
   201,                          /* internal ID */
   16,                           /* Size of digest in octets */
   2,                            /* Input block size in octets */
   { 0 },  						/* ASN.1 OID */
   1,                            /* Length OID */
   &photon128_init,
   &photon128_process,
   &photon128_done,
   NULL,
   NULL
};

// 4x4 s-box
unsigned char S4ph[16] = {
	0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

// 8x8 s-box
unsigned char S8ph[256] = {
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

// round constants
unsigned char RC[12] = {
	1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10
};

unsigned char ICd[4][8] = {
	{ 0, 1, 3, 6, 4, 0, 0, 0 },
	{ 0, 1, 3, 7, 6, 4, 0, 0 },
	{ 0, 1, 2, 5, 3, 6, 4, 0 },
	{ 0, 1, 3, 7,15,14,12, 8 }
};




// check whether the leftmost bit of the value is 1
unsigned char LMBCheck4Bit(unsigned char val) {
    return ((val & 0x08) >> 3); // returns 1 or 0
}


/* perform multiplication in GF(2^8)
multiplication of a value by x (i.e., by [02]) can be implemented as
a 1-bit left shift followed by a conditional bitwise XOR with pp (e.g. pp = 0001 1011 {1b})
if the leftmost bit of the original value (prior to the shift) is 1.
*/
unsigned char multp4bit(unsigned char x, unsigned char y, unsigned char pp) {
    unsigned char status;
    unsigned char aVal, sVal, result=0;

    aVal = y; sVal = x;

    while (aVal != 0) {
        if ( (aVal & 1) != 0 )
            result ^= sVal;

        status = LMBCheck4Bit(sVal);
        sVal = sVal << 1;

        if (status == 1)
            sVal ^= pp;

        sVal &= 0x0f;
        aVal = (aVal & 0x0f) >> 1;
    }
    return result;
}


/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int photon80_init(hash_state * md) {
	int i;
    //LTC_ARGCHK(md != NULL);

	for (i = 0; i < 25; ++i) {
		md->photon80.state[i] = 0;
	}
	// specific ones for PHOTON-80/20/16
	// The t-bit internal state S is initialized by setting it to the
	// value S_0 = IV = {0}^{t−24}||n/4||r||r', where || denotes the
	// concatenation and each value is coded on 8 bits
	// n  = 80, n/4=20 = 0x14
	// r  = 20 = 0x14
	// r' = 0x10
	// IV = 00...00||0x14||0x14||0x10
	md->photon80.state[19] = 1;
	md->photon80.state[20] = 4;
	md->photon80.state[21] = 1;
	md->photon80.state[22] = 4;
	md->photon80.state[23] = 1;

	// set the byterate (bitrate in bytes), i.e. ceil(r/8) = ceil(20/8) = ceil(2.5) = 3
	//md->photon128.byterate = 3;
	md->photon80.bitrate = 20;

    return CRYPT_OK;
}

/**
 * For simplicity, this function only accepts input which is exactly r bits
 *
 * @param md     The hash state
 * @param in     The data to hash (sequence of bytes)
 *
 */
int photon80_compress(hash_state *md, const unsigned char *in) {
	unsigned int r, i, j, k, d = 5;
	unsigned char temp;

    unsigned char A[5][5] = {
    		{  1, 2, 9, 9, 2 },
   		{  2, 5, 3, 8,13 },
        { 13,11,10,12, 1 },
        {  1,15, 2, 3,14 },
        { 14,14, 8, 5,12 }
    };
    unsigned char y[25];
    unsigned char pp = 0x13; // x^4 + x + 1
    unsigned char col;

    // XOR the current message (r-bit) with the current state
    // in is an array of bytes, state is an array of nibbles
    for (i = 0; i < 3; ++i) {
		for (j = 0; j < 2; ++j) {
			md->photon80.state[i] ^= in[(i & (0xF0 >> (j*4))) >> (1-j)*4];
		}
	}

	for (r = 0; r < 12; ++r) {
		// AddConstants (AC)
		for (i=0; i<d; i++) {
			md->photon80.state[i*d] ^= RC[r] ^ ICd[d-5][i];
		}

		// SubCells (SC)
		for (i = 0; i < d*d; ++i) {
			md->photon80.state[i] = S4ph[md->photon80.state[i]];
		}

		// ShiftRows (ShR)
		// row 0 is unmoved
		// moving row 1 to row d-1
		for (i=1; i<d; i++) {
			// number of rotations
			// row j is rotated j times to the left
			for (j=0; j<i; j++) {
				// col 0 to col d-1
				temp = md->photon80.state[i*d];
				for (k=0; k<(d-1); k++) {
					md->photon80.state[i*d+k] = md->photon80.state[i*d+k+1];
				}
				md->photon80.state[i*d+k] = temp;
			}
		}

		// MixColumnsSerial
		for (i=0; i<d*d; i++) y[i] = 0;

		for (col=0; col<d; col++) {
			for (i=0; i<d; i++) {
				for (j=0; j<d; j++) {
					y[i*d+col] ^= multp4bit(A[i][j], md->photon80.state[j*d+col], pp);
				}
			}
		}

		for (i=0; i<d*d; i++) md->photon80.state[i] = y[i];
	}

	return CRYPT_OK;
}


/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash (sequence of bytes)
   @param inlen  The length of the data to hash (bits)
   @return CRYPT_OK if successful
*/
//HASH_PROCESS(photon_process, photon_compress, photon, 64)
int photon80_process(hash_state * md, const unsigned char *in, unsigned long inlen) {
	unsigned long n;
	int err;

	if (inlen == 0) return CRYPT_OK; /* nothing to do */

	// if the length of message to be hashed is less than the bitrate,
	// then we need to save them first, and wait until the next hash call
	if (inlen < md->photon80.bitrate) {
		md->photon80.saved_state[0] = (in[0] & 0xf0) >> 4;
		md->photon80.saved_state[1] = (in[0] & 0x0f)     ;
		md->photon80.saved_state[2] = (in[1] & 0xf0) >> 4;
		md->photon80.saved_state[3] = (in[1] & 0x0f)     ;
		md->photon80.saved_state[4] = (in[2] & 0xf0) >> 4;
		md->photon80.pending = 1; // indicator to note that there are pending msg to be hashed

		return CRYPT_OK;
	}

	while (inlen > 0) {
		if ((err = photon80_compress(md, in)) != CRYPT_OK) {
			return err;
		}
		n = MIN(inlen, md->photon80.bitrate);
		in 		+= n;
		inlen 	-= n;
	}

	return CRYPT_OK;
}



/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (80 bits)
   @return CRYPT_OK if successful
*/
int photon80_done(hash_state * md, unsigned char *out) {
	unsigned int r, i, j, k, d = 5, pr, pR = 4;
	unsigned char temp;
    unsigned char A[5][5] = {
    		{  1, 2, 9, 9, 2 },
   		{  2, 5, 3, 8,13 },
        { 13,11,10,12, 1 },
        {  1,15, 2, 3,14 },
        { 14,14, 8, 5,12 }
    };
    unsigned char y[25];
    unsigned char pp = 0x13; // x^4 + x + 1
    unsigned char col;

	// do the squeezing phase

	// r' = 16
	// output digest is 80 bits = 16 x 5

    // 1 of 5 set of 16-bit output
	out[0]  = (md->photon80.state[0] << 4);
	out[0] ^= (md->photon80.state[1]);

	out[1]  = (md->photon80.state[2] << 4);
	out[1] ^= (md->photon80.state[3]);

	// Apply P for another 4 times
	for (pr = 0; pr < pR; ++pr) {
		// P has 12 rounds
		for (r = 0; r < 12; ++r) {
			// AddConstants (AC)
			for (i=0; i<d; i++) {
				md->photon.state[i*d] ^= RC[r] ^ ICd[d-5][i];
			}

			// SubCells (SC)
			for (i = 0; i < d*d; ++i) {
				md->photon.state[i] = S[md->photon.state[i]];
			}

			// ShiftRows (ShR)
			// row 0 is unmoved
			// moving row 1 to row d-1
			for (i=1; i<d; i++) {
				// number of rotations
				// row j is rotated j times to the left
				for (j=0; j<i; j++) {
					// col 0 to col d-1
					temp = md->photon.state[i*d];
					for (k=0; k<(d-1); k++) {
						md->photon.state[i*d+k] = md->photon.state[i*d+k+1];
					}
					md->photon.state[i*d+k] = temp;
				}
			}

			// MixColumnsSerial
			for (i=0; i<d*d; i++) y[i] = 0;

			for (col=0; col<d; col++) {
				for (i=0; i<d; i++) {
					for (j=0; j<d; j++) {
						y[i*d+col] ^= multp4bit(A[i][j], md->photon.state[j*d+col], pp);
					}
				}
			}

			for (i=0; i<d*d; i++) md->photon.state[i] = y[i];
		}

	    // output 16 bits
		out[(pr+1)*2  ]  = (md->photon.state[0] << 4);
		out[(pr+1)*2  ] ^= (md->photon.state[1]);

		out[(pr+1)*2+1]  = (md->photon.state[2] << 4);
		out[(pr+1)*2+1] ^= (md->photon.state[3]);
	}

	return CRYPT_OK;
}



/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int photon128_init(hash_state * md) {
	int i;
    //LTC_ARGCHK(md != NULL);

	for (i = 0; i < 36; ++i) {
		md->photon128.state[i] = 0;
	}
	// specific ones for PHOTON-128/16/16
	// The t-bit internal state S is initialized by setting it to the
	// value S_0 = IV = {0}^{t−24}||n/4||r||r', where || denotes the
	// concatenation and each value is coded on 8 bits
	// n  = 128, n/4=32 = 0x20
	// r  = 16 = 0x10
	// r' = 0x10
	// IV = 00...00||0x20||0x10||0x10
	md->photon128.state[30] = 2;
	md->photon128.state[32] = 1;
	md->photon128.state[34] = 1;

	// set the byterate (bitrate in bytes), i.e. ceil(r/8) = ceil(20/8) = ceil(2.5) = 3
	//md->photon128.byterate = 3;
	md->photon128.bitrate = 16;

    return CRYPT_OK;
}



/**
 * For simplicity, this function only accepts input which is exactly r bits
 *
 * @param md     The hash state
 * @param in     The data to hash (sequence of bytes)
 *
 */
int photon128_compress(hash_state *md, const unsigned char *in) {
	unsigned int r, i, j, k, d = 6;
	unsigned char temp;

    unsigned char A[6][6] = {
    		{ 1,  2,  8,  5,  8,  2},
		{ 2,  5,  1,  2,  6, 12},
		{12,  9, 15,  8,  8, 13},
		{13,  5, 11,  3, 10,  1},
		{ 1, 15, 13, 14, 11,  8},
		{ 8,  2,  3,  3,  2,  8}
    };
    unsigned char y[36];
    unsigned char pp = 0x13; // x^4 + x + 1
    unsigned char col;

    // XOR the current message (r-bit) with the current state
    // in is an array of bytes, state is an array of nibbles
    for (i = 0; i < 2; ++i) {
		for (j = 0; j < 2; ++j) {
			md->photon128.state[i*2+j] ^= in[(i & (0xF0 >> (j*4))) >> (1-j)*4];
		}
	}

	for (r = 0; r < 12; ++r) {
		// AddConstants (AC)
		for (i=0; i<d; i++) {
			md->photon128.state[i*d] ^= RC[r] ^ ICd[d-5][i];
		}

		// SubCells (SC)
		for (i = 0; i < d*d; ++i) {
			md->photon128.state[i] = S4ph[md->photon128.state[i]];
		}

		// ShiftRows (ShR)
		// row 0 is unmoved
		// moving row 1 to row d-1
		for (i=1; i<d; i++) {
			// number of rotations
			// row j is rotated j times to the left
			for (j=0; j<i; j++) {
				// col 0 to col d-1
				temp = md->photon128.state[i*d];
				for (k=0; k<(d-1); k++) {
					md->photon128.state[i*d+k] = md->photon128.state[i*d+k+1];
				}
				md->photon128.state[i*d+k] = temp;
			}
		}

		// MixColumnsSerial
		for (i=0; i<d*d; i++) y[i] = 0;

		for (col=0; col<d; col++) {
			for (i=0; i<d; i++) {
				for (j=0; j<d; j++) {
					y[i*d+col] ^= multp4bit(A[i][j], md->photon128.state[j*d+col], pp);
				}
			}
		}

		for (i=0; i<d*d; i++) md->photon128.state[i] = y[i];
	}

	return CRYPT_OK;
}


/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash (sequence of bytes)
   @param inlen  The length of the data to hash (bits)
   @return CRYPT_OK if successful
*/
//HASH_PROCESS(photon_process, photon_compress, photon, 64)
int photon128_process(hash_state * md, const unsigned char *in, unsigned long inlen) {
	unsigned long n;
	int err;

	if (inlen == 0) return CRYPT_OK; /* nothing to do */

	// if the length of message to be hashed is less than the bitrate,
	// then we need to save them first, and wait until the next hash call
	if (inlen < md->photon128.bitrate) {
		md->photon128.saved_state[0] = (in[0] & 0xf0) >> 4;
		md->photon128.saved_state[1] = (in[0] & 0x0f)     ;
		md->photon128.saved_state[2] = (in[1] & 0xf0) >> 4;
		md->photon128.saved_state[3] = (in[1] & 0x0f)     ;
		md->photon128.pending = 1; // indicator to note that there are pending msg to be hashed

		return CRYPT_OK;
	}

	while (inlen > 0) {
		if ((err = photon128_compress(md, in)) != CRYPT_OK) {
			return err;
		}
		n = MIN(inlen, md->photon128.bitrate);
		in 		+= n;
		inlen 	-= n;
	}

	return CRYPT_OK;
}


/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (80 bits)
   @return CRYPT_OK if successful
*/
int photon128_done(hash_state * md, unsigned char *out) {
	unsigned int r, i, j, k, d = 6, pr, pR = 7;
	unsigned char temp;
    unsigned char A[6][6] = {
    		{ 1,  2,  8,  5,  8,  2},
		{ 2,  5,  1,  2,  6, 12},
		{12,  9, 15,  8,  8, 13},
		{13,  5, 11,  3, 10,  1},
		{ 1, 15, 13, 14, 11,  8},
		{ 8,  2,  3,  3,  2,  8}
    };
    unsigned char y[36];
    unsigned char pp = 0x13; // x^4 + x + 1
    unsigned char col;

	// do the squeezing phase

	// r' = 16
	// output digest is 128 bits = 16 x 8

    // 1 of 8 set of 16-bit output. "Out" holds 8-bit value.
	out[0]  = (md->photon128.state[0] << 4);
	out[0] ^= (md->photon128.state[1]);

	out[1]  = (md->photon128.state[2] << 4);
	out[1] ^= (md->photon128.state[3]);

	// Apply P for another 7 times
	for (pr = 0; pr < pR; ++pr) {
		// P has 12 rounds
		for (r = 0; r < 12; ++r) {
			// AddConstants (AC)
			for (i=0; i<d; i++) {
				md->photon128.state[i*d] ^= RC[r] ^ ICd[d-5][i];
			}

			// SubCells (SC)
			for (i = 0; i < d*d; ++i) {
				md->photon128.state[i] = S4ph[md->photon128.state[i]];
			}

			// ShiftRows (ShR)
			// row 0 is unmoved
			// moving row 1 to row d-1
			for (i=1; i<d; i++) {
				// number of rotations
				// row j is rotated j times to the left
				for (j=0; j<i; j++) {
					// col 0 to col d-1
					temp = md->photon128.state[i*d];
					for (k=0; k<(d-1); k++) {
						md->photon128.state[i*d+k] = md->photon128.state[i*d+k+1];
					}
					md->photon128.state[i*d+k] = temp;
				}
			}

			// MixColumnsSerial
			for (i=0; i<d*d; i++) y[i] = 0;

			for (col=0; col<d; col++) {
				for (i=0; i<d; i++) {
					for (j=0; j<d; j++) {
						y[i*d+col] ^= multp4bit(A[i][j], md->photon128.state[j*d+col], pp);
					}
				}
			}

			for (i=0; i<d*d; i++) md->photon128.state[i] = y[i];
		}

	    // output 16 bits
		out[(pr+1)*2  ]  = (md->photon128.state[0] << 4);
		out[(pr+1)*2  ] ^= (md->photon128.state[1]);

		out[(pr+1)*2+1]  = (md->photon128.state[2] << 4);
		out[(pr+1)*2+1] ^= (md->photon128.state[3]);
	}

	return CRYPT_OK;
}

#endif
