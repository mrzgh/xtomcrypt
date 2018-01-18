/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

/**
  @file crypt_register_all_ciphers.c

  Steffen Jaeckel
*/

#define REGISTER_CIPHER(h) do {\
   LTC_ARGCHK((err = register_cipher(h)) != -1); \
} while(0)

int register_all_ciphers(void)
{
   int err = CRYPT_NOP;

#ifdef LTC_RIJNDAEL
#ifdef ENCRYPT_ONLY
   /* alternative would be
    * register_cipher(&rijndael_enc_desc);
    */
   REGISTER_CIPHER(&aes_enc_desc);
#else
   /* alternative would be
    * register_cipher(&rijndael_desc);
    */
   REGISTER_CIPHER(&aes_desc);
#endif
#endif
#ifdef LTC_BLOWFISH
   REGISTER_CIPHER(&blowfish_desc);
#endif
#ifdef LTC_XTEA
   REGISTER_CIPHER(&xtea_desc);
#endif
#ifdef LTC_RC5
   REGISTER_CIPHER(&rc5_desc);
#endif
#ifdef LTC_RC6
   REGISTER_CIPHER(&rc6_desc);
#endif
#ifdef LTC_SAFERP
   REGISTER_CIPHER(&saferp_desc);
#endif
#ifdef LTC_TWOFISH
   REGISTER_CIPHER(&twofish_desc);
#endif
#ifdef LTC_SAFER
   REGISTER_CIPHER(&safer_k64_desc);
   REGISTER_CIPHER(&safer_sk64_desc);
   REGISTER_CIPHER(&safer_k128_desc);
   REGISTER_CIPHER(&safer_sk128_desc);
#endif
#ifdef LTC_RC2
   REGISTER_CIPHER(&rc2_desc);
#endif
#ifdef LTC_DES
   REGISTER_CIPHER(&des_desc);
   REGISTER_CIPHER(&des3_desc);
#endif
#ifdef LTC_CAST5
   REGISTER_CIPHER(&cast5_desc);
#endif
#ifdef LTC_NOEKEON
   REGISTER_CIPHER(&noekeon_desc);
#endif
#ifdef LTC_SKIPJACK
   REGISTER_CIPHER(&skipjack_desc);
#endif
#ifdef LTC_ANUBIS
   REGISTER_CIPHER(&anubis_desc);
#endif
#ifdef LTC_KHAZAD
   REGISTER_CIPHER(&khazad_desc);
#endif
#ifdef LTC_KSEED
   REGISTER_CIPHER(&kseed_desc);
#endif
#ifdef LTC_KASUMI
   REGISTER_CIPHER(&kasumi_desc);
#endif
#ifdef LTC_MULTI2
   REGISTER_CIPHER(&multi2_desc);
#endif
#ifdef LTC_CAMELLIA
   REGISTER_CIPHER(&camellia_desc);
#endif
#ifdef LTC_PRESENT
   REGISTER_CIPHER(&present_desc);
#endif
   return err;
}

/* ref:         HEAD -> master, tag: v1.18.0 */
/* git commit:  0676c9aec7299f5c398d96cbbb64f7e38f67d73f */
/* commit time: 2017-10-10 15:51:36 +0200 */
