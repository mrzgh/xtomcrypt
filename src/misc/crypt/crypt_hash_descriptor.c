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
  @file crypt_hash_descriptor.c
  Stores the hash descriptor table, Tom St Denis
*/

struct ltc_hash_descriptor hash_descriptor[TAB_SIZE] = {
{ NULL, 0, 0, 0, { 0 }, 0, NULL, NULL, NULL, NULL, NULL }
};

LTC_MUTEX_GLOBAL(ltc_hash_mutex)


/* ref:         HEAD -> master, tag: v1.18.0 */
/* git commit:  0676c9aec7299f5c398d96cbbb64f7e38f67d73f */
/* commit time: 2017-10-10 15:51:36 +0200 */
