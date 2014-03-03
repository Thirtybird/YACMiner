#ifndef SCRYPT_JANE_H
#define SCRYPT_JANE_H

#include "miner.h"

#ifdef USE_SCRYPT
extern void sj_scrypt_regenhash(struct work *work);

extern inline void sj_be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len);

#else /* USE_SCRYPT */
static inline int sj_scrypt_test(__maybe_unused unsigned char *pdata,
			       __maybe_unused const unsigned char *ptarget,
			       __maybe_unused uint32_t nonce)
{
	return 0;
}

static inline void sj_scrypt_regenhash(__maybe_unused struct work *work)
{
}
#endif /* USE_SCRYPT */

#endif /* SCRYPT_JANE_H */
