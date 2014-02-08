#ifndef SCRYPT_H
#define SCRYPT_H

#include "miner.h"

#ifdef USE_SCRYPT
extern void scrypt_regenhash(struct work *work);

#else /* USE_SCRYPT */
static inline void scrypt_regenhash(__maybe_unused struct work *work)
{
}
#endif /* USE_SCRYPT */

#endif /* SCRYPT_H */
