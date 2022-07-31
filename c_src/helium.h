#ifndef HELIUM_H
#define HELIUM_H 1

#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>

__BEGIN_DECLS

/*
  return: 
    0: initialized,
    1: already initialized,
   -1: failed to initialized
Currently, program will quit when initialized failed
 
*/
int helium_init();

/*
  return: 
    1: deinitialized,
    0: not initialized,
*/

int helium_deinit();

/*
  generate key
*/

int gen_ecc_keypair(const uint8_t slot);
int del_ecc_keypair(const uint8_t slot);
int ecdsa_sign_digest(const uint8_t slot, void* digest_buf, size_t digest_buf_len, void* out_signature_buf, size_t* out_signature_buf_len);
int ecdsa_verify(const uint8_t slot, void* digsetbuf, size_t digestbuf_len, void* signaturebuf, size_t signaturebuf_len);

int ecdh(const uint8_t slot, const void *X, const size_t x_len, const void* Y, const size_t y_len, void *secret, size_t *secret_len);
int get_ecc_publickey(const uint8_t slot, const void *X, size_t *x_len, const void* Y, size_t *y_len);

__END_DECLS

#endif /* HELIUM_H */
