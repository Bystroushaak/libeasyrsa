#ifndef _LIBEASYRSA_H
#define _LIBEASYRSA_H

#include "polarssl/rsa.h"

#define RSA_SIGN_SIZE 512

typedef struct{
	char *N;
	char *E;
} pub_key_str;

typedef struct{
	char *N;
	char *E;
	char *D;
	char *P;
	char *Q;
	char *DP;
	char *DQ;
	char *QP;
} priv_key_str;

rsa_context generate_rsa(void);

pub_key_str rsa_to_pubkey(rsa_context *rsa);
rsa_context pubkey_to_rsa(pub_key_str pk);

priv_key_str rsa_to_privkey(rsa_context *rsa);
rsa_context privkey_to_rsa(priv_key_str pk);

bool rsa_verify(rsa_context *rsa_pub, char *msg, char *sign);
char* rsa_sign(rsa_context *rsa_priv, unsigned char *msg);

void rsa_free(rsa_context *rsa);

#endif
