/* easyrsa.h v1.0.0 (28.07.2011) by Bystroushaak (bystrousak@kitakitsune.org)
 * https://github.com/Bystroushaak/libeasyrsa
 *
 * This work is licensed under a CC BY (http://creativecommons.org/licenses/by/3.0/)
*/

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

int rsa_verify(rsa_context *rsa_pub, unsigned char *msg, unsigned char *sign);
char* rsa_sign(rsa_context *rsa_priv, unsigned char *msg);

// functions from polarssl/rsa.h
int rsa_check_privkey(const rsa_context *ctx);
int rsa_check_pubkey(const rsa_context *ctx);
void rsa_free(rsa_context *rsa);

#endif
