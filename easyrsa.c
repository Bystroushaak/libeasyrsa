/* easyrsa.c v1.0.1 (28.07.2011) by Bystroushaak (bystrousak@kitakitsune.org)
 * https://github.com/Bystroushaak/libeasyrsa
 *
 * Functions for easy work (signing and verifying) with polarssl/rsa.h.
 *
 * This work is licensed under a CC BY (http://creativecommons.org/licenses/by/3.0/)
*/

#include <stdlib.h>
#include <string.h>

#include "polarssl/havege.h"
#include "polarssl/bignum.h"
#include "polarssl/sha1.h"

#include "easyrsa.h"

#define KEY_SIZE 1024
#define EXPONENT 65537

char* mpi_to_str(mpi *m){
	size_t buff_size = 0;
	char *s;
	
	mpi_write_string(m, 16, s, &buff_size); // obtain buff_size
	s = malloc(buff_size);
	mpi_write_string(m, 16, s, &buff_size); // write m to initialized s
	
	return s;
}

rsa_context generate_rsa(void){
	rsa_context rsa;
	havege_state hs;

	havege_init(&hs);
	rsa_init(&rsa, RSA_PKCS_V15, 0);
	rsa_gen_key(&rsa, havege_rand, &hs, KEY_SIZE, EXPONENT);
	
	return rsa;
}

pub_key_str rsa_to_pubkey(rsa_context *rsa){
	pub_key_str s;
	size_t buff_size = 0;
	
	s.N = mpi_to_str(&(rsa->N));
	s.E = mpi_to_str(&(rsa->E));
	
	return s;
}

rsa_context pubkey_to_rsa(pub_key_str pk){
	rsa_context rsa;
	
	rsa_init(&rsa, RSA_PKCS_V15, 0);
	
	mpi_read_string(&(rsa.N), 16, pk.N);
	mpi_read_string(&(rsa.E), 16, pk.E);
	
	rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;

	return rsa;
}

priv_key_str rsa_to_privkey(rsa_context *rsa){
	priv_key_str s;
	size_t buff_size = 0;
	
	s.N = mpi_to_str(&(rsa->N));
	s.E = mpi_to_str(&(rsa->E));
	s.D = mpi_to_str(&(rsa->D));
	s.P = mpi_to_str(&(rsa->P));
	s.Q = mpi_to_str(&(rsa->Q));
	s.DP = mpi_to_str(&(rsa->DP));
	s.DQ = mpi_to_str(&(rsa->DQ));
	s.QP = mpi_to_str(&(rsa->QP));
	
	return s;
}

rsa_context privkey_to_rsa(priv_key_str pk){
	rsa_context rsa;
	
	rsa_init(&rsa, RSA_PKCS_V15, 0);
	
	mpi_read_string(&(rsa.N), 16, pk.N);
	mpi_read_string(&(rsa.E), 16, pk.E);
	mpi_read_string(&(rsa.D), 16, pk.D);
	mpi_read_string(&(rsa.P), 16, pk.P);
	mpi_read_string(&(rsa.Q), 16, pk.Q);
	mpi_read_string(&(rsa.DP), 16, pk.DP);
	mpi_read_string(&(rsa.DQ), 16, pk.DQ);
	mpi_read_string(&(rsa.QP), 16, pk.QP);
	
	rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;
	
	return rsa;
}

char* rsa_sign(rsa_context *rsa_priv, unsigned char *msg){
	unsigned char hash[20];
	unsigned char buff[RSA_SIGN_SIZE];

	sha1(msg, strlen(msg), hash);

	rsa_pkcs1_sign(rsa_priv, NULL, NULL, RSA_PRIVATE, SIG_RSA_SHA1, 20, hash, buff);

	// convert to printable string
	int i;
	unsigned char *out = malloc(rsa_priv->len * 2 + 1);
	unsigned char tmp_buff[2];
	for(i = 0; i < rsa_priv->len; i++){
		sprintf(tmp_buff, "%02X\0", buff[i]);
		out[i * 2] = tmp_buff[0];
		out[i * 2 + 1] = tmp_buff[1];
	}

	out[rsa_priv->len * 2] = 0;

	return out;
}

int rsa_verify(rsa_context *rsa_pub, unsigned char *msg, unsigned char *sign){
	unsigned char hash[20];
	unsigned char buff[RSA_SIGN_SIZE];

	sha1(msg, strlen(msg), hash);

	// convert sign from printable string
	int i, c;
	unsigned char tmp_buff[2];
	for(i = 0; i < rsa_pub->len; i++){
		tmp_buff[0] = sign[i * 2];
		tmp_buff[1] = sign[i * 2 + 1];
		sscanf(tmp_buff, "%02X", &c);
		buff[i] = (unsigned char) c;
	}

	return rsa_pkcs1_verify(rsa_pub, RSA_PUBLIC, SIG_RSA_SHA1, 20, hash, buff);
}
