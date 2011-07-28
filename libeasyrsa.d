//module easyrsa;

extern(C){
	struct mpi{
	    int s;              /*!<  integer sign      */
	    size_t n;           /*!<  total # of limbs  */
	    uint *p;          /*!<  pointer to limbs  */
	}

	struct rsa_context{
	    int ver;/*!<  always 0          */
	    size_t len;                 /*!<  size(N) in chars  */

	    mpi N;/*!<  public modulus    */
	    mpi E;/*!<  public exponent   */

	    mpi D;/*!<  private exponent  */
	    mpi P;/*!<  1st prime factor  */
	    mpi Q;/*!<  2nd prime factor  */
	    mpi DP; /*!<  D % (P - 1)       */
	    mpi DQ; /*!<  D % (Q - 1)       */
	    mpi QP; /*!<  1 / (Q % P)       */

	    mpi RN; /*!<  cached R^2 mod N  */
	    mpi RP; /*!<  cached R^2 mod P  */
	    mpi RQ; /*!<  cached R^2 mod Q  */

	    int padding;                /*!<  RSA_PKCS_V15 for 1.5 padding and
	               RSA_PKCS_v21 for OAEP/PSS         */
	    int hash_id;                /*!<  Hash identifier of md_type_t as
	               specified in the md.h header file
	               for the EME-OAEP and EMSA-PSS
	               encoding   */
	}

	struct priv_key_str {
		char *N;
		char *E;
		char *D;
		char *P;
		char *Q;
		char *DP;
		char *DQ;
		char *QP;
	}
	
	struct pub_key_str{
		char *N;
		char *E;
	}
	
	rsa_context generate_rsa();

	pub_key_str rsa_to_pubkey(rsa_context *rsa);
	rsa_context pubkey_to_rsa(pub_key_str pk);
	
	priv_key_str rsa_to_privkey(rsa_context *rsa);
	rsa_context privkey_to_rsa(priv_key_str pk);
	
	bool rsa_verify(rsa_context *rsa_pub, char *msg, char *sign);
	char* rsa_sign(rsa_context *rsa_priv, char *msg);
	
	void rsa_free(rsa_context *rsa);
}