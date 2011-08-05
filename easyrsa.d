/**
 * libeasyrsa D wrapper
 *
 * D2/phobos wrapper for easyrsa (signing and verifying).
 *
 * Version: 
 *     1.0.3
 * Date:    
 *     04.08.2011
 * Aurhors:  
 *     Bystroushaak (bystrousak@kitakitsune.org)
 * Website:
 *     Github; https://github.com/Bystroushaak/libeasyrsa
 * Copyright:
 *     This work is licensed under a CC BY (http://creativecommons.org/licenses/by/3.0/)
*/

module easyrsa;

import std.conv;
import std.array;
import std.string;



private extern(C){
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
	
	int rsa_verify(rsa_context *rsa_pub, char *msg, char *sign);
	char* rsa_sign(rsa_context *rsa_priv, char *msg);
	
	int rsa_check_privkey(const rsa_context *ctx);
	int rsa_check_pubkey(const rsa_context *ctx);
	void rsa_free(rsa_context *rsa);
}


/***/
class RSAException : Exception{
	this(string msg){
		super(msg);
	}
}

/***/
class InvalidKeyFormat : RSAException{
	this(string msg){
		super(msg);
	}
}

/***/
class InvalidKey : RSAException{
	this(string msg){
		super(msg);
	}
}


/**
 * This class represents public key.
*/
class PublicKey{
	private rsa_context rsa;
	
	/**
	 * Import private key from string.
	*/
	this(string key){
		string[] tmp = key.split(":");
		
		if (tmp.length < 2)
			throw new InvalidKeyFormat("Bad public key format!\n" ~ key);
		
		pub_key_str ks;
		ks.N = cast(char *) tmp[0].dup;
		ks.E = cast(char *) tmp[1].dup;
		
		this.rsa = pubkey_to_rsa(ks);
		
		// key check
		if (rsa_check_pubkey(&this.rsa) != 0)
			throw new InvalidKey("Invalid public key!");
	}
	
	/**
	 * Verify signed message.
	 *
	 * Returns: True if ok, false if not.
	*/
	public bool verify(string message, string sign){
		return 0 == rsa_verify(&this.rsa, cast(char *) message.dup, cast(char *) sign.dup);
	}
	
	/**
	 * Convert PublicKey to string. String can be used for creating this class.
	*/
	public string toString(){
		pub_key_str pk = rsa_to_pubkey(&this.rsa);
		return std.conv.to!string(pk.N) ~ ":" ~ std.conv.to!string(pk.E);
	}
	
	~this(){
		rsa_free(&this.rsa);
	}
}


/**
 * Class which holds both private and public key.
*/
class PrivateKey : PublicKey{
	private rsa_context rsa;
	
	/**
	* Generate new private and public key.
	*/
	this(){
		this.rsa = generate_rsa();
		
		priv_key_str pk = rsa_to_privkey(&this.rsa);
		super(this.getPublicKey().toString());
	}
	
	/**
	 * Import private key from string.
	 * 
	 * Throws:
	 *   InvalidKeyFormat
	 *   InvalidKey
	*/
	this(string key){
		string[] tmp = key.split(":");
		
		if (tmp.length < 8)
			throw new InvalidKeyFormat("Bad private key format!\n" ~ key);
		
		priv_key_str ks;
		ks.N = cast(char *) tmp[0].dup;
		ks.E = cast(char *) tmp[1].dup;
		ks.D = cast(char *) tmp[2].dup;
		ks.P = cast(char *) tmp[3].dup;
		ks.Q = cast(char *) tmp[4].dup;
		ks.DP = cast(char *) tmp[5].dup;
		ks.DQ = cast(char *) tmp[6].dup;
		ks.QP = cast(char *) tmp[7].dup;
		
		this.rsa = privkey_to_rsa(ks);
		
		super(this.getPublicKey().toString());
		
		// key check
		if (rsa_check_privkey(&this.rsa) != 0)
			throw new InvalidKey("Invalid private key!");
	}
	
	/**
	 * Export PublicKey.
	*/
	public PublicKey getPublicKey(){
		priv_key_str pk = rsa_to_privkey(&this.rsa);
		
		return new PublicKey(std.conv.to!string(pk.N) ~ ":" ~ std.conv.to!string(pk.E));
	}
	
	/**
	 * Sign message.
	 *
	 * Returns: 256B long string containing sign converted into hexa.
	*/
	public string sign(string message){
		if (message == "")
			throw new RSAException("Signed message can't be blank!");
			
		return std.conv.to!string(rsa_sign(&this.rsa, cast(char *) message.dup));
	}
	
	/** 
	 * Export private key into string.
	*/
	override public string toString(){
		priv_key_str pk = rsa_to_privkey(&this.rsa);
		
		return std.conv.to!string(pk.N) ~ ":" ~
		       std.conv.to!string(pk.E) ~ ":" ~
		       std.conv.to!string(pk.D) ~ ":" ~
		       std.conv.to!string(pk.P) ~ ":" ~
		       std.conv.to!string(pk.Q) ~ ":" ~
		       std.conv.to!string(pk.DP) ~ ":" ~
		       std.conv.to!string(pk.DQ) ~ ":" ~
		       std.conv.to!string(pk.QP);
	}
	
	~this(){
		rsa_free(&this.rsa);
	}
}
















