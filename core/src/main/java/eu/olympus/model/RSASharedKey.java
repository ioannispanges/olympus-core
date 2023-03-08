package eu.olympus.model;

import java.io.Serializable;
import java.math.BigInteger;

public class RSASharedKey implements Serializable {

	private BigInteger modulus;
	private BigInteger privateKey;
	private BigInteger publicExponent;
	
	public RSASharedKey() {
	}
	
	public RSASharedKey(BigInteger modulus, BigInteger privateKey, BigInteger publicExponent) {
		this.modulus = modulus;
		this.privateKey = privateKey;
		this.publicExponent = publicExponent;
	}

	public BigInteger getModulus() {
		return modulus;
	}

	public void setModulus(BigInteger modulus) {
		this.modulus = modulus;
	}

	public BigInteger getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(BigInteger privateKey) {
		this.privateKey = privateKey;
	}

	public BigInteger getPublicExponent() {
		return publicExponent;
	}

	public void setPublicExponent(BigInteger publicExponent) {
		this.publicExponent = publicExponent;
	}

}
