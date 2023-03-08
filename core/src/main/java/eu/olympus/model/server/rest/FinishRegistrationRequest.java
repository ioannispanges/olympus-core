package eu.olympus.model.server.rest;

import eu.olympus.model.SerializedKey;

public class FinishRegistrationRequest {

	private String username;
	private SerializedKey publicKey;
	private String signature;
	private long salt;
	private String idProof;
	private String sessionCookie;
	
	public FinishRegistrationRequest() {
	}
	
	public FinishRegistrationRequest(String username, String sessionCookie, SerializedKey publicKey, String signature, long salt,
			String idProof) {
		this.username = username;
		this.idProof = idProof;
		this.publicKey = publicKey;
		this.signature = signature;
		this.salt = salt;
		this.sessionCookie = sessionCookie;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public SerializedKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(SerializedKey publicKey) {
		this.publicKey = publicKey;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public long getSalt() {
		return salt;
	}

	public void setSalt(long salt) {
		this.salt = salt;
	}

	public String getIdProof() {
		return idProof;
	}

	public void setIdProof(String idProof) {
		this.idProof = idProof;
	}

	public String getSessionCookie() {
		return sessionCookie;
	}

	public void setSessionCookie(String sessionCookie) {
		this.sessionCookie = sessionCookie;
	}

}
