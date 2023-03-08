package eu.olympus.model.server.rest;

import eu.olympus.model.SerializedKey;

public class ChangePasswordRequest {

	private String username;
	private SerializedKey publicKey;
	private String oldSignature;
	private String newSignature;
	private long salt;
	private String sessionCookie;
	
	public ChangePasswordRequest() {
	}
	
	public ChangePasswordRequest(String username, String cookie, SerializedKey publicKey, String oldSignature, String newSignature, long salt) {
		this.username = username;
		this.publicKey = publicKey;
		this.oldSignature = oldSignature;
		this.newSignature = newSignature;
		this.salt = salt;
		this.setSessionCookie(cookie);
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

	public String getOldSignature() {
		return oldSignature;
	}

	public void setOldSignature(String signature) {
		this.oldSignature = signature;
	}

	public String getNewSignature() {
		return newSignature;
	}

	public void setNewSignature(String signature) {
		this.newSignature = signature;
	}
	
	public long getSalt() {
		return salt;
	}

	public void setSalt(long salt) {
		this.salt = salt;
	}

	public String getSessionCookie() {
		return sessionCookie;
	}

	public void setSessionCookie(String sessionCookie) {
		this.sessionCookie = sessionCookie;
	}
}
