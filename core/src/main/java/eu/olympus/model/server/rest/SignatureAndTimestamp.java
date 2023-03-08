package eu.olympus.model.server.rest;

public class SignatureAndTimestamp {

	private String username;
	private long saltIndex;
	private String signature;
	private long timestamp;
	private String sessionCookie;

	public SignatureAndTimestamp(){

	}

	public SignatureAndTimestamp(String username, String sessionCookie, long saltIndex, String signature,long timestamp) {
		this.username = username;
		this.saltIndex = saltIndex;
		this.signature = signature;
		this.timestamp = timestamp;
		this.sessionCookie = sessionCookie;
	}


	public String getUsername() {
		return username;
	}


	public void setUsername(String username) {
		this.username = username;
	}


	public long getSaltIndex() {
		return saltIndex;
	}


	public void setSaltIndex(long nonces) {
		this.saltIndex = nonces;
	}


	public String getSignature() {
		return signature;
	}


	public void setSignature(String signature) {
		this.signature = signature;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	public String getSessionCookie() {
		return sessionCookie;
	}

	public void setSessionCookie(String sessionCookie) {
		this.sessionCookie = sessionCookie;
	}
}
