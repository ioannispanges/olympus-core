package eu.olympus.model.server.rest;

public class SecondFactorRequest {

	private String username;
	private long saltIndex;
	private String signature;
	private String type;
	private String sessionCookie;
	
	public SecondFactorRequest() {
	}
	
	public SecondFactorRequest(String username, String cookie, long saltIndex, String signature, String type) {
		this.username = username;
		this.saltIndex = saltIndex;
		this.signature = signature;
		this.type = type;
		this.sessionCookie = cookie;
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

	public void setSaltIndex(long saltIndex) {
		this.saltIndex = saltIndex;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getSessionCookie() {
		return sessionCookie;
	}

	public void setSessionCookie(String sessionCookie) {
		this.sessionCookie = sessionCookie;
	}

}
