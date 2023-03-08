package eu.olympus.model.server.rest;

public class GetAllAttributesRequest {

	private String username;
	private long saltIndex;
	private String signature;
	private String sessionCookie;
	
	public GetAllAttributesRequest() {
	}
	
	public GetAllAttributesRequest(String username, String sessionCookie, long saltIndex, String signature) {
		this.username = username;
		this.saltIndex = saltIndex;
		this.signature = signature;
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


	public void setSaltIndex(long saltIndex) {
		this.saltIndex = saltIndex;
	}


	public String getSignature() {
		return signature;
	}


	public void setSignature(String signature) {
		this.signature = signature;
	}

	public String getSessionCookie() {
		return sessionCookie;
	}

	public void setSessionCookie(String sessionCookie) {
		this.sessionCookie = sessionCookie;
	}
}
