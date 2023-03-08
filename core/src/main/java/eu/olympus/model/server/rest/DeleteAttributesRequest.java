package eu.olympus.model.server.rest;

import java.util.List;

public class DeleteAttributesRequest {

	private String username;
	private long saltIndex;
	private String signature;
	private List<String> attributes;
	private String sessionCookie;
	
	public DeleteAttributesRequest() {
	}
	
	public DeleteAttributesRequest(String username, String sessionCookie, long saltIndex, String signature, List<String> attributes) {
		this.username = username;
		this.saltIndex = saltIndex;
		this.signature = signature;
		this.setAttributes(attributes);
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

	public List<String> getAttributes() {
		return attributes;
	}

	public void setAttributes(List<String> attributes) {
		this.attributes = attributes;
	}

	public String getSessionCookie() {
		return sessionCookie;
	}

	public void setSessionCookie(String sessionToken) {
		this.sessionCookie = sessionToken;
	}
}
