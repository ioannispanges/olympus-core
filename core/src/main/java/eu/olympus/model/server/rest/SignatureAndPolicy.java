package eu.olympus.model.server.rest;

import eu.olympus.model.Policy;

public class SignatureAndPolicy {

	private String username;
	private long saltIndex;
	private String signature;
	private Policy policy;
	private String sessionCookie;
	
	public SignatureAndPolicy() {
	}
	
	public SignatureAndPolicy(String username, String sessionCookie, long saltIndex, String signature, Policy policy) {
		this.username = username;
		this.saltIndex = saltIndex;
		this.signature = signature;
		this.policy = policy;
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

	public Policy getPolicy() {
		return policy;
	}

	public void setPolicy(Policy policy) {
		this.policy = policy;
	}

	public String getSessionCookie() {
		return sessionCookie;
	}

	public void setSessionCookie(String sessionCookie) {
		this.sessionCookie = sessionCookie;
	}
}
