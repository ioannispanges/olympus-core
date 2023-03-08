package eu.olympus.model.server.rest;

import eu.olympus.model.Policy;

public class AuthenticationAndPolicy {

	private String username;
	private Policy policy;
	private String cookie;

	public AuthenticationAndPolicy(String username, String cookie, Policy policy) {
		this.username = username;
		this.policy = policy;
		this.cookie = cookie;
	}
	
	public AuthenticationAndPolicy() {
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public Policy getPolicy() {
		return policy;
	}

	public void setPolicy(Policy policy) {
		this.policy = policy;
	}

	public String getCookie() {
		return cookie;
	}

	public void setCookie(String cookie) {
		this.cookie = cookie;
	}

}
