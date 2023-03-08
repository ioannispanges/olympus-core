package eu.olympus.model.server.rest;

import java.util.List;

public class AuthenticationAndAttributes {

	private String username;
	private List<String> attributes;
	private String cookie;

	public AuthenticationAndAttributes(String username, String cookie, List<String> attributes) {
		this.username = username;
		this.attributes = attributes;
		this.cookie = cookie;
	}

	public AuthenticationAndAttributes() {
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public List<String> getAttributes() {
		return attributes;
	}

	public void setAttributes(List<String> attributes) {
		this.attributes = attributes;
	}

	public String getCookie() {
		return cookie;
	}

	public void setCookie(String cookie) {
		this.cookie = cookie;
	}
}
