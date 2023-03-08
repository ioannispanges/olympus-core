package eu.olympus.model.server.rest;

import java.util.List;

public class PasswordAuthenticationAndAttributes extends PasswordAuthentication {

	private List<String> attributes;

	public PasswordAuthenticationAndAttributes(UsernameAndPassword usernameAndPassword, String cookie, List<String> attributes) {
		super(usernameAndPassword, cookie);
		this.attributes = attributes;
	}
	
	public PasswordAuthenticationAndAttributes() {
	}

	public List<String> getAttributes() {
		return attributes;
	}

	public void setAttributes(List<String> attributes) {
		this.attributes = attributes;
	}
}
