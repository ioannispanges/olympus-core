package eu.olympus.model.server.rest;

public class PasswordAuthenticationAndMFAType extends PasswordAuthentication {

	private String type;

	public PasswordAuthenticationAndMFAType(UsernameAndPassword usernameAndPassword,
			String cookie, String type) {
		super(usernameAndPassword, cookie);
		this.setType(type);

	}

	public PasswordAuthenticationAndMFAType() {
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

}
