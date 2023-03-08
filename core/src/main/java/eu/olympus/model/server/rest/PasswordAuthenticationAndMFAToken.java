package eu.olympus.model.server.rest;

public class PasswordAuthenticationAndMFAToken extends PasswordAuthentication {

	private String token;
	private String type;


	public PasswordAuthenticationAndMFAToken(UsernameAndPassword usernameAndPassword,
			String cookie, String token, String type) {
		super(usernameAndPassword, cookie);
		this.type = type;
		this.setToken(token);
	}

	public PasswordAuthenticationAndMFAToken() {
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

}
