package eu.olympus.model.server.rest;

public class PasswordAuthenticationAndMFATokenNoCookie {

	private UsernameAndPassword usernameAndPassword;
	private String token;
	private String type;


	public PasswordAuthenticationAndMFATokenNoCookie(UsernameAndPassword usernameAndPassword,
			String token, String type) {
		this.usernameAndPassword = usernameAndPassword;
		this.type = type;
		this.token = token;
	}

	public PasswordAuthenticationAndMFATokenNoCookie() {
	}

	public UsernameAndPassword getUsernameAndPassword() {
		return usernameAndPassword;
	}

	public void setUsernameAndPassword(UsernameAndPassword usernameAndPassword) {
		this.usernameAndPassword = usernameAndPassword;
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
