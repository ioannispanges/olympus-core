package eu.olympus.model.server.rest;

public class PasswordAuthenticationAndPassword extends PasswordAuthentication {

	private String newPassword;

	public PasswordAuthenticationAndPassword(UsernameAndPassword usernameAndPassword, String cookie, String newPassword) {
		super(usernameAndPassword, cookie);
		this.newPassword = newPassword;
	}
	
	public PasswordAuthenticationAndPassword() {
	}

	public String getNewPassword() {
		return newPassword;
	}

	public void setNewPassword(String pw) {
		this.newPassword = pw;
	}
}
