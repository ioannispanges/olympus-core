package eu.olympus.model.server.rest;

public class UsernameAndPassword {
	private String username;
	private String password;

	public UsernameAndPassword() {
	}
	
	public UsernameAndPassword(String username, String password) {
		this.username = username;
		this.password = password;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
