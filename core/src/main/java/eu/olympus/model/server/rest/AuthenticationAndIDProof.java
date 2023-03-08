package eu.olympus.model.server.rest;

public class AuthenticationAndIDProof {

	private String username;
	private IdentityProof identityProof;
	private String cookie;

	public AuthenticationAndIDProof(String username, String cookie, IdentityProof identityProof) {
		this.username = username;
		this.identityProof = identityProof;
		this.cookie = cookie;
	}

	public AuthenticationAndIDProof() {
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public IdentityProof getIdentityProof() {
		return identityProof;
	}

	public void setIdentityProof(IdentityProof idProof) {
		this.identityProof = idProof;
	}

	public String getCookie() {
		return cookie;
	}

	public void setCookie(String cookie) {
		this.cookie = cookie;
	}

}
