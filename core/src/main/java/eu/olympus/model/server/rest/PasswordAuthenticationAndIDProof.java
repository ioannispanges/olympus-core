package eu.olympus.model.server.rest;

public class PasswordAuthenticationAndIDProof extends PasswordAuthentication {
	private IdentityProof identityProof;

	public PasswordAuthenticationAndIDProof(UsernameAndPassword usernameAndPassword, String cookie, IdentityProof identityProof) {
		super(usernameAndPassword, cookie);
		this.identityProof = identityProof;
	}
	
	public PasswordAuthenticationAndIDProof() {
	}

	public IdentityProof getIdentityProof() {
		return identityProof;
	}

	public void setIdentityProof(IdentityProof idProof) {
		this.identityProof = idProof;
	}
}
