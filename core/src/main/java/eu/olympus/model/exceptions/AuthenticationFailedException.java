package eu.olympus.model.exceptions;

/**
 * To be thrown when the an authentication fails. E.g. a password is incorrect.
 */
public class AuthenticationFailedException extends Exception {

	public AuthenticationFailedException(String string) {
		super(string);
	}

	public AuthenticationFailedException(Exception e) {
		super(e);
	}
	public AuthenticationFailedException(String cause, Exception e) {
		super(cause,e);
	}

	private static final long serialVersionUID = 7483158635274840693L;

}
