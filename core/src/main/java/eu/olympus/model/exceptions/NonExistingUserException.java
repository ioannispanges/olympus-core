package eu.olympus.model.exceptions;

/**
 * To be thrown if a username does not fit an existing user.
 */
public class NonExistingUserException extends Exception {
	public NonExistingUserException(String string) {
		super(string);
	}
	public NonExistingUserException(String cause, Exception e) {
		super(cause,e);
	}
	public NonExistingUserException() {
		super();
	}

	private static final long serialVersionUID = -7213179401096051135L;

}
