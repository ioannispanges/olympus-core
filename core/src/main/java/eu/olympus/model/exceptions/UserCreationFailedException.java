package eu.olympus.model.exceptions;

public class UserCreationFailedException extends Exception{

	/**
	 * To be thrown if user creation fails
	 */
	private static final long serialVersionUID = -402767162815193144L;

	public UserCreationFailedException() {
	}
	
	public UserCreationFailedException(Exception e) {
		super(e);
	}

	public UserCreationFailedException(String string) {
		super(string);
	}

	public UserCreationFailedException(String string, Exception e) {
		super(string, e);
	}
	
}
