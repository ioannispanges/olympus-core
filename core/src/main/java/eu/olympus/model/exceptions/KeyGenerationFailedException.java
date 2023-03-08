package eu.olympus.model.exceptions;

public class KeyGenerationFailedException extends Exception {

	/**
	 * To be thrown when private or public keys fail to be generated.
	 */
	private static final long serialVersionUID = 1166242502681285887L;

	public KeyGenerationFailedException(Exception e) {
		super(e);
	}

	public KeyGenerationFailedException(String log, Exception e) {
		super(log,e);
	}

	public KeyGenerationFailedException() {
		super();
	}

}
