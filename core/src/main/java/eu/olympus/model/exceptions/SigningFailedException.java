package eu.olympus.model.exceptions;

/**
 * To be thrown if a signing fails
 */
public class SigningFailedException extends Exception{
    public SigningFailedException(Exception e) {
        super(e);
    }

    public SigningFailedException(String log, Exception e) {
        super(log,e);
    }

    public SigningFailedException() {
        super();
    }

}
