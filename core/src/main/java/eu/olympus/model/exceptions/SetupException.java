package eu.olympus.model.exceptions;

/**
 * To be thrown when a setup phase fails.
 */
public class SetupException extends Exception {

    public SetupException(String string) {
        super(string);
    }

    public SetupException(Exception e) {
        super(e);
    }
    public SetupException(String cause, Exception e) {
        super(cause,e);
    }

}
