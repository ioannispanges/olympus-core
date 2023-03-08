package eu.olympus.model.exceptions;

/**
 * To be thrown when MS(multi-signature) setup fails
 */
public class MSSetupException extends Exception{
    public MSSetupException() {
    }

    public MSSetupException(Exception e) {
        super(e);
    }

    public MSSetupException(String string) {
        super(string);
    }

    public MSSetupException(String string,Exception e) {
        super(string,e);
    }
}
