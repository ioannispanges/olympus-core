package eu.olympus.model.exceptions;

/**
 * To be thrown if the generation of a token fails
 */
public class TokenGenerationException extends Exception {

    public TokenGenerationException(String string) {
        super(string);
    }

    public TokenGenerationException(Exception e) {
        super(e);
    }
    public TokenGenerationException(String cause, Exception e) {
        super(cause,e);
    }
}
