package eu.olympus.model.exceptions;

/**
 * To be thrown when a request to perform an operation fails.
 * E.g. a request to delete an account or change the password of an account.
 */
public class OperationFailedException extends Exception{

    public OperationFailedException(String string) {
        super(string);
    }
    public OperationFailedException(){}

    public OperationFailedException(Exception e) {
        super(e);
    }
    public OperationFailedException(String cause, Exception e) {
        super(cause,e);
    }

}
