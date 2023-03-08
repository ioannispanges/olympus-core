package eu.olympus.model.exceptions;

/**
 * To be thrown if the check of a policy fails
 */
public class PolicyUnfulfilledException extends Exception{
    public PolicyUnfulfilledException(Exception e) {
        super(e);
    }

    public PolicyUnfulfilledException(String log, Exception e) {
        super(log,e);
    }

    public PolicyUnfulfilledException() {
        super();
    }

    public PolicyUnfulfilledException(String s) {
        super(s);
    }
}
