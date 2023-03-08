package eu.olympus.model.exceptions;

/**
 * To be thrown if any malicious activity is detected.
 */
public class MaliciousException extends RuntimeException {
  public MaliciousException() {
    super();
  }

  public MaliciousException(Exception e) {
    super(e);
  }

  public MaliciousException(String m) {
    super(m);
  }
}
