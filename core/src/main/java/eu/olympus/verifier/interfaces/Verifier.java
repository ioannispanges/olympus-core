package eu.olympus.verifier.interfaces;

/**
 * Interface for an OLYMPUS verifier.
 * The verifiers are primarily used for testing purposes,
 * but may also be used by a relying party.
 *
 */
public interface Verifier {
	
	/**
	 * Verifies if the signature on the token is valid.
	 *  
	 * @param token The token to verify
	 * @return Whether the signature is valid
	 */
	public boolean verify(String token);
}
