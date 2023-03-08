package eu.olympus.server.interfaces;

import eu.olympus.model.exceptions.OperationFailedException;
import java.security.PublicKey;

/**
 * Interface for storage used by the PESTO implementation
 * 
 */
public interface PestoDatabase extends Storage {

	/**
	 * Add a user to the database.
	 * @param username Username of the user
	 * @param key The public key (derived from the OPRF), used to authenticate the user 
	 * @param salt A running number used to generate nonces.
	 */
	public void addUser(String username, PublicKey key, long salt) throws OperationFailedException;
	
	/**
	 * Get the public key for a user.
	 * @param username The username of the user for to do the lookup.
	 * @return The public key belonging to the user
	 */
	public PublicKey getUserKey(String username) throws OperationFailedException;

	/**
	 * Get the last salt used by the user.
	 * @param username The username of the user
	 * @return The last used salt.
	 */
	public long getLastSalt(String username) throws OperationFailedException;
	
	/**
	 * Store a salt belonging to a user.
	 * @param username The username of the user
	 * @param salt The salt to store
	 */
	public void setSalt(String username, long salt) throws OperationFailedException;

	/**
	 * Replaces the stored user PublicKey with a publicKey  
	 * @param username The username of the user
	 * @param publicKey The new public key to store
	 * @param salt The salt used in the request
	 */
	public void replaceUserKey(String username, PublicKey publicKey, long salt) throws OperationFailedException;

	/**
	 * Get the digest on the current masterkeys
	 * @return the digest
	 */
	public byte[] getKeyDigest() throws OperationFailedException;

	/**
	 * Update the digest of the current masterkeys
	 * @param digest The new digest
	 */
	public void setKeyDigest(byte[] digest) throws OperationFailedException;

	/**
	 * Set the key shares of an other IdP's master key
	 */
	public void setKeyShare(int id, byte[] shares) throws OperationFailedException;

	/**
	 * Return the key share of an other IdP's master key
	 */
	public byte[] getKeyShare(int id) throws OperationFailedException;

}
