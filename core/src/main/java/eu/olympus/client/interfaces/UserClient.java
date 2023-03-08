package eu.olympus.client.interfaces;

import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.model.exceptions.OperationFailedException;
import java.util.List;
import java.util.Map;

import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;

/**
 * The userclient is responsible for handling the users
 * cryptographic actions, eg. given a username and password
 * the userclient can communicate with the idp and produce
 * a signed assertion or other token allowing the user to
 * authenticate with a service provider.
 * 
 * The client implemented by this interface, should be 
 * lightweight and may also be implemented in JavaScript. This
 * Java implementation is mainly for testing purposes. 
 * 
 * THIS INTERFACE SHOULD BE FAIRLY STABLE AND SHOULD NOT BE MODIFIED
 * (except the identity proof, assertion and token classes)
 *
 */
public interface UserClient {

	
	/**
	 * Create a new user account on the IdPs.
	 * 
	 * @param username The username
	 * @param password The users password
	 * @throws UserCreationFailedException If the user was not created
	 */
	public void createUser(String username, String password) throws UserCreationFailedException;
	
	/**
	 * Attempt to attach a multi-factor authentication mechanism to the user account. 
	 * @param username The username
	 * @param password The password
	 * @param type The type of multi-factor authentication
	 * @return Challenge/key material to use in the multi-factor authentication mechanism
	 */
	public String requestMFAChallenge(String username, String password, String type) throws AuthenticationFailedException, OperationFailedException;
	
	/**
	 * Finalizes the process of adding a multi-factor authentication mechanism to the account
	 * @param username The username
	 * @param password The password
	 * @param token A multi-factor token, confirming the user is in possession of the MFA mechanism
	 * @param type The type of multi-factor authentication
	 */
	public void confirmMFA(String username, String password, String token, String type) throws AuthenticationFailedException, OperationFailedException;

	/**
	 * Removes a MFA type. The MFA MUST exist and be active for the removal to be successful.
	 * Furthermore, this can only be done after MFA authentication and requires a new MFA token be verified.
	 * Returns true if successful and otherwise false. In case false is returned, the MFA remains active.
	 * @param username The username for which the MFA must be removed
	 * @param password The user's password
	 * @param token A MFA token valid for the MFA to be removed
	 * @param type The type of MFA to remove
	 * @return True if the MFA was successfully removed
	 */
	public void removeMFA(String username, String password, String token, String type) throws AuthenticationFailedException, OperationFailedException;

    /**
	 * Create a user account and attach the attributes in
	 * the id proof to the account.
	 * 
	 * @param username The username
	 * @param password The users password
	 * @param identityProof Attributes to vet and attach to the account
	 * @throws UserCreationFailedException If the user was not created
	 */
	public void createUserAndAddAttributes(String username, String password, IdentityProof identityProof) throws UserCreationFailedException;

	/**
	 * Attach the attributes in the id proof to the account. To be used when a user is already logged in, and have an active session.
	 *
	 * @param identityProof Attributes to vet and attach to the account
	 * @throws OperationFailedException
	 */
	public void addAttributes(IdentityProof identityProof) throws OperationFailedException;

	/**
	 * Log in and attach the attributes in the id proof to the account.
	 *
	 * @param username the users username
	 * @param password The users password
	 * @param identityProof Attributes to vet and attach to the account
	 * @throws OperationFailedException
	 */
	public void addAttributes(String username, String password, IdentityProof identityProof, String token, String type) throws OperationFailedException;

	/**
	 * Perform a login and obtain a signature on the presented assertion.
	 * this process may involve the combination of multiple signature
	 * shares
	 * 
	 * @param username The username
	 * @param password The users password
	 * @param policy The access policy
	 * @param token Optional MFA token (if MFA is enabled for the account)
	 * @return Access token
	 * @throws AuthenticationFailedException If the operation could not be executed
	 */
	public String authenticate(String username, String password, Policy policy, String token, String type) throws AuthenticationFailedException;

	/**
	 * Retrieve a map of all user attributes stored on the vIdP
	 * @param password The users password
	 * @throws OperationFailedException If the operation could not be executed
	 * @return Map of attributes
	 */
	public Map<String, Attribute> getAllAttributes(String username, String password, String token, String type) throws OperationFailedException;

	/**
	 * Retrieve a map of all user attributes stored on the vIdP.
	 * To be used when a user is already logged in, and have an active session.
	 * @throws OperationFailedException If the operation could not be executed
	 * @return Map of attributes
	 */
	public Map<String, Attribute> getAllAttributes() throws OperationFailedException;

	/**
	 * Deletes attributes on the vIdP
	 * @param password The users password
	 * @param attributes A list of attribute names to delete
	 * @throws OperationFailedException If the operation could not be executed
	 */
	public void deleteAttributes(String username, String password, List<String> attributes, String token, String type) throws OperationFailedException;

	/**
	 * Deletes attributes on the vIdP
	 * To be used when a user is already logged in, and have an active session.
	 * @param attributes A list of attribute names to delete
	 * @throws OperationFailedException If the operation could not be executed
	 */
	public void deleteAttributes(List<String> attributes) throws OperationFailedException;

	/**
	 * Deletes the users account on the vIdP
	 * @param password The users password
	 */
	public void deleteAccount(String username, String password, String token, String type) throws OperationFailedException;

	/**
	 * Changes the users password, without changing other stored attributed on the vIdP
	 * @param oldPassword The users existing password
	 * @param newPassword The password to use in the future 
	 */
	public void changePassword(String username, String oldPassword, String newPassword, String token, String type)
		throws OperationFailedException;

	/**
	 * Removes any session tokens (used in connection with MFA).
	 */
	public void clearSession();
}
