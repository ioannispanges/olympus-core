package eu.olympus.server;

import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.NonExistingUserException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.interfaces.VirtualIdP;
import eu.olympus.server.rest.Role;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public abstract class AbstractPasswordIdP implements VirtualIdP {

	protected PasswordHandler authenticationHandler;

	public void createUser(UsernameAndPassword creationData) throws UserCreationFailedException, OperationFailedException {
		authenticationHandler.createUser(creationData);
	}

	public void createUserAndAddAttributes(UsernameAndPassword creationData, IdentityProof idProof) throws UserCreationFailedException {
		try {
			createUser(creationData);
			addAttributes(creationData.getUsername(), idProof.getStringRepresentation());
		} catch (Exception e) {
			throw new UserCreationFailedException(e);
		}
	}

	public abstract String authenticate(String username, byte[] cookie, Policy policy) throws AuthenticationFailedException;

	public void addAttributes(String username, byte[] cookie, IdentityProof idProof) throws OperationFailedException, AuthenticationFailedException {
		if(validateSession(Base64.encodeBase64String(cookie))) {
			addAttributes(username, idProof.getStringRepresentation());
		} else {
			throw new OperationFailedException("Failed to add attributes");
		}
	}
	
	private void addAttributes(String username, String idProof) throws OperationFailedException {
		authenticationHandler.addAttributes(username, idProof);
	}

	public Map<String, Attribute> getAllAttributes(String username, byte[] cookie) throws OperationFailedException, AuthenticationFailedException {
		if(validateSession(Base64.encodeBase64String(cookie))) {
			return authenticationHandler.getAllAssertions(username);
		} else {
			throw new OperationFailedException("Failed to get Attributes");
		}
	}

	public boolean deleteAttribute(String username, byte[] cookie, List<String> attributes) throws OperationFailedException, AuthenticationFailedException {
		if(validateSession(Base64.encodeBase64String(cookie))) {
			return authenticationHandler.deleteAttributes(username, attributes);
		}
		throw new OperationFailedException("Failed to delete attribute");
	}

	public boolean deleteAccount(UsernameAndPassword authentication, byte[] cookie) throws OperationFailedException, AuthenticationFailedException {
		if(validateSession(Base64.encodeBase64String(cookie))) {
			boolean authenticated = authenticationHandler.validateUsernameAndPassword(authentication);
			if (authenticated) {
				return authenticationHandler.deleteAccount(authentication.getUsername());
			}
		}
		throw new OperationFailedException("Failed to delete account");
	}

	public void changePassword(
			UsernameAndPassword oldAuthenticationData, String newPassword, byte[] cookie)
			throws OperationFailedException, UserCreationFailedException, AuthenticationFailedException {
		try{
			if (validateSession(Base64.encodeBase64String(cookie))) {
				authenticationHandler.changePassword(oldAuthenticationData, newPassword);
			} else {
				throw new OperationFailedException("Failed to validate session");
			}
		} catch (OperationFailedException | UserCreationFailedException e){
			throw new OperationFailedException("Failed to change password",e);
		}
	}

	public String requestMFA(UsernameAndPassword authentication, byte[] cookie, String type) throws AuthenticationFailedException, OperationFailedException {
		try {
			if (validateSession(Base64.encodeBase64String(cookie))) {
				if (authenticationHandler.validateUsernameAndPassword(authentication)) {
					return authenticationHandler.requestMFASecret(authentication.getUsername(), type);
				}
			}
			throw new AuthenticationFailedException("Failed to validate session");
		} catch (NonExistingUserException | AuthenticationFailedException e) {
			throw new OperationFailedException("Failed to request MFA",e);
		}
	}

	public boolean confirmMFA(UsernameAndPassword authentication, byte[] cookie, String mfaToken,
			String type) throws OperationFailedException {
		if (validateSession(Base64.encodeBase64String(cookie))) {
			boolean authenticated = authenticationHandler.validateUsernameAndPassword(authentication);
			if (authenticated) {
				if (authenticationHandler.validateMFAToken(authentication.getUsername(), mfaToken, type)) {
					return authenticationHandler.activateMFA(authentication.getUsername(), mfaToken, type);
				}
			}
		}
		throw new OperationFailedException("Failed to confirm MFA");
	}

	public boolean removeMFA(UsernameAndPassword authentication, byte[] cookie, String mfaToken,
			String type) throws OperationFailedException {
		if (validateSession(Base64.encodeBase64String(cookie))) {
			boolean authenticated = authenticationHandler.validateUsernameAndPassword(authentication);
			if (authenticated) {
				return authenticationHandler.deleteMFA(authentication.getUsername(), mfaToken, type);
			}
		}
		throw new OperationFailedException("Failed to remove MFA");
	}

	public String startSession(UsernameAndPassword authentication, String token, String type) throws AuthenticationFailedException, OperationFailedException {
		boolean authIsValid = authenticationHandler.validateUsernameAndPassword(authentication);
		if (authIsValid) {
			boolean tokenIsValid = authenticationHandler
					.validateMFAToken(authentication.getUsername(), token, type);
			if (tokenIsValid) {
				return authenticationHandler.generateSessionCookie(authentication.getUsername());
			}
		}
		throw new AuthenticationFailedException("Failed to validate MFA token or password");
	}

	/**
	 * Validates that the password is correct and the cookie is valid
	 * @param cookie The cookie to validate
	 * @return True if the credentials and cookie are valid
	 */
	public boolean validateSession(String cookie) {
		try {
			authenticationHandler.validateSession(cookie, Arrays.asList(Role.USER));
		} catch (AuthenticationFailedException e) {
			return false;
		}
		return true;
	}
}
