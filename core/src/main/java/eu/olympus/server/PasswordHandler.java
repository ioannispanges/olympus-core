package eu.olympus.server;

import eu.olympus.model.Authorization;
import eu.olympus.model.exceptions.ExistingUserException;
import eu.olympus.model.exceptions.NonExistingUserException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.interfaces.UserPasswordDatabase;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryKeyDB;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class PasswordHandler extends AuthenticationHandler {

	private final UserPasswordDatabase database;
	private final MessageDigest md;
	private final long sessionLength = 60000l;


	public PasswordHandler(Storage database,
			ServerCryptoModule cryptoModule, InMemoryKeyDB keyDB,
			Map<String, MFAAuthenticator> mfaAuthenticators) throws SetupException {
		super(database, keyDB, mfaAuthenticators, cryptoModule);
		try {
			if (database instanceof UserPasswordDatabase) {
				this.database = (UserPasswordDatabase) database;
			} else {
				throw new SetupException("Not a valid database");
			}
			md = MessageDigest.getInstance("SHA-512");
		} catch(Exception e) {
			throw new SetupException("Setup failed", e);
		}
	}
	
	public void createUser(UsernameAndPassword creationData) throws UserCreationFailedException, OperationFailedException {
		if(this.database.hasUser(creationData.getUsername())) {
			throw new ExistingUserException();
		}
		byte[] saltBytes = crypto.getBytes(16);

		String hash = "";
		String salt = "";

		// Switch to a better suited hash algorithm
		md.reset();
		md.update(saltBytes);

		byte[] hashBytes = md.digest(creationData.getPassword().getBytes(StandardCharsets.UTF_8));

		salt = Base64.encodeBase64String(saltBytes);
		hash = Base64.encodeBase64String(hashBytes);
		this.database.addUser(creationData.getUsername(), salt, hash);
	}


	public void createUserAndAddAttributes(UsernameAndPassword creationData, String idProof) throws UserCreationFailedException, OperationFailedException {
		createUser(creationData);
		addAttributes(creationData.getUsername(), idProof);
	}
	
	public boolean validateUsernameAndPassword(UsernameAndPassword authenticationData) {
		String username =  authenticationData.getUsername();
		String password = this.database.getPassword(username);
		String salt = this.database.getSalt(username);
		String candidate = authenticationData.getPassword();
		if(password == null) {
			return false;
		}
		
		boolean valid = false;
		byte[] saltBytes = Base64.decodeBase64(salt);
			
		md.reset();
		md.update(saltBytes);

		byte[] hashBytes = md.digest(candidate.getBytes(StandardCharsets.UTF_8));
		String hash = Base64.encodeBase64String(hashBytes);
		valid = password.equals(hash);
		return valid;
	}

	public void changePassword(UsernameAndPassword old, String newPassword)
			throws UserCreationFailedException {
		if (validateUsernameAndPassword(old)) {
			byte[] saltBytes = crypto.getBytes(16);

			String hash = "";
			String salt = "";

			// Switch to a better suited hash algorithm
			md.reset();
			md.update(saltBytes);

			byte[] hashBytes = md.digest(newPassword.getBytes(StandardCharsets.UTF_8));

			salt = Base64.encodeBase64String(saltBytes);
			hash = Base64.encodeBase64String(hashBytes);
			this.database.setSalt(old.getUsername(), salt);
			this.database.setPassword(old.getUsername(), hash);

		} else {
			throw new UserCreationFailedException();
		}
	}

	@Override
	public String requestMFASecret(String username, String type) throws NonExistingUserException, OperationFailedException {
		if(!this.database.hasUser(username)) {
			throw new NonExistingUserException("User could not be found");
		}
		MFAAuthenticator authenticator = mfaAuthenticators.get(type);
		String secret = authenticator.generateSecret();
		this.database.assignMFASecret(username, type, secret);
		return secret;
	}


	@Override
	public String generateSessionCookie(String username) {
		String cookie = org.apache.commons.codec.binary.Base64.encodeBase64String(crypto.getBytes(64));
		storeAuthorization(cookie, new Authorization(username, Arrays.asList(Role.USER), System.currentTimeMillis()+this.sessionLength));
		return cookie;
	}

}
