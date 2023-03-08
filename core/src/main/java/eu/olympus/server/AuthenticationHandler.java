package eu.olympus.server;

import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeType;
import eu.olympus.model.Authorization;
import eu.olympus.model.MFAInformation;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.PolicyUnfulfilledException;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.interfaces.UserAuthorizationDatabase;
import eu.olympus.server.rest.Role;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Super class for authentication handling. The sub classes may utilize the inherited methods for
 * adding attributes to an existing user or for producing a set of claims fulfilling the specified
 * policy.
 *
 * A AuthenticationHandler subclass should provide methods for creating/enrolling users and for
 * authenticating users.
 */
public abstract class AuthenticationHandler {

	private static Logger logger = LoggerFactory.getLogger(AuthenticationHandler.class);
	protected final UserAuthorizationDatabase sessions;
	protected final Map<String, MFAAuthenticator> mfaAuthenticators;
	protected final ServerCryptoModule crypto;
	private final Storage database;
	private final List<IdentityProver> identityProvers;

	public AuthenticationHandler(Storage database, UserAuthorizationDatabase sessions,
			Map<String, MFAAuthenticator> mfaAuthenticators, ServerCryptoModule cryptoModule) {
		this.crypto = cryptoModule;
		this.database = database;
		this.sessions = sessions;
		this.identityProvers = new ArrayList<IdentityProver>();
		this.mfaAuthenticators = mfaAuthenticators;
	}

	public void addIdentityProver(IdentityProver idProver) {
		this.identityProvers.add(idProver);
	}

	/**
	 * Validates an identity proof and adds the set of contained attributes to an existing user.
	 *
	 * This method assumes the user has already been authenticated.
	 *
	 * @param username The user
	 * @param idProof The IdentityProof containing the attributes to add
	 * @throws OperationFailedException Thrown if the user does not exist or the IdentityProof is
	 * invalid.
	 */
	public void addAttributes(String username, String idProof) throws OperationFailedException {
		if (this.database.hasUser(username)) {
			for (IdentityProver idProver : this.identityProvers) {
				if (idProver.isValid(idProof, username)) {
					idProver.addAttributes(idProof, username);
					return;
				}
			}
			throw new OperationFailedException("No IdentityProver could validate " + idProof);
		} else {
			throw new OperationFailedException("User does not exist");
		}
	}


	/**
	 * Checks if a user can satisfy a policy and if so, produces
	 * a key-value mapping of the claims. 
	 * 
	 * Any policy that cannot be satisfied (e.g. the requested
	 * attribute does not exist for the user), will result in
	 * an exception.
	 * 
	 * @param username The user
	 * @param policy The policy to satisfy
	 * @return A map of the claims
	 * @throws PolicyUnfulfilledException Thrown if the policy cannot be satisfied
	 */
	public Map<String, Attribute> validateAssertions(String username, Policy policy) throws PolicyUnfulfilledException, OperationFailedException {
		Map<String, Attribute> attributes = this.database.getAttributes(username);
		logger.info("Validating assets for " + username);
		attributes.forEach((key,att) -> logger.info("Attribute " + key+":"+att.toString()));

		Map<String, Attribute> output = new HashMap<>();
		for(Predicate predicate : policy.getPredicates()) {
			String key = predicate.getAttributeName().toLowerCase();

			Attribute attribute = attributes.get(key);
			if(attribute == null) {
				throw new PolicyUnfulfilledException("User does not have the \"" + key + "\" attribute");
			}

			Operation operation = predicate.getOperation();
			if(operation == Operation.LESSTHANOREQUAL)  {
				String name = key+"LT"+getValueAsString(predicate);
				boolean added = false;
				if(attribute.getType() == AttributeType.INTEGER){
					if((Integer)attribute.getAttr() <= (Integer)predicate.getValue().getAttr()) {
						output.put(name, new Attribute(true));
						added = true;
					} else {
						throw new PolicyUnfulfilledException("Could not satisfy "+key+" LT "+predicate.getValue().getAttr());
					}
				}
				if (attribute.getType() == AttributeType.DATE) {
					if(!(((Date)attribute.getAttr()).after((Date)predicate.getValue().getAttr()))) {
						output.put(name, new Attribute(true));
						added = true;
					} else {
						throw new PolicyUnfulfilledException("Could not satisfy "+key+" LT "+predicate.getValue().getAttr());
					}
				}
				if(!added) {
					throw new PolicyUnfulfilledException("Could not satisfy "+key+" LT "+predicate.getValue().getAttr());
				}

			}
			if(operation == Operation.EQ)  {
				String name = key+"EQUALS"+getValueAsString(predicate);
				if(attribute.equals(predicate.getValue())) {
					output.put(name, new Attribute(true));
				} else {
					throw new PolicyUnfulfilledException("Could not satisfy "+key+" == "+predicate.getValue().getAttr());
				}
			}
			if(operation == Operation.GREATERTHANOREQUAL)  {
				boolean added = false;
				String name = key+"GT"+getValueAsString(predicate);
				if(attribute.getType() == AttributeType.INTEGER){
					if((Integer)attribute.getAttr() >= (Integer)predicate.getValue().getAttr()) {
						output.put(name, new Attribute(true));
						added = true;
					} else {
						throw new PolicyUnfulfilledException("Could not satisfy "+key+" GT "+predicate.getValue().getAttr());
					}
				}
				if (attribute.getType() == AttributeType.DATE) {
					if(!(((Date)attribute.getAttr()).before((Date)predicate.getValue().getAttr()))) {
						output.put(name, new Attribute(true));
						added = true;
					} else {
						throw new PolicyUnfulfilledException("Could not satisfy "+key+" GT "+predicate.getValue().getAttr());
					}
				}
				if(!added) {
					throw new PolicyUnfulfilledException("Could not satisfy "+key+" GT "+predicate.getValue().getAttr());
				}
			}
			if(operation == Operation.INRANGE)  {
				boolean added = false;
				String name = key+"INRANGE"+getValueAsString(predicate);
				if(attribute.getType() == AttributeType.INTEGER){
					if((Integer)attribute.getAttr() >= (Integer)predicate.getValue().getAttr() && (Integer)attribute.getAttr() <= (Integer)predicate.getExtraValue().getAttr() ) {
						output.put(name, new Attribute(true));
						added = true;
					} else {
						throw new PolicyUnfulfilledException("Could not satisfy "+key+" INRANGE "+predicate.getValue().getAttr()+"-"+predicate.getExtraValue().getAttr());
					}
				}
				if (attribute.getType() == AttributeType.DATE) {
					//In all Date comprobations we use !after/!before instead of before/after because these methods are not inclusive.
					if(!(((Date)attribute.getAttr()).before((Date)predicate.getValue().getAttr()) || ((Date)attribute.getAttr()).after((Date)predicate.getExtraValue().getAttr()))) {
						output.put(name, new Attribute(true));
						added = true;
					} else {
						throw new PolicyUnfulfilledException("Could not satisfy "+key+" INRANGE "+predicate.getValue().getAttr()+"-"+predicate.getExtraValue().getAttr());
					}
				}
				if(!added) {
					throw new PolicyUnfulfilledException("Could not satisfy "+key+" INRANGE "+predicate.getValue().getAttr()+"-"+predicate.getExtraValue().getAttr());
				}
			}
			if(operation == Operation.REVEAL)  {
				output.put(key, attribute);
			}
		}
		return output;
	}



	private String getValueAsString(Predicate predicate) {
		if(predicate.getOperation()==Operation.INRANGE){
			String result=predicate.getValue().toString()+"-"+predicate.getExtraValue().toString();
			if(predicate.getValue().getType() == AttributeType.DATE){
				Date dateVal = (Date)predicate.getValue().getAttr();
				result = DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).format(dateVal);
				Date dateExtra=(Date)predicate.getExtraValue().getAttr();
				result +="-"+ DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).format(dateExtra);
			}
			return result;
		}
		String value = predicate.getValue().getAttr().toString();
		if(predicate.getValue().getType() == AttributeType.DATE) {
			Date date = (Date)predicate.getValue().getAttr();
			value = DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).format(date);
		}
		return value;
	}

	public Map<String, Attribute> getAllAssertions(String username) throws OperationFailedException {
		return this.database.getAttributes(username);
	}

	public boolean deleteAttributes(String username, List<String> attributes) throws OperationFailedException {
		boolean failedDelete = true;

		for (String currentAttribute: attributes) {
			failedDelete &= this.database.deleteAttribute(username, currentAttribute.toLowerCase());
		}
		return failedDelete;
	}

	public boolean deleteAccount(String username) throws OperationFailedException {
		try {
			return this.database.deleteUser(username);
		} catch (OperationFailedException e) {
			logger.error("Database failed operation", e);
			throw new OperationFailedException(e);
		}
	}

	public void storeAuthorization(String cookie, Authorization authorization) {
		this.sessions.storeCookie(cookie, authorization);
	}

	public String refreshCookie(String cookie) {
		logger.info("refreshCookie: "+cookie);
		String newCookie = Base64.encodeBase64String(crypto.getBytes(64));
		try {
			Authorization auth = this.sessions.lookupCookie(cookie);
			storeAuthorization(newCookie, auth);
		} catch(Exception e) {
			logger.info("refreshCookie failed to refresh cookie: "+cookie, e);
			return cookie;
		}
		try {
			this.sessions.deleteCookie(cookie);
		} catch(Exception e) {
			logger.info("refreshCookie failed to delete old cookie", e);
		}
		return newCookie;
	}

	/**
	 * Verifies that AT LEAST ONE of the requestedRoles are granted to the user with the given cookie.
	 * @param cookie
	 * @param requestedRoles
	 * @throws AuthenticationFailedException
	 */
	public void validateSession(String cookie, List<Role> requestedRoles) throws AuthenticationFailedException {
		Authorization authorization = sessions.lookupCookie(cookie);
		if(authorization == null) {
			throw new AuthenticationFailedException("Session cookie invalid");
		}
		if(authorization.getExpiration() < System.currentTimeMillis()) {
			throw new AuthenticationFailedException("Session cookie expired");
		}

		List<Role> grantedRoles = authorization.getRoles();
		for(Role requires: requestedRoles) {
			if (grantedRoles.contains(requires)) {
				return;
			}
		}
		throw new AuthenticationFailedException("Session cookie invalid");
	}

	public abstract String requestMFASecret(String username, String type) throws Exception;


	/**
	 * Evaluate the MFA if ANY MFA is activated for the user in question.
	 * If so, and if the token is of an active MFA type, evaluate and return the result.
	 * If the MFA supplied is of a non-active MFA AND there is another active MFA return false
	 * (as this is a malicious attack to circumvent MFA).
	 * If no MFA is activated for this user return true as all tokens will be valid in that case.
	 * Finally return false if the user does not exist.
	 * @param username The username
	 * @param token The MFA token to verify
	 * @param type The type of MFA token
	 * @return
	 */
	public boolean validateMFAToken(String username, String token, String type) throws OperationFailedException {
		try {
			if (!this.database.hasUser(username)) {
				return false;
			}
		} catch (OperationFailedException e) {
			logger.error("Database failed operation", e);
			throw new OperationFailedException(e);
		}
		if (isMFAActivated(username)) {
			return conservativeMFAValidation(username, token, type);
		}
		return true;
	}

	/**
	 * Returns true if there is ANY active MFA for this user
	 * @param username The username
	 * @return
	 */
	private boolean isMFAActivated(String username) throws OperationFailedException {
		Map<String, MFAInformation> mfaInfo = null;
		try {
			mfaInfo = database.getMFAInformation(username);
		} catch (OperationFailedException e) {
			logger.error("Database failed operation", e);
			throw new OperationFailedException(e);
		}

		//Check if user has activate MFA
		for(String info: mfaInfo.keySet()) {
			if(mfaInfo.get(info).isActivated()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Conservatively validate a MFA token for a certain user. If MFA exists added AND is activated,
	 * the method verifies the token and returns the result of the verification. If the MFA does not
	 * exist OR it exists but is not activated returns false
	 *
	 * @param username The username
	 * @param token The MFA token to verify
	 * @param type The type of MFA token
	 */
	public boolean conservativeMFAValidation(String username, String token, String type) throws OperationFailedException {
		try {
			if (!this.database.hasUser(username)) {
				return false;
			}
			Map<String, MFAInformation> mfaInfo = this.database.getMFAInformation(username);
			if (!mfaAuthenticators.containsKey(type) || !mfaInfo.get(type).isActivated()) {
				return false;
			}

			if (mayNotAuthenticate(database.getLastMFAAttempt(username), database.getNumberOfFailedMFAAttempts(username), mfaAuthenticators.get(type).getTimeoutPeriod())) {
				return false;
			}
			String secret = mfaInfo.get(type).getSecret();
			boolean res = mfaAuthenticators.get(type).isValid(token, secret);
			if (!res) {
				this.database.failedMFAAttempt(username);
			} else {
				this.database.clearFailedMFAAttempts(username);
			}
			return res;
		} catch (OperationFailedException e){
			logger.error("Database failed operation", e);
			throw new OperationFailedException(e);
		}
	}

	protected boolean mayNotAuthenticate(long lastAttempt, int numberOfFailedAttempts,
			long timeoutFactor) {
		if (numberOfFailedAttempts == 0) {
			return false;
		}
		return calculateTimeout(lastAttempt,numberOfFailedAttempts,timeoutFactor) > System.currentTimeMillis();
	}

	/**
	 * Calculates the time at which the timeout ends
	 * @param lastAttempt time of last attempt in milliseconds
	 * @param numberOfFailedAttempts number of failed attempts
	 * @param timeoutFactor Timeout factor
	 * @return lastAttempt + timeoutFactor * 2^(numberFailedAttempts-1) > currentTimeMillis
	 */
	public static long calculateTimeout(long lastAttempt, int numberOfFailedAttempts, long timeoutFactor){
		return lastAttempt +
				timeoutFactor * (1L << (numberOfFailedAttempts-1));
	};

	/**
	 * Activates a MFA method by validating a token generated. At the same time disable the NONE type
	 * to ensure that all future authentications require a MFA
	 *
	 * @param username The username
	 * @param token The MFA token needed to verify that it has been setup correctly
	 * @param type The type of MFA
	 * @return True if the MFA got activated (i.e the token was ok), otherwise false.
	 */
	public boolean activateMFA(String username, String token, String type) throws OperationFailedException {
		try {
			if (!this.database.hasUser(username)) {
				logger.info("AuthenticationHandler.activateMFA no such user");
				return false;
			}

			Map<String, MFAInformation> mfaInfo = this.database.getMFAInformation(username);
			if (mfaInfo.containsKey(type)) {
				if (mayNotAuthenticate(database.getLastMFAAttempt(username), database.getNumberOfFailedMFAAttempts(username), mfaAuthenticators.get(type).getTimeoutPeriod())) {
					logger.info("Too many failed MFA attempts");
					return false;
				}
				String secret = mfaInfo.get(type).getSecret();
				if (mfaAuthenticators.get(type).isValid(token, secret)) {
					logger.info("AuthenticationHandler.activateMFA activating " + username);
					this.database.activateMFA(username, type);
					this.database.clearFailedMFAAttempts(username);
					return true;
				}
				logger.info("AuthenticationHandler.activateMFA token is not valid for secret");
			}
			this.database.failedMFAAttempt(username);
			logger.info("AuthenticationHandler.activateMFA returning false (invalid token or no such MFA type)");
			return false;
		} catch (OperationFailedException e){
			logger.error("Database failed operation", e);
			throw new OperationFailedException(e);
		}
	}

	public boolean deleteMFA(String username, String token, String type) throws OperationFailedException {
		try {
			if (conservativeMFAValidation(username, token, type)) {
				this.database.deleteMFA(username, type);
				this.database.clearFailedMFAAttempts(username);
				return true;
			} else {
				logger.info("AuthenticationHandler.deleteMFA could not validate MFA token, returning false");
				return false;
			}
		} catch (OperationFailedException e){
			logger.error("Database failed operation", e);
			throw new OperationFailedException(e);
		}
	}

	public abstract String generateSessionCookie(String username);
}
