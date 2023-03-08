package eu.olympus.server;

import eu.olympus.model.Authorization;
import eu.olympus.model.KeyShares;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.ExistingUserException;
import eu.olympus.model.exceptions.KeyGenerationFailedException;
import eu.olympus.model.exceptions.MaliciousException;
import eu.olympus.model.exceptions.NonExistingUserException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.interfaces.IdPRESTWrapper;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.UserAuthorizationDatabase;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryKeyDB;
import eu.olympus.util.KeySerializer;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PestoAuthenticationHandler extends AuthenticationHandler{

	private static Logger logger = LoggerFactory.getLogger(PestoAuthenticationHandler.class);

	private PestoDatabase database;
	private PestoRefresher refresher;
	private List<? extends IdPRESTWrapper> servers = new ArrayList<>();
	private InMemoryKeyDB refreshDB;
	private int id;
	/** The amount of time, in miliseconds, we allow the user's salt to be off by compared to the
	 *	current time. This is required to avoid someone doing a denial of service attack of a user by
	 *	hammering the DB with time stamps far in the future.
	 */
	private long allowedTimeDiff;
	// The maximal amount of time a server waits for a response from another server
	private long maxWaitTime;
	private long sessionLength;
	private long timeoutFactor;

	public PestoAuthenticationHandler(PestoDatabase database, ServerCryptoModule crypto,
			UserAuthorizationDatabase sessionDB,
			Map<String, MFAAuthenticator> mfaAuthenticators) throws IllegalArgumentException {
		super(database, sessionDB, mfaAuthenticators, crypto);
		this.database = database;
		this.refreshDB = (InMemoryKeyDB)sessionDB;
	}

	public boolean setup(String ssid, KeyShares master, byte[] localKeyShare, Map<Integer, byte[]> remoteShares,
		int id, long allowedTimeDifference, long waitTime, long sessionLength, List<? extends IdPRESTWrapper> serverSetup) throws OperationFailedException {
		return setup(ssid,master,localKeyShare,remoteShares,id,allowedTimeDifference,waitTime,sessionLength,serverSetup,1000L);
	}
	
	public boolean setup(String ssid, KeyShares master, byte[] localKeyShare, Map<Integer, byte[]> remoteShares,
			int id, long allowedTimeDifference, long waitTime, long sessionLength, List<? extends IdPRESTWrapper> serverSetup, long timeoutFactor) throws OperationFailedException {
		this.id = id;
		this.timeoutFactor = timeoutFactor;
		this.allowedTimeDiff = allowedTimeDifference;
		this.maxWaitTime = waitTime;
		this.sessionLength = sessionLength;
		this.servers = serverSetup;
		this.refresher = new PestoRefresher(id, crypto);
		byte[] digest = crypto.hashList(Arrays.asList(master.toBytes()));

		// Handle master key shares from configuration
		this.database.setKeyDigest(digest);
		this.database.setKeyShare(id, localKeyShare);
		for(int i : remoteShares.keySet()) {
			this.database.setKeyShare(i, remoteShares.get(i));
		}
	
		// Compute first epoch keys
		KeyShares epochKeys =  this.refresher.updateSharesFromMaster(ssid.getBytes(Charsets.UTF_8), master);
		return this.crypto.setupServer(epochKeys);
	}

	public OPRFResponse performOPRF(String salt, String username, ECP x, String mfaToken, String mfaType) throws AuthenticationFailedException, OperationFailedException {
		// We set valid to true by default since the user might not exist at this point, in which case any MFA token should be valid
		boolean valid = true;
		if(mayNotAuthenticate(database.getLastAuthAttempt(username), database.getNumberOfFailedAuthAttempts(username), timeoutFactor)){
			throw new AuthenticationFailedException("User is timed out");
		}
		if (database.hasUser(username)) {
			if(!checkSalt(username,new Long(salt))){
				throw new AuthenticationFailedException("Failed to validate salt.");
			}
			valid = validateMFAToken(username, mfaToken, mfaType);
		}
		if(!valid) {
			throw new AuthenticationFailedException("Failed to validate MFA token.");
		}
		String sessionCookie = generateSessionCookie(username);
		FP12 y = crypto.hashAndPair(username.getBytes(Charsets.UTF_8), x);
		byte[] nonce = crypto.constructNonce(username,new Long(salt));
		FP12 product = crypto.generateBlinding(Base64.encodeBase64String(nonce), id);
		y.mul(product);
		return new OPRFResponse(y, salt, sessionCookie);
	}
	
	public synchronized boolean startRefresh() {
		try {
			String mySsid = Base64.encodeBase64String(crypto.getBytes(crypto.COMPUTATION_SEC_BYTES));
			byte[] myShare = database.getKeyShare(id);
			addMasterShare(mySsid, myShare);
			// Send the other parties' shares
			for (IdPRESTWrapper idp : servers) {
				idp.addMasterShare(mySsid, database.getKeyShare(idp.getId()));
			}
			long startTime = System.currentTimeMillis();
			// Stop in case a server is dead
			while (refreshDB.getMasterShares().size() < servers.size() + 1 &&
					System.currentTimeMillis() < startTime + maxWaitTime) {
				// Keep querying the database to check when all partial signatures are in
				Thread.sleep(2);
			}
			List<byte[]> shares = refreshDB.getMasterShares();
			List<String> ssids = refreshDB.getSsids();
			if (shares.size() < servers.size() + 1 || ssids.size() < servers.size() + 1) {
				logger.info("Did not get enough shares back");
				return false;
			}
			KeyShares combined = refresher.combineMasterShares(shares);

			// Verify against digest
			byte[] combinedDigest = crypto.hashList(Arrays.asList(combined.toBytes()));
			if (!Arrays.equals(combinedDigest, database.getKeyDigest())) {
				logger.error("Digest comparison failed");
				throw new MaliciousException("Database has been compromised or a server has sent incorrect values");
			}
			// Update shares in Crypto
			byte[] combinedSsids = refresher.combineSsids(ssids);
			refresher.updateSharesFromMaster(combinedSsids, combined);

			// Reshare the masterkey
			List<byte[]> updatedShares = refresher.reshareMasterKeys(combined, servers.size()+1);
			database.setKeyShare(id, updatedShares.get(id));
			// Send the shares of my master key to the other servers
			for (IdPRESTWrapper idp : servers) {
				idp.setKeyShare(id, updatedShares.get(idp.getId()));
			}

			return true;
		} catch (Exception e) {
			logger.info("startRefresh failing: ", e);
			return false;
		} finally {
			refreshDB.deleteMasterShares();
		}
	}

	public void addPartialServerSignature(String ssid, byte[] signature) {
		logger.info("PestoAuthenticationHandler "+id+" adding a signature to storage "+this.refreshDB);
		if (this.refreshDB.getPartialSignatures(ssid).size() >= servers.size() + 1) {
			// We have already received the amount of partial signatures needed so at least one must be
			// malicious, but we don't know which so we bail. This also prevents a storage DoS attack of
			// basically filling the db with incorrect partial signatures.
			logger.warn("PestoAuthHandler "+id+" received too many signatures for ssid: "+ssid);
			this.refreshDB.deletePartialSignatures(ssid);
		}
		this.refreshDB.addPartialSignature(ssid, signature);
	}

	public void addPartialMFASecret(String ssid, String secret, String type) {
		logger.info("PestoAuthenicationHandler "+id+" adding a MFASecret to storage "+this.refreshDB);
		if (this.refreshDB.getPartialMFASecrets(hashValues(ssid, type)).size() >= servers.size() + 1) {
			// We have already received the amount of partial secrets needed so at least one must be
			// malicious, but we don't know which so we bail. This also prevents a storage DoS attack of
			// basically filling the db with incorrect partial secrets.
			logger.warn("PestoAuthHandler "+id+" received too many MFASecrets for ssid: "+ssid+", type: "+type);
			this.refreshDB.deletePartialMFASecrets(hashValues(ssid, type));
		}
		this.refreshDB.addPartialMFASecret(hashValues(ssid, type), secret);
	}
	
	/**
	 * Method to be called during refresh by each other IdP to return their shares of this IdP's master key
	 * and their contribution to the SSID they wish to use during refresh.
	 */
	public void addMasterShare(String newSsid, byte[] shares) {
		if (this.refreshDB.getMasterShares().size() >= servers.size() + 1) {
			// We have already received the amount of partial signatures needed so at least one must be
			// bad
			logger.warn("PestoAuthHandler "+id+" received too many mastershares for ssid: "+newSsid);
			this.refreshDB.deleteMasterShares();
		}
		this.refreshDB.addMasterShare(newSsid, shares);
	}

	/**
	 * Interface to allow storage of other IdP's sharings of their master keys
	 */
	public void setKeyShare(int id, byte[] newShares) throws OperationFailedException {
		this.database.setKeyShare(id, newShares);
	}
	
	public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) throws UserCreationFailedException, OperationFailedException {
		//todo validate cookie
		if(this.database.hasUser(username)) {
			throw new ExistingUserException();
		}
		try {
			if(!checkSaltRange(salt)){
				throw new AuthenticationFailedException("Failed to validate salt.");
			}
			byte[] nonce = crypto.constructNonce(username, salt);
			List<byte[]> list = new ArrayList<byte[]>();
			list.add(nonce);
			list.add(username.getBytes(Charsets.UTF_8));
			if (idProof == null) {
				idProof = "";
			}
			list.add((CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES+idProof).getBytes(Charsets.UTF_8));
			list.add(cookie);
			if (!crypto.verifySignature(publicKey, list, signature)) {
				throw new UserCreationFailedException("Invalid signature");
			}
			
			byte[] serverSignature = crypto.sign(publicKey, nonce, id);
			addPartialServerSignature(username, serverSignature);
			for (IdPRESTWrapper idp : servers) {
				idp.addPartialServerSignature(username, serverSignature);
			}

			long startTime = System.currentTimeMillis();
			// Stop in case a server is dead
			while (this.refreshDB.getPartialSignatures(username).size() < servers.size() + 1
					&& System.currentTimeMillis() < startTime + maxWaitTime) {
				// Keep querying the database to check when all partial signatures are in
				Thread.sleep(2);
			}
			
			if (refreshDB.getPartialSignatures(username).size() < servers.size() + 1) {
				logger.warn("PestoAuthenticationHandler "+id+" did not receive enough partial signatures: "+refreshDB.getPartialSignatures(username).size()+" expected "+(servers.size()+1));
				throw new UserCreationFailedException("Did not hear back from all the servers");
			}
			//	Verify combined signature
			byte[] combinedSignature = crypto
					.combineSignatures(this.refreshDB.getPartialSignatures(username));
			byte[] input = KeySerializer.serialize(publicKey).getBytes();
			boolean valid = crypto.verifySignature(crypto.getStandardRSAkey(), input, combinedSignature);
			if (!valid) {
				logger.warn("PestoAuthenticationHandler "+id+": invalid server signatures on received public key from user");
				throw new UserCreationFailedException(
						"Invalid server signature on received public key from user " + username);
			}
			this.database.addUser(username, publicKey, salt);

			if (!"".equals(idProof)) {
				addAttributes(username, idProof);
			}
			return combinedSignature;
		} catch (SignatureException | KeyGenerationFailedException | OperationFailedException | InterruptedException | AuthenticationFailedException e) {
			throw new UserCreationFailedException("Failed to finish registration", e);
		} finally {
			this.refreshDB.deletePartialSignatures(username);
		}
	}

	/**
	 * 
	 * @param username
	 * @param salt
	 * @param signature
	 * @param operation
	 * @return
	 */
	public boolean validateUsernameAndSignature(String username, byte[] sessionData, long salt, byte[] signature, String operation) throws OperationFailedException {
		if (mayNotAuthenticate(database.getLastAuthAttempt(username), database.getNumberOfFailedAuthAttempts(username), timeoutFactor)) {
			logger.info("Too many failed passwords attempts");
			return false;
		}
		PublicKey userKey = this.database.getUserKey(username);
		if (userKey == null) {
			logger.warn("PestoAuthenticationHandler.validateUsernameAndSignature no userkey, returning false");
			return false;
		}
		if (!checkSalt(username,salt)) {
			logger.warn("PestoAuthenticationHandler.validateUsernameAndSignature bad salt, returning false");
			return false;
		}
		byte[] nonce = crypto.constructNonce(username, salt);
		List<byte[]> list = new ArrayList<>(4);
		list.add(nonce != null ? nonce : new byte[0]);
		list.add(username.getBytes(Charsets.UTF_8));
		list.add(operation.getBytes(Charsets.UTF_8));
		list.add(sessionData != null ? sessionData : new byte[0]);
		boolean valid = crypto.verifySignature(userKey, list, signature);
		database.setSalt(username, salt);
		if(!valid){
			this.database.failedAuthAttempt(username);
		} else {
			this.database.clearFailedAuthAttempts(username);
		}
		return valid;
	}

	/**
	 * @param username
	 * @return
	 * @throws OperationFailedException
	 */
	public String requestMFASecret(String username, String type) throws OperationFailedException {
		try {
			if (!this.database.hasUser(username)) {
				throw new NonExistingUserException();
			}
			String secret = mfaAuthenticators.get(type).generateSecret();
			addPartialMFASecret(username, secret, type);
			for (IdPRESTWrapper idp : servers) {
				idp.addPartialMFASecret(username, secret, type);
			}

			long startTime = System.currentTimeMillis();
			// Stop in case a server is dead
			while (this.refreshDB.getPartialMFASecrets(hashValues(username, type)).size() < servers.size() + 1 && System.currentTimeMillis() < startTime + maxWaitTime) {
				// Keep querying the database to check when all partial secrets are in
				Thread.sleep(2);
			}
			List<String> input = this.refreshDB.getPartialMFASecrets(hashValues(username, type));
			if (input.size() < servers.size() + 1) {
				logger.warn("PestoAuthentication Handler "+id+" did not receive enough partial MFA secrets: "+this.refreshDB.getPartialMFASecrets(hashValues(username, type)).size()+" expected "+(servers.size()+1));
				throw new UserCreationFailedException("Did not hear back from all the servers");
			}
			String combinedSecret = mfaAuthenticators.get(type).combineSecrets(input);
			this.database.assignMFASecret(username, type, combinedSecret);
			return combinedSecret;
		} catch (NonExistingUserException | UserCreationFailedException | InterruptedException e){
				throw new OperationFailedException("Failed to request MFA secret", e);
		}
	}
	
	/**
	 * Verify that the salt is valid.
	 * @param username
	 * @param salt
	 * @return true if the request is valid. False otherwise.
	 */
	private boolean checkSalt(String username, long salt) throws OperationFailedException {
			long oldSalt = this.database.getLastSalt(username);
			if (salt <= oldSalt) {
				// Someone is reusing salt
				return false;
			}
		return checkSaltRange(salt);
	}

	private boolean checkSaltRange(long salt){
		long currentTime = System.currentTimeMillis();
		// The salt is too far from the current time
		return salt <= currentTime + allowedTimeDiff && salt >= currentTime - allowedTimeDiff;
	}

	public byte[] changePassword(String username, byte[] cookie, PublicKey publicKey, byte[] oldSignature, byte[] newSignature, long salt) throws OperationFailedException, AuthenticationFailedException {
		try{
			if(!this.database.hasUser(username)) {
				throw new NonExistingUserException();
			}
			if(!checkSalt(username,new Long(salt))){
				throw new AuthenticationFailedException("Failed to validate salt.");
			}

			byte[] nonce = crypto.constructNonce(username, salt);
			List<byte[]> list = new ArrayList<byte[]>();
			list.add(username.getBytes(Charsets.UTF_8));
			list.add(nonce);
			list.add(publicKey.getEncoded());
			list.add(CommonRESTEndpoints.CHANGE_PASSWORD.getBytes(Charsets.UTF_8));
			list.add(cookie);
			if (!crypto.verifySignature(publicKey, list, newSignature)) {
				throw new AuthenticationFailedException("Failed : Invalid signature");
			}
			if (!crypto.verifySignature(this.database.getUserKey(username), newSignature,
				oldSignature)) {
				throw new AuthenticationFailedException("Failed : Invalid signature");
			}

			byte[] serverSignature = crypto.sign(publicKey, nonce, id);
			addPartialServerSignature(username, serverSignature);
			for (IdPRESTWrapper idp : servers) {
				idp.addPartialServerSignature(username, serverSignature);
			}

			long startTime = System.currentTimeMillis();
			// Stop in case a server is dead
			while (this.refreshDB.getPartialSignatures(username).size() < servers.size() + 1
				&& System.currentTimeMillis() < startTime + maxWaitTime) {
				// Keep querying the database to check when all partial signatures are in
				Thread.sleep(2);
			}
			if (refreshDB.getPartialSignatures(username).size() < servers.size() + 1) {
				throw new OperationFailedException("Did not hear back from all the servers");
			}

			//	Verify combined signature
			byte[] combinedSignature = crypto
				.combineSignatures(this.refreshDB.getPartialSignatures(username));
			byte[] input = KeySerializer.serialize(publicKey).getBytes();
			boolean valid = crypto.verifySignature(crypto.getStandardRSAkey(), input, combinedSignature);

			if (!valid) {
				throw new OperationFailedException(
					"Invalid server signature on received public key from user " + username);
			}
			this.database.replaceUserKey(username, publicKey, salt);
			return combinedSignature;
		} catch (Exception e) {
				throw new OperationFailedException("Failed to change password",e);
		} finally {
			this.refreshDB.deletePartialSignatures(username);
		}
	}


	@Override
	public String generateSessionCookie(String username) {
		String cookie = Base64.encodeBase64String(crypto.getBytes(64));
		storeAuthorization(cookie, new Authorization(username, Arrays.asList(Role.USER), System.currentTimeMillis()+this.sessionLength));
		return cookie;
	}
	
	private String hashValues(String name, String tp) {
		return Base64.encodeBase64String(crypto.hashList(Arrays.asList(name.getBytes(Charsets.UTF_8), tp.getBytes(Charsets.UTF_8))));
	}

}
