package eu.olympus.server.storage;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import eu.olympus.model.Authorization;
import eu.olympus.server.interfaces.UserAuthorizationDatabase;

/**
 * Contains various runtime key material.
 * WARNING: This should NOT EVER be implemented as a persistent database as it only contains values
 * that should be temporary. Furthermore the values will be the IdP's master shares are thus are
 * highly security critical and should not be stored on an insecure disc.
 */
public class InMemoryKeyDB implements UserAuthorizationDatabase {

  private List<byte[]> masterShares;
  private List<String> ssids;
  private Map<String, List<byte[]>> partialServerSignatures;
  private Map<String, List<String>> partialMFASecrets;
  private final Map<String, Authorization> cookieMap;

  public InMemoryKeyDB() {
    this.masterShares = Collections.synchronizedList(new ArrayList<>());
	this.partialServerSignatures = Collections.synchronizedMap(new ConcurrentHashMap<>());
	this.partialMFASecrets = Collections.synchronizedMap(new ConcurrentHashMap<>());
    this.ssids = Collections.synchronizedList(new ArrayList<>());
	this.cookieMap = new ConcurrentHashMap<>();
  }

  /**
   * Add partial master key share retrieved from one server
   * @oaram ssid An ssid that should be used in deriving the new master keys
   * @param share The actual masterkey-shares
   */
  public synchronized void addMasterShare(String ssid, byte[] share) {
    masterShares.add(share);
    ssids.add(ssid);
  }

  /**
   * Return the list of current master shares
   * @return Returns the list of currently stored master shares
   */
  public synchronized List<byte[]> getMasterShares(){
    return masterShares;
  }

  /**
   * Return the ssids given with the master shares that must be used in constructing
   * new master keys.
   * @return
   */
  public synchronized List<String> getSsids() {
    return ssids;
  }

  /**
   * Delete the currently stored shares of the restored master key
   */
  public synchronized void deleteMasterShares() {
    masterShares = Collections.synchronizedList(new ArrayList<>());
    ssids = Collections.synchronizedList(new ArrayList<>());
  }
  
	/**
	 * Store a partial signature.
	 * The partial signature is only used during the registration.
	 * @param username The username of the user owning the signature
	 * @param signature The signature to store
	 */
	public synchronized void addPartialSignature(String username, byte[] signature) {
		if(!this.partialServerSignatures.containsKey(username)) {
			this.partialServerSignatures.put(username, new ArrayList<byte[]>());
		}
		this.partialServerSignatures.get(username).add(signature);
	}
	
	/**
	 * Get all partial signatures belonging to a user.
	 * @param username The username to lookup
	 * @return A List of partial signatures
	 */
	public synchronized List<byte[]> getPartialSignatures(String username) {
		return this.partialServerSignatures.get(username) != null ? this.partialServerSignatures.get(username) : new ArrayList<>();	
	}
	
	/**
	 * Remove all partial signatures belonging to a user.
	 * @param username The username of the owner of the signatures to delete
	 */
	public synchronized void deletePartialSignatures(String username) {
		this.partialServerSignatures.remove(username);
	}

	/**
	 * Store a partial secret.
	 * The partial secret is only used during the registration of a MFA mechanism.
	 * @param username The username of the user owning the secret
	 * @param secret The secret to store
	 */
	public synchronized void addPartialMFASecret(String username, String secret) {
		if(!this.partialMFASecrets.containsKey(username)) {
			this.partialMFASecrets.put(username, new ArrayList<String>());
		}
		this.partialMFASecrets.get(username).add(secret);
	}
	
	/**
	 * Get all partial secrets belonging to a user.
	 * @param username The username to lookup
	 * @return A List of partial signatures
	 */
	public synchronized List<String> getPartialMFASecrets(String username) {
		return this.partialMFASecrets.get(username) != null ? this.partialMFASecrets.get(username) : new ArrayList<>();	
	}
	
	/**
	 * Remove all partial secrets belonging to a user.
	 * @param username The username of the owner of the secrets to delete
	 */
	public synchronized void deletePartialMFASecrets(String username) {
		this.partialMFASecrets.remove(username);
	}
	
	@Override
	public synchronized void storeCookie(String cookie, Authorization user) {
		this.cookieMap.put(cookie, user);
	}

	@Override
	public synchronized Authorization lookupCookie(String cookie) {
		return this.cookieMap.get(cookie);
	}
	
	@Override
	public synchronized void deleteCookie(String cookie) {
		this.cookieMap.remove(cookie);
	}
}
