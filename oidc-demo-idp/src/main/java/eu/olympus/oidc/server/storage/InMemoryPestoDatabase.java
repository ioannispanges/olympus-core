package eu.olympus.oidc.server.storage;

import java.security.PublicKey;
import java.util.Map;

import eu.olympus.model.Attribute;
import eu.olympus.model.MFAInformation;
import eu.olympus.model.UserData;
import eu.olympus.server.interfaces.PestoDatabase;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In memory implementation of the PestoDatabase.
 * The implementation contains two hashmaps:
 * -A map of User and their UserData
 * -A map of the partial server signatures on user public keys (used for registration)
 *
 */
public class InMemoryPestoDatabase implements PestoDatabase{

	private final Map<String, UserData> users;
	private final Map<String, Long> lastAuthAttempt;
	private final Map<String, Long> lastMFAAttempt;
	private final Map<String, Integer> numberOfAuthAttempts;
	private final Map<String, Integer> numberOfMFAAttempts;

	private final Map<Integer, byte[]> otherIdPKeyShares;
	private byte[] digest;


	public InMemoryPestoDatabase(){
		this.users = new ConcurrentHashMap<>();
		this.numberOfAuthAttempts = new ConcurrentHashMap<>();
		this.numberOfMFAAttempts = new ConcurrentHashMap<>();
		this.lastAuthAttempt = new ConcurrentHashMap<>();
		this.lastMFAAttempt = new ConcurrentHashMap<>();
		this.otherIdPKeyShares = new ConcurrentHashMap<>();
	}

	@Override
	public synchronized void addUser(String username, PublicKey key, long salt) {
		UserData user = new UserData(key, salt);
		this.users.put(username, user);
	}


	@Override
	public Map<String, Attribute> getAttributes(String username) {
		return this.users.get(username).getAttributes();
	}

	@Override
	public synchronized void addAttributes(String username, Map<String, Attribute> attributes) {
		this.users.get(username).getAttributes().putAll(attributes);
	}

	@Override
	public synchronized void addAttribute(String username, String key, Attribute value) {
		this.users.get(username).getAttributes().put(key, value);
	}

	@Override
	public boolean hasUser(String username) {
		return this.users.containsKey(username);
	}

	@Override
	public PublicKey getUserKey(String username) {
		try {
			return this.users.get(username).getPublicKey();
		} catch (Exception e) {
			return null;
		}
	}

	@Override
	public long getLastSalt(String username) {
		return this.users.get(username).getSalt();
	}

	@Override
	public synchronized void setSalt(String username, long salt) {
		this.users.get(username).setSalt(salt);
	}

	@Override
	public synchronized boolean deleteAttribute(String username, String attributeName) {
		try {
			Attribute removed = this.users.get(username).getAttributes().remove(attributeName);
			return removed != null;
		} catch(Exception e) {
		}
		return false;
	}

	@Override
	public synchronized boolean deleteUser(String username) {
		UserData data = this.users.remove(username);
		return data !=null;
	}

	@Override
	public synchronized void replaceUserKey(String username, PublicKey publicKey, long salt) {
		UserData oldData = this.users.get(username);
		UserData user = new UserData(publicKey, salt);
		user.getAttributes().putAll(oldData.getAttributes());
		user.getSecondFactors().putAll(oldData.getSecondFactors());
		this.users.replace(username, user);
	}

	@Override
	public byte[] getKeyDigest() {
		return digest;
	}

	@Override
	public synchronized void setKeyDigest(byte[] digest) {
		this.digest = digest;
	}

	@Override
	public synchronized void setKeyShare(int id, byte[] shares) {
		otherIdPKeyShares.put(id, shares);
	}

	@Override
	public byte[] getKeyShare(int id) {
		return otherIdPKeyShares.get(id);
	}


	@Override
	public long getLastAuthAttempt(String username) {
		if (lastAuthAttempt.containsKey(username)) {
			return lastAuthAttempt.get(username);
		}
		return 0;
	}

	@Override
	public int getNumberOfFailedAuthAttempts(String username){
		if (numberOfAuthAttempts.containsKey(username)) {
			return numberOfAuthAttempts.get(username);
		}
		return 0;
	}

	@Override
	public void failedAuthAttempt(String username){
		int attempts = 1;
		if (numberOfAuthAttempts.containsKey(username)) {
			attempts = numberOfAuthAttempts.get(username);
		}
		numberOfAuthAttempts.put(username,attempts);
		lastAuthAttempt.put(username,System.currentTimeMillis());
	}

	@Override
	public void clearFailedAuthAttempts(String username) {
		numberOfAuthAttempts.put(username,0);
	}

	@Override
	public int getNumberOfFailedMFAAttempts(String username) {
		if(numberOfMFAAttempts.containsKey(username))	return numberOfMFAAttempts.get(username);
		return 0;
	}

	@Override
	public void failedMFAAttempt(String username) {
		int attempts = 1;
		if (numberOfMFAAttempts.containsKey(username)) {
			attempts = numberOfMFAAttempts.get(username);
		}
		numberOfMFAAttempts.put(username,attempts);
		lastMFAAttempt.put(username,System.currentTimeMillis());
	}

	@Override
	public void clearFailedMFAAttempts(String username) {
		numberOfMFAAttempts.put(username,0);
	}

	@Override
	public long getLastMFAAttempt(String username) {
		if (lastMFAAttempt.containsKey(username)) {
			return lastMFAAttempt.get(username);
		}
		return 0;
	}

	@Override
	public synchronized void assignMFASecret(String username, String type, String secret) {
		UserData data = this.users.get(username);

		MFAInformation secondFactorInfo = new MFAInformation(type, secret, System.currentTimeMillis(), false);
		data.putSecondFactor(type, secondFactorInfo);
		this.users.replace(username, data);
	}

	@Override
	public synchronized void activateMFA(String username, String type) {
		UserData data = this.users.get(username);
		MFAInformation information = data.getSecondFactors().get(type);
		information.setActivated(true);
		data.getSecondFactors().replace(type, information);
		this.users.replace(username, data);
	}

	@Override
	public synchronized void deleteMFA(String username, String type) {
		UserData data = this.users.get(username);
		MFAInformation information = data.getSecondFactors().get(type);
		if (information != null) {
			information.setActivated(false);
		}
		data.getSecondFactors().replace(type, information);
		this.users.replace(username, data);
	}

	@Override
	public synchronized Map<String, MFAInformation> getMFAInformation(String username) {
		UserData data = this.users.get(username);
		return data.getSecondFactors();
	}
}
