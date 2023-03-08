package eu.olympus.server.storage;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import eu.olympus.model.Attribute;
import eu.olympus.model.MFAInformation;
import eu.olympus.server.interfaces.UserPasswordDatabase;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In memory implementation of the UserPasswordDatabase.
 * The implementation contains 3 hashmaps:
 * -A map of users and their attributes
 * -A map of users and their hashed passwords 
 * -A map of users and their salts
 */
public class InMemoryUserPasswordDatabase implements UserPasswordDatabase {

	private Map<String, String> pwdb;
	private Map<String, String> saltdb;
	private Map<String, Map<String, Attribute>> attributeMap;
	private Map<String, List<MFAInformation>> mfaInfo;
	private final Map<String, Long> lastAuthAttempt;
	private final Map<String, Long> lastMFAAttempt;
	private final Map<String, Integer> numberOfAuthAttempts;
	private final Map<String, Integer> numberOfMFAAttempts;
	
	public InMemoryUserPasswordDatabase(){
		this.numberOfAuthAttempts = new ConcurrentHashMap<>();
		this.numberOfMFAAttempts = new ConcurrentHashMap<>();
		this.lastAuthAttempt = new ConcurrentHashMap<>();
		this.lastMFAAttempt = new ConcurrentHashMap<>();
		this.pwdb = new HashMap<String, String>();
		this.saltdb = new HashMap<String, String>();
		this.attributeMap = new HashMap<String, Map<String, Attribute>>();
		this.mfaInfo = new HashMap<>();
	}

	@Override
	public synchronized void addUser(String username, String salt, String password) {
		this.pwdb.put(username, password);
		this.saltdb.put(username, salt);
		this.attributeMap.put(username, new HashMap<String, Attribute>());
	}

	@Override
	public String getPassword(String username) {
		return this.pwdb.get(username);
	}
	
	@Override
	public String getSalt(String username) {
		return this.saltdb.get(username);
	}

	@Override
	public synchronized void setPassword(String username, String password) {
		this.pwdb.put(username, password);
	}
	
	@Override
	public synchronized void setSalt(String username, String salt) {
		this.saltdb.put(username, salt);
	}
	
	@Override
	public Map<String, Attribute> getAttributes(String username) {
		return this.attributeMap.get(username);
	}

	@Override
	public synchronized void addAttributes(String username, Map<String, Attribute> attributes) {
		for(String key: attributes.keySet()) {
			addAttribute(username, key, attributes.get(key));
		}
	}
	@Override
	public synchronized void addAttribute(String username, String key, Attribute value) {
		this.attributeMap.get(username).put(key.toLowerCase(), value);
	}
	
	@Override
	public boolean hasUser(String username) {
		return this.pwdb.containsKey(username);
	}

	@Override
	public synchronized boolean deleteAttribute(String username, String attributeName) {
		try {
			Attribute removed = this.attributeMap.get(username).remove(attributeName);
			return removed != null;
		} catch(NullPointerException e) {
			return false;
		}
	}

	@Override
	public boolean deleteUser(String username) {
		this.pwdb.remove(username);
		this.saltdb.remove(username);
		Map<String, Attribute> data = this.attributeMap.remove(username);
		return data !=null;
	}

	@Override
	public synchronized void assignMFASecret(String username, String type, String secret) {
		if(!mfaInfo.containsKey(username)) {
			mfaInfo.put(username, new ArrayList<>());
		}
		MFAInformation secondFactorInfo = new MFAInformation(type, secret, System.currentTimeMillis(), false);
		mfaInfo.get(username).add(secondFactorInfo);
	}

	@Override
	public synchronized void activateMFA(String username, String type) {
		for(MFAInformation info: mfaInfo.get(username)) {
			if(info.getType().equals(type)) {
				info.setActivated(true);
				break;
			}
		}
	}

	@Override
	public void deleteMFA(String username, String type) {
		for(MFAInformation info: mfaInfo.get(username)) {
			if(info.getType().equals(type)) {
				info.setActivated(false);
				break;
			}
		}
	}

	@Override
	public Map<String, MFAInformation> getMFAInformation(String username) {
		Map<String, MFAInformation> information = new HashMap<>();
		if (mfaInfo.get(username) != null) {
			for (MFAInformation info : mfaInfo.get(username)) {
				information.put(info.getType(), info);
			}
		}
		return information;
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

}
