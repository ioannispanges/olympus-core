package eu.olympus.client;

import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.DistributedRSAIdP;
import eu.olympus.util.JWTUtil;
import eu.olympus.util.Util;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class DistributedRSAClient implements UserClient {

	private final Map<Integer, DistributedRSAIdP> servers;
	private final BigInteger modulus;
	protected Map<Integer, byte[]> sessionCookies;
	protected Map<Integer, Long> sessionStartedTimes;
	public static final long sessionLength = 6000000;
	protected String savedUsername = null;

	public DistributedRSAClient(List<DistributedRSAIdP> servers) {
		RSAPublicKey pk = (RSAPublicKey)servers.get(0).getCertificate().getPublicKey();
		modulus = pk.getModulus();
		this.sessionCookies = new HashMap<>();
		this.sessionStartedTimes = new HashMap<>();
		int i = 0;
		this.servers = new HashMap<>();
		for(DistributedRSAIdP server : servers){
			this.servers.put(i,server);
			sessionStartedTimes.put(i, 0l);
			i++;
		}
	}

	@Override
	public void createUser(String username, String password) throws UserCreationFailedException {
		try {
			for (DistributedRSAIdP server : servers.values()) {
				server.createUser(new UsernameAndPassword(username, password));
			}
			ensureActiveSession(username, password, null, "NONE");
		} catch (OperationFailedException e){
			throw new UserCreationFailedException("", e);
		}
		savedUsername = username;
	}

	@Override
	public void createUserAndAddAttributes(String username, String password, IdentityProof identityProof) throws UserCreationFailedException {
		try {
			for (DistributedRSAIdP server : servers.values()) {
				server.createUserAndAddAttributes(new UsernameAndPassword(username, password), identityProof);
			}
			ensureActiveSession(username, password, null, "NONE");
		} catch (OperationFailedException e){
			throw new UserCreationFailedException("", e);
		}
		savedUsername = username;
	}

	@Override
	public void addAttributes(IdentityProof identityProof) throws OperationFailedException {
		checkActiveSession();
		performAddAttributes(getSavedUsername(), identityProof);
	}

	@Override
	public void addAttributes(String username, String password,
			IdentityProof identityProof, String token, String type) throws OperationFailedException {
			ensureActiveSession(username, password, token, type);
			performAddAttributes(username,identityProof);
	}
	public void performAddAttributes(String username, IdentityProof identityProof) throws OperationFailedException {
		try{
			for (DistributedRSAIdP server: servers.values()){
				server.addAttributes(username, sessionCookies.get(server.getId()), identityProof);
			}
		} catch(AuthenticationFailedException e) {
			throw new OperationFailedException("Failed to add attribute",e);
		}
	}

	@Override
	public String authenticate(String username, String password, Policy policy, String token, String type) throws AuthenticationFailedException {
		try {
			ensureActiveSession(username, password, token, type);
			List<String> partialTokens = new LinkedList<String>();
			for (DistributedRSAIdP server: servers.values()){
				String partialToken = server.authenticate(username, sessionCookies.get(server.getId()), policy);
				partialTokens.add(partialToken);
			}

			savedUsername = username;
			return JWTUtil.combineTokens(partialTokens, modulus);
		} catch(OperationFailedException e) {
			throw new AuthenticationFailedException("Failed to authenticate",e);
		}
	}

	@Override
	public Map<String, Attribute> getAllAttributes(String username, String password, String token, String type) throws OperationFailedException {
			ensureActiveSession(username, password, token, type);
			return performGetAllAttributes(username);
	}

	@Override
	public Map<String, Attribute> getAllAttributes() throws OperationFailedException {
		checkActiveSession();
		return performGetAllAttributes(getSavedUsername());
	}

	public Map<String, Attribute> performGetAllAttributes(String username) throws OperationFailedException {
		try {
			List<Map<String, Attribute>> maps = new ArrayList<Map<String, Attribute>>(servers.size());
			for (DistributedRSAIdP server: servers.values()){
				maps.add(server.getAllAttributes(username, sessionCookies.get(server.getId())));
			}
			if(Util.verifyIdenticalMaps(maps)) {
				return maps.get(0);
			}
			throw new OperationFailedException("Differing output from vIdP");
		}catch(Exception e) {
			throw new OperationFailedException("Failed to retrieve attributes",e);
		}
	}

	@Override
	public void deleteAttributes(String username, String password, List<String> attributes, String token, String type) throws OperationFailedException {
			ensureActiveSession(username, password, token, type);
			performDeleteAttributes(username,attributes);
	}

	@Override
	public void deleteAttributes(List<String> attributes) throws OperationFailedException {
		checkActiveSession();
		performDeleteAttributes(getSavedUsername(), attributes);
	}

	public void performDeleteAttributes(String username, List<String> attributes) throws OperationFailedException {
		try {
			for (DistributedRSAIdP server : servers.values()) {
				if (!server.deleteAttribute(username, sessionCookies.get(server.getId()), attributes)) {
					throw new OperationFailedException("vIdP failed to delete attributes");
				}
			}
		} catch(OperationFailedException | AuthenticationFailedException e) {
			throw new OperationFailedException("Failed to delete attributes",e);
		}
	}

	@Override
	public void deleteAccount(String username, String password, String token, String type) throws OperationFailedException {
		try{
			getFreshSession(username, password, token, type);
			for (DistributedRSAIdP server: servers.values()){
				if(!server.deleteAccount(new UsernameAndPassword(username, password), sessionCookies.get(server.getId())) ) {
					throw new OperationFailedException("vIdP failed to delete account");
				}
			}
		}catch(OperationFailedException | AuthenticationFailedException e ) {
			throw new OperationFailedException("Failed to delete account",e);
		}
	}

	@Override
	public void changePassword(String username, String oldPassword, String newPassword, String token, String type)
		throws OperationFailedException {
		try {
			getFreshSession(username, oldPassword, token, type);
			for (DistributedRSAIdP server : servers.values()) {
				server.changePassword(new UsernameAndPassword(savedUsername, oldPassword), newPassword,
						sessionCookies.get(server.getId()));
			}
		}catch(OperationFailedException | UserCreationFailedException | AuthenticationFailedException e) {
			throw new OperationFailedException("Failed to change password",e);
		}
	}

	@Override
	public String requestMFAChallenge(String username, String password, String type) throws OperationFailedException {
		try{
        ensureActiveSession(username, password, null, "NO_MFA");
        List<String> partialChallenges = new LinkedList<String>();
        for (DistributedRSAIdP server : servers.values()) {
            String currentChallenge = server.requestMFA(new UsernameAndPassword(username, password),
                sessionCookies.get(server.getId()), type);
            partialChallenges.add(currentChallenge);
        }
        // Check that all challenges are equal
        if (!partialChallenges.stream().allMatch(c -> c.equals(partialChallenges.get(0)))) {
            throw new OperationFailedException(
                "The authenticators of all the servers are not supplying the same secret");
        }
        return partialChallenges.get(0);
		} catch (OperationFailedException | AuthenticationFailedException e){
			throw new OperationFailedException("Failed to confirm MFA",e);
		}
	}

	@Override
	public void confirmMFA(String username, String password, String token, String type)
			throws OperationFailedException {
		try{
		getFreshSession(username, password, null, "NO_MFA");
		for (DistributedRSAIdP server : servers.values()) {
			if (!server.confirmMFA(new UsernameAndPassword(username, password),
					sessionCookies.get(server.getId()), token, type)) {
					throw new OperationFailedException("vIdP failed to confirm MFA");
				}
			}
		} catch (OperationFailedException e){
			throw new OperationFailedException("Failed to confirm MFA",e);
		}
	}

	@Override
	public void removeMFA(String username, String password, String token, String type) throws OperationFailedException {
		try {
			getFreshSession(username, password, token, type);
			for (DistributedRSAIdP server : servers.values()) {
				if (!server.removeMFA(new UsernameAndPassword(username, password), sessionCookies.get(server.getId()), token, type)) {
					throw new OperationFailedException("vIdP failed to remove MFA");
				}
			}
		} catch (OperationFailedException e){
			throw new OperationFailedException("Failed to remove MFA",e);
		}
	}

	@Override
	public void clearSession() {
		this.sessionCookies.clear();
		this.sessionStartedTimes.clear();
		for(int i=0; i< servers.size(); i++){
			sessionStartedTimes.put(i, 0l);
		}
		savedUsername = null;
	}

	public String getSavedUsername() throws OperationFailedException {
		if(savedUsername != null){
			return savedUsername;
		}
		throw new OperationFailedException("No user is logged in");
	}


	private void ensureActiveSession(String username, String password, String token, String type) throws OperationFailedException {
		long largestSessionTime = sessionStartedTimes.values().stream().mapToLong(v->v).max().getAsLong();
		if (System.currentTimeMillis() >= (largestSessionTime + sessionLength)) {
			getFreshSession(username, password, token, type);
		}
	}

	protected void checkActiveSession() throws OperationFailedException {
		long largestSessionTime = sessionStartedTimes.values().stream().mapToLong(v -> v).max().getAsLong();
		if (System.currentTimeMillis() >= (largestSessionTime + sessionLength)) {
			throw new OperationFailedException("User has no active session");
		}
	}

	private void getFreshSession(String username, String password, String token, String type) throws OperationFailedException {
		try {
			for (DistributedRSAIdP server : servers.values()) {
				String sessionCookie = servers.get(server.getId()).startSession(new UsernameAndPassword(username, password), token, type);
				sessionCookies.put(server.getId(), Base64.decodeBase64(sessionCookie));
				sessionStartedTimes.put(server.getId(), System.currentTimeMillis());
			}
		}catch (AuthenticationFailedException e){
			throw new OperationFailedException("Failed to start session", e);
		}
	}
}
