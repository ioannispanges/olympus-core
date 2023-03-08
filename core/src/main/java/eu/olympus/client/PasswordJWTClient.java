package eu.olympus.client;

import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.PasswordJWTIdP;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class PasswordJWTClient implements UserClient {

	private final Map<Integer, PasswordJWTIdP> servers;
	protected Map<Integer, byte[]> sessionCookies;
	protected Map<Integer, Long> sessionStartedTimes;
	public static final long sessionLength = 6000000;
	public String password = null;
	private String savedUsername;

	public PasswordJWTClient(List<PasswordJWTIdP> servers) {
		this.servers = new HashMap<>();
		this.sessionCookies = new HashMap<>();
		this.sessionStartedTimes = new HashMap<>();
		int i = 0;
		for(PasswordJWTIdP server:servers){
			this.servers.put(i,server);
			sessionStartedTimes.put(i, 0l);
			i++;
		}
	}

	@Override
	public void createUser(String username, String password) throws UserCreationFailedException {
		try{
			servers.get(0).createUser(new UsernameAndPassword(username, password));
			getFreshSession(username,password,null,"NONE");
		} catch (OperationFailedException e){
			throw new UserCreationFailedException("Failed get fresh session",e);
		}
		savedUsername = username;
	}

	@Override
	public void createUserAndAddAttributes(String username, String password, IdentityProof identityProof) throws UserCreationFailedException {
		try{
			servers.get(0).createUserAndAddAttributes(new UsernameAndPassword(username, password), identityProof);
			getFreshSession(username,password,null,"NONE");
		} catch (OperationFailedException e){
			throw new UserCreationFailedException("Failed get fresh session",e);
		}
		savedUsername = username;
	}

	@Override
	public void addAttributes(IdentityProof identityProof) throws OperationFailedException {
      checkActiveSession();
      try{
          servers.get(0).addAttributes(getSavedUsername(), sessionCookies.get(0), identityProof);
      } catch (AuthenticationFailedException e) {
          throw new OperationFailedException("Failed to add attributes",e);
      }
  }

	@Override
	public void addAttributes(String username, String password,
			IdentityProof identityProof, String token, String type) throws OperationFailedException {
		try {
			ensureActiveSession(getSavedUsername(), password, token, type);
			servers.get(0).addAttributes(getSavedUsername(), sessionCookies.get(0), identityProof);
		} catch(AuthenticationFailedException | OperationFailedException e) {
			throw new OperationFailedException("Failed to add attribute",e);
		}
	}

	@Override
	public String authenticate(String username, String password, Policy policy, String token, String type) throws AuthenticationFailedException {
		try {
			ensureActiveSession(username, password, token, type);
			String reply = servers.get(0).authenticate(username, sessionCookies.get(0), policy);
			if (reply == null) {
				throw new AuthenticationFailedException("No token was retrieved");
			}
			savedUsername = username;
			return reply;
		} catch (OperationFailedException | AuthenticationFailedException e){
			throw new AuthenticationFailedException("Failed to authenticate",e);
		}
	}

	@Override
	public Map<String, Attribute> getAllAttributes() throws OperationFailedException {
		checkActiveSession();
		try{
			return servers.get(0).getAllAttributes(getSavedUsername(), sessionCookies.get(0));
		} catch (AuthenticationFailedException e) {
			throw new OperationFailedException("Failed to get attributes",e);
		}
	}

	@Override
	public Map<String, Attribute> getAllAttributes(String  username, String password, String token, String type) throws OperationFailedException {
		try {
			ensureActiveSession(getSavedUsername(), password, token, type);
			return servers.get(0).getAllAttributes(getSavedUsername(), sessionCookies.get(0));
		}catch(OperationFailedException | AuthenticationFailedException e) {
			throw new OperationFailedException("Failed to get attributes",e);
		}
	}

	@Override
	public void deleteAttributes(String username, String password, List<String> attributes, String token, String type) throws OperationFailedException {
		try {
			ensureActiveSession(getSavedUsername(), password, token, type);
			if(!servers.get(0).deleteAttribute(getSavedUsername(), sessionCookies.get(0), attributes)) {
				throw new AuthenticationFailedException("vIdP failed to delete attributes");
			}
		}catch(OperationFailedException | AuthenticationFailedException e) {
			throw new OperationFailedException("Failed to delete attributes",e);
		}
	}

	@Override
	public void deleteAttributes(List<String> attributes) throws OperationFailedException {
		checkActiveSession();
		try{
			if(!servers.get(0).deleteAttribute(getSavedUsername(), sessionCookies.get(0), attributes)) {
				throw new AuthenticationFailedException("vIdP failed to delete attributes");
			}
			} catch (AuthenticationFailedException e) {
			throw new OperationFailedException("Failed to get delete attributes",e);
		}
	}

	@Override
	public void deleteAccount(String username, String password, String token, String type) throws OperationFailedException {
		try{
			getFreshSession(getSavedUsername(), password, token, type);

			if (!servers.get(0).deleteAccount(new UsernameAndPassword(getSavedUsername(), password), sessionCookies.get(0))) {
				throw new OperationFailedException("vIdP failed to delete account");
			}
		}catch(OperationFailedException | AuthenticationFailedException e) {
			throw new OperationFailedException("Failed to delete account",e);
		}
	}

	@Override
	public void changePassword(String username, String oldPassword, String newPassword, String token, String type)
		throws OperationFailedException {
		try {
			getFreshSession(getSavedUsername(), oldPassword, token, type);
			servers.get(0).changePassword(new UsernameAndPassword(getSavedUsername(), oldPassword), newPassword,
					sessionCookies.get(0));
		}catch(OperationFailedException | AuthenticationFailedException | UserCreationFailedException e) {
			throw new OperationFailedException("Failed to change password",e);
		}
	}

	@Override
	public String requestMFAChallenge(String username, String password, String type)
			throws OperationFailedException {
		try{
			ensureActiveSession(username, password, null, "NO_MFA");
			return servers.get(0)
				.requestMFA(new UsernameAndPassword(username, password), sessionCookies.get(0), type);
		}  catch (AuthenticationFailedException e){
			throw new OperationFailedException("Failed to request MFA challenge",e);
		}
	}

	@Override
	public void confirmMFA(String username, String password, String token, String type) throws OperationFailedException {
		try{
			getFreshSession(username, password, null, "NO_MFA");
			if (!servers.get(0)
				.confirmMFA(new UsernameAndPassword(username, password), sessionCookies.get(0), token,
					type)) {
				throw new AuthenticationFailedException("vIdP failed to confirm MFA");
			}
		}catch (AuthenticationFailedException e){
			throw new OperationFailedException("Failed to confirm MFA",e);
		}
	}

	@Override
	public void removeMFA(String username, String password, String token, String type) throws AuthenticationFailedException, OperationFailedException {
		try{
			getFreshSession(username, password, token, type);
			if (!servers.get(0)
				.removeMFA(new UsernameAndPassword(username, password), sessionCookies.get(0), token,
					type)) {
				throw new AuthenticationFailedException("vIdP failed to remove MFA");
			}
		}catch (AuthenticationFailedException e){
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
		if (System.currentTimeMillis() >= (sessionStartedTimes.get(0) + sessionLength)) {
			getFreshSession(username, password, token, type);
		}
	}

	protected void checkActiveSession() throws OperationFailedException {
		if (System.currentTimeMillis() >= (sessionStartedTimes.get(0) + sessionLength)) {
			throw new OperationFailedException("User has no active session");
		}
	}

	private void getFreshSession(String username, String password, String token, String type) throws OperationFailedException {
		try {
			String sessionCookie = servers.get(0).startSession(new UsernameAndPassword(username, password), token, type);
			sessionCookies.put(0, Base64.decodeBase64(sessionCookie));
			// Renew current session
			sessionStartedTimes.put(0, System.currentTimeMillis());
		} catch (AuthenticationFailedException e){
			throw new OperationFailedException("Failed to start session", e);
		}
	}
}
