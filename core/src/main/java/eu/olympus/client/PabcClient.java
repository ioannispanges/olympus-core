package eu.olympus.client;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.model.PSCredential;
import eu.olympus.model.Policy;
import eu.olympus.model.PresentationToken;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.PolicyUnfulfilledException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.server.interfaces.PabcIdP;
import eu.olympus.server.rest.CommonRESTEndpoints;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;


public class PabcClient extends PestoAuthClient {

	private CredentialManagement credentialManagement;

	// Maybe instead of a list (and derive the integer identifier from the inferred order) a map with identifiers.
	public PabcClient(List<? extends PabcIdP> servers, CredentialManagement credentialManagement, ClientCryptoModule cryptoModule) {
		super(servers, cryptoModule);
		this.credentialManagement = credentialManagement;
	}

	@Override
	public String authenticate(String username, String password, Policy policy, String token, String type) throws AuthenticationFailedException {
		if(!credentialManagement.checkStoredCredential()){ //If no stored credential, get a new one
			try {
				ensureActiveSession(username, password, token, type);
				long salt = getFreshSalt();
				byte[][] signature = getSignedNonceAndUid(username, salt,
						CommonRESTEndpoints.AUTHENTICATE);

				Map<Integer,Future<String>> authentications = retrievePartialCredentials(username,cookies,salt,signature);
				PresentationToken generatedToken= combineCredentials(authentications, policy);

				updateCurrentSessionTimes();
				savedUsername = username;
				return generatedToken.getEncoded();
			} catch(Exception e) {
				throw new AuthenticationFailedException("Failed to authenticate", e);
			}
		}
		try{
			savedUsername = username;
			return credentialManagement.generatePresentationToken(policy).getEncoded();
		} catch (TokenGenerationException e){
			throw new AuthenticationFailedException("Failed to generate token", e);
		}
	}

	private PresentationToken combineCredentials(Map<Integer, Future<String>> authentications, Policy policy) throws AuthenticationFailedException {
		try{
			Map<Integer,PSCredential> partialCredentials = new HashMap<>();
			for(Integer iresp : authentications.keySet()) {
				PSCredential reconstructedCredential=new PSCredential(authentications.get(iresp).get());
				partialCredentials.put(iresp,reconstructedCredential);
			}
			return credentialManagement.combineAndGeneratePresentationToken(partialCredentials, policy);
		} catch (InterruptedException | ExecutionException | InvalidProtocolBufferException |
				TokenGenerationException | PolicyUnfulfilledException e){
			throw new AuthenticationFailedException("Failed to combine credentials",e);
		}
	}

	private Map<Integer, Future<String>> retrievePartialCredentials(String username, Map<Integer,byte[]> cookies, long salt, byte[][] signature) {
			Map<Integer,Future<String>> authentications = new HashMap<>();
			for (Integer i: servers.keySet()){
				authentications.put(i,executorService.submit(() -> ((PabcIdP) servers.get(i)).getCredentialShare(username, cookies
					.get(i), salt, signature[i], salt)));
			}
			return authentications;
	}

	public void clearCredentials(){
		if(credentialManagement.checkStoredCredential()){
			credentialManagement.clearCredential();
		}
	}

	@Override
	public void clearSession() {
		super.clearSession();
	}
}
