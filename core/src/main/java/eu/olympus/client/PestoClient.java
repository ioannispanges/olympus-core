package eu.olympus.client;

import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.server.interfaces.PestoBasedIdP;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.util.JWTUtil;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Future;

public class PestoClient extends PestoAuthClient {

	public PestoClient(List<? extends PestoIdP> servers, ClientCryptoModule cryptoModule) {
		super(servers, cryptoModule);
	}

	@Override
	public String authenticate(String username, String password, Policy policy, String token, String type) throws AuthenticationFailedException {
		try{
			ensureActiveSession(username, password, token, type);
			long salt = getFreshSalt();
			byte[][] signature = getSignedNonceAndUid(username, salt,
					CommonRESTEndpoints.AUTHENTICATE);
			List<String> partialTokens = new LinkedList<String>();
			List<Future<String>> authentications = new ArrayList<Future<String>>();
			for (PestoBasedIdP server: servers.values()){
				authentications.add(executorService.submit(() -> ((PestoIdP) server).authenticate(username, cookies.get(server.getId()), salt, signature[server.getId()], policy)));
			}
			for(Future<String> resp : authentications) {
				partialTokens.add(resp.get());
			}
			updateCurrentSessionTimes();

			String result = JWTUtil.combineTokens(partialTokens, cryptoModule.getModulus());
			savedUsername = username;
			return result;
		} catch(Exception e) {
			throw new AuthenticationFailedException("Failed to authenticate",e);
		}
	}
}

