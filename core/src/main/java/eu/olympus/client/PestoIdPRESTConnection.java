package eu.olympus.client;

import eu.olympus.model.Policy;
import eu.olympus.model.server.rest.SignatureAndPolicy;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.PestoRESTEndpoints;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import org.apache.commons.codec.binary.Base64;

/**
 * REST wrapper for the IdP
 *
 */
public class PestoIdPRESTConnection extends IdPRESTConnection implements PestoIdP {

	/**
	 * Create a new rest connections to a PestoIdP
	 * @param url includes port, eg. http://127.0.0.1:9090
	 */
	public PestoIdPRESTConnection(String url, String accessToken, int id, int rateLimit) {
		super(url, accessToken, id, rateLimit);
	}

	@Override
	public String authenticate(String username, byte[] cookie, long salt, byte[] signature, Policy policy) {
		SignatureAndPolicy data = new SignatureAndPolicy(username, Base64.encodeBase64String(cookie), salt, Base64.encodeBase64String(signature), policy);
		return client.target(host+PestoRESTEndpoints.AUTHENTICATE).request()
				.post(Entity.entity(data, MediaType.APPLICATION_JSON), String.class);
	}
}
