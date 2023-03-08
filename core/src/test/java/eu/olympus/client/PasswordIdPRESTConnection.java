package eu.olympus.client;

import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.SerializedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.AttributeMap;
import eu.olympus.model.server.rest.AuthenticationAndAttributes;
import eu.olympus.model.server.rest.AuthenticationAndIDProof;
import eu.olympus.model.server.rest.AuthenticationAndPolicy;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.model.server.rest.PasswordAuthentication;
import eu.olympus.model.server.rest.KeyAndCert;
import eu.olympus.model.server.rest.PasswordAuthenticationAndIDProof;
import eu.olympus.model.server.rest.PasswordAuthenticationAndMFAToken;
import eu.olympus.model.server.rest.PasswordAuthenticationAndMFATokenNoCookie;
import eu.olympus.model.server.rest.PasswordAuthenticationAndMFAType;
import eu.olympus.model.server.rest.PasswordAuthenticationAndPassword;
import eu.olympus.model.server.rest.UsernameAndCookie;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.PasswordJWTIdP;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.rest.PasswordRESTEndpoints;
import eu.olympus.util.KeySerializer;
import eu.olympus.util.keyManagement.CertificateUtil;
import eu.olympus.util.keyManagement.PemUtil;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.eclipse.jetty.http.HttpStatus;


/**
 * REST wrapper for the IdP
 */
public class PasswordIdPRESTConnection extends PasswordJWTIdP {

	private final String host;
	private final Client client;

	/**
	 * Create a new rest connections to an IdP
	 * @param url includes port, eg. http://127.0.0.1:9090
	 */
	public PasswordIdPRESTConnection(String url) {
		super(null, new LinkedList<IdentityProver>(), null);
		this.host = url + "/idp/";
		this.client = ClientBuilder.newClient();
	}
	
	@Override
	public void setup(RSAPrivateKey privKey, Certificate certificate) throws Exception {
		SerializedKey serializedKey = KeySerializer.serialize(privKey);
		String pemEncodedCert = PemUtil.encodeDerToPem(certificate.getEncoded(), "CERTIFICATE");
		KeyAndCert pair = new KeyAndCert(serializedKey, pemEncodedCert);
	    client.target(host + CommonRESTEndpoints.SETUP).request().post(Entity.entity(pair, MediaType.APPLICATION_JSON));
	}

	@Override
	public Certificate getCertificate() {
		try {
			String output = client.target(host + CommonRESTEndpoints.GET_PUBLIC_KEY).request().get(String.class);
			return CertificateUtil.decodePemCert(output);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String authenticate(String username, byte[] cookie, Policy policy) throws AuthenticationFailedException {
		try {
			AuthenticationAndPolicy data = new AuthenticationAndPolicy(username,
					Base64.encodeBase64String(cookie), policy);
			return client.target(host+ CommonRESTEndpoints.AUTHENTICATE).request().post(Entity.entity(data, MediaType.APPLICATION_JSON), String.class);
		} catch (Exception e) {
	    	throw new AuthenticationFailedException(e);
	    }
	}

	@Override
	public void createUser(UsernameAndPassword creationData) throws UserCreationFailedException {
		try{
			Response response = client.target(host+ CommonRESTEndpoints.CREATE_USER).request().post(Entity.entity(creationData, MediaType.APPLICATION_JSON));
		    if(response.getStatus() != 204) {
		    	throw new UserCreationFailedException();
		    }
		} catch (Exception e) {
			throw new UserCreationFailedException(e);
		}
	}

	@Override
	public void createUserAndAddAttributes(UsernameAndPassword creationData, IdentityProof idProof)
			throws UserCreationFailedException {
		try{
			PasswordAuthenticationAndIDProof passwordAuthenticationAndIDProof = new PasswordAuthenticationAndIDProof(creationData, null, idProof);
			Response response = client.target(host+ CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES).request().post(Entity.entity(passwordAuthenticationAndIDProof, MediaType.APPLICATION_JSON));
		    if(response.getStatus() != 204) {
		    	throw new UserCreationFailedException();
		    }
		} catch (Exception e) {
			throw new UserCreationFailedException(e);
		}
	}

	@Override
	public void addAttributes(String username, byte[] cookie, IdentityProof idProof) throws AuthenticationFailedException {
		try{
			AuthenticationAndIDProof pwAndProof = new AuthenticationAndIDProof(username, Base64.encodeBase64String(cookie), idProof);
			Response response = client.target(host+ CommonRESTEndpoints.ADD_ATTRIBUTES).request().post(Entity.entity(pwAndProof, MediaType.APPLICATION_JSON));

		    if(response.getStatus() != 204) {
		    	throw new UserCreationFailedException();
		    }
		} catch (Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public Map<String, Attribute> getAllAttributes(String username, byte[] cookie) throws AuthenticationFailedException {
	    try {
				UsernameAndCookie usernameAndCookie = new UsernameAndCookie(username, Base64.encodeBase64String(cookie));
	    	AttributeMap attributes = client.target(host+ CommonRESTEndpoints.GET_ALL_ATTRIBUTES).request().post(Entity.entity(usernameAndCookie, MediaType.APPLICATION_JSON), AttributeMap.class);
	    	return attributes.getAttributes();
	    } catch (Exception e) {
	    	throw new AuthenticationFailedException(e);
	    }
	}

	@Override
	public boolean deleteAttribute(String username, byte[] cookie, List<String> attributes) throws AuthenticationFailedException {
		try {
			AuthenticationAndAttributes data = new AuthenticationAndAttributes(username, Base64.encodeBase64String(cookie), attributes);
			return client.target(host+ CommonRESTEndpoints.DELETE_ATTRIBUTES).request().post(Entity.entity(data, MediaType.APPLICATION_JSON), Boolean.class);
		} catch(Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public boolean deleteAccount(UsernameAndPassword authentication, byte[] cookie) throws AuthenticationFailedException {
		try {
			PasswordAuthentication data = new PasswordAuthentication(authentication, Base64.encodeBase64String(cookie));
			return  client.target(host+ CommonRESTEndpoints.DELETE_ACCOUNT).request().post(Entity.entity(data, MediaType.APPLICATION_JSON), Boolean.class);
		} catch(Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public void changePassword(
			UsernameAndPassword oldAuthenticationData, String newPassword, byte[] cookie)
			throws UserCreationFailedException, AuthenticationFailedException {
		PasswordAuthenticationAndPassword request = new PasswordAuthenticationAndPassword(
				oldAuthenticationData, Base64.encodeBase64String(cookie), newPassword);
		Response resp;
		try {
			resp = client.target(host + CommonRESTEndpoints.CHANGE_PASSWORD).request()
					.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		} catch (Exception e) {
			throw new UserCreationFailedException(e);
		}
		// If the response is not a Success
		if (!HttpStatus.getCode(resp.getStatus()).isSuccess()) {
			throw new AuthenticationFailedException("Could not change password");
		}
	}

	@Override
	public String requestMFA(UsernameAndPassword authentication, byte[] cookie, String type)
			throws AuthenticationFailedException {
		PasswordAuthenticationAndMFAType request = new PasswordAuthenticationAndMFAType(authentication,
				Base64.encodeBase64String(cookie), type);
		try {
			return client.target(host + CommonRESTEndpoints.REQUEST_MFA).request()
					.post(Entity.entity(request, MediaType.APPLICATION_JSON), String.class);
		} catch (Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public boolean confirmMFA(UsernameAndPassword authentication, byte[] cookie, String mfaToken,
			String type) {
		PasswordAuthenticationAndMFAToken request = new PasswordAuthenticationAndMFAToken(
				authentication,
				Base64.encodeBase64String(cookie), mfaToken, type);

		try {
			return client.target(host + CommonRESTEndpoints.CONFIRM_MFA).request()
					.post(Entity.entity(request, MediaType.APPLICATION_JSON), Boolean.class);
		} catch (Exception e) {
			throw e;
		}
	}

	@Override
	public boolean removeMFA(UsernameAndPassword authentication, byte[] cookie, String mfaToken,
			String type) {
		PasswordAuthenticationAndMFAToken request = new PasswordAuthenticationAndMFAToken(
				authentication, Base64.encodeBase64String(cookie),
				mfaToken, type);

		try {
			return client.target(host + CommonRESTEndpoints.REMOVE_MFA).request()
					.post(Entity.entity(request, MediaType.APPLICATION_JSON), Boolean.class);
		} catch (Exception e) {
			throw e;
		}
	}

	@Override
	public String startSession(UsernameAndPassword authentication, String token, String type)  throws AuthenticationFailedException {
		PasswordAuthenticationAndMFATokenNoCookie request = new PasswordAuthenticationAndMFATokenNoCookie(
				authentication,
				token, type);
		try {
			return client.target(host + PasswordRESTEndpoints.START_SESSION).request()
					.post(Entity.entity(request, MediaType.APPLICATION_JSON), String.class);
		} catch (Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}
}
