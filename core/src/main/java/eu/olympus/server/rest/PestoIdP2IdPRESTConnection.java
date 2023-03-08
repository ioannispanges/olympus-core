package eu.olympus.server.rest;

import eu.olympus.model.server.rest.AddMasterShare;
import eu.olympus.model.server.rest.AddPartialMFARequest;
import eu.olympus.model.server.rest.AddPartialSignatureRequest;
import eu.olympus.model.server.rest.SetKeyShare;
import eu.olympus.server.interfaces.IdPRESTWrapper;
import eu.olympus.util.keyManagement.CertificateUtil;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;
import javax.net.ssl.HostnameVerifier;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * REST wrapper for the IdP
 *
 */
public class PestoIdP2IdPRESTConnection implements IdPRESTWrapper {
	private String host;
	private Client client;
	private int id;
	private String authentication;
	private static final Logger logger = LoggerFactory.getLogger(PestoIdP2IdPRESTConnection.class);
	
	/**
	 * Create a new mutual authenticated and encrypted TLS rest connections to an IdP
	 * @param url includes port, eg. http://127.0.0.1:9090
	 */
	public PestoIdP2IdPRESTConnection(String url, int id, String keyStore,
			String keyStorePW, String trustStore, String trustStorePW, String authentication) {
		this(url, id, authentication);

		Properties systemProps = System.getProperties();
		systemProps.put("javax.net.ssl.keyStorePassword", keyStorePW);
		systemProps.put("javax.net.ssl.keyStore", keyStore);
		systemProps.put("javax.net.ssl.trustStore", trustStore);
		systemProps.put("javax.net.ssl.trustStorePassword", trustStorePW);
		// Ensure that there is a certificate in the trust store for the webserver connecting
		HostnameVerifier verifier = new DefaultHostnameVerifier();
		javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(verifier);
	}

	public PestoIdP2IdPRESTConnection(String url, int id,
			String authentication) {
		this.id = id;
		this.authentication = "Bearer "+authentication;
		this.host = url+"/idp/";
	    this.client = ClientBuilder.newClient();
	}

	@Override
	public int getId() {
		return id;
	}

	@Override
	public Certificate getCertificate() throws CertificateException {
		Response response = client.target(host+PestoRESTEndpoints.GET_PUBLIC_KEY).request()
			.header("Authorization", authentication)
			.get();
		logger.info("PestoIdP2IdP: getCertificate returned: "+response.getStatus());
		return CertificateUtil.decodePemCert(response.readEntity(String.class));
	}

	@Override
	public void addPartialServerSignature(String ssid, byte[] signature) {
		AddPartialSignatureRequest request = new AddPartialSignatureRequest(ssid, Base64.encodeBase64String(signature));
		logger.info("Attempting to retrieve partial signature from: " + host);
		Response response = client.target(host+PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request()
			.header("Authorization", authentication)
			.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		logger.info("PestoIdP2IdP: addPartialServerSignature returned: "+response.getStatus());
	}

	@Override
	public void addPartialMFASecret(String ssid, String secret, String type) {
		AddPartialMFARequest request = new AddPartialMFARequest(ssid, secret, type);
		Response response = client.target(host+PestoRESTEndpoints.ADD_PARTIAL_MFA_SECRET).request()
			.header("Authorization", authentication)
			.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		logger.info("PestoIdP2IdP: addPartialMFASecret returned: "+response.getStatus());
	}
	
	@Override
	public void addMasterShare(String newSsid, byte[] newShare) {
		AddMasterShare request = new AddMasterShare(newSsid, Base64.encodeBase64String(newShare));
		Response resp = client.target(host+PestoRESTEndpoints.ADD_MASTER_SHARE).request()
			.header("Authorization", authentication)
			.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		logger.info("PestoIdP2IdP: addMasterShare returned: "+resp.getStatus());
		authentication = resp.getHeaderString("Authorization");
	}

	@Override
	public void setKeyShare(int id, byte[] newShare) {
		SetKeyShare request = new SetKeyShare(id, Base64.encodeBase64String(newShare));
		Response response = client.target(host+PestoRESTEndpoints.SET_KEY_SHARE).request()
			.header("Authorization", authentication)
			.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		logger.info("PestoIdP2IdP: setKeyShare returned: "+response.getStatus());
	}
}
