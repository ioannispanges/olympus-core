package eu.olympus.unit.server.rest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import eu.olympus.TestParameters;
import eu.olympus.model.Authorization;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.PestoIdP2IdPRESTConnection;
import eu.olympus.server.rest.PestoIdPServlet;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.util.keyManagement.CertificateUtil;
import eu.olympus.util.keyManagement.SecureStoreUtil;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.junit.Ignore;
import org.junit.Test;

public class TestPestoIdP2IdPRESTConnection {
	
	private boolean addPartialReached = false;
	private boolean addMasterReached = false;
	private boolean setKeyShareReached = false;
	

	@Test
	public void testBasic() throws Exception {
		RESTIdPServer server = new RESTIdPServer();
		PestoDatabase db = new InMemoryPestoDatabase();
		PestoIdPImpl testIdP = new PestoIdPImpl(db,  new ArrayList<>(), new HashMap<String, MFAAuthenticator>(), new SoftwareServerCryptoModule(new Random(1)), 1000) {

			@Override
			public Certificate getCertificate(){
				try {
					return CertificateUtil.loadCertificate(TestParameters.TEST_DIR +"testCert.crt");
				} catch (Exception e) {
					return null;
				}
			}

			@Override
			public void addPartialServerSignature(String ssid, byte[] signature) {
				addPartialReached = true;
			}
			
			@Override
			public void addMasterShare(String newSsid, byte[] newShares) {
				addMasterReached = true;
			}
			
			@Override
			public void setKeyShare(int id, byte[] newShares) {
				setKeyShareReached = true;
			}
		};
		server.setIdP(testIdP);
		
		List<String> types = new ArrayList<String>();
		types.add(PestoIdPServlet.class.getCanonicalName());
		
		testIdP.addSession("server1", new Authorization("user",  Arrays.asList(new Role[]{Role.SERVER}), System.currentTimeMillis()+10000l));
		
		server.start(10666, types, 10667, null, null, null);

		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"bad_token");
		connection.addPartialServerSignature("ssid", "signature".getBytes());
		assertFalse(addPartialReached);
		connection.addMasterShare("newSsid", "newShare".getBytes());
		assertFalse(addMasterReached);
		connection.setKeyShare(1, "newShare".getBytes());
		assertFalse(setKeyShareReached);
		connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1, "server1");
		connection.addPartialServerSignature("ssid", "signature".getBytes());
		connection.addMasterShare("newSsid", "newShare".getBytes());
		connection.setKeyShare(1, "newShare".getBytes());
		Certificate certificate = connection.getCertificate();
		assertNotNull(certificate);
		assertEquals(certificate,CertificateUtil.loadCertificate(TestParameters.TEST_DIR +"testCert.crt"));
		server.stop();
		assertTrue(addPartialReached);
		assertTrue(addMasterReached);
		assertTrue(setKeyShareReached);
	}

	@Ignore
	@Test(expected = CertificateException.class)
	public void testWrongDomainCert() throws Exception {
		KeyStore ks = SecureStoreUtil.getEmptySecurityStore();
		Certificate cert = CertificateUtil.loadCertificate(TestParameters.TEST_DIR +"testCert.crt");
		ks.setCertificateEntry("testCert", cert);
		SecureStoreUtil.writeSecurityStore(ks, "password", TestParameters.TEST_DIR +"testStoreWrongDomain");

		PestoIdP idp = new PestoIdPImpl(new InMemoryPestoDatabase(), new LinkedList<IdentityProver>(),
				new HashMap<>(), new SoftwareServerCryptoModule(new Random(0)), 100000);
		RESTIdPServer restServer = new RESTIdPServer();
		restServer.setIdP(idp);
		List<String> types = new ArrayList<String>();
		types.add(PestoIdPServlet.class.getCanonicalName());
//		restServer.start(10666, types, 10667, TestParameters.TEST_DIR +"testStoreWrongDomain", "password", "password" );
		restServer.start(10666, types, 10667, TestParameters.TEST_KEY_STORE_LOCATION, TestParameters.TEST_KEY_STORE_PWD, TestParameters.TEST_KEY_STORE_PWD );
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"token");
		PABCConfigurationImpl conf = new PABCConfigurationImpl(); // TODO once we can actually load configuration with ObjectMapper. I.e. after OIDC-front has been merged
		conf.setMyAuthorizationCookie("token");
		assertTrue(((PestoIdPImpl) idp).setup("setup", conf, Arrays.asList(connection)));
		connection.addPartialServerSignature("test", "test".getBytes()); // TODO assert that the right error occurs, probably will have to inspect error code
	}

}
