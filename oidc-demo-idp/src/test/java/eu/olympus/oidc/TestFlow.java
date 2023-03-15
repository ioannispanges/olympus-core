package eu.olympus.oidc;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.client.PasswordJWTClient;
import eu.olympus.client.PestoClient;
import eu.olympus.client.PestoIdPRESTConnection;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeIdentityProof;
import eu.olympus.model.Operation;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.oidc.server.identityprovers.DemoIdentityProver;
import eu.olympus.oidc.server.storage.InMemoryPestoDatabase;
import eu.olympus.oidc.server.storage.SqlitePestoDatabase;
import eu.olympus.server.AttributeIdentityProver;
import eu.olympus.server.OIDCPestoIdPImpl;
import eu.olympus.server.PasswordJWTIdP;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.interfaces.UserPasswordDatabase;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import eu.olympus.verifier.interfaces.Verifier;
import java.io.File;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPublicKey;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class TestFlow {

	private List<PABCConfigurationImpl> configurations = new LinkedList<>();
	private final int serverCount = 3;

	@Before
	public void setupConfigurations() throws Exception {
		ObjectMapper mapper = new ObjectMapper();
		for(int i = 0; i< serverCount; i++) {
			configurations.add(mapper.readValue(new File("src/test/resources/setup"+i+".json"), PABCConfigurationImpl.class));
		}
	}
	
	@Ignore
	@Test
	public void testPasswordJWTDirect() throws CertificateEncodingException{
		UserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		PasswordJWTIdP idp = null;
		List<IdentityProver> identityProvers = new LinkedList<IdentityProver>();
		identityProvers.add(new DemoIdentityProver(db));
		try {
			idp = new PasswordJWTIdP(db, identityProvers, new HashMap<>());
		} catch(Exception e) {
			fail("Failed to start IdP");
		}
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		idps.add(idp);
		UserClient client = new PasswordJWTClient(idps);
		try{
			idp.setup(TestParameters.getRSAPrivateKey1(), TestParameters.getRSA1Cert());
		} catch(Exception e) {
			fail("Failed to generate key");
		}
//		Verifier verifier = new JWTVerifier(idp.getPublicKey());
//		testCreateTwoStepFlow(client, verifier);
	}

	// This test should be compatible with the docker-compose deployment
	// ie. after running docker-compose up, this test should be able to succeed
	@Ignore
	@Test
	public void testPestoRunning() throws Exception{

		String path = "src/test/resources/volatile/truststore.jks";
		String PW = "OLYMPUS";
		Properties systemProps = System.getProperties();

		systemProps.put("javax.net.ssl.trustStore", path);
		systemProps.put("javax.net.ssl.trustStorePassword", PW);
		System.setProperties(systemProps);

		List<PestoIdP> idps = new LinkedList<>();
		idps.add(new PestoIdPRESTConnection("https://localhost:9933", "", 0,100));
		idps.add(new PestoIdPRESTConnection("https://localhost:9934", "", 1, 100));
		idps.add(new PestoIdPRESTConnection("https://localhost:9935", "", 2, 100));
		ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate().getPublicKey()).getModulus());
		UserClient client = new PestoClient(idps, cryptoModule);

	
		Verifier verifier = new JWTVerifier(idps.get(0).getCertificate().getPublicKey());
		testSimple(client, verifier);
	}

	@Test
	public void testPestoDirect() throws Exception{
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		for(int i = 0; i< serverCount; i++) {
			PestoDatabase db = new InMemoryPestoDatabase();
			OIDCPestoIdPImpl idp = null;
			List<IdentityProver> identityProvers = new LinkedList<IdentityProver>();
			identityProvers.add(new AttributeIdentityProver(db));
			try {
				idp = new OIDCPestoIdPImpl(db, identityProvers, new HashMap<>(), new SoftwareServerCryptoModule(new Random(1)), configurations.get(i).getIssuerId(), 100000);
			} catch(Exception e) {
				e.printStackTrace();
				fail("Failed to start IdP");
			}
			idps.add(idp);
		}

		for(int i = 0; i< serverCount; i++) {
			try {
				PestoIdPImpl idp = idps.get(i);
				List<PestoIdP> others = new ArrayList<PestoIdP>();
				others.addAll(idps);
				others.remove(idp);
				idp.setup("setup", configurations.get(i), others);
			} catch(Exception e) {
				fail("Failed to start IdP");
			}
		}

		ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate().getPublicKey()).getModulus());
		UserClient client = new PestoClient(idps, cryptoModule);

		Verifier verifier = new JWTVerifier(idps.get(0).getCertificate().getPublicKey());
		testSimple(client, verifier);
	}

	@Test
	public void testCombinedSqliteDb() throws Exception{
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		for(int i = 0; i< serverCount; i++) {
			// Remove previous database
			new File("src/test/resources/db_"+i).delete();
			// Create clean database
			String pathToDb = SqlitePestoDatabase.createDatabase("src/test/resources/db_"+i);
			Connection con = SqlitePestoDatabase.constructConnection(pathToDb);
			PestoDatabase db = new SqlitePestoDatabase(con);
			OIDCPestoIdPImpl idp = null;
			List<IdentityProver> identityProvers = new LinkedList<IdentityProver>();
			identityProvers.add(new AttributeIdentityProver(db));
			try {
				idp = new OIDCPestoIdPImpl(db, identityProvers, new HashMap<>(), new SoftwareServerCryptoModule(new Random(1)), configurations.get(i).getIssuerId(), 100000);
			} catch(Exception e) {
				e.printStackTrace();
				fail("Failed to start IdP");
			}
			idps.add(idp);
		}

		for(int i = 0; i< serverCount; i++) {
			try {
				PestoIdPImpl idp = idps.get(i);
				List<PestoIdP> others = new ArrayList<PestoIdP>();
				others.addAll(idps);
				others.remove(idp);
				idp.setup("setup", configurations.get(i), others);
			} catch(Exception e) {
				fail("Failed to start IdP");
			}
		}

		ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate().getPublicKey()).getModulus());
		UserClient client = new PestoClient(idps, cryptoModule);

		Verifier verifier = new JWTVerifier(idps.get(0).getCertificate().getPublicKey());
		testWithPersistentDb(client, verifier);
	}



	public void testSimple(UserClient client, Verifier verifier) {
		try{
			client.createUser("test", "pw1");
		} catch(UserCreationFailedException e) {
			fail("Failed to create user");
		}

			Map<String, Attribute> attributes = new HashMap<>();
			attributes.put("name", new Attribute("John Doe"));
			attributes.put("nationality", new Attribute("Se"));
			attributes.put("age",new Attribute(30));
			attributes.put("email", new Attribute("John@mail.com"));
			attributes.put("birthdate", new Attribute("1980-11-25"));
		AttributeIdentityProof proof = new AttributeIdentityProof(attributes);

		try{
			client.addAttributes("test", "pw1", proof, "", "NONE");
		} catch(OperationFailedException e) {
			e.printStackTrace();
			fail("Failed to add user certificate: " + e);
		}

		try{
			client.createUserAndAddAttributes("test2", "pw2", proof);
		} catch (UserCreationFailedException e){
			fail("Could not create user and add attributes at the same time");
		}

		//Create a policy to reveal

		String token;
		try {
			List<Predicate> predicates = new ArrayList<>();
			predicates.add(new Predicate("name", Operation.REVEAL, null));
			predicates.add(new Predicate("audience", Operation.REVEAL, new Attribute("Test-SP")));
			Policy policy = new Policy(predicates, "c368dd0e2db04cd6ba4ae2d5809774aa");

			token = client.authenticate("test", "pw1", policy, "", "NONE");
			//Create proper verification
			assertTrue(verifier.verify(token));
		} catch (AuthenticationFailedException  e) {
			e.printStackTrace();
			// TODO Auto-generated catch block
			fail();
		}

	}

	public void testWithPersistentDb(UserClient client, Verifier verifier) {
		try{
			client.createUser("test", "pw1");
		} catch(UserCreationFailedException e) {
			fail();
		}

			Map<String, Attribute> attributes = new HashMap<>();
			attributes.put("name", new Attribute("John Doe"));
			attributes.put("nationality", new Attribute("Se"));
			attributes.put("age",new Attribute(30));
			attributes.put("email", new Attribute("John@mail.com"));
			attributes.put("birthdate", new Attribute("1980-11-25"));
		AttributeIdentityProof proof = new AttributeIdentityProof(attributes);

		try{
			client.addAttributes("test", "pw1", proof, "", "NONE");
		} catch(OperationFailedException e) {
			e.printStackTrace();
			fail("Failed to add user certificate: " + e);
		}

		try{
			client.createUserAndAddAttributes("test2", "pw2", proof);
		} catch (UserCreationFailedException e){
			fail();
		}

		//Create a policy to reveal

		String token;
		try {
			List<Predicate> predicates = new ArrayList<>();
			predicates.add(new Predicate("name", Operation.REVEAL, null));
			predicates.add(new Predicate("audience", Operation.REVEAL, new Attribute("Test-SP")));
			Policy policy = new Policy(predicates, "c368dd0e2db04cd6ba4ae2d5809774aa");

			token = client.authenticate("test", "pw1", policy, "", "NONE");
			//Create proper verification
			assertTrue(verifier.verify(token));
		} catch (AuthenticationFailedException  e) {
			fail();
		}

	}
}
