package eu.olympus.cfp;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import eu.olympus.cfp.model.TestIdentityProof;
import eu.olympus.cfp.verifier.JWTVerifier;
import eu.olympus.client.PSCredentialManagement;
import eu.olympus.client.PabcClient;
import eu.olympus.client.PabcIdPRESTConnection;
import eu.olympus.client.PestoClient;
import eu.olympus.client.PestoIdPRESTConnection;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.util.Util;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.verifier.PSPABCVerifier;
import eu.olympus.verifier.VerificationResult;
import eu.olympus.verifier.interfaces.Verifier;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestFlow {
	private static Logger logger = LoggerFactory.getLogger(TestFlow.class);
	private static final byte[] seed = "random value random value random value random value random".getBytes();

	@Ignore
	@Test
	public void testPestoRunning() throws Exception{
		logger.info("Starting testPestoRunning");
		// Need to set trust store so the user application trusts the self-signed example SSL certificate used by the IdPs
		Properties systemProps = System.getProperties();
		systemProps.put("javax.net.ssl.trustStore", TestParameters.TEST_TRUST_STORE_LOCATION);
		systemProps.put("javax.net.ssl.trustStorePassword", TestParameters.TEST_TRUST_STORE_PWD);
		System.setProperties(systemProps);
		List<PestoIdPRESTConnection> idps = new ArrayList<PestoIdPRESTConnection>();
		int serverCount = 3;
		String administratorCookie="eimLN2/sr73deAVV8D/3FXFUNbSRdu3d/FJtWLCXGhu9+i6fiHcS54MyIOG6MczVR7r941CI+H1dbgDIVi+xHQ==";
		int[] ports=new int[serverCount];
		int basePort=9090;
		for(int i=0;i<serverCount;i++)
			ports[i]=basePort+i;
		for(int i = 0; i< serverCount; i++) {
			PestoIdPRESTConnection rest = new PestoIdPRESTConnection("https://localhost:"+(ports[i]),
					administratorCookie, i, 100000);
			idps.add(rest);
		}
		ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate().getPublicKey()).getModulus());
		UserClient client = new PestoClient(idps, cryptoModule);
		Verifier verifier = new JWTVerifier(idps.get(0).getCertificate().getPublicKey());
		testPestoFlow(client, verifier);
	}


	@Ignore
	@Test
	public void testPabcRunning() throws Exception{
		logger.info("Starting testPabcPestoRunning");
		// Need to set trust store so the user application trusts the self-signed example SSL certificate used by the IdPs
		Properties systemProps = System.getProperties();
		systemProps.put("javax.net.ssl.trustStore", TestParameters.TEST_TRUST_STORE_LOCATION);
		systemProps.put("javax.net.ssl.trustStorePassword", TestParameters.TEST_TRUST_STORE_PWD);
		System.setProperties(systemProps);
		List<PabcIdPRESTConnection> idps = new ArrayList<PabcIdPRESTConnection>();
		int serverCount = 3;
		String administratorCookie="eimLN2/sr73deAVV8D/3FXFUNbSRdu3d/FJtWLCXGhu9+i6fiHcS54MyIOG6MczVR7r941CI+H1dbgDIVi+xHQ==";
		int[] ports=new int[serverCount];
		int basePort=9090;
		for(int i=0;i<serverCount;i++)
			ports[i]=basePort+i;
		for(int i = 0; i< serverCount; i++) {
			PabcIdPRESTConnection rest = new PabcIdPRESTConnection("https://localhost:"+(ports[i]),
					administratorCookie, i, 100000);
			idps.add(rest);
		}
		Map<Integer, MSverfKey> publicKeys = new HashMap<>();
		for (Integer j = 0; j< serverCount; j++){
			publicKeys.put(j, idps.get(j).getPabcPublicKeyShare());
		}
		CredentialManagement credentialManagement=new PSCredentialManagement(true, new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialManagement).setup(idps,seed);
		ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate().getPublicKey()).getModulus());
		UserClient client = new PabcClient(idps, credentialManagement, cryptoModule);
		PSPABCVerifier verifier = new PSPABCVerifier();
		verifier.setup(idps,seed);
		testPabcFlow(client, verifier);
	}

	public void testPabcFlow(UserClient client, PSPABCVerifier verifier) throws AuthenticationFailedException, TokenGenerationException, OperationFailedException {
		try{
			client.createUser("user_1", "password");
		} catch(UserCreationFailedException e) {
			fail("Failed to create user");
		}
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("https://olympus-project.eu/example/model/name", new Attribute("John Doe"));
		attributes.put("https://olympus-project.eu/example/model/nationality", new Attribute("Spanish"));
		attributes.put("https://olympus-project.eu/example/model/height",new Attribute(185));
		attributes.put("https://olympus-project.eu/example/model/dateOfBirth",new Attribute(Util.fromRFC3339UTC("1998-01-05T00:00:00")));

		try {

			// 	Prove identity with cached key
			client.addAttributes(new TestIdentityProof("proof", attributes));
		} catch(OperationFailedException e) {
			fail("Failed to prove identity: " + e);
		}
		client.clearSession();
		String signedMessage="SignedMessage";
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("https://olympus-project.eu/example/model/name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		predicate = new Predicate();
		predicate.setAttributeName("https://olympus-project.eu/example/model/height");
		predicate.setOperation(Operation.GREATERTHANOREQUAL);
		predicate.setValue(new Attribute(150));
		predicate = new Predicate();
		predicate.setAttributeName("https://olympus-project.eu/example/model/dateOfBirth");
		predicate.setOperation(Operation.INRANGE);
		predicate.setValue(new Attribute(Util.fromRFC3339UTC("1990-01-05T00:00:00")));
		predicate.setExtraValue(new Attribute(Util.fromRFC3339UTC("2000-01-05T00:00:00")));
		predicates.add(predicate);
		Policy policy = new Policy(predicates, signedMessage);
		Policy verifierPolicy = new Policy(policy.getPredicates(), signedMessage);
		try{
			client.authenticate("user_1", "wrong password", policy, null, "NONE");
			fail("Could authenticate with a bad password");
		}catch(AuthenticationFailedException e){
		}
		client.clearSession();
		String token = client.authenticate("user_1", "password", policy, null, "NONE");
		assertThat(verifier.verifyPresentationToken(token, verifierPolicy), is(VerificationResult.VALID));
		client.deleteAccount("username","password", null, "NONE");
	}


	public void testPestoFlow(UserClient client, Verifier verifier) throws AuthenticationFailedException, TokenGenerationException, OperationFailedException {
		try{
			client.createUser("user_1", "password");
		} catch(UserCreationFailedException e) {
			fail("Failed to create user");
		}
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("https://olympus-project.eu/example/model/name", new Attribute("John Doe"));
		attributes.put("https://olympus-project.eu/example/model/nationality", new Attribute("Spanish"));
		attributes.put("https://olympus-project.eu/example/model/height",new Attribute(185));
		attributes.put("https://olympus-project.eu/example/model/dateOfBirth",new Attribute(Util.fromRFC3339UTC("1998-01-05T00:00:00")));

		try {

			// 	Prove identity with cached key
			client.addAttributes(new TestIdentityProof("proof", attributes));
		} catch(OperationFailedException e) {
			fail("Failed to prove identity: " + e);
		}
		client.clearSession();
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("https://olympus-project.eu/example/model/name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		predicate = new Predicate();
		predicate.setAttributeName("https://olympus-project.eu/example/model/height");
		predicate.setOperation(Operation.GREATERTHANOREQUAL);
		predicate.setValue(new Attribute(150));
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "testPolicy");
		try{ //
			client.authenticate("user_1", "bad_password", policy, null, "NONE");
			fail("Could authenticate with a bad password");
		} catch(AuthenticationFailedException e) {
		}
		client.clearSession();
		String token = client.authenticate("user_1", "password", policy, null, "NONE");
		assertThat(verifier.verify(token), is(true));
		client.deleteAccount("user_1","password", null, "NONE");
	}

}
