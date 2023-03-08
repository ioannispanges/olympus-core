package eu.olympus.unit.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.KeyShares;
import eu.olympus.model.MFAInformation;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.ExistingUserException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.PestoAuthenticationHandler;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.PestoRefresher;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryKeyDB;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.apache.commons.codec.Charsets;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;
import org.mockito.ArgumentCaptor;

@SuppressWarnings("unused")
public class TestPestoUsernameAndCookieHandler {
	@Rule
	public final ExpectedException exception = ExpectedException.none();
	
	PestoAuthenticationHandler pestoHandler;
	InMemoryPestoDatabase db;
	BigInteger modulus;
	InMemoryKeyDB sessionDb;
	long salt;
	SoftwareServerCryptoModule crypto;
	private KeyShares masterKey;
	private long allowedTimeDiff = 1000000;
	private long waitTime = 1000;
	private long sessionLength = 10000;
	private final String user = "user1";

	@Before
	public void setup() throws Exception{
		db = new InMemoryPestoDatabase();
		sessionDb = new InMemoryKeyDB();
		crypto = new SoftwareServerCryptoModule(new Random(0));

		RSAPrivateKey pk = TestParameters.getRSAPrivateKey1();
		
		BigInteger d = pk.getPrivateExponent();
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, new BigInteger(1024, new Random(0)));
		BigInteger oprfKey = new BigInteger("42");
		Map<Integer, BigInteger> oprfBlindings = new HashMap<>();
		oprfBlindings.put(0, new BigInteger(1024, new Random(1)));
				
		modulus = pk.getModulus();
		
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		RSASharedKey sharedKey = new RSASharedKey(modulus, d, TestParameters.getRSAPublicKey1().getPublicExponent());
		masterKey = new KeyShares(sharedKey, rsaBlindings, oprfKey, oprfBlindings);
		cm.setupServer(masterKey);
		Map<String, MFAAuthenticator> mfas = new HashMap<>();
		mfas.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, crypto, sessionDb, mfas);
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		pestoHandler.addIdentityProver(TestIdentityProver.getMock(db));
		
		salt = System.currentTimeMillis();
		db.addUser(user, TestParameters.getRSAPublicKey2(), salt);
	}

	@Test
	public void testAddPartialMFASecretAlreadyReceivedEnoughSecrets() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		InMemoryKeyDB sessionDb = mock(InMemoryKeyDB.class);
		List<byte[]> partialSignatures = mock(List.class);
		doReturn(100).when(partialSignatures).size();
		doReturn(partialSignatures).when(sessionDb).getPartialSignatures(any());
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>());
		pestoHandler.addPartialServerSignature("ssid",new byte[256]);
		verify(sessionDb, times(1)).deletePartialSignatures(any());
	}

	
	@Test
	public void testPerformOPRF() throws Exception {
		ServerCryptoModule cryptoModule = new SoftwareServerCryptoModule(new Random(1));
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, new BigInteger("25"));
		Map<Integer, BigInteger> oprfBlindings = new HashMap<>();
		oprfBlindings.put(0, new BigInteger("52"));

		Long ssid = System.currentTimeMillis();
		boolean res = cryptoModule.setupServer(new KeyShares(masterKey.getRsaShare(), rsaBlindings, new BigInteger("42"),
        oprfBlindings));
		assertTrue(res);
		PestoAuthenticationHandler handler = new PestoAuthenticationHandler(db, cryptoModule, sessionDb, new HashMap<>());
		handler.setup("",masterKey,new byte[254],new HashMap<>(),0,1000000,1000,10000,new ArrayList<>());
		ECP x = ECP.generator();
		OPRFResponse response = handler.performOPRF(String.valueOf(ssid), user, x, "", "NONE");
		
		assertEquals(String.valueOf(ssid), response.getSsid());
		FP12 expectedValue = cryptoModule.hashAndPair(user.getBytes(), x);
		FP12 val2 = cryptoModule.generateBlinding(String.valueOf(ssid), 0);
		expectedValue.mul(val2);
		assertEquals(expectedValue.toString(), response.getY().toString());
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testPerformOPRFUserTimedOut() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		doReturn(System.currentTimeMillis()).when(db).getLastAuthAttempt(anyString());
		doReturn(10).when(db).getNumberOfFailedAuthAttempts(anyString());

		ServerCryptoModule cryptoModule = new SoftwareServerCryptoModule(new Random(1));
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, new BigInteger("25"));
		Map<Integer, BigInteger> oprfBlindings = new HashMap<>();
		oprfBlindings.put(0, new BigInteger("52"));

		boolean res = cryptoModule.setupServer(new KeyShares(masterKey.getRsaShare(), rsaBlindings, new BigInteger("42"),
        oprfBlindings));
		assertTrue(res);
		PestoAuthenticationHandler handler = new PestoAuthenticationHandler(db, cryptoModule, sessionDb, new HashMap<>());
		handler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		handler.performOPRF("124235", user, ECP.generator(), "", "NONE");
		fail();
	}

	@Test
	public void testNotEnoughRefreshShares() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>());
		List<PestoIdP> others = new LinkedList<PestoIdP>();
		PestoIdP other = new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), cm, 100000);

		others.add(other);
		byte[] localShare = new byte[32];
		Map<Integer, byte[]> otherShares = new HashMap<>();
		otherShares.put(1, new byte[32]);
		boolean res = pestoHandler.setup("setup", masterKey, localShare, otherShares, 1, allowedTimeDiff, waitTime, sessionLength, others);
		assertTrue(res);
		pestoHandler.addIdentityProver(TestIdentityProver.getMock(db));

		boolean refreshRes = pestoHandler.startRefresh();
		assertFalse(refreshRes);
	}

	@Test
	public void testFinishRegistrationSingleIdP() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return true;
			}

			@Override
			public boolean verifySignature(PublicKey pk, byte[] input, byte[] sig) {
				return true;
			}

			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures) {
				assertEquals(1, partialSignatures.size());
				assertEquals(new String(partialSignatures.get(0)), "signature");
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey() {
				return TestParameters.getRSAPublicKey2();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);

		pestoHandler.addIdentityProver(TestIdentityProver.getMock(db));
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(TestParameters.getRSAPrivateKey2());
		sig.update(TestParameters.getRSAPublicKey2().getEncoded());
		byte[] signature =  sig.sign();
		
		long salt = System.currentTimeMillis();
		byte[] result = pestoHandler.finishRegistration(user, "session".getBytes(), TestParameters.getRSAPublicKey2(), signature, salt, "");
		assertEquals("combinedSignature", new String(result));
	}
	
	@Test(expected = ExistingUserException.class)
	public void testFinishRegistrationExistingUser() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		pestoHandler.finishRegistration(user, "session".getBytes(), null, null, 0, null);
		fail();
	}
	
	@Test(expected = UserCreationFailedException.class)
	public void testFinishRegistrationBadSalt() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );

		long salt = System.currentTimeMillis()-10001;
		pestoHandler.finishRegistration(user, "session".getBytes(), null, null, salt, null);
		fail();
	}
	
	@Test(expected = UserCreationFailedException.class)
	public void testFinishRegistrationBadSalt2() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );

		long salt = System.currentTimeMillis()+10001;
		pestoHandler.finishRegistration(user, "session".getBytes(), null, null, salt, null);
		fail();
	}
	
	@Test
	public void testFinishRegistrationMultiIdP() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return true;
			}

			@Override
			public boolean verifySignature(PublicKey pk, byte[] input, byte[] sig) {
				return true;
			}
			
			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures)  {
				assertEquals(2, partialSignatures.size());
				assertEquals(new String(partialSignatures.get(1)), "signature");
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey() {
				return TestParameters.getRSAPublicKey2();
			}
			
			@Override
			public byte[] getBytes(int len) {
				Random rnd = new Random(0);
				byte[] res = new byte[len];
				rnd.nextBytes(res);
				return res;
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		List<PestoIdP> others = new LinkedList<PestoIdP>();

		others.add(new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), cm, 10000));
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, others);
		assertTrue(res);

		pestoHandler.addIdentityProver(TestIdentityProver.getMock(db));
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(TestParameters.getRSAPrivateKey2());
		sig.update(TestParameters.getRSAPublicKey2().getEncoded());
		sig.update(CommonRESTEndpoints.CREATE_USER.getBytes(Charsets.UTF_8));
		byte[] signature =  sig.sign();
		
		long salt = System.currentTimeMillis();
		pestoHandler.addPartialServerSignature(user, signature);
		byte[] result = pestoHandler.finishRegistration(user, "session".getBytes(), TestParameters.getRSAPublicKey2(), signature, salt, null);
		assertEquals("combinedSignature", new String(result));
	}
 	
	@Test(expected = UserCreationFailedException.class)
	public void testFinishRegistrationMultiIdPNoRespondingServer() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return true;
			}
			
			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures)  {
				assertEquals(2, partialSignatures.size());
				assertEquals(new String(partialSignatures.get(0)), "signature");
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey() {
				return TestParameters.getRSAPublicKey2();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		List<PestoIdPImpl> others = new LinkedList<PestoIdPImpl>();
		others.add(new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), cm, 10000));

		PABCConfigurationImpl conf = new PABCConfigurationImpl();
		conf.setKeyMaterial(masterKey.getRsaShare());
		conf.setRsaBlindings(masterKey.getRsaBlindings());
		conf.setOprfKey(masterKey.getOprfKey());
		conf.setOprfBlindings(masterKey.getOprfBlindings());
		conf.setId(0);
		conf.setAllowedTimeDifference(allowedTimeDiff);
		conf.setServers(Arrays.asList("1", "2", "3"));
		conf.setAttrDefinitions(generateAttributeDefinitions());
		conf.setSeed("seed".getBytes());
		conf.setLifetime(10000);
		conf.setLocalKeyShare(new byte[6]);
		conf.setRemoteShares(new HashMap<Integer, byte[]>());

		
		boolean res = others.get(0).setup("setup", conf, new LinkedList<>());
		assertTrue(res);
		res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, others);
		assertTrue(res);
		
		pestoHandler.addIdentityProver(TestIdentityProver.getMock(db));
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(TestParameters.getRSAPrivateKey2());
		sig.update(TestParameters.getRSAPublicKey2().getEncoded());
		byte[] signature =  sig.sign();
		
		long salt = System.currentTimeMillis();
		byte[] result = pestoHandler.finishRegistration(user, "session".getBytes(), TestParameters.getRSAPublicKey2(), signature, salt, "");
		fail();
	}

	private static Set<AttributeDefinition> generateAttributeDefinitions() {
		Set<AttributeDefinition> res=new HashSet<>();
		res.add(new AttributeDefinitionString("Name","Name",0,16));
		res.add(new AttributeDefinitionInteger("Age","Age",0,123));
		res.add(new AttributeDefinitionString("Nationality","Nationality",0,16));
		return res;
	}

	@Test(expected = UserCreationFailedException.class)
	public void testFinishRegistrationBadUserSignature() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return false;
			}
			
			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures)  {
				assertEquals(1, partialSignatures.size());
				assertEquals(new String(partialSignatures.get(0)), "signature");
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey(){
				return TestParameters.getRSAPublicKey2();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);

		pestoHandler.addIdentityProver(TestIdentityProver.getMock(db));
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(TestParameters.getRSAPrivateKey2());
		sig.update(TestParameters.getRSAPublicKey2().getEncoded());
		byte[] signature =  sig.sign();
		
		long salt = System.currentTimeMillis();
		pestoHandler.finishRegistration(user, "session".getBytes(), TestParameters.getRSAPublicKey2(), signature, salt, "");
		fail();
	}
	
	@Test(expected = UserCreationFailedException.class)
	public void testFinishRegistrationBadServerSignature() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				if("combinedSignature".equals(new String(sig))) {
					return false;
				}
				return true;
			}
			
			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures) {
				assertEquals(1, partialSignatures.size());
				assertEquals(new String(partialSignatures.get(0)), "signature");
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey() {
				return TestParameters.getRSAPublicKey2();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);

		pestoHandler.addIdentityProver(TestIdentityProver.getMock(db));
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(TestParameters.getRSAPrivateKey2());
		sig.update(TestParameters.getRSAPublicKey2().getEncoded());
		byte[] signature =  sig.sign();
		
		long salt = System.currentTimeMillis();
		pestoHandler.finishRegistration(user, "session".getBytes(), TestParameters.getRSAPublicKey2(), signature, salt, "");
		fail();
	}
	
	@Test
	public void testFinishRegistrationSingleIdPWithIdProof() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase() {
			private Map<String, Attribute> attributes;
			private boolean hasUser = false;
			@Override
			public boolean hasUser(String user) {
				boolean returnValue = hasUser;
				hasUser = true;
				return returnValue;
			}

			@Override
			public long getLastSalt(String username){
				return 0;
			}

			@Override
			public void addAttributes(String user, Map<String, Attribute> attributes) {
				this.attributes = attributes;
			}
			@Override
			public Map<String, Attribute> getAttributes(String user) {
				return attributes;
			}
		};
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return true;
			}

			@Override
			public boolean verifySignature(PublicKey pk, byte[] input, byte[] sig) {
				return true;
			}
			
			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures)  {
				assertEquals(1, partialSignatures.size());
				assertEquals(new String(partialSignatures.get(0)), "signature");
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey(){
				return TestParameters.getRSAPublicKey2();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);

		pestoHandler.addIdentityProver(TestIdentityProver.getMock(db));
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(TestParameters.getRSAPrivateKey2());
		sig.update(TestParameters.getRSAPublicKey2().getEncoded());
		byte[] signature =  sig.sign();
		
		long salt = System.currentTimeMillis();
		TestIdentityProof testIdProof = new TestIdentityProof();
		testIdProof.setSignature("sig");
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		testIdProof.setAttributes(attributes);
		byte[] result = pestoHandler.finishRegistration(user, "session".getBytes(), TestParameters.getRSAPublicKey2(), signature, salt, testIdProof.getStringRepresentation());
		assertEquals("combinedSignature", new String(result));
		assertEquals(1, db.getAttributes(user).keySet().size());
		assertEquals(new Attribute("John"), db.getAttributes(user).get("name"));
	}

	@Test
	public void testFinishRegistrationSingleIdPNoIdProof() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase() {
			private Map<String, Attribute> attributes;
			private boolean hasUser = false;
			@Override
			public boolean hasUser(String user) {
				boolean returnValue = hasUser;
				hasUser = true;
				return returnValue;
			}

			@Override
			public long getLastSalt(String username){
				return 0;
			}

			@Override
			public void addAttributes(String user, Map<String, Attribute> attributes) {
				this.attributes = attributes;
			}
			@Override
			public Map<String, Attribute> getAttributes(String user) {
				return attributes;
			}
		};
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return true;
			}

			@Override
			public boolean verifySignature(PublicKey pk, byte[] input, byte[] sig) {
				return true;
			}

			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures)  {
				assertEquals(1, partialSignatures.size());
				assertEquals(new String(partialSignatures.get(0)), "signature");
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey(){
				return TestParameters.getRSAPublicKey2();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);

		pestoHandler.addIdentityProver(TestIdentityProver.getMock(db));
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(TestParameters.getRSAPrivateKey2());
		sig.update(TestParameters.getRSAPublicKey2().getEncoded());
		byte[] signature =  sig.sign();
		
		long salt = System.currentTimeMillis();



		byte[] result = pestoHandler.finishRegistration(user, "session".getBytes(), TestParameters.getRSAPublicKey2(), signature, salt, null);
		assertEquals("combinedSignature", new String(result));
	}

	
	
	@Test
	public void testAuthenticate() throws OperationFailedException {
		Long globalSalt = System.currentTimeMillis();
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(globalSalt-3).when(db).getLastSalt(anyString());
		doReturn(TestParameters.getRSAPublicKey1()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = mockCrypto();

		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		boolean auth = pestoHandler.validateUsernameAndSignature(user, "session".getBytes(), globalSalt, "signature".getBytes(), "dummy");
		assertTrue(auth);
		ArgumentCaptor<String> userCaptor  = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<Long> longCaptor = ArgumentCaptor.forClass(Long.class);
		verify(db,times(1)).getLastSalt(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
		verify(db,times(1)).setSalt(anyString(),longCaptor.capture());
		verify(db,times(1)).clearFailedAuthAttempts(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
		assertEquals(longCaptor.getValue(),globalSalt);
	}

	//Test that failed authenticate results in db.failedAuthAttempt is called with username as argument.
	@Test
	public void testFailedAuthenticate() throws OperationFailedException {
		Long globalSalt = System.currentTimeMillis();
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		doReturn(globalSalt-3).when(db).getLastSalt(anyString());
		doReturn(TestParameters.getRSAPublicKey1()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = mockCrypto();

		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		boolean auth = pestoHandler.validateUsernameAndSignature(user, "session".getBytes(), globalSalt, "invalidSignature".getBytes(), "dummy");
		assertFalse(auth);
		ArgumentCaptor<String> userCaptor  = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<Long> longCaptor = ArgumentCaptor.forClass(Long.class);
		verify(db,times(1)).failedAuthAttempt(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
	}

	@Test
	public void testRepeatedFailedAuthenticate() throws OperationFailedException {
		Long globalSalt = System.currentTimeMillis();
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		doReturn(globalSalt-3).when(db).getLastSalt(anyString());
		doReturn(TestParameters.getRSAPublicKey1()).when(db).getUserKey(anyString());
		doReturn(System.currentTimeMillis()).when(db).getLastAuthAttempt(anyString());
		doReturn(10).when(db).getNumberOfFailedAuthAttempts(anyString());

		ServerCryptoModule cm = mockCrypto();

		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		boolean auth = pestoHandler.validateUsernameAndSignature(user, "session".getBytes(), globalSalt, "signature".getBytes(), "dummy");
		assertFalse(auth);
		ArgumentCaptor<String> userCaptor  = ArgumentCaptor.forClass(String.class);
		verify(db,times(1)).getLastAuthAttempt(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
		verify(db,times(1)).getNumberOfFailedAuthAttempts(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
	}
	
	@Test
	public void testAuthenticateBadSignature() throws Exception {
		Long globalSalt = System.currentTimeMillis();
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(globalSalt-3).when(db).getLastSalt(anyString());
		doReturn(TestParameters.getRSAPublicKey1()).when(db).getUserKey(anyString());


		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return false;
			}
			
			@Override
			public byte[] constructNonce(String username, long salt) {
				return "nonce".getBytes();
			}
			
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		boolean auth = pestoHandler.validateUsernameAndSignature(user, "session".getBytes(), globalSalt, "signature".getBytes(), "dummy");
		assertFalse(auth);

		ArgumentCaptor<String> userCaptor  = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<Long> longCaptor = ArgumentCaptor.forClass(Long.class);
		verify(db,times(1)).getLastSalt(userCaptor.capture());
		verify(db,times(1)).setSalt(anyString(),longCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
		assertEquals(longCaptor.getValue(),globalSalt);
	}
	
	@Test
	public void testAuthenticateNoUserKey() throws Exception {
		long globalSalt = System.currentTimeMillis();
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(null).when(db).getUserKey(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		boolean auth = pestoHandler.validateUsernameAndSignature(user, "session".getBytes(), globalSalt, "signature".getBytes(), "dummy");
		assertFalse(auth);

		ArgumentCaptor<String> userCaptor  = ArgumentCaptor.forClass(String.class);
		verify(db,times(1)).getUserKey(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
	}
	
	@Test
	public void testAuthenticateTooOldSalt() throws Exception {
		long globalSalt = System.currentTimeMillis();
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(globalSalt+3).when(db).getLastSalt(anyString());
		doReturn(TestParameters.getRSAPublicKey2()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		boolean auth = pestoHandler.validateUsernameAndSignature(user, "session".getBytes(), globalSalt, "signature".getBytes(), "dummy");
		assertFalse(auth);

		ArgumentCaptor<String> userCaptor  = ArgumentCaptor.forClass(String.class);
		verify(db,times(1)).getLastSalt(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
		verify(db,times(1)).getUserKey(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
	}
	
	@Test
	public void testAuthenticateSaltDeviateFromCurrentTime() throws Exception {
		long globalSalt = System.currentTimeMillis()+10501;
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(globalSalt-3).when(db).getLastSalt(anyString());
		doReturn(TestParameters.getRSAPublicKey2()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		boolean auth = pestoHandler.validateUsernameAndSignature(user, "session".getBytes(), globalSalt, "signature".getBytes(), "dummy");
		assertFalse(auth);


		ArgumentCaptor<String> userCaptor  = ArgumentCaptor.forClass(String.class);
		verify(db,times(1)).getLastSalt(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
		verify(db,times(1)).getUserKey(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
	}
	
	@Test
	public void testAuthenticateSaltDeviateFromCurrentTime2() throws Exception {
		long globalSalt = System.currentTimeMillis()-10501;
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(globalSalt-3).when(db).getLastSalt(anyString());
		doReturn(TestParameters.getRSAPublicKey2()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		boolean auth = pestoHandler.validateUsernameAndSignature(user, "session".getBytes(), globalSalt, "signature".getBytes(), "dummy");
		assertFalse(auth);

		ArgumentCaptor<String> userCaptor  = ArgumentCaptor.forClass(String.class);
		verify(db,times(1)).getLastSalt(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
		verify(db,times(1)).getUserKey(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
	}
	
	@Test
	public void testChangePassword() throws Exception {

		long globalSalt = System.currentTimeMillis()-10501;
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(globalSalt-3).when(db).getLastSalt(anyString());
		doReturn(TestParameters.getRSAPublicKey1()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return verifySignature(pk, list.get(0), sig);
			}

			@Override
			public boolean verifySignature(PublicKey pk, byte[] input, byte[] sig) {
				if(pk.equals(TestParameters.getRSAPublicKey1()) && "oldKeySignature".equals(new String(sig))) {
					return true;
				}
				if(pk.equals(TestParameters.getRSAPublicKey2()) && "combinedSignature".equals(new String(sig))) {
					return true;
				}
				if(pk.equals(TestParameters.getRSAPublicKey2()) && "newKeySignature".equals(new String(sig))) {
					return true;
				}
				return false;
			}
			
			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures)  {
				assertEquals(1, partialSignatures.size());
				assertEquals("signature", new String(partialSignatures.get(0)));
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey(){
				return TestParameters.getRSAPublicKey2();
			}
			
			@Override
			public byte[] constructNonce(String username, long salt) {
				return "nonce".getBytes();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		byte[] oldSignature =  "oldKeySignature".getBytes();
		byte[] newSignature =  "newKeySignature".getBytes();
		
		long salt = System.currentTimeMillis();
		byte[] result = pestoHandler.changePassword(user, "cookie".getBytes(), TestParameters.getRSAPublicKey2(), oldSignature, newSignature, salt);
		assertEquals("combinedSignature", new String(result));


		ArgumentCaptor<String> userCaptor  = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<PublicKey> keyCaptor  = ArgumentCaptor.forClass(PublicKey.class);
		verify(db,times(1)).replaceUserKey(userCaptor.capture(),keyCaptor.capture(),anyLong());
		assertEquals(userCaptor.getValue(),user);
		assertEquals(keyCaptor.getValue(),TestParameters.getRSAPublicKey2());

		verify(db,times(1)).getUserKey(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
	}
	
	@Test
	public void testChangePasswordMultiIdP() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(TestParameters.getRSAPublicKey1()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return verifySignature(pk, list.get(0), sig);
			}

			@Override
			public boolean verifySignature(PublicKey pk, byte[] input, byte[] sig) {
				if(pk.equals(TestParameters.getRSAPublicKey1()) && "oldKeySignature".equals(new String(sig))) {
					return true;
				}
				if(pk.equals(TestParameters.getRSAPublicKey2()) && "combinedSignature".equals(new String(sig))) {
					return true;
				}
				if(pk.equals(TestParameters.getRSAPublicKey2()) && "newKeySignature".equals(new String(sig))) {
					return true;
				}
				return false;
			}
			
			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures)  {
				assertEquals(2, partialSignatures.size());
				assertEquals("signature", new String(partialSignatures.get(1)));
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey(){
				return TestParameters.getRSAPublicKey2();
			}
			
			@Override
			public byte[] constructNonce(String username, long salt) {
				return "nonce".getBytes();
			}
			
			@Override
			public byte[] getBytes(int len) {
				Random rnd = new Random(0);
				byte[] res = new byte[len];
				rnd.nextBytes(res);
				return res;
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		
		List<PestoIdP> others = new LinkedList<PestoIdP>();

		others.add(new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), cm, 10000));
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, others);
		assertTrue(res);
		byte[] oldsignature =  "oldKeySignature".getBytes();
		byte[] newSignature =  "newKeySignature".getBytes();
		
		long salt = System.currentTimeMillis();
		pestoHandler.addPartialServerSignature(user, oldsignature);
		byte[] result = pestoHandler.changePassword(user, "cookie".getBytes(), TestParameters.getRSAPublicKey2(), oldsignature, newSignature, salt);
		assertEquals("combinedSignature", new String(result));

		ArgumentCaptor<String> userCaptor  = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<PublicKey> keyCaptor  = ArgumentCaptor.forClass(PublicKey.class);
		verify(db,times(1)).replaceUserKey(userCaptor.capture(),keyCaptor.capture(),anyLong());
		assertEquals(userCaptor.getValue(),user);
		assertEquals(keyCaptor.getValue(),TestParameters.getRSAPublicKey2());

		verify(db,times(1)).getUserKey(userCaptor.capture());
		assertEquals(userCaptor.getValue(),user);
	}
	
	@Test(expected = OperationFailedException.class)
	public void testChangePasswordMultiIdPNonRespondingServer() throws Exception {

		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(TestParameters.getRSAPublicKey1()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
			return verifySignature(pk, list.get(0), sig);
			}

			@Override
			public boolean verifySignature(PublicKey pk, byte[] input, byte[] sig) {
				if(pk.equals(TestParameters.getRSAPublicKey1()) && "oldKeySignature".equals(new String(sig))) {
					return true;
				}
				if(pk.equals(TestParameters.getRSAPublicKey2()) && "combinedSignature".equals(new String(sig))) {
					return true;
				}
				if(pk.equals(TestParameters.getRSAPublicKey2()) && "newKeySignature".equals(new String(sig))) {
					return true;
				}
				return false;
			}
			
			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures)  {
				assertEquals(2, partialSignatures.size());
				assertEquals("signature", new String(partialSignatures.get(0)));
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey(){
				return TestParameters.getRSAPublicKey2();
			}
			
			@Override
			public byte[] constructNonce(String username, long salt) {
				return "nonce".getBytes();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		
		List<PestoIdPImpl> others = new LinkedList<PestoIdPImpl>();
		others.add(new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), cm, 10000));
		PABCConfigurationImpl conf = new PABCConfigurationImpl();
		conf.setKeyMaterial(masterKey.getRsaShare());
		conf.setRsaBlindings(masterKey.getRsaBlindings());
		conf.setOprfKey(masterKey.getOprfKey());
		conf.setOprfBlindings(masterKey.getOprfBlindings());
		conf.setId(0);
		conf.setAllowedTimeDifference(allowedTimeDiff);
		conf.setServers(Arrays.asList("1", "2", "3"));
		conf.setAttrDefinitions(generateAttributeDefinitions());
		conf.setSeed("seed".getBytes());
		conf.setLifetime(10000);
		conf.setLocalKeyShare(new byte[6]);
		conf.setRemoteShares(new HashMap<Integer, byte[]>());
		boolean res = others.get(0).setup("setup", conf, new ArrayList<>());
		assertTrue(res);
		res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, others);
		assertTrue(res);
		byte[] oldsignature =  "oldKeySignature".getBytes();
		byte[] newSignature =  "newKeySignature".getBytes();
		
		long salt = System.currentTimeMillis();
		byte[] result = pestoHandler.changePassword(user, "cookie".getBytes(), TestParameters.getRSAPublicKey2(), oldsignature, newSignature, salt);
		fail();
	}
	
	@Test(expected = OperationFailedException.class)
	public void testChangePasswordNoUser() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		doReturn(TestParameters.getRSAPublicKey1()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		pestoHandler.changePassword(user, "cookie".getBytes(), null, null, null, 0);
		fail();
	}
	
	@Test(expected = OperationFailedException.class)
	public void testChangePasswordBadSalt() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		long salt = System.currentTimeMillis()-10001;
		pestoHandler.changePassword(user, "cookie".getBytes(), null, null, null, salt);
		fail();
	}
	
	@Test(expected = OperationFailedException.class)
	public void testChangePasswordBadSalt2() throws Exception {
		long globalSalt = System.currentTimeMillis()-10501;
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(globalSalt-3).when(db).getLastSalt(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		pestoHandler.changePassword(user, "cookie".getBytes(), null, null, null, globalSalt);
		fail();
	}
	
	@Test(expected = OperationFailedException.class)
	public void testChangePasswordBadSignature() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(TestParameters.getRSAPublicKey1()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return false;
			}
			
			@Override
			public byte[] constructNonce(String username, long salt) {
				return "nonce".getBytes();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);
		byte[] signature =  "oldKeySignature".getBytes();
		byte[] newSignature =  "newKeySignature".getBytes();
		
		long salt = System.currentTimeMillis();
		pestoHandler.changePassword(user, "cookie".getBytes(), TestParameters.getRSAPublicKey2(), signature, newSignature, salt);
		fail();
	}
	
	
	@Test(expected = OperationFailedException.class)
	public void testChangePasswordBadServerSignature() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());
		doReturn(TestParameters.getRSAPublicKey1()).when(db).getUserKey(anyString());

		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public boolean verifySignature(PublicKey pk, List<byte[]> list, byte[] sig) {
				return verifySignature(pk, list.get(0), sig);
			}

			@Override
			public boolean verifySignature(PublicKey pk, byte[] input, byte[] sig) {
				if(pk.equals(TestParameters.getRSAPublicKey1()) && "oldKeySignature".equals(new String(sig))) {
					return true;
				}
				if(pk.equals(TestParameters.getRSAPublicKey2()) && "newKeySignature".equals(new String(sig))) {
					return true;
				}
				return false;
			}
			
			@Override
			public byte[] sign(PublicKey pk, byte[] bytes, int myId) {
				assertEquals(TestParameters.getRSAPublicKey2(), pk);
				assertEquals(0, myId);
				return "signature".getBytes();
			}
			
			@Override
			public byte[] combineSignatures(List<byte[]> partialSignatures)  {
				assertEquals(1, partialSignatures.size());
				assertEquals("signature", new String(partialSignatures.get(0)));
				return "combinedSignature".getBytes();
			}
			@Override
			public PublicKey getStandardRSAkey(){
				return TestParameters.getRSAPublicKey2();
			}
			
			@Override
			public byte[] constructNonce(String username, long salt) {
				return "nonce".getBytes();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, new LinkedList<PestoIdP>());
		assertTrue(res);

		byte[] signature =  "oldKeySignature".getBytes();
		byte[] newSignature =  "newKeySignature".getBytes();
		
		long salt = System.currentTimeMillis();
		pestoHandler.changePassword(user, "cookie".getBytes(), TestParameters.getRSAPublicKey2(), signature, newSignature, salt);
		fail();
	}
	
	@Test //Tests that we cannot add server signatures for the same ssid indefinitely 
	public void testAddPartialServerSignature() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto) throws Exception {
				super(database, crypto, sessionDb, new HashMap<>() );
			}

			public int countPartialSignatures(String username) {
				return sessionDb.getPartialSignatures(username).size();
			}
		}
		
		InMemoryPestoDatabase db = new InMemoryPestoDatabase();
		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));

		RSAPrivateKey pk = TestParameters.getRSAPrivateKey1();
		
		BigInteger d = pk.getPrivateExponent();
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, new BigInteger(1024, new Random(0)));
		BigInteger oprfKey = new BigInteger("42");
		Map<Integer, BigInteger> oprfBlindings = new HashMap<>();
		oprfBlindings.put(0, new BigInteger(1024, new Random(1)));
				
		BigInteger modulus = pk.getModulus();
		
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		RSASharedKey sharedKey = new RSASharedKey(modulus, d, TestParameters.getRSAPublicKey1().getPublicExponent());
		cm.setupServer(new KeyShares(sharedKey, rsaBlindings, oprfKey, oprfBlindings));
		
		TestHandler handler = new TestHandler(db, crypto);

		handler.addPartialServerSignature("ssid", "signature".getBytes());
		assertEquals(1, handler.countPartialSignatures("ssid"));
		handler.addPartialServerSignature("ssid", "signature".getBytes());
		assertEquals(1, handler.countPartialSignatures("ssid"));
	}
	
	@Test //Tests that we cannot add mastershares indefinitely
	public void testAddMasterShares() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto) throws Exception {
				super(database, crypto, sessionDb, new HashMap<>() );
			}

			public int countMasterShares() {
				return sessionDb.getMasterShares().size();
			}
		}
		
		InMemoryPestoDatabase db = new InMemoryPestoDatabase();
		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));

		RSAPrivateKey pk = TestParameters.getRSAPrivateKey1();
		
		BigInteger d = pk.getPrivateExponent();
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, new BigInteger(1024, new Random(0)));
		BigInteger oprfKey = new BigInteger("42");
		Map<Integer, BigInteger> oprfBlindings = new HashMap<>();
		oprfBlindings.put(0, new BigInteger(1024, new Random(1)));
				
		BigInteger modulus = pk.getModulus();
		
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		RSASharedKey sharedKey = new RSASharedKey(modulus, d, TestParameters.getRSAPublicKey1().getPublicExponent());
		cm.setupServer(new KeyShares(sharedKey, rsaBlindings, oprfKey, oprfBlindings));
		
		TestHandler handler = new TestHandler(db, crypto);

		handler.addMasterShare("ssid", "signature".getBytes());
		assertEquals(1, handler.countMasterShares());
		handler.addMasterShare("ssid", "signature".getBytes());
		assertEquals(1, handler.countMasterShares());
	}
	
	@Test
	public void testGenerateMFAToken() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto, Map<String, MFAAuthenticator> mfas) throws Exception {
				super(database, crypto, sessionDb, mfas);
			}
		}

		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());

		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public byte[] getBytes(int count) {
				return "asdasdasdasdasdasdas".getBytes();
			}
		};
		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
		TestHandler handler = new TestHandler(db, crypto, mfaAuthenticators);
		String secret = handler.requestMFASecret("user1", GoogleAuthenticator.TYPE);
		assertEquals("MFZWIYLTMRQXGZDBONSGC43EMFZWIYLT", secret);


		ArgumentCaptor<String> stringArgumentCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<PublicKey> keyCaptor  = ArgumentCaptor.forClass(PublicKey.class);
		verify(db,times(1)).assignMFASecret(stringArgumentCaptor.capture(),stringArgumentCaptor.capture(),stringArgumentCaptor.capture());
		assertEquals("user1",stringArgumentCaptor.getAllValues().get(0));
		assertEquals(GoogleAuthenticator.TYPE,stringArgumentCaptor.getAllValues().get(1));
		assertEquals("MFZWIYLTMRQXGZDBONSGC43EMFZWIYLT",stringArgumentCaptor.getAllValues().get(2));
	}
	
	@Test
	public void testGenerateMFATokenMultiServer() throws Exception {
		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public byte[] getBytes(int count) {
				return "asdasdasdasdasdasdas".getBytes();
			}
		};

		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());

		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, crypto, sessionDb, mfaAuthenticators);

		List<PestoIdP> others = new LinkedList<PestoIdP>();

		others.add(new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), crypto, 10000) {
			@Override
			public void addPartialMFASecret(String user, String bytes, String type) {
				assertEquals("user1", user);
			}
		});
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, others);
		assertTrue(res);
		// A is 0 in base32
		pestoHandler.addPartialMFASecret("user1", new String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), GoogleAuthenticator.TYPE);

		String secret = pestoHandler.requestMFASecret("user1", GoogleAuthenticator.TYPE);
		assertEquals("MFZWIYLTMRQXGZDBONSGC43EMFZWIYLT", secret);

		ArgumentCaptor<String> stringArgumentCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<PublicKey> keyCaptor  = ArgumentCaptor.forClass(PublicKey.class);
		verify(db,times(1)).assignMFASecret(stringArgumentCaptor.capture(),stringArgumentCaptor.capture(),stringArgumentCaptor.capture());
		assertEquals("user1",stringArgumentCaptor.getAllValues().get(0));
		assertEquals(GoogleAuthenticator.TYPE,stringArgumentCaptor.getAllValues().get(1));
		assertEquals("MFZWIYLTMRQXGZDBONSGC43EMFZWIYLT",stringArgumentCaptor.getAllValues().get(2));
	}

	@Test(expected = OperationFailedException.class)
	public void testGenerateMFATokenNonRespondingServer() throws Exception {
		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public byte[] getBytes(int count) {
				return "asdasdasdasdasdasdas".getBytes();
			}
		};

		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser(anyString());

		Map<String, MFAAuthenticator> mfas = new HashMap<>();
		mfas.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, crypto, sessionDb, mfas);
		List<PestoIdP> others = new LinkedList<PestoIdP>();

		others.add(new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), crypto, 10000) {
			@Override
			public void addPartialMFASecret(String user, String bytes, String type) {
				assertEquals("user1", user);
			}
		});
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, others);
		assertTrue(res);
		String secret = pestoHandler.requestMFASecret("user1", GoogleAuthenticator.TYPE);
		fail();
	}
	
	@Test(expected=OperationFailedException.class)
	public void testGenerateMFATokenNoUser() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto, Map<String, MFAAuthenticator> mfaAuthenticators ) throws Exception {
				super(database, crypto, sessionDb, mfaAuthenticators);
			}
		}


		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());

		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));
		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
		TestHandler handler = new TestHandler(db, crypto, mfaAuthenticators);
		String secret = handler.requestMFASecret("user1", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test //Tests that we cannot add server secrets for the same ssid indefinitely 
	public void testAddPartialMFASecret() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto, Map<String, MFAAuthenticator> mfaAuthenticators) throws Exception {
				super(database, crypto, sessionDb, mfaAuthenticators );
			}

			public int countPartialSecrets(String username) {
				return sessionDb.getPartialMFASecrets(username).size();
			}
		}
		
		InMemoryPestoDatabase db = new InMemoryPestoDatabase();
		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));
		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
		TestHandler handler = new TestHandler(db, crypto, mfaAuthenticators);

		handler.addPartialMFASecret("ssid", "signature", "Test");
		assertEquals(1, handler.countPartialSecrets("i9eNeib6iCk+a0zB/HGsMS6NB9burrUQUh8BbE2Tc/g/wKiRwriP7Dfzisa7Kpzq7TyHNcMg4dnghyguDfUg0g=="));
	}
	
	@Test
	public void testValidateMFAToken() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto, Map<String, MFAAuthenticator> mfaAuthenticators) throws Exception {
				super(database, crypto, sessionDb, mfaAuthenticators );
			}
		}
		
		InMemoryPestoDatabase db = new InMemoryPestoDatabase();
		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));
		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		GoogleAuthenticator ga = new GoogleAuthenticator(crypto);
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, ga);
		TestHandler handler = new TestHandler(db, crypto, mfaAuthenticators);
		
		db.addUser("user1", TestParameters.getRSAPublicKey1(), salt);
		db.assignMFASecret("user1", GoogleAuthenticator.TYPE, "secret");
		// If no MFA in place, any token or type will be validated
		assertTrue(handler.validateMFAToken("user1", null, null));
		// However, if no MFA is in place, it will not be possible to validate it conservatively
		assertFalse(handler.conservativeMFAValidation("user1", null, null));
		// If the MFA is not activated, any token will pass
		assertTrue(handler.validateMFAToken("user1", null, GoogleAuthenticator.TYPE));
		// Unless evaluated conservatively
		assertFalse(handler.conservativeMFAValidation("user1", null, GoogleAuthenticator.TYPE));
		// This is even the case if the correct secret is used
		assertFalse(handler.conservativeMFAValidation("user1", "secret", GoogleAuthenticator.TYPE));
		
		db.activateMFA("user1", GoogleAuthenticator.TYPE);
		assertTrue(handler.validateMFAToken("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));
		assertFalse(handler.validateMFAToken("user1", ga.generateTOTP("not_my_secret"), GoogleAuthenticator.TYPE));
		assertFalse(handler.validateMFAToken("user1", "Not a token", GoogleAuthenticator.TYPE));
		// Cannot validate against a wrong MFA
		assertFalse(handler.validateMFAToken("user1", ga.generateTOTP("secret"), "NONE"));
		assertFalse(handler.validateMFAToken("user1", null, "NONE"));
		// Cannot validate for a non-existent user
		assertFalse(handler.validateMFAToken("user", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));

		db.deleteMFA("user1", GoogleAuthenticator.TYPE);
		// Cannot conservatively validate after the MFA has been deleted
		assertFalse(handler.conservativeMFAValidation("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));
		// However, in general validation should pass when there is no MFA
		assertTrue(handler.validateMFAToken("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));
	}

	@Test
	public void testMFAThrottling() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto, Map<String, MFAAuthenticator> mfaAuthenticators) throws Exception {
				super(database, crypto, sessionDb, mfaAuthenticators );
			}
		}
		Map<String, MFAInformation> mockMFAInfo = new HashMap<>();
		MFAInformation mfaInfo = new MFAInformation(GoogleAuthenticator.TYPE,"secret",1000,true);
		mockMFAInfo.put(GoogleAuthenticator.TYPE, mfaInfo);

		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser("user1");
		doReturn(mockMFAInfo).when(db).getMFAInformation("user1");
		doReturn(0).when(db).getNumberOfFailedMFAAttempts("user1");

		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));
		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		GoogleAuthenticator ga = mock(GoogleAuthenticator.class);
		doReturn(true).when(ga).isValid(anyString(),anyString());
		doReturn(10L).when(ga).getTimeoutPeriod();

		mfaAuthenticators.put(GoogleAuthenticator.TYPE, ga);
		TestHandler handler = new TestHandler(db, crypto, mfaAuthenticators);


		// Valid MFA token
		assertTrue(handler.conservativeMFAValidation("user1", "token", GoogleAuthenticator.TYPE));
		ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);
		verify(db, times(1)).clearFailedMFAAttempts(usernameCaptor.capture());
		assertEquals("user1",usernameCaptor.getValue());

		// Invalid MFA token
		doReturn(false).when(ga).isValid(anyString(),anyString());
		assertFalse(handler.conservativeMFAValidation("user1", "token", GoogleAuthenticator.TYPE));
		verify(db, times(1)).failedMFAAttempt(usernameCaptor.capture());
		assertEquals("user1",usernameCaptor.getValue());

		// Too many failed attempts, timeout not over
		doReturn(5).when(db).getNumberOfFailedMFAAttempts("user1");
		doReturn(System.currentTimeMillis()).when(db).getLastMFAAttempt("user1");
		assertFalse(handler.conservativeMFAValidation("user1", "token", GoogleAuthenticator.TYPE));

		// Too many failed attempts, timeout over, valid token
		doReturn(true).when(ga).isValid(anyString(),anyString());
		doReturn(3).when(db).getNumberOfFailedMFAAttempts("user1");
		doReturn(System.currentTimeMillis()).when(db).getLastMFAAttempt("user1");
		assertFalse(handler.conservativeMFAValidation("user1", "token", GoogleAuthenticator.TYPE));
		doReturn(System.currentTimeMillis() - 400).when(db).getLastMFAAttempt("user1");
		assertTrue(handler.conservativeMFAValidation("user1", "token", GoogleAuthenticator.TYPE));
	}
	
	@Test
	public void testActivateMFA() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto, Map<String, MFAAuthenticator> mfaAuthenticators) throws Exception {
				super(database, crypto, sessionDb, mfaAuthenticators );
			}
		}

		InMemoryPestoDatabase db = new InMemoryPestoDatabase();
		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));
		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		GoogleAuthenticator ga = new GoogleAuthenticator(crypto);
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, ga);
		TestHandler handler = new TestHandler(db, crypto, mfaAuthenticators);

		db.addUser("user1", TestParameters.getRSAPublicKey1(), salt);
		db.assignMFASecret("user1", GoogleAuthenticator.TYPE, "secret");

		assertTrue(handler.activateMFA("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));
		// Double activate works fine
		assertTrue(handler.activateMFA("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));
		// Does not validate with wrong secret
		assertFalse(handler.activateMFA("user1", ga.generateTOTP("3fes4"), GoogleAuthenticator.TYPE));
		// Or with wrong type
		assertFalse(handler.activateMFA("user1", ga.generateTOTP("secret"), "NONE"));
		// Or wrong username
		assertFalse(handler.activateMFA("user", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));
		// Can still activate
		assertTrue(handler.activateMFA("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));
	}

	@Test
	public void testActivationTimeout() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto, Map<String, MFAAuthenticator> mfaAuthenticators) throws Exception {
				super(database, crypto, sessionDb, mfaAuthenticators );
			}
		}
		Map<String, MFAInformation> mockMFAInfo = new HashMap<>();
		MFAInformation mfaInfo = new MFAInformation(GoogleAuthenticator.TYPE,"secret",1000,true);
		mockMFAInfo.put(GoogleAuthenticator.TYPE, mfaInfo);

		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(true).when(db).hasUser("user1");
		doReturn(mockMFAInfo).when(db).getMFAInformation("user1");
		doReturn(0).when(db).getNumberOfFailedMFAAttempts("user1");

		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));
		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		GoogleAuthenticator ga = mock(GoogleAuthenticator.class);
		doReturn(true).when(ga).isValid(anyString(),anyString());
		doReturn(10L).when(ga).getTimeoutPeriod();

		mfaAuthenticators.put(GoogleAuthenticator.TYPE, ga);
		TestHandler handler = new TestHandler(db, crypto, mfaAuthenticators);

		// Cannot activate in case of time out
		doReturn(3).when(db).getNumberOfFailedMFAAttempts("user1");
		doReturn(System.currentTimeMillis()).when(db).getLastMFAAttempt("user1");
		assertFalse(handler.activateMFA("user1","secret", GoogleAuthenticator.TYPE));
		// Timeout period is 10 ms, so 10*2^3 = 80
		doReturn(System.currentTimeMillis() - 80).when(db).getLastMFAAttempt("user1");
		// Should now be able to activate
		assertTrue(handler.activateMFA("user1", "secret", GoogleAuthenticator.TYPE));
		// Should also be able to validate
		assertTrue(handler.conservativeMFAValidation("user1", "secret", GoogleAuthenticator.TYPE));
	}

	@Test
	public void testDeleteMFA() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto, Map<String, MFAAuthenticator> mfaAuthenticators) throws Exception {
				super(database, crypto, sessionDb, mfaAuthenticators );
			}
		}

		InMemoryPestoDatabase db = new InMemoryPestoDatabase();
		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));
		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		GoogleAuthenticator ga = new GoogleAuthenticator(crypto);
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, ga);
		TestHandler handler = new TestHandler(db, crypto, mfaAuthenticators);

		db.addUser("user1", TestParameters.getRSAPublicKey1(), salt);
		// Cannot delete a non existing MFA
		assertFalse(handler.deleteMFA("user1", null, "NONE"));

		db.assignMFASecret("user1", GoogleAuthenticator.TYPE, "secret");
		// Cannot delete a non activated MFA
		assertFalse(handler.deleteMFA("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));
		// Ensure the authenticator is still there and usable
		assertTrue(handler.activateMFA("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));
		assertTrue(handler.validateMFAToken("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));

		// Ensure that it can be deleted
		assertTrue(handler.deleteMFA("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));

		// Ensure that it can be added again
		db.assignMFASecret("user1", GoogleAuthenticator.TYPE, "2ndsecret");
		assertTrue(handler.activateMFA("user1", ga.generateTOTP("2ndsecret"), GoogleAuthenticator.TYPE));
		assertTrue(handler.validateMFAToken("user1", ga.generateTOTP("2ndsecret"), GoogleAuthenticator.TYPE));

		// Ensure that the right MFA is needed for deletion
		assertFalse(handler.deleteMFA("user1", ga.generateTOTP("secret"), GoogleAuthenticator.TYPE));
		// and right username
		assertFalse(handler.deleteMFA("user", ga.generateTOTP("2ndsecret"), GoogleAuthenticator.TYPE));
		// and right type
		assertFalse(handler.deleteMFA("user1", ga.generateTOTP("2ndsecret"), "NONE"));
		assertTrue(handler.deleteMFA("user1", ga.generateTOTP("2ndsecret"), GoogleAuthenticator.TYPE));
	}


	@Test
	public void testGenerateSessionCookie() throws Exception {
		class TestHandler extends PestoAuthenticationHandler {
			public TestHandler(PestoDatabase database, ServerCryptoModule crypto, Map<String, MFAAuthenticator> mfaAuthenticators) throws Exception {
				super(database, crypto, sessionDb, mfaAuthenticators );
			}
			
			@Override
			public void validateSession(String cookie, List<Role> roles) {
			}
		}
		final List<String> tokens = new LinkedList<>();
		InMemoryPestoDatabase db = new InMemoryPestoDatabase();
		SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));
		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
		TestHandler handler = new TestHandler(db, crypto, mfaAuthenticators);
		String cookie = handler.generateSessionCookie("user1");

		handler.validateSession(cookie, Arrays.asList(Role.USER));
	}
	
	@Test
	public void testStartRefreshIdPFailing() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		List<PestoIdP> others = new LinkedList<PestoIdP>();
		others.add(new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), cm, 10000) {
			@Override
			public void addMasterShare(String ssid, byte[] share) {
				throw new RuntimeException();
			}
		});
		boolean res = pestoHandler.setup("setup", masterKey, new byte[6], new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, others);
		assertTrue(res);
		assertFalse(pestoHandler.startRefresh());
	}
	
	
	@Test
	public void testStartRefreshSSIDSAndSharesInconsistant() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0)) {
			@Override
			public byte[] hashList(List<byte[]> input) {
				fail("Test should have failed earlier");
				return null;
			}
		};
		InMemoryKeyDB keyDB = new InMemoryKeyDB() {
			@Override
			public List<String> getSsids() {
				return Arrays.asList();
			}
		};
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, keyDB, new HashMap<>() );
		List<PestoIdP> others = new LinkedList<PestoIdP>();
		others.add(new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), cm, 10000));
		assertFalse(pestoHandler.startRefresh());
	}
	
	@Test
	public void testStartRefreshBadKeyDigest() throws Exception {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(new byte[] {0x00, 0x11, 0x22, 0x33}).when(db).getKeyDigest();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(0));
		PestoAuthenticationHandler pestoHandler = new PestoAuthenticationHandler(db, cm, sessionDb, new HashMap<>() );
		List<PestoIdP> others = new LinkedList<PestoIdP>();
		others.add(new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), cm, 10000));
		//others.get(0).startRefresh();
		PestoRefresher refresher = new PestoRefresher(0, cm);
		List<byte[]> shares = refresher.reshareMasterKeys(masterKey, 1);
		boolean res = pestoHandler.setup("setup", masterKey, shares.get(0), new HashMap<Integer, byte[]>(), 0, allowedTimeDiff, waitTime, sessionLength, others);
		assertTrue(res);
		byte[] share1 = db.getKeyShare(0);
		sessionDb.addMasterShare("some-ssid", new byte[1851]);
		boolean val = pestoHandler.startRefresh();
		assertFalse(val);
	}

	private ServerCryptoModule mockCrypto(){
		ServerCryptoModule cm = mock(ServerCryptoModule.class);
		doAnswer(i -> "signature".equals(new String(i.getArgument(2,byte[].class)))).when(cm).verifySignature(any(),anyList(),any());
		doReturn("nonce".getBytes()).when(cm).constructNonce(anyString(),anyLong());
		doReturn(new byte[256]).when(cm).hashList(any());
		doReturn(true).when(cm).setupServer(any());
		return cm;
	}
}
