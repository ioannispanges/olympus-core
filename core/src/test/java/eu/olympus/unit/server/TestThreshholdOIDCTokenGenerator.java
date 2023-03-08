package eu.olympus.unit.server;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.PolicyUnfulfilledException;
import eu.olympus.server.ThresholdOIDCTokenGenerator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.Storage;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONObject;
import org.junit.Test;

public class TestThreshholdOIDCTokenGenerator {
	
	private static final String SP_NAME = "test-service-provider";
	ThresholdOIDCTokenGenerator generator;
	String issuerId = "https://olympus-vidp.com/issuer1";
	
	@Test
	public void testGenerateTokenSimple() throws Exception{
		ServerCryptoModule cryptoModule = mockCrypto();
		doReturn("signature".getBytes()).when(cryptoModule).sign(any());
		generator = new ThresholdOIDCTokenGenerator(mockDb(), cryptoModule, issuerId);
		String username = "user";
		String policyId = "policyId";
		Policy policy = new Policy();
		policy.setPolicyId(policyId);
		policy.setPredicates(new ArrayList<Predicate>());
		policy.getPredicates().add(new Predicate("audience", Operation.REVEAL, new Attribute(SP_NAME)));
		policy.getPredicates().add(new Predicate("name", Operation.REVEAL, null));
		String token = generator.generateOIDCToken(username, policy, 1000);
		String header = token.substring(0, token.indexOf("."));
		assertEquals("eyJ4NXQiOiJFQTcyQzBFODczNDg2QUQzRjAyRjgzQUFDMDAwQjM2MUM1RUIyNERFIiwiYWxnIjoiUlMyNTYifQ", header);

		String body = token.substring(token.indexOf(".")+1, token.lastIndexOf("."));
		String json = new String(Base64.decodeBase64(body));
		JSONObject obj = new JSONObject(json);
		assertEquals("098f6bcd-4621-3373-8ade-4e832627b4f6", obj.get("sub"));
		assertEquals(SP_NAME, obj.get("aud")); 
		assertEquals(System.currentTimeMillis()/1000, obj.getLong("auth_time"));
		assertEquals(issuerId, obj.get("iss"));
		assertEquals(policyId, obj.get("nonce"));
		String sig = token.substring(token.lastIndexOf(".")+1);
		assertEquals("c2lnbmF0dXJl", sig);
	}

	@Test
	public void testGenerateTokenNoNonce() throws Exception{
		ServerCryptoModule cryptoModule = mockCrypto();
		doReturn("signature".getBytes()).when(cryptoModule).sign(any());
		generator = new ThresholdOIDCTokenGenerator(mockDb(), cryptoModule, issuerId);
		String username = "user";
		Policy policy = new Policy();
		policy.setPredicates(new ArrayList<Predicate>());
		policy.getPredicates().add(new Predicate("audience", Operation.REVEAL, new Attribute(SP_NAME)));
		String token = generator.generateOIDCToken(username, policy, 1000);
		String header = token.substring(0, token.indexOf("."));
		assertEquals("eyJ4NXQiOiJFQTcyQzBFODczNDg2QUQzRjAyRjgzQUFDMDAwQjM2MUM1RUIyNERFIiwiYWxnIjoiUlMyNTYifQ", header);

		String body = token.substring(token.indexOf(".")+1, token.lastIndexOf("."));
		String json = new String(Base64.decodeBase64(body));
		JSONObject obj = new JSONObject(json);
		assertEquals("098f6bcd-4621-3373-8ade-4e832627b4f6", obj.get("sub"));
		assertEquals(SP_NAME, obj.get("aud")); 
		assertEquals(System.currentTimeMillis()/1000, obj.getLong("auth_time"));
		assertEquals(issuerId, obj.get("iss"));
		assertFalse(obj.has("nonce"));
		String sig = token.substring(token.lastIndexOf(".")+1);
		assertEquals("c2lnbmF0dXJl", sig);
	}
	
	@Test(expected = PolicyUnfulfilledException.class)
	public void testGenerateTokenNoAudience() throws Throwable{
		ServerCryptoModule cryptoModule = mockCrypto();
		doReturn("signature".getBytes()).when(cryptoModule).sign(any());
		generator = new ThresholdOIDCTokenGenerator(mockDb(), cryptoModule, issuerId);
		String username = "user";
		String policyId = "policyId";
		Policy policy = new Policy();
		policy.setPolicyId(policyId);
		policy.setPredicates(new ArrayList<Predicate>());
		policy.getPredicates().add(new Predicate("name", Operation.REVEAL, null));
		try {
			generator.generateOIDCToken(username, policy, 1000);
		} catch (Exception e) {
			throw e.getCause();
		}
		fail();
	}
	
	@Test(expected = PolicyUnfulfilledException.class)
	public void testGenerateTokenInvalidOperation() throws Throwable{
		ServerCryptoModule cryptoModule = mockCrypto();
		doReturn("signature".getBytes()).when(cryptoModule).sign(any());
		generator = new ThresholdOIDCTokenGenerator(mockDb(), cryptoModule, issuerId);
		String username = "user";
		String policyId = "policyId";
		Policy policy = new Policy();
		policy.setPolicyId(policyId);
		policy.setPredicates(new ArrayList<Predicate>());
		policy.getPredicates().add(new Predicate("audience", Operation.REVEAL, new Attribute(SP_NAME)));
		policy.getPredicates().add(new Predicate("name", Operation.GREATERTHANOREQUAL, new Attribute("somethnig")));

		try {
			generator.generateOIDCToken(username, policy, 1000);
		} catch (Exception e) {
			throw e.getCause();
		}
		fail();
	}
	
	@Test(expected = PolicyUnfulfilledException.class)
	public void testGenerateTokenNonExistingAttribute() throws Throwable{
		ServerCryptoModule cryptoModule = mockCrypto();
		doReturn("signature".getBytes()).when(cryptoModule).sign(any());
		generator = new ThresholdOIDCTokenGenerator(mockDb(), cryptoModule, issuerId);
		String username = "user";
		String policyId = "policyId";
		Policy policy = new Policy();
		policy.setPolicyId(policyId);
		policy.setPredicates(new ArrayList<Predicate>());
		policy.getPredicates().add(new Predicate("audience", Operation.REVEAL, new Attribute(SP_NAME)));
		policy.getPredicates().add(new Predicate("email", Operation.REVEAL, null));
		try {
			generator.generateOIDCToken(username, policy, 1000);
		} catch (Exception e) {
			throw e.getCause();
		}
		fail();
	}
	
	@Test(expected = PolicyUnfulfilledException.class)
	public void testGenerateTokenNonStandardClaim() throws Throwable{
		ServerCryptoModule cryptoModule = mockCrypto();
		doReturn("signature".getBytes()).when(cryptoModule).sign(any());
		generator = new ThresholdOIDCTokenGenerator(mockDb(), cryptoModule, issuerId);
		String username = "user";
		String policyId = "policyId";
		Policy policy = new Policy();
		policy.setPolicyId(policyId);
		policy.setPredicates(new ArrayList<Predicate>());
		policy.getPredicates().add(new Predicate("audience", Operation.REVEAL, new Attribute(SP_NAME)));
		policy.getPredicates().add(new Predicate("nationality", Operation.REVEAL, null));
		try {
			generator.generateOIDCToken(username, policy, 1000);
		} catch (Exception e) {
			throw e.getCause();
		}
		fail();
	}
	
	@Test(expected = Exception.class)
	public void testGenerateTokenNotSupported() throws Exception {
		generator = new ThresholdOIDCTokenGenerator(mockDb(), mockCrypto(), issuerId);
		generator.generateToken(new HashMap<>());
		fail();
	}
	
	
	@Test(expected = Exception.class)
	public void testBadConstructor() throws Exception{
		new ThresholdOIDCTokenGenerator(mock(Storage.class), mockCrypto(), issuerId);
		fail();
	}

	@Test
	public void testGetPublicKey() throws Exception {
		generator = new ThresholdOIDCTokenGenerator(mockDb(), mockCrypto(), issuerId);
		PublicKey pk = generator.getPublicKey();
		assertThat(pk, is(instanceOf(RSAPublicKey.class)));
		assertEquals(TestParameters.getRSAPublicKey1(), pk);
	}

	@Test(expected = RuntimeException.class)
	public void testGetPublicKeyCryptoModuleException() throws Exception {
		ServerCryptoModule cryptoModule = mockCrypto();
		doThrow(new RuntimeException()).when(cryptoModule).getStandardRSAkey();
		generator = new ThresholdOIDCTokenGenerator(mockDb(), cryptoModule, issuerId);
		generator.getPublicKey();
		fail();
	}

	private PestoDatabase mockDb() throws OperationFailedException {
		PestoDatabase db = mock(PestoDatabase.class);
		doReturn(false).when(db).hasUser(anyString());
		doReturn(false).when(db).deleteUser(anyString());
		doReturn(false).when(db).deleteAttribute(anyString(),anyString());
		doReturn(0L).when(db).getLastSalt(anyString());
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("name", new Attribute("John Doe"));
		attributes.put("nationality", new Attribute("English"));
		doReturn(attributes).when(db).getAttributes(anyString());
		return db;
	}

	private ServerCryptoModule mockCrypto() throws Exception {
		ServerCryptoModule crypto = mock(ServerCryptoModule.class);
		doReturn(TestParameters.getRSAPublicKey1()).when(crypto).getStandardRSAkey();
		doReturn(false).when(crypto).verifySignature(any(),anyList(),any());
		doReturn(false).when(crypto).setupServer(any());
		doReturn("test".getBytes()).when(crypto).hashList(any());
		return crypto;
	}
}
