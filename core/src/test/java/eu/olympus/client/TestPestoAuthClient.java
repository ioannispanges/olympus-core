package eu.olympus.client;

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
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.TestParameters;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.model.Attribute;
import eu.olympus.model.KeyShares;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.Policy;
import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.unit.server.TestIdentityProof;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.commons.codec.Charsets;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;


public class TestPestoAuthClient {
	@Rule
	public final ExpectedException exception = ExpectedException.none();
	
	private ServerCryptoModule sCryptoModule = new SoftwareServerCryptoModule(new Random(1));
	private SoftwareClientCryptoModule cCryptoModule = null;
	private List<PestoIdPImpl> idps;
	
	@Before
	public void setupCrypto() {
		RSAPrivateKey pk = TestParameters.getRSAPrivateKey2();
		BigInteger d = pk.getPrivateExponent();
		RSASharedKey keyMaterial = new RSASharedKey(pk.getModulus(), d, TestParameters.getRSAPublicKey2().getPublicExponent());
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		BigInteger oprfKey = new BigInteger("42");
		sCryptoModule.setupServer(new KeyShares(keyMaterial, rsaBlindings, oprfKey, null));
		cCryptoModule = new SoftwareClientCryptoModule(new Random(1), pk.getModulus());
		idps = new ArrayList<PestoIdPImpl>();
	}
	
	@Test
	public void testCreateUserAndAddAttributes() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule) {
		};
		
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.createUserAndAddAttributes("username", "password", idProof);
	}
	
	@Test
	public void testCreateUserWithoutID() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username", "password");
	}
	
	@Test(expected=UserCreationFailedException.class)
	public void testCreateUserBadServerSignature() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doAnswer(invocationOnMock -> {
			String username = invocationOnMock.getArgument(0);
			PublicKey publicKey = invocationOnMock.getArgument(2, PublicKey.class);
			byte[] signature = invocationOnMock.getArgument(3);
			long salt = invocationOnMock.getArgument(4);

			assertEquals("username", username);
			List<byte[]> input = new ArrayList<>();
			input.add(sCryptoModule.constructNonce(username, salt));
			input.add(username.getBytes());
			try {
				assertTrue(sCryptoModule.verifySignature(publicKey, input, signature));
			} catch (Exception e) {
				fail();
			}
			try {
				byte[] serverSignature = new byte[256];
				new Random(1).nextBytes(serverSignature);
				return serverSignature;
			} catch(Exception e) {
				fail();
			}
			return null;
		}).when(idp).finishRegistration(anyString(),any(),any(),any(),anyLong(),anyString());
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username", "password");
		fail();
	}
	
	@Test(expected=UserCreationFailedException.class)
	public void testCreateUserAndAddAttributesBadServerSignature() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doAnswer(invocationOnMock -> {
			String username = invocationOnMock.getArgument(0);
			PublicKey publicKey = invocationOnMock.getArgument(2, PublicKey.class);
			byte[] signature = invocationOnMock.getArgument(3);
			long salt = invocationOnMock.getArgument(4);
			String idProof = invocationOnMock.getArgument(5);

			assertEquals("username", username);
			List<byte[]> input = new ArrayList<>();
			input.add(sCryptoModule.constructNonce(username, salt));
			input.add(username.getBytes());
			if (idProof == null) {
				idProof = "";
			}
			input.add((CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES+idProof).getBytes(Charsets.UTF_8));
			try {
				assertTrue(sCryptoModule.verifySignature(publicKey, input, signature));
			} catch (Exception e) {
				fail();
			}
			try {
				byte[] serverSignature = new byte[384];
				new Random(1).nextBytes(serverSignature);
				return serverSignature;
			} catch(Exception e) {
				fail();
			}
			return null;
		}).when(idp).finishRegistration(anyString(),any(),any(),any(),anyLong(),anyString());
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.createUserAndAddAttributes("username", "password", idProof);
		fail();
	}
	
	
	@Test(expected=UserCreationFailedException.class)
	public void testCreateUserAndAddAttributes1BadServerSignature() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doAnswer(invocationOnMock -> {
			String username = invocationOnMock.getArgument(0);
			PublicKey publicKey = invocationOnMock.getArgument(2, PublicKey.class);
			byte[] signature = invocationOnMock.getArgument(3);
			long salt = invocationOnMock.getArgument(4);
			String idProof = invocationOnMock.getArgument(5);

			assertEquals("username", username);
			List<byte[]> input = new ArrayList<>();
			input.add(sCryptoModule.constructNonce(username, salt));
			input.add(username.getBytes());
			if (idProof == null) {
				idProof = "";
			}
			input.add((CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES+idProof).getBytes(Charsets.UTF_8));
			try {
				byte[] serverSignature = new byte[384];
				new Random(1).nextBytes(serverSignature);
				return serverSignature;
			} catch(Exception e) {
				fail();
			}
			return null;
		}).when(idp).finishRegistration(anyString(),any(),any(),any(),anyLong(),anyString());
		idps.add(idp);
		PestoIdPImpl idp2 = mockIdp();
		idps.add(idp2);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.createUserAndAddAttributes("username", "password", idProof);
		fail();
	}
	
	@Test
	public void testAddAttributes() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.createUser("username","password");
		authClient.addAttributes("username","password", idProof, null, "NONE");
	}

	@Test
	public void testAddAttributesWithMFA() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.createUser("username","password");
		authClient.addAttributes("username","password", idProof, "TOKEN", GoogleAuthenticator.TYPE);
	}
	
	@Test(expected=OperationFailedException.class)
	public void testAddAttributesServerFails() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doThrow(new RuntimeException()).when(idp).addAttributes(anyString(),any(),anyLong(),any(),anyString());

		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.createUser("username","password");
		authClient.addAttributes("username","password", idProof, null, "NONE");
		fail();
	}
	
	@Test
	public void testAddAttributesServerNegativeAnswer() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doReturn(false).when(idp).addAttributes(anyString(),any(),anyLong(),any(),anyString());

		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		try {
			authClient.addAttributes("username","password", idProof, null, "NONE");
			fail();
		}catch(OperationFailedException e) {
			return;
		}
		fail();
	}
	
	@Test
	public void testGetAllAttributes() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		Map<String, Attribute> attributes = authClient.getAllAttributes("username","password", null, "NONE");
		assertEquals(2, attributes.size());
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(new Attribute("John2"), attributes.get("name2"));
	}

	@Test
	public void testGetAllAttributesWithMFA() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		Map<String, Attribute> attributes = authClient.getAllAttributes("username","password", "TOKEN", GoogleAuthenticator.TYPE);
		assertEquals(2, attributes.size());
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(new Attribute("John2"), attributes.get("name2"));
	}
	
	@Test(expected = OperationFailedException.class)
	public void testGetAllAttributesServerFailure() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doThrow(new RuntimeException()).when(idp).getAllAttributes(anyString(),any(),anyLong(),any());

		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.getAllAttributes("username","password", null, "NONE");
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testGetAllAttributesDifferingServerOutputs() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doAnswer(invocationOnMock -> {
			Map<String, Attribute> output = new HashMap<>();
			output.put("name", new Attribute("John"));
			return output;
		}).when(idp).getAllAttributes(anyString(),any(),anyLong(),any());

		PestoIdPImpl idp2 = mockIdp();
		doAnswer(invocationOnMock -> {
			Map<String, Attribute> output = new HashMap<>();
			output.put("name", new Attribute("Bob"));
			return output;
		}).when(idp2).getAllAttributes(anyString(),any(),anyLong(),any());

		idps.add(idp);
		idps.add(idp2);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.getAllAttributes("username","password", null, "NONE");
		fail();
	}

	
	@Test
	public void testDeleteAttributes() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");

		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username","password", toDelete, null, "NONE");
	}

	@Test
	public void testDeleteAttributesWithMFA() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username","password", toDelete, "TOKEN", GoogleAuthenticator.TYPE);
	}
	
	@Test(expected = OperationFailedException.class)
	public void testDeleteAttributesServerFailure() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doThrow(new RuntimeException()).when(idp).deleteAttributes(anyString(),any(),anyLong(),any(),anyList());

		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username","password", toDelete, null, "NONE");
		fail();
	}
	
	@Test(expected = OperationFailedException.class)
	public void testDeleteAttributesServerNegativeAnswer() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doReturn(false).when(idp).deleteAttributes(anyString(),any(),anyLong(),any(),anyList());

		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username","password", toDelete, null, "NONE");
		fail();
	}
	
	@Test
	public void testDeleteAccount() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.deleteAccount("username","password", null, "NONE");
	}
	
	@Test
	public void testDeleteAccountWithMFA() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.deleteAccount("username","password", "TOKEN", GoogleAuthenticator.TYPE);
	}

	@Test(expected = OperationFailedException.class)
	public void testDeleteAccountServerFailure() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doThrow(new RuntimeException()).when(idp).deleteAccount(anyString(),any(),anyLong(),any());

		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.deleteAccount("username","password", null, "NONE");
		fail();
	}
	
	@Test(expected = OperationFailedException.class)
	public void testDeleteAccountServerFailureNice() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doReturn(false).when(idp).deleteAccount(anyString(),any(),anyLong(),any());

		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.deleteAccount("username","password", null, "NONE");
		fail();
	}
	
	@Test
	public void testChangePassword() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.changePassword("username","password", "password2", null, "NONE");
	}
	
	@Test
	public void testChangePasswordWithMFA() throws Exception {
//		should be tested that the server accepts
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.changePassword("username","password", "password2", "session", GoogleAuthenticator.TYPE);
	}
	
	@Test(expected=OperationFailedException.class)
	public void testChangePasswordBadServerSignature() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doReturn(new byte[256]).when(idp).changePassword(anyString(),any(),any(),any(),any(),anyLong());
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.changePassword("username","password", "password2", null, "NONE");
		fail();
	}
	
	@Test(expected=OperationFailedException.class)
	public void testOPRFBadServerSSID() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doReturn(new OPRFResponse(null, "ssid", "session")).when(idp).performOPRF(anyString(),anyString(),any(),any(),anyString());
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.setSavedUsername("username");
		authClient.changePassword("username","password", "password2", null, "NONE");
		fail();
	}

	@Test(expected=OperationFailedException.class)
	public void testRequestMFAChallengeBadResponses() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doReturn("request1").when(idp).requestMFA(anyString(),any(),anyLong(),anyString(),any());
		PestoIdPImpl idp2 = mockIdp();
		doReturn("request2").when(idp2).requestMFA(anyString(),any(),anyLong(),anyString(),any());
		idps.add(idp);
		idps.add(idp2);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.requestMFAChallenge("username", "password", "NONE");
		fail();
	}
	
	@Test(expected=OperationFailedException.class)
	public void testConfirmMFABadServerAuth() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doReturn(false).when(idp).confirmMFA(anyString(),any(),anyLong(),anyString(),anyString(),any());
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");

		authClient.confirmMFA("username", "password", "token", "NONE");
		fail();
	}

	@Test(expected=OperationFailedException.class)
	public void testRemoveMFABadServerAuth() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doReturn(false).when(idp).removeMFA(anyString(),any(),anyLong(),anyString(),anyString(),any());
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.removeMFA("username", "password", "token", "NONE");
		fail();
	}

	@Test(expected=OperationFailedException.class)
	public void testRemoveMFAServerError() throws Exception {
		PestoIdPImpl idp = mockIdp();
		doThrow(new RuntimeException()).when(idp).confirmMFA(anyString(),any(),anyLong(),anyString(),anyString(),any());
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username","password");
		authClient.removeMFA("username", "password", "token", "NONE");
		fail();
	}

	@Test
	public void testFreshSaltWait() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		long firstSalt = authClient.getFreshSalt();
		long secondSalt = authClient.getFreshSalt();
		assertFalse(firstSalt == secondSalt);
	}

	@Test
	public void testFreshSaltNoWait() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		long firstSalt = authClient.getFreshSalt();
		Thread.sleep(2);
		long secondSalt = authClient.getFreshSalt();
		assertFalse(firstSalt == secondSalt);
	}

	@Test
	public void getSavedUsername() throws Exception {
		PestoIdPImpl idp = mockIdp();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		try{
			authClient.getSavedUsername();
			fail();
		} catch (OperationFailedException e) {
		}
		authClient.setSavedUsername("something");
		assertEquals(authClient.getSavedUsername(),"something");
	}

	private static class ConcreteAuthClient extends PestoAuthClient {

		public ConcreteAuthClient(List<? extends PestoIdP> servers,
				ClientCryptoModule cryptoModule) {
			super(servers, cryptoModule);
		}

		@Override
		public String authenticate(String username, String password, Policy policy, String token, String type) {
			//Not used for testing
			return null;
		}
	}
	
	private PestoIdPImpl mockIdp() throws Exception {
		PestoIdPImpl idp = mock(PestoIdPImpl.class);

		doAnswer(invocationOnMock -> {
			ObjectMapper mapper = new ObjectMapper();
			TestIdentityProof proof;
			try {
				proof = mapper.readValue(invocationOnMock.getArgument(4,String.class), TestIdentityProof.class);
				assertEquals("sig", proof.getSignature());
				assertEquals(new Attribute("John"),proof.getAttributes().get("name"));
				assertEquals(1, proof.getAttributes().size());
				return true;
			} catch (Exception e) {
				fail();
			}
			return false;
		}).when(idp).addAttributes(anyString(),any(),anyLong(),any(),anyString());

		when(idp.finishRegistration(anyString(), any(), any(), any(), anyLong(), anyString())).then(invocationOnMock -> {
			String username = invocationOnMock.getArgument(0);
			byte[] cookie = invocationOnMock.getArgument(1);
			PublicKey publicKey = invocationOnMock.getArgument(2, PublicKey.class);
			byte[] signature = invocationOnMock.getArgument(3);
			long salt = invocationOnMock.getArgument(4);
			String idProof = invocationOnMock.getArgument(5);

			assertEquals("username", username);
			List<byte[]> input = new ArrayList<>();
			input.add(sCryptoModule.constructNonce(username, salt));
			input.add(username.getBytes());
			if(idProof != null) {
				input.add((CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES+idProof).getBytes(Charsets.UTF_8));
			} else {
				input.add((CommonRESTEndpoints.CREATE_USER+"").getBytes(Charsets.UTF_8));
			}
			input.add(cookie);
			try {
				assertTrue(sCryptoModule.verifySignature(publicKey, input, signature));
			} catch (Exception e) {
				fail();
			}
			try {
				byte[] serverSignature = sCryptoModule.sign(publicKey, sCryptoModule.constructNonce(username, salt), 0);
				return serverSignature;
			} catch(Exception e) {
				fail();
			}
			return null;
		});

		when(idp.getAllAttributes(anyString(), any(), anyLong(), any())).then(invocationOnMock -> {
			Map<String, Attribute> attributes = new HashMap<String, Attribute>();
			attributes.put("name", new Attribute("John"));
			attributes.put("name2", new Attribute("John2"));
			return attributes;
		});

		when(idp.changePassword(anyString(), any(), any(), any(), any(), anyLong())).then(invocationOnMock -> {
			String username = invocationOnMock.getArgument(0);
			try {
				return sCryptoModule.sign(invocationOnMock.getArgument(2), sCryptoModule.constructNonce(username, invocationOnMock.getArgument(5)), 0);
			} catch (Exception ignored) {
			}
			return null;
		});

		when(idp.performOPRF(anyString(), anyString(), any(), any(), anyString())).then(invocationOnMock -> {
			String ssid = invocationOnMock.getArgument(0);
			ECP x = invocationOnMock.getArgument(2);
			FP12 output = sCryptoModule.hashAndPair(ssid.getBytes(), x);
			return new OPRFResponse(output, ssid, "session");
		});
		doReturn(true).when(idp).deleteAttributes(anyString(),any(),anyLong(),any(),anyList());
		doReturn(true).when(idp).deleteAccount(anyString(),any(),anyLong(),any());

		return idp;
	}

}
