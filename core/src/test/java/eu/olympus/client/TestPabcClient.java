package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import eu.olympus.TestParameters;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.model.Attribute;
import eu.olympus.model.KeyShares;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.Operation;
import eu.olympus.model.PSCredential;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.PresentationToken;
import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PabcIdP;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSsignature;
import eu.olympus.util.psmultisign.PSzkToken;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.Before;
import org.junit.Test;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;


public class TestPabcClient {
	
	private ServerCryptoModule sCryptoModule = new SoftwareServerCryptoModule(new Random(1));
	private SoftwareClientCryptoModule cCryptoModule = null;
	private PresentationToken token = null;
	private Map<String, MFAAuthenticator> mfaAuthenticators;
	private final static String user = "username";
	private final static String password = "password";
	
	@Before
	public void setupCrypto() {
		RSAPrivateKey pk = TestParameters.getRSAPrivateKey2();
		BigInteger d = pk.getPrivateExponent();
		RSASharedKey keyMaterial = new RSASharedKey(pk.getModulus(), d, TestParameters.getRSAPublicKey2().getPublicExponent());
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, BigInteger.ONE);
		BigInteger oprfKey = new BigInteger("42");
		sCryptoModule.setupServer(new KeyShares(keyMaterial, rsaBlindings, oprfKey, null));
		cCryptoModule = new SoftwareClientCryptoModule(new Random(1), pk.getModulus());
		
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		ZpElement zpElement = new ZpElementBLS461(new BIG(5));
		Group2Element g1Element = new PairingBuilderBLS461().getGroup2Generator();
		
		PSzkToken psZKToken = new PSzkToken(g1Element, g1Element, zpElement, new HashMap<String, ZpElement>(), zpElement, zpElement);
		token = new PresentationToken(System.currentTimeMillis(), attributes, psZKToken,null);

		mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(cCryptoModule));
	}
	
	@Test
	public void testAuthenticate() throws Exception {
		List<PabcIdP> idps = new ArrayList<PabcIdP>();
		PabcIdP idp = mockIdp();
		
		idps.add(idp);
		CredentialManagement cManager = mock(CredentialManagement.class);
		when(cManager.combineAndGeneratePresentationToken(any(),any())).thenReturn(token);
		PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);

		String token = authClient.authenticate("username", "password", mockPolicy(), null, "NONE");

		ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
		Mockito.verify(idp, times(1)).getCredentialShare(stringCaptor.capture(),any(),anyLong(),any(),anyLong());
		assertEquals("username",stringCaptor.getValue());
		assertEquals(this.token.getEncoded(), token);
	}
	
	@Test
	public void testAuthenticateWithStoredCredential() throws Exception {
		List<PabcIdP> idps = new ArrayList<PabcIdP>();
		PabcIdP idp = mockIdp();
		
		idps.add(idp);
		CredentialManagement cManager = mock(CredentialManagement.class);
		when(cManager.checkStoredCredential()).thenReturn(true);
		when(cManager.generatePresentationToken(any())).thenReturn(token);
		PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);

		String token = authClient.authenticate("username", "password", mockPolicy(), null, "NONE");
		assertEquals(this.token.getEncoded(), token);
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testAuthenticateServerThrowsException() throws Exception {
		List<PabcIdP> idps = new ArrayList<PabcIdP>();
		PabcIdP idp = mockIdp();
		when(idp.getCredentialShare(anyString(),any(),anyLong(),any(),anyLong())).thenThrow(new RuntimeException("simulated server failure"));

		idps.add(idp);
		CredentialManagement cManager = new PSCredentialManagement(true, new InMemoryCredentialStorage());
		PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);

		authClient.authenticate("username", "password", mockPolicy(), null, "NONE");
	}

	@Test(expected = OperationFailedException.class)
	public void testMissingRequestMFAChallenge() throws Exception {
		List<PabcIdP> idps = new ArrayList<>();
		PabcIdP idp = mockIdp();
		idps.add(idp);
		CredentialManagement cManager = new PSCredentialManagement(true, new InMemoryCredentialStorage());
		PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);
		authClient.requestMFAChallenge(user, password, GoogleAuthenticator.TYPE);
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testMissingConfirmMFA() throws Exception {
		List<PabcIdP> idps = new ArrayList<>();
		PabcIdP idp = mockIdp();
		idps.add(idp);
		CredentialManagement cManager = new PSCredentialManagement(true, new InMemoryCredentialStorage());
		PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);
		authClient.confirmMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testMissingRemoveMFA() throws Exception {
		List<PabcIdP> idps = new ArrayList<>();
		PabcIdP idp = mockIdp();
		idps.add(idp);
		CredentialManagement cManager = new PSCredentialManagement(true, new InMemoryCredentialStorage());
		PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);
		authClient.removeMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	private Policy mockPolicy() {
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		return new Policy(predicates, "messageToBeSigned");
	}

	private PabcIdP mockIdp() throws Exception {
		PabcIdP idp = mock(PabcIdP.class);
		doAnswer(invocationOnMock -> {
			Map<String, Attribute> attributes = new HashMap<String, Attribute>();
			attributes.put("name", new Attribute("John"));
			BIG x = new BIG(5);
			ZpElement zpElement = new ZpElementBLS461(x);
			Group2Element g1Element = new PairingBuilderBLS461().getGroup2Generator();

			PSsignature psSignature = new PSsignature(zpElement, g1Element, g1Element);
			PSCredential credential = new PSCredential(System.currentTimeMillis(), attributes, psSignature);
			return credential.getEncoded();
		}).when(idp).getCredentialShare(anyString(), any(), anyLong(), any(), anyLong());

		doAnswer(invocationOnMock -> {
			String ssid = invocationOnMock.getArgument(0);
			ECP x = invocationOnMock.getArgument(2);
			FP12 output = sCryptoModule.hashAndPair(ssid.getBytes(), x);
			assertEquals("username", invocationOnMock.getArgument(1));
			assertNotNull(ssid);
			assertNotNull(x);
			return new OPRFResponse(output, ssid, "session");
		}).when(idp).performOPRF(any(), any(), any(), any(), any());
		return idp;
	}
	
}
