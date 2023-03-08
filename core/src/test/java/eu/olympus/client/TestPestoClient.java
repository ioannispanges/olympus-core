package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import eu.olympus.TestParameters;
import eu.olympus.model.KeyShares;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.ServerCryptoModule;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.Before;
import org.junit.Test;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;


public class TestPestoClient {
	
	private ServerCryptoModule sCryptoModule = new SoftwareServerCryptoModule(new Random(1));
	private SoftwareClientCryptoModule cCryptoModule = null;
	
	@Before
	public void setupCrypto() {
		RSAPrivateKey pk = TestParameters.getRSAPrivateKey1();
		BigInteger d = pk.getPrivateExponent();
		RSASharedKey keyMaterial = new RSASharedKey(pk.getModulus(), d, TestParameters.getRSAPublicKey1().getPublicExponent());
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, BigInteger.ONE);
		BigInteger oprfKey = new BigInteger("42");
		sCryptoModule.setupServer(new KeyShares(keyMaterial, rsaBlindings, oprfKey, null));
		cCryptoModule = new SoftwareClientCryptoModule(new Random(1), pk.getModulus());
	}
	
	@Test
	public void testAuthenticate() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		PestoIdPImpl idp = mockIdp();
		
		idps.add(idp);
		PestoClient authClient = new PestoClient(idps, cCryptoModule);
		
		Policy policy = new Policy();
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		policy.setPredicates(predicates);
		
		String token = authClient.authenticate("username", "password", policy, null, "NONE");
		assertEquals("token", token);
	}
	
	@Test
	public void testAuthenticateServerThrowsException() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		PestoIdPImpl idp = mockIdp();
		doThrow(new RuntimeException()).when(idp).authenticate(anyString(), any(), anyLong(), any(), any());
		idps.add(idp);
		PestoClient authClient = new PestoClient(idps, cCryptoModule);
		
		Policy policy = new Policy();
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		policy.setPredicates(predicates);
		
		try {
			authClient.authenticate("username", "password", policy, null, "NONE");
			fail();
		} catch(AuthenticationFailedException e) {
		}
	}

	private PestoIdPImpl mockIdp() throws Exception {
		PestoIdPImpl idp = mock(PestoIdPImpl.class);

		when(idp.authenticate(anyString(), any(), anyLong(), any(), any())).thenReturn("token");

		when(idp.performOPRF(anyString(), anyString(), any(), any(), anyString())).then(invocationOnMock -> {
			String ssid = invocationOnMock.getArgument(0);
			ECP x = invocationOnMock.getArgument(2);
			FP12 output = sCryptoModule.hashAndPair(ssid.getBytes(), x);
			return new OPRFResponse(output, ssid, "session");
		});

		return idp;
	}
	
}
