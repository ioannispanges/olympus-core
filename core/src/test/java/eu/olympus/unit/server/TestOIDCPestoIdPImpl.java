package eu.olympus.unit.server;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.ECP2;
import org.miracl.core.BLS12461.FP12;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.KeyShares;
import eu.olympus.model.Operation;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.server.OIDCPestoIdPImpl;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.storage.InMemoryPestoDatabase;

public class TestOIDCPestoIdPImpl {
	@Rule
	public final ExpectedException exception = ExpectedException.none();

	PABCConfigurationImpl configuration;

	@Test
	public void testAuthenticate() throws Exception {

		RSAPrivateCrtKey pk = (RSAPrivateCrtKey)TestParameters.getRSAPrivateKey2();
		BigInteger di = pk.getPrivateExponent();

		PestoDatabase database = new InMemoryPestoDatabase() {
			@Override
			public PublicKey getUserKey(String username) {
				if("user".equals(username)) {
					return TestParameters.getRSAPublicKey1();
				}
				return null;
			}
			
			@Override
			public long getLastSalt(String username) {
				return System.currentTimeMillis()-10000;
			}
			
			@Override
			public void setSalt(String s, long salt) {
			}
			
			@Override
			public Map<String, Attribute> getAttributes(String username) {
				Map<String, Attribute> output = new HashMap<>();
				return output;
			}
		};
		ServerCryptoModule crypto = mockCrypto();
		
		PestoIdPImpl idp = new OIDCPestoIdPImpl(database, new ArrayList<IdentityProver>(), new HashMap<String, MFAAuthenticator>(), crypto, "https://olympus-vidp.com/issuer1", 100000);
		configuration = new PABCConfigurationImpl();
		configuration.setAttrDefinitions(generateAttributeDefinitions());
		configuration.setServers(Arrays.asList("server"));
		configuration.setSeed(new byte[2]);
		configuration.setLifetime(72000000);
		configuration.setAllowedTimeDifference(10000l);
		configuration.setKeyMaterial(new RSASharedKey(pk.getModulus(), di, pk.getPublicExponent()));
		Map<Integer, BigInteger> blindings = new HashMap<>();
		configuration.setOprfBlindings(blindings);
		configuration.setRsaBlindings(blindings);
		configuration.setOprfKey(BigInteger.ONE);
		configuration.setId(0);
		configuration.setWaitTime(1000);
		configuration.setLocalKeyShare(new byte[32]);
		configuration.setRemoteShares(new HashMap<Integer, byte[]>());
		
		boolean complete = idp.setup("setup", configuration, new ArrayList<>());
		assertTrue(complete);
		Policy policy = new Policy();
		policy.setPredicates(new ArrayList<Predicate>());
		policy.getPredicates().add(new Predicate("audience", Operation.REVEAL, new Attribute("test-service-provider")));
		String token = idp.authenticate("user", "cookie".getBytes(), System.currentTimeMillis(), "signature".getBytes(), policy);
		String sig = token.substring(token.lastIndexOf(".")+1);
		assertEquals("c2ln", sig);
		try {
			idp.authenticate("user_not_existing", "cookie".getBytes(), System.currentTimeMillis(), "signature".getBytes(), policy);
			fail();
		} catch(Exception e) {
			assertTrue(e instanceof AuthenticationFailedException);
		}
		try {
			idp.authenticate("user", "cookie".getBytes(), System.currentTimeMillis(), "signature".getBytes(), null);
			fail();
		} catch(Exception e) {
			assertTrue(e instanceof AuthenticationFailedException);
		}
	}

	private ServerCryptoModule mockCrypto() throws Exception {
		ServerCryptoModule crypto = mock(ServerCryptoModule.class);
		doReturn(true).when(crypto).setupServer(any());
		doReturn(new byte[57]).when(crypto).getBytes(anyInt());
		doReturn("nonce".getBytes()).when(crypto).constructNonce(anyString(),anyLong());
		doReturn(true).when(crypto).verifySignature(any(),anyList(),any());
		doReturn(TestParameters.getRSAPublicKey1()).when(crypto).getStandardRSAkey();
		doReturn("sig".getBytes()).when(crypto).sign(any());
		doReturn("pseudonym".getBytes()).when(crypto).hashList(any());
		return crypto;
	}
	private Set<AttributeDefinition> generateAttributeDefinitions() {
		Set<AttributeDefinition> res=new HashSet<>();
		res.add(new AttributeDefinitionString("name","name",0,16));
		res.add(new AttributeDefinitionInteger("age","age",1,100));
		return res;
	}
}
