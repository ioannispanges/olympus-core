package eu.olympus.unit.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.Signature;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import eu.olympus.util.ECKeyGenerator;

public class TestECKeyGenerator{

	@Test
	public void testBasics() throws Exception {
		
		byte[] seed = "thisIsMySeed".getBytes();
		KeyPair pair1 = ECKeyGenerator.generateKey(seed);
		String encoded = "ME0CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEMzAxAgEBBCBLM1Wu1tN+1ThVlDOgqEQGsN4bnoun+JEqIxIGezWWvKAKBggqhkjOPQMBBw==";

		KeyPair pair2 = ECKeyGenerator.generateKey("someOtherSeed".getBytes());
		KeyPair pair3 = ECKeyGenerator.generateKey("thisIsMySeed".getBytes());
		testKeys(pair1);
		testKeys(pair2);
		
		assertEquals(encoded, b64(pair1.getPrivate().getEncoded()));
		assertNotEquals(encoded, b64(pair2.getPrivate().getEncoded()));
		
		assertEquals(b64(pair1.getPrivate().getEncoded()), b64(pair3.getPrivate().getEncoded()));

	}
	
	private void testKeys(KeyPair ukp) {
		try {
			byte[] bytes = "This is message to be signed".getBytes();
			Signature sig2 = Signature.getInstance("SHA256withECDSA");
			sig2.initSign(ukp.getPrivate());
			sig2.update(bytes);
			byte[] signature = sig2.sign();

			Signature sig = null;
			sig = Signature.getInstance("SHA256withECDSA");
			sig.initVerify(ukp.getPublic());
			sig.update(bytes);

			assertTrue(sig.verify(signature));
		}catch(Exception e) {
		}
	}
	
	private String b64(byte[] input) {
		return Base64.encodeBase64String(input);
	}
	
}
