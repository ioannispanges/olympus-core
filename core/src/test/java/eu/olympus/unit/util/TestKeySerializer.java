package eu.olympus.unit.util;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import eu.olympus.util.multisign.MS;
import eu.olympus.util.multisign.MSauxArg;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.psmultisign.PSauxArg;
import eu.olympus.util.psmultisign.PSms;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import eu.olympus.TestParameters;
import eu.olympus.model.SerializedKey;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.util.KeySerializer;

public class TestKeySerializer{

	private static final String PAIRING_NAME="eu.olympus.util.pairingBLS461.PairingBuilderBLS461";
	private final byte[] seed = "random value random value random value random value random".getBytes();

	private Set<String> attrNames=new HashSet<>(Arrays.asList("name","age"));

	@Test
	public void testKeySerializerEC() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {

		ECPublicKey publicKey = TestParameters.getECPublicKey1();

		SerializedKey key = KeySerializer.serialize(publicKey);
		ECPublicKey result = (ECPublicKey) KeySerializer.deSerialize(key);
		assertThat(result, is(publicKey));
		
		key = KeySerializer.serialize(TestParameters.getECPrivateKey1());
		assertEquals(TestParameters.getECPrivateKey1(), KeySerializer.deSerialize(key));
	}
	
	@Test
	public void testKeySerializerRSA() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
		RSAPublicKey publicKey = TestParameters.getRSAPublicKey1();

		SerializedKey key = KeySerializer.serialize(publicKey);
		RSAPublicKey result = (RSAPublicKey) KeySerializer.deSerialize(key);
		
		assertThat(result, is(publicKey));
		key = KeySerializer.serialize(TestParameters.getRSAPrivateKey1());
		assertEquals(TestParameters.getRSAPrivateKey1(), KeySerializer.deSerialize(key));
	}

	@Test
	public void testKeySerializerPSverfKey() throws NoSuchAlgorithmException, InvalidKeyException, MSSetupException, InvalidKeySpecException {
		MS psScheme=new PSms();
		int nServers=3;
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		MSverfKey publicKey=psScheme.kg().getSecond();

		SerializedKey key = KeySerializer.serialize(publicKey);
		MSverfKey result = (MSverfKey) KeySerializer.deSerialize(key);

		assertThat(result, is(publicKey));
	}

	@Test (expected = InvalidKeyException.class)
	public void testBadPSverfKey() throws NoSuchAlgorithmException, InvalidKeyException, MSSetupException, InvalidKeySpecException {
		MS psScheme=new PSms();
		int nServers=3;
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		MSverfKey publicKey=psScheme.kg().getSecond();

		SerializedKey key = KeySerializer.serialize(publicKey);
		key.setEncoded(Base64.encodeBase64String("This is not an encoded key!!".getBytes()));
		KeySerializer.deSerialize(key);
		fail();
	}
	
	@Test(expected = Exception.class)	
	public void testKeySerializerUnknown() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
		ECPublicKey publicKey = TestParameters.getECPublicKey1();

		SerializedKey key = KeySerializer.serialize(publicKey);
		key.setAlgorithm("SHA");
		KeySerializer.deSerialize(key);
		fail();
	}

	
}
