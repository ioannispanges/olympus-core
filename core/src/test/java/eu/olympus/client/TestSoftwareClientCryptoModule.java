package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import eu.olympus.TestParameters;
import eu.olympus.client.interfaces.ClientCryptoModule;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;

public class TestSoftwareClientCryptoModule {

	private final BigInteger modulus = new BigInteger("1692653793237283178"
			+ "02095979470165564762540986145283170380070329250448153326949"
			+ "02620941127722957895783030645359332697065350909516256222749"
			+ "39954786381642292178998250679033136907201643648185142250141"
			+ "57779435918374097259509906191697335879160010473715585561329"
			+ "17730028100298823236433259405983281664568650475598367869076"
			+ "30285969138714777606722811345389631922951468015303013611718"
			+ "46218097014429092089680883412967387138413337923553586431481"
			+ "57170767560339357020918008852864926335997159916869547088339"
			+ "14319460219856455867125987074077998909016307802570248407193"
			+ "03331855604730713974984313369625580744252999429176146016735"
			+ "83116227");

	@Test
	public void testSign() throws Exception {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		List<byte[]> message = new ArrayList<>();
		message.add("message".getBytes());
		message.add("salt".getBytes());
		byte[] signature = crypto.signECDSA(TestParameters.getECPrivateKey1(), message);

		Signature sig = Signature.getInstance("SHA256withECDSA");
		sig.initVerify(TestParameters.getECPublicKey1());
		sig.update(crypto.hashList(message));
		assertTrue(sig.verify(signature));
	}
	
	@Test
	public void testGetModulus() {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		assertEquals(modulus, crypto.getModulus());
	}

	@Test
	public void testGenerateKeyFromBytes() throws Exception {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		byte[] seed = "thisIsMySeed".getBytes();
		KeyPair pair1 = crypto.generateKeysFromBytes(seed);
		assertTrue(pair1.getPrivate() instanceof PrivateKey);
		assertTrue(pair1.getPublic() instanceof PublicKey);
	}

	@Test
	public void testHashAndMultiply() {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		
		BIG r = BIG.fromBytes(Base64.decodeBase64("HE5cdHpR6FWeCjsAQZApcpH"
				+ "xluW9CEU8wbkseMn6q1McTlx0elHoVZ4KOwBBkClykfGW5b0IRTzBuQ"
				+ "=="));
		
		ECP point = crypto.hashAndMultiply(r, "inputValue".getBytes());
		byte[] bytes = new byte[58*2+1];
		point.toBytes(bytes, false);
		String expected = "BBQ0UhpUSpoVirzk86PKkrs62yDfaDtgRkhfPHXL9cKE+YJy9W+XkdLFecPuA7I68AWStuxHtmKw" +
				"cMsGonBq/ePeJksuRq6nvnSdSFaHtBqZvbXzpdSr6zOdJhgOHUgiuU+N750SOzhew5qW1tIgJmmAEr/C";
		assertEquals(expected, b64(bytes));
	}
	
	private String b64(byte[] input) {
		return Base64.encodeBase64String(input);
	}

}
