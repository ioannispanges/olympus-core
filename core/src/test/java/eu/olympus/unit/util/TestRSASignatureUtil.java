package eu.olympus.unit.util;

import static org.junit.Assert.assertEquals;

import eu.olympus.util.RSASignatureUtil;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

public class TestRSASignatureUtil {

	private final BigInteger privateKey = new BigInteger("134171036063420089132872"
			+ "78998879458815400829591316836928871131626762792189422272857"
			+ "39766306178097453396797222594830828154957349985496003186836"
			+ "61439705716521059523817881643085878539124280284350447235645"
			+ "26781091011151768131157594160400363891212748601483628315961"
			+ "32306609127009642600962633970885442844230826646929641795406"
			+ "96499685179492276066597865791570778369148199182140087330540"
			+ "83653808971577967725166316654083363488068435935252850459733"
			+ "75958313602839877754183485323564713395515815547205098981076"
			+ "06123369144556816276221976832706718009780285794778766329126"
			+ "71092450589613312840441605621432803632699380444350433080962"
			+ "505");
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
	public void testSignature() throws Exception {

		byte[] toBeSigned = "message".getBytes();
		BigInteger b1 = new BigInteger("13417103606342");
		BigInteger b2 = new BigInteger("13417103606343");
		Map<Integer, BigInteger> blindings = new HashMap<>();
		blindings.put(1, b1); blindings.put(2, b2);
		
		byte[] signature = RSASignatureUtil
        .signWithBlinding(toBeSigned, modulus, privateKey, blindings, 0, "salt".getBytes());
		String expected = "J2K2IL5ihIJ4zPqijMLKKHEcIbTuC1dm/1TrvELrZsRVqcg37YP" +
				"s/MwimAuY8PVW0PS0i7SrFWG9q1qzRQWw0bYTkk0dreg1tuLkMo8W4IRvCXXI" +
				"Uk5DJrVnPno08eEzVcM7AlLfyfPB6VUZq6TJ3aZyIFYcON0ankqbvTvvxvDZB" +
				"FQ0CKsc0zqszGKf610xJzkMCyiVN8ARueGivNHcz/dOdGpf5JyEjsh81dbIZp" +
				"RjPF5XBqk4gXoM4W3HeH0Dbqms8uVZi2cEtpaV7RacGSK/RGuuQibFKb80CSk" +
				"BUfKPSBU3pWTVfz0JAlb+RpToxnJcv89eFcESItvzkWT6HA==";
		assertEquals(expected, b64(signature));
	}
	
	@Test
	public void testSignatureWithoutBlinding() throws Exception {

		byte[] toBeSigned = "message".getBytes();
		Map<Integer, BigInteger> blindings = new HashMap<>();
		byte[] signature = RSASignatureUtil
        .signWithBlinding(toBeSigned, modulus, privateKey, blindings, 0, "salt".getBytes());

		String expected = "hLvQy8Vpxp1Zlx+OG5Lp6Go8QSCfmu5aTPKmf82qj/4I3Fl"
				+ "nbqSZoKj4d39zGqOyuAkfKrbOG38tTjl9VTimuQWVf5K63BAi9BfjIL"
				+ "Tk3Gox+2IKSe/nwB8AKlAKex5xmYa9sQXj4USbjrHx24FZ4Ssr7UeXF"
				+ "0lUS3oIbPIsBY8XeBm30mcqz/dXFjkCVi8uSlsqynI44WTiQLIdJcsa"
				+ "EWj+SK6p/tttarjsEOIfCsM2y1IowtLFVtg/djzmjk/byXBmQO7Mdcs"
				+ "g1ZAf62nBcTP7gADXAn+cCmnq+3apPC8pa+ZX0uH6IjWvhHs0t959gs"
				+ "vRmdym0GarZ88eUexEag==";
	
		assertEquals(expected, b64(signature));
	}
	
	@Test
	public void testSignatureSmallModulus() throws Exception {

		BigInteger modulus = new BigInteger("10000000000000000001"
				+ "0000000000000556476254098614528317038007032925044815332"
				+ "0000000000000556476254098614528317038007032925044815332"
				+ "0000000000000556476254098614528317038007032925044815332"
				+ "6949");
		
		byte[] toBeSigned = "message".getBytes();
		Map<Integer, BigInteger> blindings = new HashMap<>();
		
		byte[] signature = RSASignatureUtil
        .signWithBlinding(toBeSigned, modulus, privateKey, blindings, 0, "salt".getBytes());
		
		Signature sig = Signature.getInstance("SHA256withRSA");
		KeyFactory factory = KeyFactory.getInstance("RSA");
		RSAPrivateKeySpec keySpecPriv = new RSAPrivateKeySpec(modulus, privateKey);
		PrivateKey privKey = factory.generatePrivate(keySpecPriv); 
		
		sig.initSign(privKey);
		sig.update(toBeSigned);
		byte[] si = sig.sign();
		String expected = b64(si);
		assertEquals(expected, b64(signature));
		
	}
	
	@Test
	public void testCombineSignatures() throws Exception {

		BigInteger b1 = new BigInteger("40");
		BigInteger b2 = new BigInteger("10000000");
		BigInteger b3 = new BigInteger("300");
		List<byte[]> signatures = new ArrayList<>();
		
		signatures.add(b1.toByteArray());
		BigInteger c1 = new BigInteger(RSASignatureUtil.combineSignatures(signatures, modulus));

		signatures.add(b2.toByteArray());
		BigInteger c2 = new BigInteger(RSASignatureUtil.combineSignatures(signatures, modulus));

		signatures.add(b3.toByteArray());
		BigInteger c3 = new BigInteger(RSASignatureUtil.combineSignatures(signatures, modulus));

		assertEquals(b1, c1);
		assertEquals(b1.multiply(b2), c2);
		assertEquals(b1.multiply(b2).multiply(b3), c3);
	}
	
	@Test
	public void testCombineSignaturesSmallModulus() throws Exception {

		BigInteger modulus = new BigInteger("20000001");
		BigInteger b1 = new BigInteger("40");
		BigInteger b2 = new BigInteger("10000000");
		BigInteger b3 = new BigInteger("300");
		List<byte[]> signatures = new ArrayList<>();
		
		signatures.add(b1.toByteArray());
		BigInteger c1 = new BigInteger(RSASignatureUtil.combineSignatures(signatures, modulus));

		signatures.add(b2.toByteArray());
		BigInteger c2 = new BigInteger(RSASignatureUtil.combineSignatures(signatures, modulus));

		signatures.add(b3.toByteArray());
		BigInteger c3 = new BigInteger(RSASignatureUtil.combineSignatures(signatures, modulus));

		assertEquals(b1, c1);
		assertEquals(new BigInteger("19999981"), c2);
		assertEquals(new BigInteger("19994001"), c3);
	}
	
	private String b64(byte[] signature) {
		return Base64.encodeBase64String(signature);
	}
}
