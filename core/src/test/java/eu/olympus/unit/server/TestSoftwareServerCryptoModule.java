package eu.olympus.unit.server;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import eu.olympus.model.KeyShares;
import eu.olympus.model.RSASharedKey;
import eu.olympus.server.SoftwareServerCryptoModule;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.commons.codec.binary.Base64;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.ECP2;
import org.miracl.core.BLS12461.FP12;

public class TestSoftwareServerCryptoModule {
	@Rule
	public final ExpectedException exception = ExpectedException.none();

	SoftwareServerCryptoModule crypto = null;
	private final BigInteger di = new BigInteger("134171036063420089132872"
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
	private final BigInteger exponent = new BigInteger("65537");

	@Test
	public void testSetup() {
		RSASharedKey key = new RSASharedKey(modulus, di, exponent);
		BigInteger b1 = new BigInteger("13417103606342");
		BigInteger b2 = new BigInteger("13417103606343");
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(1, b1); rsaBlindings.put(2, b2);

		BigInteger oprfKey = new BigInteger("42");
		BigInteger s1 = new BigInteger("13417103606345");
		BigInteger s2 = new BigInteger("13417103606346");
		Map<Integer, BigInteger> oprfBlindings = new HashMap<>();
		oprfBlindings.put(1, s1); oprfBlindings.put(2, s2);

		crypto = new SoftwareServerCryptoModule(new Random(0));
		boolean complete = crypto.setupServer(new KeyShares(key, rsaBlindings, oprfKey, oprfBlindings));
		assertTrue(complete);
	}

	@Ignore
	@Test
	public void testSetupBadKey() {
		BigInteger modulus = new BigInteger("1692653793237283178020959794701655647625409861452831703"
				+ "80070329250448153326949026209411277229578957830306453593326970653509095162562227493995478"
				+ "63816422921789982506790331369072016436481851422501415777943591837409725950990619169733587"
				+ "91600104737155855613291773002810029882323643325940598328166456865047559836786907630285969"
				+ "13871477760672281134538963192295146801530301361171846218097014429092089680883412967387138"
				+ "41333792355358643148157170767560339357020918008852864926335997159916869547088339143194602"
				+ "19856455867125987074077998909016307802570248407193033318556047307139749843133696255807442"
				+ "5299942917614601673583116227");
		BigInteger di = new BigInteger(1, modulus.toByteArray());
		BigInteger exponent = new BigInteger("65537");
		RSASharedKey key = new RSASharedKey(modulus, di, exponent);
		BigInteger b0 = new BigInteger("13417103606341");
		BigInteger b1 = new BigInteger("13417103606342");
		BigInteger b2 = new BigInteger("13417103606343");
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, b0); rsaBlindings.put(1, b1); rsaBlindings.put(2, b2);

		// Modulus is going to be too big
		BigInteger oprfKey = new BigInteger(1, modulus.toByteArray());
		BigInteger s0 = new BigInteger("13417103606344");
		BigInteger s1 = new BigInteger("13417103606345");
		BigInteger s2 = new BigInteger("13417103606346");
		Map<Integer, BigInteger> oprfBlindings = new HashMap<>();
		oprfBlindings.put(0, s0); oprfBlindings.put(1, s1); oprfBlindings.put(2, s2);

		crypto = new SoftwareServerCryptoModule(new Random(0));
		boolean complete = crypto.setupServer(new KeyShares(null, rsaBlindings, oprfKey, oprfBlindings));
		assertFalse(complete);
	}

	@Test
	public void testSignature() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modulus, exponent);
		PublicKey publicKey = kf.generatePublic(pubSpec);
		byte[] salt = "salt".getBytes();

		byte[] signature = crypto.sign(publicKey, salt, 0);
		String correctSignature = "QGWhAslz0LVlDDh4T0mxiOpYZVkRSI5SAOELBP7Of7wNCdcnptavdDQxoU"
        + "HfrSly06ZvU0syK03IZoGgQrAE0d7IU/6VMX5CRlSdp87YzdoXTGDay969F1IKpJrMKRyCrK4Nx02a"
        + "lmsMQPKwMddu9nwE6bUqCm3znx9489ZpFk2JMSKTODnWxkQnLR2uRqe1xbZQL7Yk3OYAf/UtkVRItS"
        + "a8MDJB+8zsBkEWGDUaIdyFJH9W2RZDnvteor+Uw2x9UsdUO5Z9cQ8c7ayv0V3AmLpPiS9kODi4THYW"
        + "g95adki5JstnchpcgolJqqDnEWexLePGvNWr62BdMo+YRr9RSg==";
		assertEquals(correctSignature, Base64.encodeBase64String(signature));
	}

	@Test
	public void testCombineSignatures() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		BigInteger s1 = new BigInteger("1000");
		BigInteger s2 = new BigInteger("3000");
		BigInteger s3 = new BigInteger("2");
		List<byte[]> partialSignatures = new ArrayList<byte[]>();
		partialSignatures.add(s1.toByteArray());
		byte[] signature = crypto.combineSignatures(partialSignatures);
		assertEquals( new BigInteger("1000"), new BigInteger(signature));

		partialSignatures.add(s2.toByteArray());
		signature = crypto.combineSignatures(partialSignatures);
		assertEquals( new BigInteger("3000000"), new BigInteger(signature));

		partialSignatures.add(s3.toByteArray());
		signature = crypto.combineSignatures(partialSignatures);
		assertEquals( new BigInteger("6000000"), new BigInteger(signature));
	}

	@Test
	public void testGetModulus() {
		if(crypto == null) {
			testSetup();
		}
		BigInteger mod = crypto.getModulus();
		assertEquals(modulus, mod);
	}

	@Test
	public void testHashAndPair() {
		if(crypto == null) {
			testSetup();
		}
		ECP point = ECP.generator();
		FP12 fp = crypto.hashAndPair("inputValue".getBytes(), point);
		byte[] bytes = new byte[696];
		fp.toBytes(bytes);
		String expected = "BjJlmm9TPJaMLqIzvsAvgZynah8VQvudJIoc+NkK0YM5HouW52pufawgwokS1rLnH/lfxhwRTs3+P" +
				"AGvKeQ8rO7TIFlSFZKh6prWcYjVfTzksriz8M2FAIyJNZpb4u7ap2dtkOGMgoQIcSX/8iLbuSDb860HTb07xSgo" +
				"mNOnQ7B0wbZ2dQvQDdKTXo9NKmKMWZl7FzTD77VWHjFQB/BPAV7XCtnpamxuM38gEFYmARoZOAS7xP9whxkVlyY" +
				"DcNIbv2Q8Aks2aovfUrODvy2SxOw/CEGnX4QiNjs95I5vMgxCad/PQUNiUQziNBFM+dc0BUGUtp4TGgg8gHwaTB" +
				"RccuV0JI7Vjmd3XTQBJfF8P4B4mqrXbmiQS1hfPs4dCUi0dP0BuC/LncIiA/OmgLXhdQ/CfieQZqWqW515QPks5" +
				"1QBaYHDI9anFyoXBp/S3rzc5P984Qd7AHOZCvBtE/GlO3JGjNkokyA+wCdtwraG6bm5GO/oenfKizW6RsE0nkyk" +
				"ykhU3CyBWVhQ1XKP5iMLnPDWiDGXlQwE8SO5n6l6T97atiDWx+FF5DC1JvFlgV6gFNMaoQ8dC62zSrGk1VWbc5F" +
				"UwRumfuNGKBzqF+Cy5JgAFnuE06586VHSuUcqP5xW0bORQ7qpw9ZLLCel4hYAzl69y/WepfxBJJrOhUspY3h0OK" +
				"MN/sotqMeLCRNXPagdJeUKEuR/ujWd+vFpGZ19ESOYUaY2pLWjh2akYn/qBqPCJNFvxcEBVY8MsaMlm56qdB0XP" +
				"BFD4VPfeCaImLD0sRbIi61K7UAxDDZcyznu4FmlfImY++9kq3RZxG+G36Wby+8hHtd4S1shjCU/IH8PyvPtiRUc" +
				"FyWY6N4BDS617u46nbNKCZt9d7uaypTH15GvBNh7jLjoeaii54/BZ+moT0WgHH2Wc+yc";
		assertEquals(expected, b64(bytes));
	}

	@Test
	public void testGenerateBlinding() {
		if(crypto == null) {
			testSetup();
		}

		FP12 fp = crypto.generateBlinding("ssid", 0);

		byte[] bytes = new byte[696];
		fp.toBytes(bytes);
		String expected = "AU0DowJOl5MCLEs6bQ3jO9QICkUf4J88mnE7vPsbn/zGqO7SHRLknmt+YuUi5ZLRf9drL3RmKHjW"
				+ "UQ+YlVH+W0RPG8zOzmFs1FyXwASNLmHiY5pMnBA5MMUHB+gTgfG/B4KW/bq7pZjfqzKcVEh3oQW/n3YIFNN+AJuY"
				+ "ybDcd29rcLRrdioDT6HrFTS8j8EdtpzElKrMQlCZ8qtM3gHy+eywKaEJGh5dpnifG2IiBqFnN3ifzj8khcIOQiaA"
				+ "4yPmWCeelYo/7GQ+1tnzpSvi4zUJdx6JuFbOgC72PdjYWDvGnbdz2NexbwAjN2GhxG60o5qCV4VLSAY1hcuhD8ho"
				+ "uUnojPAHFhP6kzPl5/ZW++oa42eLAeUlk/9q9cipdC1opjEQGNb6l5AULy3aWvpnZzA9sGq7MIg6G9lQzdUCOMR8"
				+ "mwoLYK/JOJa4PnDewLcZNs0fQVzmXhXF9SA+AYe/Wvs7VGgT7Fki0XFfQgdyjXkXC2irg+2ptkZTm4wRiajjQzQx"
				+ "Nu/yYy4OG0wXklMhrkS7E0MTGQddLLAItjfRXr3EM50Nqn8vuTM16FgqL3druTDnmjbcfXobc8R/DBYau+H7QOwm"
				+ "tJw3C0fNAg8da9UHrLhG6DdlhAgnC7yCcVWicC0dH61MlDA7HOihyckFZLjMne72retvPKFIv+qMXETUUGAfHNTh"
				+ "3RzmD9l4w/XA+U8umK3GcKF2xi8oB1WO2Ra+cOvzX9PJLORG/q5ML67BD6iJZ975fWjG210YVd/lcXgpRAJ+P1yn"
				+ "oliLAMqacdbEqwHBe7IHlgcPEXsHpEwfgoh7bNb4VHLhD55MYBpr2Mwu5DLPMMlYoXFKDCEPIsWBP4GAixc23ODP"
				+ "EMKaHj8z7kdYc4hhAHLxhk76/fT6RZylezNzWgRH47En9BtNZRhFiyVeDGTn";
		assertEquals(expected, b64(bytes));
	}

	@Test
	public void sanityCheckCurveHashing() {
		if(crypto == null) {
			testSetup();
		}
		ECP point = crypto.hashToGroup1Element("something".getBytes());
		assertThat(point.is_infinity(), is(false));
		ECP2 point2 = crypto.hashToGroup2("something".getBytes());
		assertThat(point2.is_infinity(), is(false));
	}

	@Test
	public void sanityCheckCurveOperations() {
		if(crypto == null) {
			testSetup();
		}
		ECP point = crypto.hashToGroup1Element("something".getBytes());
		FP12 fp12 = crypto.hashAndPair("something else".getBytes(), point);
		FP12 zero = new FP12();
		zero.zero();
		FP12 one = new FP12();
		one.one();
		assertThat(fp12.equals(one), is(false));
	}

	private String b64(byte[] input) {
		return Base64.encodeBase64String(input);
	}

}
