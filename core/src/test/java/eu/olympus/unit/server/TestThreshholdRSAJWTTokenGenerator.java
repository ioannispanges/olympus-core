package eu.olympus.unit.server;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import eu.olympus.model.Attribute;
import eu.olympus.model.KeyShares;
import eu.olympus.model.RSASharedKey;

import org.junit.Test;

import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.ThresholdRSAJWTTokenGenerator;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.verifier.JWTVerifier;

public class TestThreshholdRSAJWTTokenGenerator {
	
	ThresholdRSAJWTTokenGenerator generator = new ThresholdRSAJWTTokenGenerator(new SoftwareServerCryptoModule(new Random(1)));
	private final BigInteger di = new BigInteger("13417103606342008913287278998879458815400829591316836928871131626762792189422272857397663061780974533967972225948308281549573499854960031868366143970571652105952381788164308587853912428028435044723564526781091011151768131157594160400363891212748601483628315961323066091270096426009626339708854428442308266469296417954069649968517949227606659786579157077836914819918214008733054083653808971577967725166316654083363488068435935252850459733759583136028398777541834853235647133955158155472050989810760612336914455681627622197683270671800978028579477876632912671092450589613312840441605621432803632699380444350433080962505");
	private final BigInteger modulus = new BigInteger("16926537932372831780209597947016556476254098614528317038007032925044815332694902620941127722957895783030645359332697065350909516256222749399547863816422921789982506790331369072016436481851422501415777943591837409725950990619169733587916001047371558556132917730028100298823236433259405983281664568650475598367869076302859691387147776067228113453896319229514680153030136117184621809701442909208968088341296738713841333792355358643148157170767560339357020918008852864926335997159916869547088339143194602198564558671259870740779989090163078025702484071930333185560473071397498431336962558074425299942917614601673583116227");
	private final BigInteger exponent = new BigInteger("65537");
	
	
	@Test
	public void testGetPublicKey() throws Exception {
		ServerCryptoModule cryptoModule = new SoftwareServerCryptoModule(new Random(1));;
		cryptoModule.setupServer(new KeyShares(new RSASharedKey(modulus, di, exponent), null, null, null));
		generator = new ThresholdRSAJWTTokenGenerator(cryptoModule);
		PublicKey pk = generator.getPublicKey();
		assertThat(pk, is(instanceOf(RSAPublicKey.class)));
		assertEquals(exponent, ((RSAPublicKey)pk).getPublicExponent());
		assertEquals(modulus, ((RSAPublicKey)pk).getModulus());
	}

	@Test(expected = RuntimeException.class)
	public void testGetPublicKeyCryptoModuleNotInitialized() throws Exception {
		generator = new ThresholdRSAJWTTokenGenerator(new SoftwareServerCryptoModule(new Random(1)));
		generator.getPublicKey();
	}
	
	@Test
	public void testGenerateTokenSimple() throws Exception{
		ServerCryptoModule cryptoModule = new SoftwareServerCryptoModule(new Random(1));;
		cryptoModule.setupServer(new KeyShares(new RSASharedKey(modulus, di, exponent), null, null, null));
		generator = new ThresholdRSAJWTTokenGenerator(cryptoModule);
		Map<String, Attribute> assertions = new HashMap<String, Attribute>();
		assertions.put("Name", new Attribute("John"));
		
		String token = generator.generateToken(assertions);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
		JWTVerifier verifier = new JWTVerifier(factory.generatePublic(spec));
		assertTrue(verifier.verify(token));
		
	}
	
	@Test
	public void testGenerateTokenLongSignature() throws Exception{
		BigInteger d = new BigInteger("23775991894031987125629130522911925"
				+ "2832862915623290368939175090952688507769576356605940866"
				+ "9593988392745591045999954876054489355398449958950857655"
				+ "2347426430693757488553021129193254198561404496760208084"
				+ "9662822650584245855078929994078485730315404332146267862"
				+ "1235335524636472601629685274656572256173645743474648242"
				+ "1741789619795066214840033705761565208172628529541029321"
				+ "9114336554369059051219791091562504712024520802114704730"
				+ "3685949053527890308805113271239122728305793264389964932"
				+ "8113203262636206597464750581291478117856966693230368348"
				+ "2333950788476789550760344670259399874694727846270762548"
				+ "54420238921038746761920024712513");
		BigInteger m = new BigInteger("25729973262205652910375764978204736"
				+ "5800979803520534691366689529982931749235381863984206515"
				+ "8176704380702902912511542977410552656617374751647330880"
				+ "9630008024907146375946158285071636400447799975300095067"
				+ "1141882563595437922792401503003991402042282921332066659"
				+ "1808127217273786408404965056888503565932170097260535399"
				+ "6299208680281588175601094799415687221174454680630708147"
				+ "6912723664520839860079870342673864402282171858076087975"
				+ "8563940881491656706786252508189014919058051434171100961"
				+ "4764470844191310849795462338269677512018036072804036314"
				+ "4052574878182970169782894131741022849201970725514553786"
				+ "06404831929066260755184914388433");
		BigInteger e = new BigInteger("65537");

		ServerCryptoModule cryptoModule = new SoftwareServerCryptoModule(new Random(1));;
		cryptoModule.setupServer(new KeyShares(new RSASharedKey(m, d, e), null, null, null));
		generator = new ThresholdRSAJWTTokenGenerator(cryptoModule);
		Map<String, Attribute> assertions = new HashMap<String, Attribute>();
		assertions.put("Name", new Attribute("John"));
		
		String token = generator.generateToken(assertions);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec spec = new RSAPublicKeySpec(m, e);
		JWTVerifier verifier = new JWTVerifier(factory.generatePublic(spec));
		assertTrue(verifier.verify(token));
	}
}
