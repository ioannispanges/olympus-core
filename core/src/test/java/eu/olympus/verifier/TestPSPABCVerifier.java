package eu.olympus.verifier;

import static org.junit.Assert.fail;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionDate;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.Operation;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.server.PabcIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.util.multisign.MSpublicParam;
import eu.olympus.util.psmultisign.PSauxArg;
import eu.olympus.util.psmultisign.PSpublicParam;
import eu.olympus.util.psmultisign.PSverfKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class TestPSPABCVerifier {

	@Rule
	public final ExpectedException exception = ExpectedException.none();
	private static final String key0 = "CnoKeAo6EisbfOFyTuoKozbyRISSwM85o5IXfiYZltcKGwoHoVFoHkBXJvnjn8YDczF/nZ8sdu/8QpHsMZX4IhI6B7/noK3X0V5VAZ7cHLJNypLqZWxSgqwMKDwj7Yk7k9L7j4Dk9S1u5zf2h3t5dQO04KT3111w1baUBRJ6CngKOhLrSyt1mP/V9WdMeO9EOSxLNKSGARwEHyktfSMVtoeDp9vMXNkUPJi70CV82k0rhF/3lFllvfuhFlQSOgk9TB/91EjG93BwdeZBKWDTkV3lhGGGCU2Lon4goo7Jmu4E0yAsy3Cw45/nCXziiu/l5vBiXm9/j68aegp4CjoQfH7QJG1AXoKkLQ0d7jWqFKV3eXpvGa7MiDB2miyW8y/SXxnT/ANYrLboa9YuZMQzUAL1F8MXI9b6EjoJlBYVWdBNKysboy8Ii4+ioiFmfTY4FlRSIZwLIj3V0gqscd0xjSSQKFxoBMtIe6oIGI4+eT/MvGBQIoEBCgNub3cSegp4CjoABFx2HPX7IrN/u40TelnmU8QcMvCL4iiWmB3Pw2hq3eeBB8L+9ycKu9Xrl0pDCEpeKGNKcb4XCJwfEjoBaQxyimDo/Q/Q8j4fiWz/+DYcTF9aBlCxz8NMg4j9do2La6juzzckAcK22K23wzdxR4/ySjF2IAjOIoIBCgRuYW1lEnoKeAo6AzuLurQtXjxmt9nHOisR7THToYYnL/Gvqh43HAHdpwv75iO1QtORycj7UL4vIAJop8VuvE+eAWkKoRI6BBMy5BG+qKntrFM5Z4k2pR7ToSp3zH4UYCKDNcZhXpiy0IjqpVG/4dGrciQY6x/gepIjOKl8ROOSrCKBAQoDYWdlEnoKeAo6ENU3Q1V8IOB6MMCyzcKN3Yb7PAaQuhL1BykECm93gcIXmo21hax1nHIgaiC7/38lis0jGdEkwYmPtRI6BP/9iapNM6cybddFYNiGfxGTISD3lX9tR31hnEwhB7sGEBAoVbuJa8EUWQOwW8171D9Jfct2EkI4Zw==";
	private static final String param = "CAMSRAoyZXUub2x5bXB1cy51dGlsLnBhaXJpbmdCTFM0NjEuUGFpcmluZ0J1aWxkZXJCTFM0NjESA25vdxIEbmFtZRIDYWdl";
	private static final byte[] seed = "random value random value random value random value random".getBytes();
	
	@Test(expected = IllegalArgumentException.class)
	public void testVerifyPresentationTokenUnsupportedPredicate() throws InvalidProtocolBufferException, MSSetupException {
		PSPABCVerifier verifier = new PSPABCVerifier();
		PSverfKey key = new PSverfKey(Base64.decodeBase64(key0));
		PabcPublicParameters publicParameters = new PabcPublicParameters(generateAttributeDefinitions(),param);
		verifier.setup(publicParameters, key, seed);
		
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("Name", Operation.EQ, new Attribute(15)));
		Policy policy = new Policy(predicates, "message");
		String testToken = "CN6ZhYDyLhIPCgNBZ2USCAoEAAAAFRABIrEGCvMBCvABCjoIlIzhiR3lE04K17TQs1MPXSxvdqNDaC3VxMsyBWqW+Px3xc8tts90OonUe+Opi3TPO0bmxgmoD3xUEjoRsxmeWHAq24oV0S/fl3DbklY8IUfyy3Odw1TA+KcPFpM0NU06I1zfrOkRAD3/bN0kh0ZuFKYw4nBnGjoSFMsQAPHocIy08YzXmby6htgbo21OhfxcYLPg7BaNUA9hROfAwnBIOe5EA2FpJxWx9KrLsgu0Z06fIjoLCnEbCrzuiD7gef5dIVoiVUIy+0qC4BYoHlLfgf8enMocwugxFcHEVEahnEMhjUJNfk/amEURLZhPEvMBCvABCjoGBrUCBMRmTmG5x0jeNegd1L8UKBLjYnibFdksEG7ddjl0MWCI05x6zsaNkIS93m4svWn2SpCgvtFsEjoQ/Cyco/PgTT8tAA95/zM8JMuHdA32b/J2XSf76m39BwErDfMOWEmv+WgC1KMq36VI+dT9UhmyU5GoGjoC4wZrQrVlZPd+xsh3zmcPG/II6bjiiQmF5fBcUgVlz//6euGYI57cNzx1ELTucbiwFbMBxDEnSCQHIjoNaHY8NbipEzwm1VzRmKiwnna9jVfB7wjkUWizGi/TDAaOWduUe7pPL10EyxAIUzPqdck3Cj/rFxbsGjwKOgAAAAAAAAAAAAAAAAAAAAAAAAACKlDC7crysZxafk4uSrkp5Qpq+oVnbEZeYmf3YhcgLTseSiFPRtsiQwoDTm93EjwKOgAAAAAAAAAAAAAAAAAAAAAAAAAJ5CoJ5lmgScCzU12DN8q4OmzZxDJicZT38yzhBjONRvwgsWt94+siRAoETmFtZRI8CjoAAAAAAAAAAAAAAAAAAAAAAAAAAUoTSPJ1ISEJ68XXZasWdSq+/puIGPq4co1E1O/WDQw6BzUcFVKZKjwKOgAAAAAAAAAAAAAAAAAAAAAAAAAPLiB4b4SMisd607PXiX2eUeqEnW7XFxJ1LNGemIaHIMgNZl0WeOsyPAo6AAAAAAAAAAAAAAAAAAAAAAAAAAJ2i1oQ9Z/w9t3ELwZZ+36N4wuamR4c7GDrOeM70cel4biQfilRRA==";
		verifier.verifyPresentationToken(testToken, policy);
		fail();
	}

	@Test(expected = IllegalArgumentException.class)
	public void testVerifyPresentationTokenWrongPolicyRepeated() throws InvalidProtocolBufferException, MSSetupException {
		PSPABCVerifier verifier = new PSPABCVerifier();
		PSverfKey key = new PSverfKey(Base64.decodeBase64(key0));
		PabcPublicParameters publicParameters = new PabcPublicParameters(generateAttributeDefinitions(),param);
		verifier.setup(publicParameters, key, seed);

		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("Age", Operation.GREATERTHANOREQUAL, new Attribute(15)));
		predicates.add(new Predicate("Age", Operation.LESSTHANOREQUAL, new Attribute(30)));
		Policy policy = new Policy(predicates, "message");
		String testToken = "CN6ZhYDyLhIPCgNBZ2USCAoEAAAAFRABIrEGCvMBCvABCjoIlIzhiR3lE04K17TQs1MPXSxvdqNDaC3VxMsyBWqW+Px3xc8tts90OonUe+Opi3TPO0bmxgmoD3xUEjoRsxmeWHAq24oV0S/fl3DbklY8IUfyy3Odw1TA+KcPFpM0NU06I1zfrOkRAD3/bN0kh0ZuFKYw4nBnGjoSFMsQAPHocIy08YzXmby6htgbo21OhfxcYLPg7BaNUA9hROfAwnBIOe5EA2FpJxWx9KrLsgu0Z06fIjoLCnEbCrzuiD7gef5dIVoiVUIy+0qC4BYoHlLfgf8enMocwugxFcHEVEahnEMhjUJNfk/amEURLZhPEvMBCvABCjoGBrUCBMRmTmG5x0jeNegd1L8UKBLjYnibFdksEG7ddjl0MWCI05x6zsaNkIS93m4svWn2SpCgvtFsEjoQ/Cyco/PgTT8tAA95/zM8JMuHdA32b/J2XSf76m39BwErDfMOWEmv+WgC1KMq36VI+dT9UhmyU5GoGjoC4wZrQrVlZPd+xsh3zmcPG/II6bjiiQmF5fBcUgVlz//6euGYI57cNzx1ELTucbiwFbMBxDEnSCQHIjoNaHY8NbipEzwm1VzRmKiwnna9jVfB7wjkUWizGi/TDAaOWduUe7pPL10EyxAIUzPqdck3Cj/rFxbsGjwKOgAAAAAAAAAAAAAAAAAAAAAAAAACKlDC7crysZxafk4uSrkp5Qpq+oVnbEZeYmf3YhcgLTseSiFPRtsiQwoDTm93EjwKOgAAAAAAAAAAAAAAAAAAAAAAAAAJ5CoJ5lmgScCzU12DN8q4OmzZxDJicZT38yzhBjONRvwgsWt94+siRAoETmFtZRI8CjoAAAAAAAAAAAAAAAAAAAAAAAAAAUoTSPJ1ISEJ68XXZasWdSq+/puIGPq4co1E1O/WDQw6BzUcFVKZKjwKOgAAAAAAAAAAAAAAAAAAAAAAAAAPLiB4b4SMisd607PXiX2eUeqEnW7XFxJ1LNGemIaHIMgNZl0WeOsyPAo6AAAAAAAAAAAAAAAAAAAAAAAAAAJ2i1oQ9Z/w9t3ELwZZ+36N4wuamR4c7GDrOeM70cel4biQfilRRA==";
		verifier.verifyPresentationToken(testToken, policy);
		fail();
	}

	@Test()
	public void testVerifyPresentationTokenWrongPolicyRequestedAttributes() throws InvalidProtocolBufferException, MSSetupException {
		PSPABCVerifier verifier = new PSPABCVerifier();
		PSverfKey key = new PSverfKey(Base64.decodeBase64(key0));
		PabcPublicParameters publicParameters = new PabcPublicParameters(generateAttributeDefinitions(),param);
		verifier.setup(publicParameters, key, seed);
		List<Predicate> predicates3 = new ArrayList<>();
		predicates3.add(new Predicate("NotPresent", Operation.REVEAL, null));
		Policy policyNotPresentReveal=new Policy(predicates3, "signedMessage");
		List<Predicate> predicates4 = new ArrayList<>();
		predicates4.add(new Predicate("NotPresent", Operation.GREATERTHANOREQUAL, new Attribute(10)));
		Policy policyNotPresentRange=new Policy(predicates4, "signedMessage");
		String testToken = "CN6ZhYDyLhIPCgNBZ2USCAoEAAAAFRABIrEGCvMBCvABCjoIlIzhiR3lE04K17TQs1MPXSxvdqNDaC3VxMsyBWqW+Px3xc8tts90OonUe+Opi3TPO0bmxgmoD3xUEjoRsxmeWHAq24oV0S/fl3DbklY8IUfyy3Odw1TA+KcPFpM0NU06I1zfrOkRAD3/bN0kh0ZuFKYw4nBnGjoSFMsQAPHocIy08YzXmby6htgbo21OhfxcYLPg7BaNUA9hROfAwnBIOe5EA2FpJxWx9KrLsgu0Z06fIjoLCnEbCrzuiD7gef5dIVoiVUIy+0qC4BYoHlLfgf8enMocwugxFcHEVEahnEMhjUJNfk/amEURLZhPEvMBCvABCjoGBrUCBMRmTmG5x0jeNegd1L8UKBLjYnibFdksEG7ddjl0MWCI05x6zsaNkIS93m4svWn2SpCgvtFsEjoQ/Cyco/PgTT8tAA95/zM8JMuHdA32b/J2XSf76m39BwErDfMOWEmv+WgC1KMq36VI+dT9UhmyU5GoGjoC4wZrQrVlZPd+xsh3zmcPG/II6bjiiQmF5fBcUgVlz//6euGYI57cNzx1ELTucbiwFbMBxDEnSCQHIjoNaHY8NbipEzwm1VzRmKiwnna9jVfB7wjkUWizGi/TDAaOWduUe7pPL10EyxAIUzPqdck3Cj/rFxbsGjwKOgAAAAAAAAAAAAAAAAAAAAAAAAACKlDC7crysZxafk4uSrkp5Qpq+oVnbEZeYmf3YhcgLTseSiFPRtsiQwoDTm93EjwKOgAAAAAAAAAAAAAAAAAAAAAAAAAJ5CoJ5lmgScCzU12DN8q4OmzZxDJicZT38yzhBjONRvwgsWt94+siRAoETmFtZRI8CjoAAAAAAAAAAAAAAAAAAAAAAAAAAUoTSPJ1ISEJ68XXZasWdSq+/puIGPq4co1E1O/WDQw6BzUcFVKZKjwKOgAAAAAAAAAAAAAAAAAAAAAAAAAPLiB4b4SMisd607PXiX2eUeqEnW7XFxJ1LNGemIaHIMgNZl0WeOsyPAo6AAAAAAAAAAAAAAAAAAAAAAAAAAJ2i1oQ9Z/w9t3ELwZZ+36N4wuamR4c7GDrOeM70cel4biQfilRRA==";
		try{
			verifier.verifyPresentationToken(testToken, policyNotPresentReveal);
			fail();
		}catch (IllegalArgumentException e){
		}
		try{
			verifier.verifyPresentationToken(testToken, policyNotPresentRange);
			fail();
		}catch (IllegalArgumentException e){
		}
	}

	//Revealed/Range attributes not in AttrDefinitions


	private Set<AttributeDefinition> generateAttributeDefinitions() {
		Set<AttributeDefinition> res=new HashSet<>();
		res.add(new AttributeDefinitionString("Name","Name",0,16));
		res.add(new AttributeDefinitionInteger("Age","Age",0,123));
		res.add(new AttributeDefinitionDate("Now","Now","1900-01-01T00:00:00","2100-09-01T00:00:00"));
		return res;
	}

	@Test(expected = RuntimeException.class)
	public void testSetupBadInput() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(1));
		
		List<PabcIdPImpl> idps = new ArrayList<PabcIdPImpl>();
		idps.add(new PabcIdPImpl(db, null, new HashMap<String, MFAAuthenticator>(), cm, 10000) {
			@Override
			public PabcPublicParameters getPabcPublicParam() {
				return new PabcPublicParameters(new HashSet<>(),"Wrong");
			}
		});
		PSPABCVerifier verifier = new PSPABCVerifier();
		verifier.setup(idps,seed);
	}


	@Test(expected = RuntimeException.class)
	public void testSetupWrongSchemeName() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(1));

		List<PabcIdPImpl> idps = new ArrayList<PabcIdPImpl>();
		idps.add(new PabcIdPImpl(db, null,null, cm, 10000) {
			@Override
			public PabcPublicParameters getPabcPublicParam() {
				MSpublicParam params=new PSpublicParam(1,new PSauxArg("WrongName",new HashSet<>()));
				return new PabcPublicParameters(new HashSet<>(),params.getEncoded());
			}
		});
		PSPABCVerifier verifier = new PSPABCVerifier();
		verifier.setup(idps,seed);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetupConflictingAttributeNames() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(1));

		List<PabcIdPImpl> idps = new ArrayList<PabcIdPImpl>();
		idps.add(new PabcIdPImpl(db, null,null, cm, 10000) {
			@Override
			public PabcPublicParameters getPabcPublicParam() {
				return new PabcPublicParameters(new HashSet<>(),param);
			}
		});
		PSPABCVerifier verifier = new PSPABCVerifier();
		verifier.setup(idps,seed);
	}

}
