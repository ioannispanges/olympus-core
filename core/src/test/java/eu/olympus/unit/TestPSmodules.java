package eu.olympus.unit;


import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

import eu.olympus.client.PSCredentialManagement;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.CredentialStorage;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionDate;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.Operation;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.model.PSCredential;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.PresentationToken;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.server.PabcIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.ThresholdPSSharesGenerator;
import eu.olympus.server.interfaces.CredentialGenerator;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PabcIdP;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.unit.util.MockFactory;
import eu.olympus.util.Pair;
import eu.olympus.util.multisign.MSauxArg;
import eu.olympus.util.multisign.MSpublicParam;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.psmultisign.PSauxArg;
import eu.olympus.util.psmultisign.PSms;
import eu.olympus.util.psmultisign.PSpublicParam;
import eu.olympus.util.rangeProof.RangePredicateToken;
import eu.olympus.verifier.PSPABCVerifier;
import eu.olympus.verifier.VerificationResult;
import eu.olympus.verifier.interfaces.PABCVerifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class TestPSmodules {
	@Rule
	public final ExpectedException exception = ExpectedException.none();
	
	private static final int nServers = 3;
	private final byte[] seed = "random value random value random value random value random".getBytes();
	private long lifetime = 72000000;
	private long allowedTimeDifference = 10000l;

	private Set<AttributeDefinition> generateAttributeDefinitions() {
		Set<AttributeDefinition> res=new HashSet<>();
		res.add(new AttributeDefinitionString("name","name",0,16));
		res.add(new AttributeDefinitionInteger("age","age",0,123));
		res.add(new AttributeDefinitionDate("now","now","1900-01-01T00:00:00","2100-09-01T00:00:00"));
		return res;
	}

	@Test(expected = IllegalStateException.class)
	public void testGetVerificationKeyNoSetup() throws SetupException {
		ThresholdPSSharesGenerator generator = new ThresholdPSSharesGenerator(mock(Storage.class),new byte[256]);
		generator.getVerificationKeyShare();
	}

	@Test(expected = IllegalStateException.class)
	public void testCreateCredentialShareNoSetup() throws SetupException, OperationFailedException {
		ThresholdPSSharesGenerator generator = new ThresholdPSSharesGenerator(mock(Storage.class),new byte[256]);
		generator.createCredentialShare("",0L);
	}

	@Test
	public void testCorrectFlowWithStorage() throws Exception {
		String username="userJoe";
		PestoDatabase database= new InMemoryPestoDatabase();
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed );
		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule).setup(publicParams,aggregatedVerificationKey,seed );
		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("now", Operation.REVEAL, null));
		predicates.add(new Predicate("age", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);
		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		PresentationToken zkPT = credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policy);
		//Client uses module to generate presentation token for the policy
//		PresentationToken zkPT=credentialClientModule.generatePresentationToken(policy);
		//Verification of the presentation token
		VerificationResult result=credentialVerifierModule.verifyPresentationToken(zkPT.getEncoded(),policy);
		assertEquals(VerificationResult.VALID, result);
		String signedMessage2="signedMessage2"; 
		List<Predicate> predicates2 = new ArrayList<>();
		predicates2.add(new Predicate("Age", Operation.REVEAL, null));
		Policy policy2=new Policy(predicates2, signedMessage2);
		//Client has the credential and uses it without contacting servers
		assertThat(credentialClientModule.checkStoredCredential(),is(true));
		PresentationToken zkPT2 = credentialClientModule.generatePresentationToken(policy2);
		VerificationResult result2=credentialVerifierModule.verifyPresentationToken(zkPT2.getEncoded(),policy2);
		assertEquals(VerificationResult.VALID, result2);
	}

	@Test
	public void testCorrectFlowNoStorage() throws Exception {
		String username="userJoe";
		PestoDatabase database=new InMemoryPestoDatabase();
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1 );
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(false,null);
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);
		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule).setup(publicParams,aggregatedVerificationKey,seed);

		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("now", Operation.REVEAL, null));
		predicates.add(new Predicate("age", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);
		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		//Client uses module to generate presentation token for the policy
		PresentationToken zkPT=credentialClientModule.combineAndGeneratePresentationToken(credentialShares,policy);
		//Verification of the presentation token
		VerificationResult result=credentialVerifierModule.verifyPresentationToken(zkPT.getEncoded(),policy);
		assertEquals(VerificationResult.VALID, result);
	}

	@Test
	public void testExpiredCredential() throws Exception {
		String username="userJoe";
		PestoDatabase database=new InMemoryPestoDatabase();
		Set<AttributeDefinition> definitions=new HashSet<>();
		definitions.add(new AttributeDefinitionString("name","name",0,16));
		definitions.add(new AttributeDefinitionInteger("age","age",0,123));
		definitions.add(new AttributeDefinitionInteger("height","age",10,300));
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("height", new Attribute(170));
		database.addUser(username,null, 1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(definitions);
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			((ThresholdPSSharesGenerator)credentialServerModule).setLifetime(2000); //Later lifetime should be configurable (in a better way)
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);
		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule).setup(publicParams,aggregatedVerificationKey,seed);

		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("name", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);
		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		PresentationToken zkPT = credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policy);
		//Client uses module to generate presentation token for the policy
		
		//Verification of the presentation token
		VerificationResult result=credentialVerifierModule.verifyPresentationToken(zkPT.getEncoded(),policy);
		assertThat(result, is(VerificationResult.VALID));
		TimeUnit.SECONDS.sleep(3);
		result=credentialVerifierModule.verifyPresentationToken(zkPT.getEncoded(),policy);
		assertThat(result, is(VerificationResult.BAD_TIMESTAMP));
	}

	@Test(expected=IllegalArgumentException.class)
	public void testWrongTimestamp() throws Exception {
		String username="userJoe";
		PestoDatabase database=new InMemoryPestoDatabase();
		Set<AttributeDefinition> definitions=new HashSet<>();
		definitions.add(new AttributeDefinitionString("name","name",0,16));
		definitions.add(new AttributeDefinitionInteger("age","age",0,123));
		definitions.add(new AttributeDefinitionInteger("height","age",10,300));
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("height", new Attribute(170));
		database.addUser(username,null, 1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(definitions);
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);
		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule).setup(publicParams,aggregatedVerificationKey,seed);

		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage"; 
		//Policy creation

		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("name", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);

		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis()+11000; // As in the user tries to say it was 11 seconds later
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
	}

	@Test(expected = RuntimeException.class)
	public void testCredentialManagementBadSetupServers() throws Exception {
		List<PabcIdP> servers = new LinkedList<>();
		servers.add(new PabcIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), null, 100) {
			@Override
			public PabcPublicParameters getPabcPublicParam() {
				MSpublicParam param = new MSpublicParam() {

					@Override
					public int getN() {
						return 0;
					}

					@Override
					public MSauxArg getAuxArg() {
						return new PSauxArg("pairingName", new HashSet<String>());
					}

					@Override
					public String getEncoded() {
						return "WrongEncoded";
					}
				};
				return new PabcPublicParameters(new HashSet<>(),param.getEncoded());
			}
		});
		PSCredentialManagement credentialManagement=new PSCredentialManagement(false,null);
		credentialManagement.setup(servers,seed);
		fail("Should throw RuntimeException");
	}

	@Test(expected = RuntimeException.class)
	public void testVerifierBadConstructor() throws Exception {
		List<PabcIdP> servers = new LinkedList<>();
		servers.add(new PabcIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), null, 100) {
			@Override
			public PabcPublicParameters getPabcPublicParam() {
				MSpublicParam param = new MSpublicParam() {

					@Override
					public int getN() {
						return 0;
					}

					@Override
					public MSauxArg getAuxArg() {
						return new PSauxArg("pairingName", new HashSet<String>());
					}

					@Override
					public String getEncoded() {
						return "WrongEncoded";
					}
				};
				return new PabcPublicParameters(new HashSet<>(),param.getEncoded());
			}
		});
		PSPABCVerifier credentialVerifierModule = new PSPABCVerifier();
		credentialVerifierModule.setup(servers,seed);
		fail("Should throw RuntimeException");
	}

	@Test
	public void testVerifierSetupExceptions() throws Exception {
		Set<String> attr=new HashSet<>();
		attr.add("test");
		MSpublicParam wrongPublicParam=new PSpublicParam(1,new PSauxArg("WrongPairingName",attr));
		PSPABCVerifier credentialVerifierModule = new PSPABCVerifier();
		MSpublicParam differentAttrPublicParam=new PSpublicParam(1,new PSauxArg("eu.olympus.util.pairingBLS461.PairingBuilderBLS461",attr));
		try {
			credentialVerifierModule.setup(new PabcPublicParameters(generateAttributeDefinitions(),differentAttrPublicParam.getEncoded()),null,seed);
			fail("Should throw IllegalArgumentException, conflictingAttr");
		}catch (IllegalArgumentException e){
		}
		try {
			credentialVerifierModule.setup(new PabcPublicParameters(generateAttributeDefinitions(),"ExtraWrong"+wrongPublicParam.getEncoded()),null,seed);
			fail("Should throw IllegalArgumentException, wrongPublicParam");
		}catch (IllegalArgumentException e){
		}
		try {
			credentialVerifierModule.setup(new PabcPublicParameters(new HashSet<>(),wrongPublicParam.getEncoded()),null,seed);
			fail("Should throw MSSetupException");
		}catch (MSSetupException e){
		}

	}


	@Test(expected = IllegalStateException.class)
	public void testVerifierNoSetupException() throws Exception {
		String username="userJoe";
		PestoDatabase database= new InMemoryPestoDatabase();
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);
		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("now", Operation.REVEAL, null));
		predicates.add(new Predicate("age", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);

		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		PresentationToken zkPT = credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policy);
		//Client uses module to generate presentation token for the policy
//		PresentationToken zkPT=credentialClientModule.generatePresentationToken(policy);
		//Verification of the presentation token
		credentialVerifierModule.verifyPresentationToken(zkPT.getEncoded(),policy);
		fail("Should throw IllegalSateException");
	}

	@Test()
	public void testVerifierMalformedToken() throws Exception {
		String username="userJoe";
		PestoDatabase database= new InMemoryPestoDatabase();
		Set<String> attrNames=new HashSet<>(Arrays.asList("Name","Age","Now"));
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);
		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("Now", Operation.REVEAL, null));
		predicates.add(new Predicate("Age", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);
		((PSPABCVerifier)credentialVerifierModule).setup(publicParams,aggregatedVerificationKey,seed);
		assertThat(credentialVerifierModule.verifyPresentationToken("MalformedToken",policy),is(VerificationResult.INVALID_SIGNATURE));
	}

	@Test
	public void testPolicyNotfulfilled() throws Exception {
		String username="userJoe";
		PestoDatabase database=new InMemoryPestoDatabase();
		Set<AttributeDefinition> definitions=new HashSet<>();
		definitions.add(new AttributeDefinitionString("name","name",0,16));
		definitions.add(new AttributeDefinitionInteger("age","age",0,123));
		definitions.add(new AttributeDefinitionInteger("height","age",10,300));
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("height", new Attribute(170));
		database.addUser(username,null, 1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(definitions);
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);
		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule).setup(publicParams,aggregatedVerificationKey,seed);

		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("name", Operation.REVEAL, null));
		predicates.add(new Predicate("age", Operation.REVEAL, null));
		Policy policyRequested=new Policy(predicates, signedMessage);
		List<Predicate> predicatesRevealed = new ArrayList<>();
		predicatesRevealed.add(new Predicate("name", Operation.REVEAL, null));
		Policy policyRevealed=new Policy(predicatesRevealed, signedMessage);
		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		PresentationToken zkPT = credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policyRevealed);
		//Client uses module to generate presentation token for the policy
		//PresentationToken zkPT=credentialClientModule.generatePresentationToken(policy);
		//Verification of the presentation token
		VerificationResult result=credentialVerifierModule.verifyPresentationToken(zkPT.getEncoded(),policyRequested);
		assertThat(result, is(VerificationResult.POLICY_NOT_FULFILLED));
	}

	@Test
	public void testWrongMessageSigned() throws Exception {
		String username="userJoe";
		PestoDatabase database=new InMemoryPestoDatabase();
		Set<AttributeDefinition> definitions=new HashSet<>();
		definitions.add(new AttributeDefinitionString("name","name",0,16));
		definitions.add(new AttributeDefinitionInteger("age","age",0,123));
		definitions.add(new AttributeDefinitionInteger("height","age",10,300));
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("Age", new Attribute(21));
		userAttr.put("Height", new Attribute(170));
		database.addUser(username,null, 1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(definitions);
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);
		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule).setup(publicParams,aggregatedVerificationKey,seed);

		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage";
		String requestedSignedMessage="message";
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("Name", Operation.REVEAL, null));
		Policy policyRequested=new Policy(predicates, requestedSignedMessage);
		Policy policyCredential=new Policy(predicates, signedMessage);
		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		PresentationToken zkPT = credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policyCredential);
		//Client uses module to generate presentation token for the policy
		//PresentationToken zkPT=credentialClientModule.generatePresentationToken(policy);
		//Verification of the presentation token
		VerificationResult result=credentialVerifierModule.verifyPresentationToken(zkPT.getEncoded(),policyRequested);
		assertThat(result, is(VerificationResult.INVALID_SIGNATURE));
	}

	@Test
	public void testCompleteFlowWithRange() throws Exception {
		String username="userJoe";
		PestoDatabase database= new InMemoryPestoDatabase();
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());

		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed );
		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule).setup(publicParams,aggregatedVerificationKey,seed );

		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("now", Operation.REVEAL, null));
		predicates.add(new Predicate("age", Operation.GREATERTHANOREQUAL, new Attribute(18)));
		Policy policy=new Policy(predicates, signedMessage);
		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		PresentationToken zkPT = credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policy);
		//Client uses module to generate presentation token for the policy
//		PresentationToken zkPT=credentialClientModule.generatePresentationToken(policy);
		//Verification of the presentation token
		VerificationResult result=credentialVerifierModule.verifyPresentationToken(zkPT.getEncoded(),policy);
		assertEquals(VerificationResult.VALID, result);

		String signedMessage2="signedMessage2"; 
		List<Predicate> predicates2 = new ArrayList<>();
		predicates2.add(new Predicate("age", Operation.LESSTHANOREQUAL, new Attribute(30)));
		Policy policy2=new Policy(predicates2, signedMessage2);
		//Client has the credential and uses it without contacting servers
		assertThat(credentialClientModule.checkStoredCredential(),is(true));
		PresentationToken zkPT2 = credentialClientModule.generatePresentationToken(policy2);
		VerificationResult result2=credentialVerifierModule.verifyPresentationToken(zkPT2.getEncoded(),policy2);
		assertEquals(VerificationResult.VALID, result2);
	}

	@Test
	public void testInvalidVerifications() throws Exception {
		String username="userJoe";
		PestoDatabase database= new InMemoryPestoDatabase();
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed );
		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule).setup(publicParams,aggregatedVerificationKey,seed );
		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage";
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("now", Operation.REVEAL, null));
		predicates.add(new Predicate("age", Operation.GREATERTHANOREQUAL, new Attribute(18)));
		Policy policyRange=new Policy(predicates, signedMessage);
		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		PresentationToken zkPTrange = credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policyRange);
		List<Predicate> predicates2 = new ArrayList<>();
		predicates2.add(new Predicate("now", Operation.REVEAL, null));
		Policy policyNoRange=new Policy(predicates2, signedMessage);
		PresentationToken zkPTnoRange = credentialClientModule.generatePresentationToken(policyNoRange);
		// Range tokens keys different from range preds
        PresentationToken zkPTbadRangeTokens=new PresentationToken(zkPTrange.getEpoch(),zkPTrange.getRevealedAttributes(),zkPTrange.getZkToken(),null);
		// Reconstructed token of different type for both (simply cross tokens/policies in two verifications)
		// PS Signature failed in range case
        PresentationToken zkPTbadSignatureEpochModified=new PresentationToken(zkPTrange.getEpoch()+2,zkPTrange.getRevealedAttributes(),zkPTrange.getZkToken(),zkPTrange.getRangeTokens());
        // RangePredicate proof failed
        Map<String, RangePredicateToken> badRangeTokens=zkPTrange.getRangeTokens().entrySet().stream()
                .collect(Collectors.toMap(e->e.getKey(),e->new RangePredicateToken(e.getValue().getProofLowerBound(),e.getValue().getProofLowerBound(),e.getValue().getCommitV())));
        PresentationToken zkPTbadRangeToken=new PresentationToken(zkPTrange.getEpoch(),zkPTrange.getRevealedAttributes(),zkPTrange.getZkToken(),badRangeTokens);
        assertThat(credentialVerifierModule.verifyPresentationToken(zkPTnoRange.getEncoded(),policyNoRange),is(VerificationResult.VALID));
        assertThat(credentialVerifierModule.verifyPresentationToken(zkPTrange.getEncoded(),policyRange),is(VerificationResult.VALID));
        assertThat(credentialVerifierModule.verifyPresentationToken(zkPTrange.getEncoded(),policyNoRange),is(VerificationResult.INVALID_SIGNATURE));
        assertThat(credentialVerifierModule.verifyPresentationToken(zkPTnoRange.getEncoded(),policyRange),is(VerificationResult.INVALID_SIGNATURE));
        assertThat(credentialVerifierModule.verifyPresentationToken(zkPTbadRangeTokens.getEncoded(),policyRange),is(VerificationResult.INVALID_SIGNATURE));
        assertThat(credentialVerifierModule.verifyPresentationToken(zkPTbadSignatureEpochModified.getEncoded(),policyRange),is(VerificationResult.INVALID_SIGNATURE));
        assertThat(credentialVerifierModule.verifyPresentationToken(zkPTbadRangeToken.getEncoded(),policyRange),is(VerificationResult.INVALID_SIGNATURE));
    }

	@Test
	public void testPSCredManagerSetupExceptions() throws Exception {
		PSCredentialManagement manager=new PSCredentialManagement(true,new InMemoryCredentialStorage());
		PSms psScheme=new PSms();
		int n=3;
		MSpublicParam pp=psScheme.setup(n,new PSauxArg("eu.olympus.util.pairingBLS461.PairingBuilderBLS461",new HashSet<>(Arrays.asList("age","name","now"))),seed);
		//Create wrong elements
		Map<Integer,MSverfKey> correctNumberVks=new HashMap<>();
		correctNumberVks.put(1, MockFactory.mockVerfKey());
		correctNumberVks.put(2,MockFactory.mockVerfKey());
		correctNumberVks.put(3,MockFactory.mockVerfKey());
		Map<Integer,MSverfKey> wrongNumberVks=new HashMap<>();
		wrongNumberVks.put(1,MockFactory.mockVerfKey());
		MSverfKey mockKey=MockFactory.mockVerfKey();
		MSpublicParam wrongPP=new PSpublicParam(n,new PSauxArg("wrongName",new HashSet<>(Arrays.asList("age","name","now"))));
		MSpublicParam differentAttrPublicParam=new PSpublicParam(n,new PSauxArg("eu.olympus.util.pairingBLS461.PairingBuilderBLS461",new HashSet<>(Arrays.asList("Age","Name"))));
		PabcIdP mockIdpConflict=new MockIdPForSetup(new PabcPublicParameters(generateAttributeDefinitions(),differentAttrPublicParam.getEncoded()));
		PabcIdP mockIdpWrongPP=new MockIdPForSetup(new PabcPublicParameters(generateAttributeDefinitions(),wrongPP.getEncoded()));
		PabcIdP mockIdpWrongPPSerial=new MockIdPForSetup(new PabcPublicParameters(generateAttributeDefinitions(),"wrongExtra"+pp.getEncoded()));
		try{
			manager.setup(Collections.singletonList(mockIdpConflict),seed);
			fail("Should throw SetupException, listIdp conflictingAttributeNames");
		}catch (SetupException e){
		}
		try{
			manager.setup(Collections.singletonList(mockIdpWrongPP),seed);
			fail("Should throw SetupException, listIdp wrongPP");
		}catch (SetupException e){
		}
		try{
			manager.setup(Collections.singletonList(mockIdpWrongPPSerial),seed);
			fail("Should throw SetupException, listIdp Could not retrieve scheme public param");
		}catch (SetupException e){
		}
		try{
			manager.setup(new PabcPublicParameters(generateAttributeDefinitions(),differentAttrPublicParam.getEncoded()),correctNumberVks,seed);
			fail("Should throw SetupException, conflictingAttributeNames");
		}catch (SetupException e){
		}
		try{
			manager.setup(new PabcPublicParameters(generateAttributeDefinitions(),wrongPP.getEncoded()),correctNumberVks,seed);
			fail("Should throw SetupException, wrongPP");
		}catch (SetupException e){
		}
		try{
			manager.setup(new PabcPublicParameters(generateAttributeDefinitions(),"wrongExtra"+pp.getEncoded()),wrongNumberVks,seed);
			fail("Should throw SetupException, Could not retrieve scheme public param");
		}catch (SetupException e){
		}
		try{
			manager.setup(new PabcPublicParameters(generateAttributeDefinitions(),pp.getEncoded()),wrongNumberVks,seed);
			fail("Should throw IllegalArgumentException, wrong number of vks");
		}catch (IllegalArgumentException e){
		}
		try{
			manager.setup(new PabcPublicParameters(generateAttributeDefinitions(),pp.getEncoded()),correctNumberVks,seed);
			fail("Should throw IllegalArgumentException, wrong vk type");
		}catch (IllegalArgumentException e){
		}
		try{
			manager.setupForOffline(new PabcPublicParameters(generateAttributeDefinitions(),differentAttrPublicParam.getEncoded()),mockKey,seed);
			fail("Should throw IllegalArgumentException, setupOffline conflictingAttributeNames");
		}catch (IllegalArgumentException e){
		}
		try{
			manager.setupForOffline(new PabcPublicParameters(generateAttributeDefinitions(),wrongPP.getEncoded()),mockKey,seed);
			fail("Should throw SetupException, setupOffline wrongPP");
		}catch (SetupException e){
		}
		try{
			manager.setupForOffline(new PabcPublicParameters(generateAttributeDefinitions(),"wrongExtra"+pp.getEncoded()),mockKey,seed);
			fail("Should throw SetupException, setupOffline Could not retrieve scheme public param");
		}catch (SetupException e){
		}

	}

	@Test
	public void testPSCredManagerCheckStoredCredential() throws Exception {
		String username="userJoe";
		PestoDatabase database= new InMemoryPestoDatabase();
		Set<String> attrNames=new HashSet<>(Arrays.asList("Name","Age","Now"));
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("Name", new Attribute("Joe"));
		userAttr.put("Age", new Attribute(21));
		userAttr.put("Now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(2000);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);

		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("Now", Operation.REVEAL, null));
		predicates.add(new Predicate("Age", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);
		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		assertThat(credentialClientModule.checkStoredCredential(),is(false));
		credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policy);
		assertThat(credentialClientModule.checkStoredCredential(),is(true));
		TimeUnit.SECONDS.sleep(3);
		assertThat(credentialClientModule.checkStoredCredential(),is(false));
		PSCredentialManagement credentialClientModule2=new PSCredentialManagement(false,null);
		credentialClientModule2.setup(publicParams,verificationKeyShares,seed);
		assertThat(credentialClientModule2.checkStoredCredential(),is(false));
	}

	@Test
	public void testPSCredManagerGeneratePresentationTokenExceptions() throws Exception {
		String username="userJoe";
		PestoDatabase database=new InMemoryPestoDatabase();
		Set<String> attrNames=new HashSet<>(Arrays.asList("Name","Age","Now"));
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("Name", new Attribute("John"));
		userAttr.put("Now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1 );
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("Now", Operation.REVEAL, null));
		predicates.add(new Predicate("Name", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);
		List<Predicate> predicates2 = new ArrayList<>();
		predicates2.add(new Predicate("Name", Operation.REVEAL, null));
		predicates2.add(new Predicate("Age", Operation.REVEAL, null));
		Policy policy2=new Policy(predicates2, signedMessage);
		List<Predicate> predicates3 = new ArrayList<>();
		predicates3.add(new Predicate("Name", Operation.EQ, null));
		Policy policy3=new Policy(predicates3, signedMessage);
		List<Predicate> predicates4 = new ArrayList<>();
		predicates4.add(new Predicate("Age", Operation.GREATERTHANOREQUAL, new Attribute(10)));
		Policy policy4=new Policy(predicates4, signedMessage);
		List<Predicate> predicates5 = new ArrayList<>();
		predicates5.add(new Predicate("Now", Operation.GREATERTHANOREQUAL, new Attribute(10)));
		predicates5.add(new Predicate("Now", Operation.LESSTHANOREQUAL, new Attribute(20)));
		Policy policy5=new Policy(predicates5, signedMessage);
		try{
			credentialClientModule.generatePresentationToken(policy);
			fail("Should throw IllegalStateException, no setup");
		}catch (IllegalStateException e){
		}
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);
		//Client uses module to generate presentation token for the policy
		try{
			credentialClientModule.generatePresentationToken(policy);
			fail("Should throw IllegalStateException, no credential");
		}catch (IllegalStateException e){
		}
		Map<Integer, PSCredential> goodCredentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(int id=0;id<nServers; id++)
			goodCredentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		Assert.assertNotNull(credentialClientModule.combineAndGeneratePresentationToken(goodCredentialShares,policy));
		Assert.assertNotNull(credentialClientModule.generatePresentationToken(policy));
		try{
			credentialClientModule.generatePresentationToken(policy2);
			fail("Should throw IllegalArgumentException, unfulfilled policy reveal");
		}catch (TokenGenerationException e){
		}
		try{
			credentialClientModule.generatePresentationToken(policy3);
			fail("Should throw TokenGenerationException, unsupported policy");
		}catch (TokenGenerationException e){
		}
		try{
			credentialClientModule.generatePresentationToken(policy4);
			fail("Should throw TokenGenerationException, unfulfilled policy range");
		}catch (TokenGenerationException e){
		}
		try{
			credentialClientModule.generatePresentationToken(policy5);
			fail("Should throw TokenGenerationException, illegal policy repeated");
		}catch (TokenGenerationException e){
		}
	}

	@Test
	public void testPSCredManagerCombineAndGeneratePresentationTokenExceptions() throws Exception {
		String username="userJoe";
		PestoDatabase database=new InMemoryPestoDatabase();
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("Age", new Attribute(21));
		userAttr.put("Now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1 );
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		//Setup client module
		CredentialManagement credentialClientModule= new PSCredentialManagement(false,null);
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("Now", Operation.REVEAL, null));
		predicates.add(new Predicate("Age", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);
		List<Predicate> predicates2 = new ArrayList<>();
		predicates2.add(new Predicate("Name", Operation.REVEAL, null));
		predicates2.add(new Predicate("Age", Operation.REVEAL, null));
		Policy policy2=new Policy(predicates2, signedMessage);
		try{
			credentialClientModule.combineAndGeneratePresentationToken(null,policy);
			fail("Should throw IllegalStateException, no setup");
		}catch (IllegalStateException e){
		}
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);
		//Create wrong shares
		Map<Integer, PSCredential> wrongNumberCredentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(int id=0;id<nServers-1; id++)
			wrongNumberCredentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		Map<Integer, PSCredential> wrongIdsCredentialShares=new HashMap<>();
		for(int id=0;id<nServers; id++)
			wrongIdsCredentialShares.put(id+1,mapServers.get(id).createCredentialShare(username,timestamp));
		Map<Integer, PSCredential> wrongCombinationShares=new HashMap<>();
		for(int id=0;id<nServers; id++)
			wrongCombinationShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp+id));
		Map<Integer, PSCredential> goodCredentialShares=new HashMap<>();
		for(int id=0;id<nServers; id++)
			goodCredentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		try{
			credentialClientModule.combineAndGeneratePresentationToken(wrongNumberCredentialShares,policy);
			fail("Should throw IllegalArgumentException, wrong number credential shares");
		}catch (IllegalArgumentException e){
		}
		try{
			credentialClientModule.combineAndGeneratePresentationToken(wrongIdsCredentialShares,policy);
			fail("Should throw IllegalArgumentException, wrong ids shares");
		}catch (TokenGenerationException e){
		}
		try{
			credentialClientModule.combineAndGeneratePresentationToken(goodCredentialShares,policy2);
			fail("Should throw TokenGenerationException, unfulfilled policy");
		}catch (TokenGenerationException e){
		}
		try{
			credentialClientModule.combineAndGeneratePresentationToken(wrongCombinationShares,policy);
		} catch (TokenGenerationException e){
		}
		Assert.assertNotNull(credentialClientModule.combineAndGeneratePresentationToken(goodCredentialShares,policy));
	}



	@Test
	public void credentialManagerGetPublicParam() throws Exception {
		String username="userJoe";
		PestoDatabase database= new InMemoryPestoDatabase();
		Set<String> attrNames=new HashSet<>(Arrays.asList("name","age","now"));
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialManagement credentialClientModule1= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule1).setup(publicParams,verificationKeyShares,seed);
		Pair<PabcPublicParameters,Map<Integer,MSverfKey>> pp=((PSCredentialManagement) credentialClientModule1).getPublicParams();
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,new InMemoryCredentialStorage());
		((PSCredentialManagement)credentialClientModule).setup(pp.getFirst(),pp.getSecond(),seed);

		//Setup verifier module
		PABCVerifier credentialVerifierModule1 = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule1).setup(publicParams,aggregatedVerificationKey,seed);
		Pair<PabcPublicParameters,MSverfKey> ppV=((PSPABCVerifier) credentialVerifierModule1).getPublicParams();
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule).setup(ppV.getFirst(),ppV.getSecond(),seed);

		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage"; 
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("now", Operation.REVEAL, null));
		predicates.add(new Predicate("age", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);
		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		PresentationToken zkPT = credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policy);
		//Client uses module to generate presentation token for the policy
//		PresentationToken zkPT=credentialClientModule.generatePresentationToken(policy);
		//Verification of the presentation token
		VerificationResult result=credentialVerifierModule.verifyPresentationToken(zkPT.getEncoded(),policy);
		assertThat(result, is(VerificationResult.VALID));

		List<Predicate> predicates2 = new ArrayList<>();
		predicates2.add(new Predicate("age", Operation.REVEAL, null));
		Policy policy2=new Policy(predicates2, signedMessage);
		//Client has the credential and uses it without contacting servers
		assertThat(credentialClientModule.checkStoredCredential(),is(true));
		PresentationToken zkPT2 = credentialClientModule.generatePresentationToken(policy2);
		VerificationResult result2=credentialVerifierModule.verifyPresentationToken(zkPT2.getEncoded(),policy2);
		assertThat(result2, is(VerificationResult.VALID));
	}


	@Test(expected = IllegalStateException.class)
	public void pabcVerifierGetPublicParamException(){
		PSPABCVerifier pabcVerifier=new PSPABCVerifier();
		pabcVerifier.getPublicParams();
	}

	@Test
	public void testFlowOfflineSetup() throws Exception {
		String username="userJoe";
		PestoDatabase database= new InMemoryPestoDatabase();
		Map<String, Attribute> userAttr=new HashMap<>();
		userAttr.put("name", new Attribute("Joe"));
		userAttr.put("age", new Attribute(21));
		userAttr.put("now", new Attribute(new Date(System.currentTimeMillis())));
		database.addUser(username,null,1);
		database.addAttributes(username,userAttr);
		//Create and credentialGenerator module for each server.
		Map<Integer,CredentialGenerator> mapServers=new HashMap<>();
		PabcPublicParameters publicParams=null;
		for(int i=0;i<nServers; i++){
			CredentialGenerator credentialServerModule=new ThresholdPSSharesGenerator(database,seed);
			PABCConfigurationImpl config = new PABCConfigurationImpl();
			config.setAttrDefinitions(generateAttributeDefinitions());
			config.setSeed(seed);
			config.setLifetime(lifetime);
			config.setAllowedTimeDifference(allowedTimeDifference);
			config.setServers(Arrays.asList("1", "2"));
			credentialServerModule.setup(config);
			publicParams=credentialServerModule.getPublicParam();
			mapServers.put(i,credentialServerModule);
		}
		MSpublicParam schemePublicParam=new PSpublicParam(publicParams.getEncodedSchemePublicParam());
		//Obtain publicKeyShares and aggregatedKey
		Map<Integer, MSverfKey> verificationKeyShares=new HashMap<>();
		MSverfKey[] verificationKeys=new MSverfKey[nServers];
		int i=0;
		for(Integer id:mapServers.keySet()){
			MSverfKey key=(MSverfKey)mapServers.get(id).getVerificationKeyShare();
			verificationKeys[i]=key;
			verificationKeyShares.put(id,key);
			i++;
		}
		PSms auxSignScheme=new PSms();
		auxSignScheme.setup(schemePublicParam.getN(),schemePublicParam.getAuxArg(), seed);
		MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
		//Setup client module
		CredentialStorage storage=new InMemoryCredentialStorage();
		CredentialManagement credentialClientModule= new PSCredentialManagement(true,storage);
		((PSCredentialManagement)credentialClientModule).setup(publicParams,verificationKeyShares,seed);

		//Setup verifier module
		PABCVerifier credentialVerifierModule = new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule).setup(publicParams,aggregatedVerificationKey,seed);

		//*********Credential creation, proof of policy and verification***********
		String signedMessage="signedMessage";
		//Policy creation
		List<Predicate> predicates = new ArrayList<>();
		predicates.add(new Predicate("now", Operation.REVEAL, null));
		predicates.add(new Predicate("age", Operation.REVEAL, null));
		Policy policy=new Policy(predicates, signedMessage);
		//Client receives a credential share from each IdP (simplified) and passes them to the credential manager
		Map<Integer, PSCredential> credentialShares=new HashMap<>();
		long timestamp=System.currentTimeMillis();
		for(Integer id: mapServers.keySet())
			credentialShares.put(id,mapServers.get(id).createCredentialShare(username,timestamp));
		PresentationToken zkPT = credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policy);
		//Client uses module to generate presentation token for the policy
//		PresentationToken zkPT=credentialClientModule.generatePresentationToken(policy);
		//Verification of the presentation token
		VerificationResult result=credentialVerifierModule.verifyPresentationToken(zkPT.getEncoded(),policy);
		assertThat(result, is(VerificationResult.VALID));

		String signedMessage2="signedMessage2";
		List<Predicate> predicates2 = new ArrayList<>();
		predicates2.add(new Predicate("age", Operation.REVEAL, null));
		Policy policy2=new Policy(predicates2, signedMessage2);
		//Client has the credential and uses it without contacting servers
		assertThat(credentialClientModule.checkStoredCredential(),is(true));
		PresentationToken zkPT2 = credentialClientModule.generatePresentationToken(policy2);
		VerificationResult result2=credentialVerifierModule.verifyPresentationToken(zkPT2.getEncoded(),policy2);
		assertThat(result2, is(VerificationResult.VALID));
		//Get public parameters for offline and setup two new modules
		Pair<PabcPublicParameters,MSverfKey> pp=((PSCredentialManagement) credentialClientModule).getPublicParamsForOffline();
		CredentialManagement credentialClientModule2=new PSCredentialManagement(true,storage);
		((PSCredentialManagement)credentialClientModule2).setupForOffline(pp.getFirst(),pp.getSecond(),seed);
		Pair<PabcPublicParameters,MSverfKey> ppV=((PSPABCVerifier) credentialVerifierModule).getPublicParams();
		PABCVerifier credentialVerifierModule2=new PSPABCVerifier();
		((PSPABCVerifier)credentialVerifierModule2).setup(ppV.getFirst(),ppV.getSecond(),seed);
		//Presentation
		String signedMessage3="signedMessage3";
		List<Predicate> predicates3 = new ArrayList<>();
		predicates3.add(new Predicate("Now", Operation.REVEAL, null));
		Policy policy3=new Policy(predicates3, signedMessage3);
		//Client has the credential and uses it without contacting servers
		assertThat(credentialClientModule2.checkStoredCredential(),is(true));
		PresentationToken zkPT3 = credentialClientModule2.generatePresentationToken(policy3);
		VerificationResult result3=credentialVerifierModule2.verifyPresentationToken(zkPT3.getEncoded(),policy3);
		assertThat(result3, is(VerificationResult.VALID));

	}

	private class MockIdPForSetup extends PabcIdPImpl {
		PabcPublicParameters pp;
		public MockIdPForSetup(PabcPublicParameters p0) throws Exception {
			super(new InMemoryPestoDatabase(),null,null,new SoftwareServerCryptoModule(new Random(1)), 1000);
			pp=p0;
		}

		@Override
		public PabcPublicParameters getPabcPublicParam() {
			return pp;
		}
	}
}
