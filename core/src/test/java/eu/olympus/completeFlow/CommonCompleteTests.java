package eu.olympus.completeFlow;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.TestParameters;
import eu.olympus.client.PabcClient;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionDate;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.Authorization;
import eu.olympus.model.DateGranularity;
import eu.olympus.model.Operation;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PabcIdP;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.Role;
import eu.olympus.unit.server.TestIdentityProof;
import eu.olympus.unit.util.TestKeyManagementUtils;
import eu.olympus.util.ConfigurationUtil;
import eu.olympus.util.Util;
import eu.olympus.verifier.JWTVerifier;
import eu.olympus.verifier.VerificationResult;
import eu.olympus.verifier.interfaces.PABCVerifier;
import eu.olympus.verifier.interfaces.Verifier;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.commons.codec.binary.Base64;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CommonCompleteTests {

    protected static final byte[] seed = "random value random value random value random value random".getBytes();

    public static Logger logger = LoggerFactory.getLogger(CommonCompleteTests.class);

    private static final byte[] seed0 = "random value random value random value random value random0".getBytes();
    private static final byte[] seed1 = "random value random value random value random value random1".getBytes();
    private static final byte[] seed2 = "random value random value random value random value random2".getBytes();

    public static PABCConfigurationImpl[] configuration;

    private static Verifier verifier;

    private static long lifetime = 72000000;
    private static long allowedTimeDiff = 100000l;
    private static long sessionLength = 600000l;
    private static String adminCookie;
    private static final int serverCount = 3;

    @BeforeClass
    public static void setup() throws Exception {
        // TODO bit of a hack to ensure we setup volatile keys
        TestKeyManagementUtils.setupSecurityStores();

        configuration = new PABCConfigurationImpl[3];

        TestConfigurationUtil configGenerator = new TestConfigurationUtil();

        Certificate cert = configGenerator.splitKeys(
            (RSAPrivateCrtKey) TestParameters.getRSAPrivateKey2(),
            configuration.length);

        byte[][] seeds=new byte[3][];
        seeds[0]=seed0;
        seeds[1]=seed1;
        seeds[2]=seed2;

        Random rnd = new Random(1);
        List<String> servers = new ArrayList<>();
        Map<String, Authorization> authorizationCookies = new HashMap<String, Authorization>();
        for(int i=0; i< serverCount; i++) {
            servers.add(Integer.toString(i));
            byte[] rawCookie = new byte[64];
            rnd.nextBytes(rawCookie);
            authorizationCookies.put(Base64.encodeBase64String(rawCookie), new Authorization("server"+i, Arrays.asList(new Role[] {Role.SERVER}), System.currentTimeMillis()+1000000l));
        }
        byte[] rawCookie = new byte[64];
        rnd.nextBytes(rawCookie);
        adminCookie = Base64.encodeBase64String(rawCookie);
        authorizationCookies.put(adminCookie, new Authorization("Administrator", Arrays.asList(new Role[] {Role.ADMIN}), System.currentTimeMillis()+1000000l));
        for(int i = 0; i< serverCount; i++) {
            configuration[i] = new PABCConfigurationImpl();
            List<String> otherServers=new LinkedList<>(servers);
            otherServers.remove(i);
            Map<String, Authorization> authorizedUsers = new HashMap<>();
            for(String cookie: authorizationCookies.keySet()) {
                if(("server"+i).equals(authorizationCookies.get(cookie).getId())) {
                    configuration[i].setMyAuthorizationCookie(cookie);
                } else {
                    authorizedUsers.put(cookie, authorizationCookies.get(cookie));
                }
            };
            verifier = new JWTVerifier(cert.getPublicKey());

            configuration[i].setIssuerId("https://olympus-vidp.com/issuer1");
            configuration[i].setAuthorizationCookies(authorizedUsers);
            configuration[i].setSessionLength(sessionLength);
            configuration[i].setServers(otherServers);
            configuration[i].setKeyMaterial(configGenerator.rsaSharedKeys[i]);
            configuration[i].setRsaBlindings(configGenerator.rsaBlindings[i]);
            configuration[i].setOprfBlindings(configGenerator.oprfBlindings[i]);
            configuration[i].setOprfKey(configGenerator.oprfKeys[i]);
            configuration[i].setLocalKeyShare(configGenerator.localKeyShares[i]);
            configuration[i].setRemoteShares(configGenerator.remoteKeyShares[i]);
            configuration[i].setId(i);
            configuration[i].setAllowedTimeDifference(allowedTimeDiff);
            configuration[i].setWaitTime(10000);
            configuration[i].setLifetime(lifetime);;
            configuration[i].setAttrDefinitions(generateAttributeDefinitions());
            configuration[i].setSeed(seeds[i]);
            configuration[i].setPort(9080+i);
            configuration[i].setTlsPort(9090+i);
            configuration[i].setKeyStorePath(TestParameters.TEST_KEY_STORE_LOCATION);
            configuration[i].setTrustStorePath(TestParameters.TEST_TRUST_STORE_LOCATION);
            configuration[i].setKeyStorePassword(TestParameters.TEST_KEY_STORE_PWD);
            configuration[i].setTrustStorePassword(TestParameters.TEST_TRUST_STORE_PWD);
            configuration[i].setCert(cert);
        }
    }

    private static Set<AttributeDefinition> generateAttributeDefinitions() {
        Set<AttributeDefinition> res=new HashSet<>();
        res.add(new AttributeDefinitionString("name","name",0,16));
        res.add(new AttributeDefinitionInteger("age","age",0,123));
        res.add(new AttributeDefinitionString("nationality","nationality",0,16));
        res.add(new AttributeDefinitionDate("dateofbirth","date of birth","1900-01-01T00:00:00","2020-09-01T00:00:00", DateGranularity.DAYS));
        return res;
    }


    public static class TestConfigurationUtil extends ConfigurationUtil {

        public RSASharedKey[] rsaSharedKeys;
        public Map<Integer, BigInteger>[] rsaBlindings;
        public Map<Integer, BigInteger>[]  oprfBlindings;
        public Map<Integer, byte[]>[] remoteKeyShares;
        public BigInteger[] oprfKeys;
        public byte[][] localKeyShares;
        Certificate splitKeys(RSAPrivateCrtKey sk, int amount) {
            try {
                rng = new Random();
                RDN = "CN=olympus-vidp.com,O=Olympus,OU=www.olympus-project.eu,C=EU";

                rsaSharedKeys = new RSASharedKey[amount];
                rsaBlindings = new Map[amount];
                oprfBlindings = new Map[amount];
                remoteKeyShares = new Map[amount];
                oprfKeys = new BigInteger[amount];
                localKeyShares = new byte[amount][];

                Certificate certificate = doKeyShares(sk, amount, rng,
                    rsaSharedKeys, rsaBlindings, oprfBlindings, oprfKeys,
                    localKeyShares, remoteKeyShares, RDN);
                return certificate;

            }catch(Exception e ) {
                logger.error("Failed to generate configurations", e);
                throw new RuntimeException(e);
            }
        }
    }

    public String getAdminCookie() {
        return adminCookie;
    }

    public Verifier getVerifier() {
        return verifier;
    }

    public PABCConfigurationImpl[] getConfiguration() {
        return configuration;
    }

    public static int getServerCount() {
        return serverCount;
    }

    public void testSimpleFlow(UserClient client, Verifier verifier) throws AuthenticationFailedException, TokenGenerationException {
        try{
            client.createUser("user_1_pesto", "password");
        } catch(UserCreationFailedException e) {
            e.printStackTrace();
            fail("Failed to create user");
        }
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("name", new Attribute("John Doe"));
        attributes.put("nationality", new Attribute("DK"));
        attributes.put("age",new Attribute(22));

        try {
            // Prove identity using the key cache
            client.addAttributes( new TestIdentityProof("proof",attributes));
        } catch(OperationFailedException e) {
            fail("Failed to prove identity: " + e);
        }
        client.clearSession();

        Map<String, Attribute> attributes2 = new HashMap<>();
        attributes2.put("name", new Attribute("Jane Doe"));
        attributes2.put("nationality", new Attribute("Se"));
        attributes2.put("age",new Attribute(30));
        try{
            client.createUserAndAddAttributes("user_2", "password2", new TestIdentityProof("proof", attributes2));
            client.clearSession();
        } catch(UserCreationFailedException e) {
            fail("Failed to create user");
        }

        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("name");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        predicate = new Predicate();
        predicate.setAttributeName("age");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        Policy policy = new Policy(predicates, "testPolicy");
        String token = client.authenticate("user_1_pesto", "password", policy, null, "NONE");
        assertThat(verifier.verify(token), is(true));
        client.clearSession();

        try{ //
            client.authenticate("user_1_pesto", "bad_password", policy, null, "NONE");
            fail("Could authenticate with a bad password");
        } catch(AuthenticationFailedException  e) {
        }
        client.clearSession();

        token = client.authenticate("user_2", "password2", policy, null, "NONE");
        assertThat(verifier.verify(token), is(true));
        client.clearSession();
    }


    public void testRefreshFlow(UserClient client, Verifier verifier, List<? extends PestoIdP> idps) throws Exception {
        // Create user to survive refresh

        try{
            client.createUser("aUser_pesto", "password");
        } catch(UserCreationFailedException e) {
            fail();
        }

        // Perform refresh
        List<Future<Boolean>> res = new ArrayList<>();
        ExecutorService executorService = Executors.newFixedThreadPool(idps.size());
        for (PestoIdP idp : idps) {
            res.add(executorService.submit(idp::startRefresh));
        }
        for (Future<Boolean> current : res) {
            assertTrue(current.get());
        }

        // User already exists
        try{
            client.createUser("aUser_pesto", "password");
            fail();
        } catch(UserCreationFailedException e) {
            // Expected
        }

        // User can still prove
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("Name", new Attribute("John Doe"));
        attributes.put("Nationality", new Attribute("Se"));
        attributes.put("Age",new Attribute(30));
        try {
            client.addAttributes("aUser_pesto", "password", new TestIdentityProof("proof", attributes),null, "NONE");
        } catch(OperationFailedException e) {
            fail("Failed to prove identity: " + e);
        }
        client.clearSession();

        // User can still reveal
        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("Age");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        Policy policy = new Policy(predicates, "SignedMessage");
        String token = client.authenticate("aUser_pesto", "password", policy, null, "NONE");
        assertThat(verifier.verify(token), is(true));
        client.clearSession();

        // We can still make new users
        try{
            client.createUser("newUser_pesto", "password2");
        } catch(UserCreationFailedException e) {
            fail();
        }
        client.clearSession();

        // Ensure that a failed refresh does not break functionality
        res = new ArrayList<>();
        executorService = Executors.newFixedThreadPool(idps.size());
        res.add(executorService.submit(() -> idps.get(0).startRefresh()));
        for (Future<Boolean> current : res) {
            assertFalse(current.get());
        }
        // User already exists
        try{
            client.createUser("aUser_pesto", "password");
            fail();
        } catch(UserCreationFailedException e) {
        }

        // User can still prove
        try {
            client.addAttributes("aUser_pesto", "password",  new TestIdentityProof("proof", attributes), null, "NONE");
        } catch(OperationFailedException e) {
            fail("Failed to prove identity: " + e);
        }
        client.clearSession();

        // User can still reveal
        policy = new Policy(predicates, "SignedMessage");
        token = client.authenticate("aUser_pesto", "password", policy, null, "NONE");
        assertThat(verifier.verify(token), is(true));
        client.clearSession();

        // We can still make new users
        try{
            client.createUser("newUser2_pesto", "password2");
        } catch(UserCreationFailedException e) {
            fail();
        }
        client.clearSession();
    }

    public void testRefreshFlowPabc(UserClient client, PABCVerifier verifier, List<? extends PabcIdP> idps) throws Exception {

        // Create user to survive refresh
    	logger.info("testRefreshFlowPabc started");
        try{
            client.createUser("aUser_pabc", "password");
        } catch(UserCreationFailedException e) {
            fail();
        }
        client.clearSession();
    	logger.info("testRefreshFlowPabc starting refresh");
        // Perform refresh
        List<Future<Boolean>> res = new ArrayList<>();
        ExecutorService executorService = Executors.newFixedThreadPool(idps.size());
        for (PabcIdP idp : idps) {
            res.add(executorService.submit(() -> idp.startRefresh()));
        }
        for (Future<Boolean> current : res) {
            assertTrue(current.get());
        }
    	logger.info("testRefreshFlowPabc create user - expect fail");
        // User already exists
        try{
            client.createUser("aUser_pabc", "password");
            fail();
        } catch(UserCreationFailedException e) {
        }


        // User can still prove
    	logger.info("testRefreshFlowPabc add attributes");
        // User can still prove
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("name", new Attribute("John Doe"));
        attributes.put("nationality", new Attribute("Se"));
        attributes.put("age",new Attribute(30));
        try {
            client.addAttributes("aUser_pabc","password",new TestIdentityProof("proof", attributes), null, "NONE");
        } catch(OperationFailedException e) {
            fail("Failed to prove identity: " + e);
        }
        client.clearSession();

    	logger.info("testRefreshFlowPabc authenticate");
        // User can still reveal
        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("name");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        Policy policy = new Policy(predicates, "SignedMessage");
        String token = client.authenticate("aUser_pabc", "password", policy, null, "NONE");

        client.clearSession();
        assertThat(verifier.verifyPresentationToken(token, policy), is(VerificationResult.VALID));
    	logger.info("testRefreshFlowPabc create final");
        // We can still make new users
        try{
            client.createUser("newUser_pabc", "password2");
        } catch(UserCreationFailedException e) {
            fail();
        }
        client.clearSession();
    }

    public  void testMFAFlowPabc(PabcClient client, PABCVerifier verifier) throws AuthenticationFailedException, OperationFailedException, TokenGenerationException {
    	logger.info("testMFAFlowPabc start");
        try{
            client.createUser("user_mfa_pabc", "password");
        } catch(UserCreationFailedException e) {
            fail("Failed to create user");
        }
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("name", new Attribute("John Doe"));
        attributes.put("nationality", new Attribute("DK"));
        attributes.put("age",new Attribute(22));
    	logger.info("testMFAFlowPabc add attributes");

        try {
            client.addAttributes(new TestIdentityProof("proof", attributes));
            client.clearSession();
        } catch(OperationFailedException e) {
            fail("Failed to prove identity: " + e);
        }
        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("name");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        predicate = new Predicate();
        predicate.setAttributeName("age");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        Policy policy = new Policy(predicates, "testPolicy");
    	logger.info("testMFAFlowPabc first authenticate");

        // Check that we can log on without MFA
        String token = client.authenticate("user_mfa_pabc", "password", policy, "", null);
        client.clearSession();
        assertThat(verifier.verifyPresentationToken(token, policy), is(VerificationResult.VALID));

        // Check that we can not request a MFA with wrong password
        try {
            client.requestMFAChallenge("user_mfa_pabc", "bad_password", GoogleAuthenticator.TYPE);
            fail();
        }catch (Exception e) {
        }

        String challenge = client.requestMFAChallenge("user_mfa_pabc", "password", GoogleAuthenticator.TYPE);
        client.clearSession();
        // Check that MFA is not required while the registration process is active
        token = client.authenticate("user_mfa_pabc", "password", policy, "", "NONE");
        client.clearSession();
        assertThat(verifier.verifyPresentationToken(token, policy), is(VerificationResult.VALID));

        String secondFactorToken;
        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
        //we need the proper public  key to confirm mfa activation
        try {
            client.confirmMFA("user_mfa_pabc", "bad_password", secondFactorToken, GoogleAuthenticator.TYPE);
            fail();
        } catch(Exception e) {
        }
        //we need the proper challenge to confirm mfa activation
        try {
            client.confirmMFA("user_mfa_pabc", "password", "231312", GoogleAuthenticator.TYPE);
            fail();
        } catch(Exception e) {
        }
        // Cannot confirm with other token
        try {
            client.confirmMFA("user_mfa_pabc", "password", null, "NONE");
            fail();
        } catch(Exception e) {
        }
    	logger.info("testMFAFlowPabc confirm expect success");

        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
        try {
        	client.confirmMFA("user_mfa_pabc", "password", secondFactorToken, GoogleAuthenticator.TYPE);
        }catch(Exception e) {
        	// Occasionally the MFA token is generated in step 1 and validated in step 2, hence validation
    		// fails. In that case we try once more
    		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
    		client.confirmMFA("user_mfa_pabc", "password", secondFactorToken, GoogleAuthenticator.TYPE);
        }
        client.clearSession();
        client.clearCredentials();

        // Check that we cannot log on with a bad MFA code
        try {
            client.authenticate("user_mfa_pabc", "password", policy, "123123", GoogleAuthenticator.TYPE);
            fail();
        } catch (AuthenticationFailedException ignored){
        }

        // Check that we can log on using MFA
    	logger.info("testMFAFlowPabc log on with MFA");

        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
        try {
        	token = client.authenticate("user_mfa_pabc", "password", policy, secondFactorToken, GoogleAuthenticator.TYPE);
        }catch(Exception e) {
        	// Occasionally the MFA token is generated in step 1 and validated in step 2, hence validation
    		// fails. In that case we try once more
    		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
    		token = client.authenticate("user_mfa_pabc", "password", policy, secondFactorToken, GoogleAuthenticator.TYPE);
        }
        assertThat(verifier.verifyPresentationToken(token, policy), is(VerificationResult.VALID));

        // Check that the session token is locally cached
        token = client.authenticate("user_mfa_pabc", "password", policy, null, "NONE");
        assertThat(verifier.verifyPresentationToken(token, policy), is(VerificationResult.VALID));

        client.clearSession();
        client.clearCredentials();
        // Check that cookie gets removed after a clearSession
        try {
            client.authenticate("user_mfa_pabc", "password", policy, null, "NONE")  ;
            fail();
        } catch (AuthenticationFailedException ignored){
        }

        //we need the proper public  key to remove mfa activation
        try {
            secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
            client.removeMFA("user_mfa_pabc", "bad_password", secondFactorToken, GoogleAuthenticator.TYPE);
            fail();
        } catch(Exception e) {
        }
        //we need the proper challenge to remove mfa activation
        try {
            client.removeMFA("user_mfa_pabc", "password", "231312", GoogleAuthenticator.TYPE);
            fail();
        } catch(Exception e) {
        }
    	logger.info("testMFAFlowPabc remove MFA");

        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
        try {
        	client.removeMFA("user_mfa_pabc", "password", secondFactorToken, GoogleAuthenticator.TYPE);
        }catch(Exception e) {
        	// Occasionally the MFA token is generated in step 1 and validated in step 2, hence validation
    		// fails. In that case we try once more
    		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
    		client.removeMFA("user_mfa_pabc", "password", secondFactorToken, GoogleAuthenticator.TYPE);
        }
        client.clearSession();
    	logger.info("testMFAFlowPabc final authenticate");

        // Check that you can authenticate without MFA
        token = client.authenticate("user_mfa_pabc", "password", policy, null, "NONE");
        assertThat(verifier.verifyPresentationToken(token, policy), is(VerificationResult.VALID));

    }

    public  void testAccManagement(UserClient client, Verifier verifier) throws AuthenticationFailedException, OperationFailedException, TokenGenerationException {
        Map<String, Attribute> att = new HashMap<>();
        att.put("name", new Attribute("John Doe"));
        att.put("nationality", new Attribute("DK"));
        att.put("age",new Attribute(22));

        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("Nationality");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        Policy policy = new Policy(predicates, "testPolicy");

        try{
            client.createUserAndAddAttributes("user_1_accManagement", "password", new TestIdentityProof("proof",att));
        } catch(UserCreationFailedException e) {
            e.printStackTrace();
            fail("Failed to create user");
        }

        //simple flow has already been run, so we have some data to work with already
        //Try to get all attributes
        Map<String, Attribute> attributes = client.getAllAttributes();
        assertEquals(3, attributes.keySet().size());
        assertEquals(new Attribute("John Doe"), attributes.get("name"));
        assertEquals(new Attribute("DK"), attributes.get("nationality"));
        assertEquals(new Attribute(22), attributes.get("age"));
        client.clearSession();

        try{
            client.createUserAndAddAttributes("user_2_accManagement", "password", new TestIdentityProof("proof",att));
        } catch(UserCreationFailedException e) {
            e.printStackTrace();
            fail("Failed to create user");
        }
        //Delete Name and Age attribute
        List<String> attributesToDelete = new ArrayList<String>();
        attributesToDelete.add("Name");
        attributesToDelete.add("Age");
        client.deleteAttributes(attributesToDelete);


        attributes = client.getAllAttributes();
        client.clearSession();
        assertEquals(1, attributes.keySet().size());
        assertEquals(new Attribute("DK"), attributes.get("nationality"));

        //try to get all attributes with wrong password
        try {
            attributes = client.getAllAttributes("user_2_accManagement","wrong_password", null, "NONE");
            fail();
        } catch (OperationFailedException e) {
        }

        //Change password - wrong password
        try {
            client.changePassword( "user_2_accManagement","incorrect_password", "newPassword", null, "NONE");
            fail();
        } catch (OperationFailedException e) {
            // Expected
        }

        //Change password - Proper password
        try {
            client.clearSession();
            client.createUserAndAddAttributes("user_3_accManagement", "password", new TestIdentityProof("proof",att));
            client.changePassword( "user_3_accManagement","password", "tempPassword", null, "NONE");
            client.changePassword("user_3_accManagement","tempPassword", "newPassword", null, "NONE");
        } catch (OperationFailedException | UserCreationFailedException e) {
            fail();
        }
        client.clearSession();

        //Verify the new password works
        String token = client.authenticate("user_3_accManagement", "newPassword", policy,null,"NONE");
        client.clearSession();
        assertThat(verifier.verify(token), is(true));

        //Try policy that cant be satisfies (with bad password)
        predicates = new ArrayList<>();
        predicate = new Predicate();
        predicate.setAttributeName("Invalid");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            client.authenticate("user_3_accManagement", "password", policy, null, "NONE");
            fail();
        } catch(AuthenticationFailedException  e) {
        }


        //Try policy that cant be satisfies (with proper password)
        //	policy = new Policy(revealAttributes);
        try {
            client.authenticate("user_3_accManagement", "newPassword", policy, null, "NONE");
            fail();
        } catch(AuthenticationFailedException e) {
        }
        client.clearSession();

        try{
            client.createUserAndAddAttributes("user_4_accManagement", "password", new TestIdentityProof("proof",att));
        } catch(UserCreationFailedException e) {
            e.printStackTrace();
            fail("Failed to create user");
        }
        //Try to delete account using wrong password
        try{
            client.deleteAccount("user_4_accManagement","wrong_Password", null, "NONE");
            fail();
        } catch(Exception e) {
        }

        //Try to delete account using proper password
        client.deleteAccount("user_4_accManagement","password", null, "NONE");
        client.clearSession();

        predicates = new ArrayList<>();
        predicate = new Predicate();
        predicate.setAttributeName("Nationality");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        policy.setPredicates(predicates);
        //policy = new Policy(revealAttributes);
        try {
            client.authenticate("user_4_accManagement", "password", policy, null, "NONE");
            fail();
        } catch(AuthenticationFailedException e) {

        }

    }

    public void testMFAFlow(UserClient client, Verifier verifier) throws AuthenticationFailedException, UserCreationFailedException, TokenGenerationException, OperationFailedException {
    	logger.info("testMFAFlow start");
    	try{
            client.createUser("user_mfa_pesto", "password");
        } catch(UserCreationFailedException e) {
            fail("Failed to create user");
        }
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("Name", new Attribute("John Doe"));
        attributes.put("Nationality", new Attribute("DK"));
        attributes.put("Age",new Attribute(22));
    	logger.info("testMFAFlow - addAttributes");
        try {
            client.addAttributes(new TestIdentityProof("proof", attributes));
        } catch(OperationFailedException e) {
            fail("Failed to prove identity: " + e);
        }
        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("Name");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        predicate = new Predicate();
        predicate.setAttributeName("Age");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        Policy policy = new Policy(predicates, "testPolicy");
        // Check that we can log on without MFA
    	logger.info("testMFAFlow first authenticate");
        String token = client.authenticate("user_mfa_pesto", "password", policy, "", null);
        client.clearSession();
        assertThat(verifier.verify(token), is(true));

        // Check that we can not request a MFA for non-existing users
        try {
            client.requestMFAChallenge("user_mfa_pesto", "password", null);
            fail();
        }catch (Exception e) {
        }

        // Check that we can not request a MFA with wrong password
        try {
            client.requestMFAChallenge("user_mfa_pesto", "bad_password", GoogleAuthenticator.TYPE);
            fail();
        }catch (Exception e) {
        }
    	logger.info("testMFAFlow request MFA challenge");
        String challenge = client.requestMFAChallenge("user_mfa_pesto", "password", GoogleAuthenticator.TYPE);
        client.clearSession();
        // Check that MFA is not required while the registration process is active
        token = client.authenticate("user_mfa_pesto", "password", policy, "", "NONE");
        assertThat(verifier.verify(token), is(true));
        // also check that starting a second MFA request flow does not break functionality
    	logger.info("testMFAFlow second request MFA");
        String dummyChallenge = client.requestMFAChallenge("user_mfa_pesto", "password", "dummy");
        assertThat(dummyChallenge, is("alice"));
        client.clearSession();

        String secondFactorToken;
        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
    	logger.info("testMFAFlow failing confirms");
        //we need the proper public  key to confirm mfa activation
        try {
            client.confirmMFA("user_mfa_pesto", "bad_password", secondFactorToken, GoogleAuthenticator.TYPE);
            fail();
        } catch(Exception e) {
        }
        //we need the proper challenge to confirm mfa activation
        try {
            client.confirmMFA("user_mfa_pesto", "password", "231312", GoogleAuthenticator.TYPE);
            fail();
        } catch(Exception e) {
        }
        // Cannot confirm with other token
        try {
            client.confirmMFA("user_mfa_pesto", "password", null, "NONE");
            fail();
        } catch(Exception e) {
        }
        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
    	logger.info("testMFAFlow successful confirm");
    	try {

    		client.confirmMFA("user_mfa_pesto", "password", secondFactorToken, GoogleAuthenticator.TYPE);
    	}catch(Exception e) {
    		// Occasionally the MFA token is generated in step 1 and validated in step 2, hence validation
    		// fails. In that case we try once more
    		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
    		client.confirmMFA("user_mfa_pesto", "password", secondFactorToken, GoogleAuthenticator.TYPE);
    	}
        client.clearSession();

        // Check that we cannot log on with a bad MFA code
        try {
            client.authenticate("user_mfa_pesto", "password", policy, "123123", GoogleAuthenticator.TYPE);
            fail();
        }catch(AuthenticationFailedException e) {
        }
    	logger.info("testMFAFlow second authenticate");
        // Check that we can log on using MFA
        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
        try {
        	token = client.authenticate("user_mfa_pesto", "password", policy, secondFactorToken, GoogleAuthenticator.TYPE);
        } catch (Exception e) {
        	// Occasionally the MFA token is generated in step 1 and validated in step 2, hence validation
    		// fails. In that case we try once more
    		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
    		token = client.authenticate("user_mfa_pesto", "password", policy, secondFactorToken, GoogleAuthenticator.TYPE);
        }
        assertThat(verifier.verify(token), is(true));

        // Check that the session token is locally cached
        token = client.authenticate("user_mfa_pesto", "password", policy, null, "NONE");
        assertThat(verifier.verify(token), is(true));
        client.clearSession();

        // Check that cookie gets removed after a clearSession
        try {
            client.authenticate("user_mfa_pesto", "password", policy, null, "NONE")  ;
            fail();
        }catch(AuthenticationFailedException e) {
        }

    	logger.info("testMFAFlow second mechanism start");
        // check that the second MFA mechanism can also be used
        try {
            client.authenticate("user_mfa_pesto", "password", policy, "bob", "dummy");
            fail(); //the dummy MFA is not yet active
        }catch(AuthenticationFailedException e) {
        }
        try {
            client.confirmMFA("user_mfa_pesto", "password", "bob", "dummy");
            fail(); //we cannot activate a second MFA 
        }catch(OperationFailedException e) {
        }

        try {
            client.authenticate("user_mfa_pesto", "password", policy, "bob", "dummy");
            fail(); //we cannot use the inactive MFA 
        }catch(AuthenticationFailedException e) {
        }
        client.clearSession();
    	logger.info("testMFAFlow change password");
        //check that changing passwords, does not affect MFA
        try {
            client.authenticate("user_mfa_pesto", "password", policy, secondFactorToken, GoogleAuthenticator.TYPE);
        } catch (Exception e) {
            // Occasionally the MFA token is generated in step 1 and validated in step 2, hence validation
            // fails. In that case we try once more
            secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
            client.authenticate("user_mfa_pesto", "password", policy, secondFactorToken, GoogleAuthenticator.TYPE);
        }
        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
        try {
        	client.changePassword("user_mfa_pesto", "password", "newPassword", secondFactorToken, GoogleAuthenticator.TYPE);
        }catch(Exception e) {
        	// Occasionally the MFA token is generated in step 1 and validated in step 2, hence validation
    		// fails. In that case we try once more
            secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
            client.changePassword("user_mfa_pesto", "password", "newPassword", secondFactorToken, GoogleAuthenticator.TYPE);
        }
        client.clearSession();

        // ie. we should not be able to login without MFA
        try {
            client.authenticate("user_mfa_pesto", "newPassword", policy, null, "NONE")  ;
            fail();
        }catch(AuthenticationFailedException e) {
        }

        //and MFA should still work
        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
        try {
        	token = client.authenticate("user_mfa_pesto", "newPassword", policy, secondFactorToken, GoogleAuthenticator.TYPE);
        }catch(Exception e) {
        	// Occasionally the MFA token is generated in step 1 and validated in step 2, hence validation
    		// fails. In that case we try once more
    		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
    		token = client.authenticate("user_mfa_pesto", "newPassword", policy, secondFactorToken, GoogleAuthenticator.TYPE);
        }
        assertThat(verifier.verify(token), is(true));
        client.clearSession();

        //we need the proper public  key to remove mfa activation
        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
    	logger.info("testMFAFlow attempt to remove MFA");
        client.authenticate("user_mfa_pesto", "newPassword", policy, secondFactorToken, GoogleAuthenticator.TYPE);
        try {
            client.removeMFA("user_mfa_pesto", "bad_password", secondFactorToken, GoogleAuthenticator.TYPE);
            fail();
        } catch(Exception e) {
        }
        //we need the proper challenge to remove mfa activation
        try {
            client.removeMFA("user_mfa_pesto", "newPassword", "231312", GoogleAuthenticator.TYPE);
            fail();
        } catch(Exception e) {
        }


    	logger.info("testMFAFlow remove MFA");
        secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
        try {
        	client.removeMFA("user_mfa_pesto", "newPassword", secondFactorToken, GoogleAuthenticator.TYPE);
        }catch(Exception e) {
        	// Occasionally the MFA token is generated in step 1 and validated in step 2, hence validation
    		// fails. In that case we try once more
    		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
    		client.removeMFA("user_mfa_pesto", "newPassword", secondFactorToken, GoogleAuthenticator.TYPE);
        }
        client.clearSession();

        // Check that you can authenticate without MFA
        token = client.authenticate("user_mfa_pesto", "newPassword", policy, null, "NONE");
        assertThat(verifier.verify(token), is(true));
        client.clearSession();

    	logger.info("testMFAFlow final confirm dummy MFA");
        // Check that we can activate and use the dummy mfa:
        client.confirmMFA("user_mfa_pesto", "newPassword", "bob", "dummy");
        client.clearSession();
        token = client.authenticate("user_mfa_pesto", "newPassword", policy, "bob", "dummy");
        assertThat(verifier.verify(token), is(true));
        client.clearSession();


    }

    public  void testErrorCases(UserClient client, Verifier verifier) throws AuthenticationFailedException {
        //The acc flow has been run, removing all data from the db
        try {
            client.createUser("user", "password");
        } catch(Exception e) {
            fail();
        }

        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("Name", new Attribute("John Doe"));
        attributes.put("Nationality", new Attribute("DK"));
        attributes.put("Age",new Attribute(22));
        TestIdentityProof proof = new TestIdentityProof("proof", attributes);


        //Prove identity: Id proof without suitable Id proving component
        try {
            BadIdentityProof badProof = new BadIdentityProof();
            client.addAttributes(badProof);
            fail();
        } catch (Exception e) {
        }
        client.clearSession();

        //Prove identity: No Id proof
        try {
            client.addAttributes("user","password", null, null, "NONE");
            fail();
        } catch (NullPointerException | OperationFailedException e) {
        }
        client.clearSession();

        //Prove identity:no active session
        try {
            client.clearSession();
            client.addAttributes(proof);
            fail();
        } catch (OperationFailedException e) {
        }

        //Prove identity: wrong password
        try {
            client.addAttributes("user","wrong_password", proof, null, "NONE");
            fail();
        } catch (OperationFailedException e) {
        }
        //Authenticate: Can not satisfy policy
        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("Email");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        Policy policy = new Policy(predicates, "testPolicy");
        try{ //
            client.authenticate("user", "password", policy, null, "NONE");
            fail("Produced token containing email attribute");
        } catch(AuthenticationFailedException e) {
        }
        client.clearSession();

        //GetAllAttributes:no active session
        try {
            client.clearSession();
            Map<String, Attribute> attrib = client.getAllAttributes();
            assertEquals(0, attrib.size());
        } catch (OperationFailedException e) {
        }

        //GetAllAttributes: wrong password
        try {
            Map<String, Attribute> attrib = client.getAllAttributes("user","wrong_password", null, "NONE");
            assertEquals(0, attrib.size());
        } catch (OperationFailedException e) {
        }

        List<String> attributesToDelete = new ArrayList<String>();
        attributesToDelete.add("Name");
        attributesToDelete.add("Nationality");
        //DeleteAttributes:no active session
        try {
            client.clearSession();
            client.deleteAttributes(attributesToDelete);
            fail();
        } catch (OperationFailedException e) {
        }

        //DeleteAttributes: wrong password
        try {
            client.deleteAttributes("user","wrong_password", attributesToDelete, null, "NONE");
            fail();
        } catch (OperationFailedException e) {
        }

        //DeleteAccount: wrong password
        try {
            client.deleteAccount("user","wrong_password", null, "NONE");
            fail();
        } catch (OperationFailedException e) {
        }
    }

    void testSimpleFlowPabc(UserClient client, PABCVerifier verifier) throws AuthenticationFailedException {
        long start = System.currentTimeMillis();
        try{
            client.createUser("user_1_pabc", "password");
        } catch(UserCreationFailedException e) {
            fail("Failed to create user" + e);
        }
        long creation = System.currentTimeMillis();
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("name", new Attribute("John Doe"));
        attributes.put("nationality", new Attribute("DK"));
        attributes.put("age",new Attribute(22));
        attributes.put("dateofbirth",new Attribute(Util.fromRFC3339UTC("1998-01-05T00:00:00")));

        try {
            // 	Prove identity with cached key
            client.addAttributes(new TestIdentityProof("proof", attributes));
        } catch(OperationFailedException e) {
            fail("Failed to prove identity: " + e);
        }
        client.clearSession();
        long addAttributesTime = System.currentTimeMillis();
        String signedMessage="SignedMessage";
        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("name");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        predicate = new Predicate();
        predicate.setAttributeName("age");
        predicate.setOperation(Operation.GREATERTHANOREQUAL);
        predicate.setValue(new Attribute(18));
        predicate = new Predicate();
        predicate.setAttributeName("dateofbirth");
        predicate.setOperation(Operation.INRANGE);
        predicate.setValue(new Attribute(Util.fromRFC3339UTC("1990-01-05T00:00:00")));
        predicate.setExtraValue(new Attribute(Util.fromRFC3339UTC("2000-01-05T00:00:00")));
        predicates.add(predicate);
        Policy policy = new Policy(predicates, signedMessage);
        Policy verifierPolicy = new Policy(policy.getPredicates(), signedMessage);


        try {
            client.authenticate("user_1_pabc", "wrong password", policy, null, "NONE");
            fail();
        } catch (AuthenticationFailedException ignored){
        }
        client.clearSession();
        String token = client.authenticate("user_1_pabc", "password", policy, null, "NONE");
        assertThat(verifier.verifyPresentationToken(token, verifierPolicy), is(VerificationResult.VALID));
        client.clearSession();

        long end = System.currentTimeMillis();
        logger.info("PABC Create: "+(creation-start));
        logger.info("PABC prove: "+(addAttributesTime-creation));
        logger.info("PABC auth: "+(end-addAttributesTime));
        logger.info("PABC total time: "+((end-start))+" ms");
    }



    void testPestoCreateAndAddAttributes(UserClient client){
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("name", new Attribute("John Doe"));
        attributes.put("email", new Attribute("John.Doe@example.com"));
        attributes.put("birthdate",new Attribute(Util.fromRFC3339UTC("1998-01-05T00:00:00")));

        try{
            client.createUserAndAddAttributes("user_1337", "password", new TestIdentityProof("proof2",attributes));
        } catch(UserCreationFailedException e) {
            fail("Failed to create user" + e);
        }

    }

    public static class BadIdentityProof extends IdentityProof {

        public BadIdentityProof() {
        }
        @Override
        public String getStringRepresentation() {
            return null;
        }
    }

    public static class DummyAuthenticator implements MFAAuthenticator {
        @Override
        public long getTimeoutPeriod() {
            return 100;
        }

        @Override
        public boolean isValid(String token, String secret) {
            return "bob".equals(token) && "alice".equals(secret);
        }

        @Override
        public String generateTOTP(String secret) {
            return "bob";
        }

        @Override
        public String generateSecret() {
            return "alice";
        }

        @Override
        public String combineSecrets(List<String> secrets) {
            return "alice";
        }
    }

}
