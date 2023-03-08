package eu.olympus.unit.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import eu.olympus.TestParameters;
import eu.olympus.client.PestoClient;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.Authorization;
import eu.olympus.model.KeyShares;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.PestoRefresher;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoBasedIdP;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryPestoDatabase;

import java.math.BigInteger;
import java.security.PublicKey;
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
import java.util.concurrent.Future;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class TestPestoIdPImpl {
    @Rule
    public final ExpectedException exception = ExpectedException.none();

    PABCConfigurationImpl configuration;

    @Test
    public void testSetup() throws Exception {

        RSAPrivateCrtKey pk = (RSAPrivateCrtKey) TestParameters.getRSAPrivateKey2();
        BigInteger di = pk.getPrivateExponent();

        PestoDatabase database = new InMemoryPestoDatabase();

        PestoIdPImpl idp = new PestoIdPImpl(database, new ArrayList<IdentityProver>(), new HashMap<String, MFAAuthenticator>(), new SoftwareServerCryptoModule(new Random(1)), 100000);
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
    }

    private Set<AttributeDefinition> generateAttributeDefinitions() {
        Set<AttributeDefinition> res = new HashSet<>();
        res.add(new AttributeDefinitionString("name", "name", 0, 16));
        res.add(new AttributeDefinitionInteger("age", "age", 1, 100));
        return res;
    }

    @Test //Test exception handling in setup (use a null-configuration to cause nullpointer)
    public void testBadSetup() throws Exception {
        PestoDatabase database = new InMemoryPestoDatabase();
        PestoIdPImpl idp = new PestoIdPImpl(database, new ArrayList<IdentityProver>(), new HashMap<>(), new SoftwareServerCryptoModule(new Random(1)), 100000);
        boolean complete = idp.setup("setup", null, new ArrayList<>());
        assertFalse(complete);
    }

    @Test
    public void testReplay() throws Exception {
        testSetup();
        PestoRefresher refresher = new PestoRefresher(0, new SoftwareServerCryptoModule(new Random(1)));
        List<byte[]> shares =
            refresher.reshareMasterKeys(new KeyShares(configuration.getKeyMaterial(), configuration.getRsaBlindings(), configuration.getOprfKey(), configuration.getOprfBlindings()), 1);
        configuration.setLocalKeyShare(shares.remove(0));
        PestoDatabase database = new InMemoryPestoDatabase();
        PestoIdPImpl idp = new PestoIdPImpl(database, new ArrayList<IdentityProver>(), new HashMap<String, MFAAuthenticator>(), new SoftwareServerCryptoModule(new Random(1)) {

        }, 100000);
        idp.setup("setup", configuration, new ArrayList<>());

        PestoClient maliciousClient = new PestoClient(Arrays.asList(new PestoIdP[]{idp}), new SoftwareClientCryptoModule(new Random(1), configuration.getKeyMaterial().getModulus())) {

            @Override
            public void deleteAccount(String username, String password, String token, String type) throws OperationFailedException {
                try {
                    long salt = System.currentTimeMillis();
                    byte[][] signature = getSignedNonceAndUid(getSavedUsername(), salt, CommonRESTEndpoints.GET_ALL_ATTRIBUTES);

                    List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();

                    for (PestoBasedIdP server : servers.values()) {
                        authentications.add(executorService.submit(() -> server.deleteAccount(getSavedUsername(), "session".getBytes(), salt, signature[server.getId()])));
                    }
                    for (Future<Boolean> future : authentications) {
                        if (!future.get()) {
                            throw new AuthenticationFailedException("Server failed to delete account");
                        }
                    }
                } catch (Exception e) {
                    throw new OperationFailedException(e);
                }
            }

        };
        maliciousClient.createUser("user", "password");
        maliciousClient.getAllAttributes( "user","password", null, "NONE");
        try {
            maliciousClient.deleteAccount( "user","password", null, "NONE");
            fail();
        } catch (OperationFailedException e) {

        }
    }

    @Test(expected = OperationFailedException.class)
    public void testRequestMFATokenNonRespondingServer() throws Exception {
        SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0)) {
            @Override
            public boolean verifySignature(PublicKey key, List<byte[]> list, byte[] sig) {
                return true;
            }
        };
        PestoDatabase db = mockDb();

        PestoIdPImpl idp = new PestoIdPImpl(db, null, new HashMap<String, MFAAuthenticator>(), crypto, 100000);

        PABCConfigurationImpl pabcConfiguration = new PABCConfigurationImpl();
        pabcConfiguration.setAllowedTimeDifference(10000);
        pabcConfiguration.setKeyMaterial(new RSASharedKey(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE));
        pabcConfiguration.setRsaBlindings(new HashMap<>());
        pabcConfiguration.setOprfBlindings(new HashMap<>());
        pabcConfiguration.setOprfKey(BigInteger.ONE);
        pabcConfiguration.setLocalKeyShare("dd".getBytes());
        pabcConfiguration.setRemoteShares(new HashMap<>());
        pabcConfiguration.setServers(new LinkedList<>());
        pabcConfiguration.setSeed("dd".getBytes());
        pabcConfiguration.setAttrDefinitions(generateAttributeDefinitions());

        idp.setup("ssid", pabcConfiguration, new ArrayList<PestoIdP>());

        idp.requestMFA("user", "session".getBytes(), System.currentTimeMillis(), GoogleAuthenticator.TYPE, "signature".getBytes());
        fail();
    }


    @Test
    public void testRequestMFA() throws Exception {
        SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0)) {
            @Override
            public boolean verifySignature(PublicKey key, List<byte[]> list, byte[] sig) {
                return "signature".equals(new String(sig));
            }
        };

        PestoDatabase db = mockDb();

        Map<String, MFAAuthenticator> authenticators = new HashMap<>();
        authenticators.put(GoogleAuthenticator.TYPE, mockAuthenticator());

        PestoIdPImpl idp = new PestoIdPImpl(db, null, authenticators, crypto, 100000);

        PABCConfigurationImpl pabcConfiguration = new PABCConfigurationImpl();
        pabcConfiguration.setAllowedTimeDifference(10000);
        pabcConfiguration.setKeyMaterial(new RSASharedKey(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE));
        pabcConfiguration.setRsaBlindings(new HashMap<>());
        pabcConfiguration.setOprfBlindings(new HashMap<>());
        pabcConfiguration.setOprfKey(BigInteger.ONE);
        pabcConfiguration.setLocalKeyShare("dd".getBytes());
        pabcConfiguration.setRemoteShares(new HashMap<>());
        pabcConfiguration.setServers(new LinkedList<>());
        pabcConfiguration.setSeed("dd".getBytes());
        pabcConfiguration.setAttrDefinitions(generateAttributeDefinitions());

        idp.setup("ssid", pabcConfiguration, new ArrayList<PestoIdP>());
        idp.addSession("c2Vzc2lvbg==", new Authorization("user", Arrays.asList(Role.USER), System.currentTimeMillis() + 10000));
        db.addUser("user", TestParameters.getECPublicKey1(), 100000l);

        String resp = idp.requestMFA("user", "session".getBytes(), System.currentTimeMillis(), GoogleAuthenticator.TYPE, "signature".getBytes());
        assertEquals("combined secret", resp);

        try {
            resp = idp.requestMFA("user", "bad_session".getBytes(), System.currentTimeMillis(), GoogleAuthenticator.TYPE, "signature".getBytes());
            fail();
        } catch (OperationFailedException e) {
        }

        try {
            resp = idp.requestMFA("user", "session".getBytes(), System.currentTimeMillis(), GoogleAuthenticator.TYPE, "bad_signature".getBytes());
            fail();
        } catch (OperationFailedException e) {
        }

        try {
            resp = idp.requestMFA(null, "session".getBytes(), System.currentTimeMillis(), GoogleAuthenticator.TYPE, "bad_signature".getBytes());
            fail();
        } catch (NullPointerException e) {
        }
    }


    @Test
    public void testConfirmMFA() throws Exception {
        SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0)) {
            @Override
            public boolean verifySignature(PublicKey key, List<byte[]> list, byte[] sig) {
                return "signature".equals(new String(sig));
            }
        };

        PestoDatabase db = mockDb();
        Map<String, MFAAuthenticator> authenticators = new HashMap<>();
        authenticators.put(GoogleAuthenticator.TYPE, mockAuthenticator());

        PestoIdPImpl idp = new PestoIdPImpl(db, null, authenticators, crypto, 100000);

        PABCConfigurationImpl pabcConfiguration = new PABCConfigurationImpl();
        pabcConfiguration.setAllowedTimeDifference(10000);
        pabcConfiguration.setKeyMaterial(new RSASharedKey(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE));
        pabcConfiguration.setRsaBlindings(new HashMap<>());
        pabcConfiguration.setOprfBlindings(new HashMap<>());
        pabcConfiguration.setOprfKey(BigInteger.ONE);
        pabcConfiguration.setLocalKeyShare("dd".getBytes());
        pabcConfiguration.setRemoteShares(new HashMap<>());
        pabcConfiguration.setServers(new LinkedList<>());
        pabcConfiguration.setSeed("dd".getBytes());
        pabcConfiguration.setAttrDefinitions(generateAttributeDefinitions());

        idp.setup("ssid", pabcConfiguration, new ArrayList<PestoIdP>());
        idp.addSession("c2Vzc2lvbg==", new Authorization("user", Arrays.asList(Role.USER), System.currentTimeMillis() + 10000));
        db.addUser("user", TestParameters.getECPublicKey1(), 100000l);
        db.assignMFASecret("user", GoogleAuthenticator.TYPE, "secret");

        assertTrue(idp.confirmMFA("user", "session".getBytes(), System.currentTimeMillis(), "token", GoogleAuthenticator.TYPE, "signature".getBytes()));

        try{

            idp.confirmMFA("user", "session".getBytes(), System.currentTimeMillis(), "wrong_token", GoogleAuthenticator.TYPE, "signature".getBytes());
        } catch (OperationFailedException e){
        }
        try {
            idp.confirmMFA("user", "bad_session".getBytes(), System.currentTimeMillis(), "token", GoogleAuthenticator.TYPE, "signature".getBytes());
            fail();
        } catch (AuthenticationFailedException e) {
        }

        assertFalse(idp.confirmMFA("user", "session".getBytes(), System.currentTimeMillis(), "token", GoogleAuthenticator.TYPE, "bad_signature".getBytes()));
    }

    @Test
    public void testRemoveMFA() throws Exception {
        SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0)) {
            @Override
            public boolean verifySignature(PublicKey key, List<byte[]> list, byte[] sig) {
                return "signature".equals(new String(sig));
            }
        };

        PestoDatabase db = mockDb();


        Map<String, MFAAuthenticator> authenticators = new HashMap<>();
        authenticators.put(GoogleAuthenticator.TYPE, mockAuthenticator());

        PestoIdPImpl idp = new PestoIdPImpl(db, null, authenticators, crypto, 100000);

        PABCConfigurationImpl pabcConfiguration = new PABCConfigurationImpl();
        pabcConfiguration.setAllowedTimeDifference(10000);
        pabcConfiguration.setKeyMaterial(new RSASharedKey(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE));
        pabcConfiguration.setRsaBlindings(new HashMap<>());
        pabcConfiguration.setOprfBlindings(new HashMap<>());
        pabcConfiguration.setOprfKey(BigInteger.ONE);
        pabcConfiguration.setLocalKeyShare("dd".getBytes());
        pabcConfiguration.setRemoteShares(new HashMap<>());
        pabcConfiguration.setServers(new LinkedList<>());
        pabcConfiguration.setSeed("dd".getBytes());
        pabcConfiguration.setAttrDefinitions(generateAttributeDefinitions());

        idp.setup("ssid", pabcConfiguration, new ArrayList<PestoIdP>());
        idp.addSession("c2Vzc2lvbg==", new Authorization("user", Arrays.asList(Role.USER), System.currentTimeMillis() + 10000));
        db.addUser("user", TestParameters.getECPublicKey1(), 100000l);
        db.assignMFASecret("user", GoogleAuthenticator.TYPE, "secret");
        db.activateMFA("user", GoogleAuthenticator.TYPE);

        assertTrue(idp.removeMFA("user", "session".getBytes(), System.currentTimeMillis(), "token", GoogleAuthenticator.TYPE, "signature".getBytes()));

        assertFalse(idp.removeMFA("user", "session".getBytes(), System.currentTimeMillis(), "wrong_token", GoogleAuthenticator.TYPE, "signature".getBytes()));

        try {
            idp.removeMFA("user", "bad_session".getBytes(), System.currentTimeMillis(), "token", GoogleAuthenticator.TYPE, "signature".getBytes());
            fail();
        } catch (AuthenticationFailedException e) {
        }

        assertFalse(idp.removeMFA("user", "session".getBytes(), System.currentTimeMillis(), "token", GoogleAuthenticator.TYPE, "bad_signature".getBytes()));

    }


    @Test
    public void testChangePassword() throws Exception {
        SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0)) {
            private int verifyCount = 0;

            @Override
            public boolean verifySignature(PublicKey key, List<byte[]> list, byte[] sig) {
                verifyCount++;
                assertTrue(verifyCount < 6); //We should never reach this place more than 5 times (1+3+1)
                return "newSignature".equals(new String(sig)) || "oldSignature".equals(new String(sig)) || "combinedSig".equals(new String(sig));
            }

            @Override
            public boolean verifySignature(PublicKey key, byte[] input, byte[] sig) {
                verifyCount++;
                assertTrue(verifyCount < 6); //We should never reach this place more than 5 times (1+3+1)
                return "newSignature".equals(new String(sig)) || "oldSignature".equals(new String(sig)) || "combinedSig".equals(new String(sig));
            }

            @Override
            public byte[] sign(PublicKey publicKey, byte[] input, int myId) {
                return "serverSig".getBytes();
            }

            @Override
            public byte[] combineSignatures(List<byte[]> partialSignatures) {
                return "combinedSig".getBytes();
            }

        };

        PestoDatabase db = mockDb();


        Map<String, MFAAuthenticator> authenticators = new HashMap<>();
        authenticators.put(GoogleAuthenticator.TYPE, mockAuthenticator());

        PestoIdPImpl idp = new PestoIdPImpl(db, null, authenticators, crypto, 100000);

        PABCConfigurationImpl pabcConfiguration = new PABCConfigurationImpl();
        pabcConfiguration.setAllowedTimeDifference(10000);
        pabcConfiguration.setKeyMaterial(new RSASharedKey(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE));
        pabcConfiguration.setRsaBlindings(new HashMap<>());
        pabcConfiguration.setOprfBlindings(new HashMap<>());
        pabcConfiguration.setOprfKey(BigInteger.ONE);
        pabcConfiguration.setLocalKeyShare("dd".getBytes());
        pabcConfiguration.setRemoteShares(new HashMap<>());
        pabcConfiguration.setServers(new LinkedList<>());
        pabcConfiguration.setSeed("dd".getBytes());
        pabcConfiguration.setAttrDefinitions(generateAttributeDefinitions());

        idp.setup("ssid", pabcConfiguration, new ArrayList<PestoIdP>());
        idp.addSession("c2Vzc2lvbg==", new Authorization("user", Arrays.asList(Role.USER), System.currentTimeMillis() + 10000));
        db.addUser("user", TestParameters.getECPublicKey1(), 100000l);
        db.assignMFASecret("user", GoogleAuthenticator.TYPE, "secret");
        db.activateMFA("user", GoogleAuthenticator.TYPE);

        Map<String, Attribute> map = idp.getAllAttributes("user", "session".getBytes(), System.currentTimeMillis(), "oldSignature".getBytes());
        byte[] resp = idp.changePassword("user", "session".getBytes(), TestParameters.getECPublicKey1(), "oldSignature".getBytes(), "newSignature".getBytes(), System.currentTimeMillis());
        assertEquals("combinedSig", new String(resp));
        map = idp.getAllAttributes("user", "session".getBytes(), System.currentTimeMillis(), "newSignature".getBytes());
        assertEquals(0, map.size());
        try {
            resp = idp.changePassword("user", "bad_session".getBytes(), TestParameters.getECPublicKey1(), "oldSignature".getBytes(), "newSignature".getBytes(), System.currentTimeMillis());
            fail();
        } catch (AuthenticationFailedException e) {

        }
    }


    private MFAAuthenticator mockAuthenticator() {
        MFAAuthenticator auth = mock(MFAAuthenticator.class);
        doAnswer(invocationOnMock -> "token".equals(invocationOnMock.getArgument(0))).when(auth).isValid(anyString(),anyString());
        doReturn("generated secret").when(auth).generateSecret();
        doReturn("combined secret").when(auth).combineSecrets(anyList());
        return auth;
    }

    private InMemoryPestoDatabase mockDb() {
        return new InMemoryPestoDatabase() {
            @Override
            public boolean hasUser(String user) {
                return true;
            }

            @Override
            public long getLastSalt(String username) {
                return 10000;
            }

            @Override
            public void setSalt(String user, long salt) {
            }

            @Override
            public PublicKey getUserKey(String u) {
                return TestParameters.getRSAPublicKey1();
            }
        };
    }
}
