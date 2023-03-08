package eu.olympus.completeFlow;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.client.CombinedIdPRESTConnection;
import eu.olympus.client.PSCredentialManagement;
import eu.olympus.client.PabcClient;
import eu.olympus.client.PestoClient;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.server.CombinedIdP;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdPRESTWrapper;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.rest.CombinedIdPServlet;
import eu.olympus.server.rest.PestoIdP2IdPRESTConnection;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.unit.server.TestIdentityProver;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.verifier.JWTVerifier;
import eu.olympus.verifier.PSPABCVerifier;
import eu.olympus.verifier.interfaces.Verifier;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestCombinedIdpCompleteFlow extends CommonCompleteTests{
    private static Logger logger = LoggerFactory.getLogger(TestCombinedIdpCompleteFlow.class);

    private static Map<Integer, PestoDatabase> databases = new HashMap<Integer, PestoDatabase>();
	
    @Test
    public void testCombinedDirect() throws Exception{
        logger.info("Starting testCombinedDirect");
        int serverAmount = 3;
        List<CombinedIdP> idps = setupCombinedIdPs( serverAmount);
        for(int i = 0; i< serverAmount; i++) {
            try {
                CombinedIdP idp = idps.get(i);
                for(String cookie: configuration[i].getAuthorizationCookies().keySet()) {
                    idp.addSession(cookie, configuration[i].getAuthorizationCookies().get(cookie));
                }
                List<CombinedIdP> others = new ArrayList<CombinedIdP>();
                others.addAll(idps);
                others.remove(idp);
                boolean complete = idp.setup("setup", configuration[i], others);
                assertTrue(complete);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
        }

        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        for (Integer j = 0; j< getServerCount(); j++){
            publicKeys.put(j, idps.get(j).getPabcPublicKeyShare());
        }

        CredentialManagement credentialManagement=new PSCredentialManagement(true, new InMemoryCredentialStorage());
        ((PSCredentialManagement)credentialManagement).setup(idps,seed);

        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate().getPublicKey()).getModulus());

        PabcClient pabcClient = new PabcClient(idps, credentialManagement, cryptoModule);
        PSPABCVerifier pabcVerifier = new PSPABCVerifier();
        pabcVerifier.setup(idps,seed);

        testSimpleFlowPabc(pabcClient,pabcVerifier);
        testRefreshFlowPabc(pabcClient, pabcVerifier, idps);
        CredentialManagement credentialManagementWithoutStorage=new PSCredentialManagement(false, null);
        ((PSCredentialManagement)credentialManagementWithoutStorage).setup(idps,seed);
        testMFAFlowPabc(pabcClient, pabcVerifier);

        UserClient pestoClient = new PestoClient(idps, cryptoModule);

        Verifier verifier = new JWTVerifier(idps.get(0).getCertificate().getPublicKey());
        logger.info(":testCombinedDirect - starting pesto client simpleFlow");
        testSimpleFlow(pestoClient, verifier);
        logger.info(":testCombinedDirect - starting test acc management");
        testAccManagement(pestoClient, verifier);
        logger.info(":testCombinedDirect - starting test error cases");
        testErrorCases(pestoClient, verifier);
        logger.info(":testCombinedDirect - starting pesto refresh flow");
        testRefreshFlow(pestoClient, verifier, idps);
        logger.info(":testCombinedDirect - starting mfa flow");
        testMFAFlow(pestoClient, verifier);
    }

    @Test
    public void testPestoAndPabcREST() throws Exception{
        logger.info("Starting testPestoREST");
        int serverCount = 3;
        List<CombinedIdP> idps = setupCombinedIdPs(serverCount);
        List<RESTIdPServer> restServers = new ArrayList<>();
        List<String> servlets=new LinkedList<>();
        servlets.add(CombinedIdPServlet.class.getCanonicalName());
        for(int i = 0; i< serverCount; i++) {
            try {
                RESTIdPServer restServer = new RESTIdPServer();
                restServer.setIdP(idps.get(i));
                restServer.start(configuration[i].getPort(), servlets, 0, null, null, null);
                restServers.add(restServer);
            } catch (Exception e) {
                fail("Failed to start IdP");
            }
        }
        List<CombinedIdPRESTConnection> restIdps = new ArrayList<>();
        for(int i = 0; i< serverCount; i++) {
            try {
                CombinedIdPRESTConnection restConnection = new CombinedIdPRESTConnection("http://127.0.0.1:"+(configuration[i].getPort()),
                    getAdminCookie(), i, 100000);
                List<IdPRESTWrapper> others = new ArrayList<>();
                for(int j = 0; j< serverCount; j++) {
                    if (j != i) {
                        others.add(new PestoIdP2IdPRESTConnection("http://127.0.0.1:" + (configuration[j].getPort()), j,
                            configuration[i].getMyAuthorizationCookie()));
                    }
                }
                for(String cookie: configuration[i].getAuthorizationCookies().keySet()) {
                    idps.get(i).addSession(cookie, configuration[i].getAuthorizationCookies().get(cookie));
                }
                boolean res = idps.get(i).setup("setup", configuration[i], others);
                assertTrue(res);
                restIdps.add(restConnection);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
        }

        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus());
        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        for (int j = 0; j< serverCount; j++){
            publicKeys.put(j, restIdps.get(j).getPabcPublicKeyShare());
        }
        PabcPublicParameters publicParam= restIdps.get(0).getPabcPublicParam();

        PSCredentialManagement credentialManagement=new PSCredentialManagement(true, new InMemoryCredentialStorage());
        credentialManagement.setup(publicParam,publicKeys,seed);

        UserClient pabcClient = new PabcClient(restIdps, credentialManagement, cryptoModule);
        UserClient pestoClient = new PestoClient(restIdps, cryptoModule);

        PSPABCVerifier verifier = new PSPABCVerifier();
        verifier.setup(idps,seed);
        testSimpleFlowPabc(pabcClient, verifier);
        testRefreshFlowPabc(pabcClient, verifier, restIdps);
        PSCredentialManagement credentialManagementWithoutStorage=new PSCredentialManagement(false, null);
        credentialManagementWithoutStorage.setup(publicParam,publicKeys,seed);
        testMFAFlowPabc(new PabcClient(restIdps, credentialManagementWithoutStorage, cryptoModule), verifier);

        testSimpleFlow(pestoClient, getVerifier());
        testAccManagement(pestoClient, getVerifier());
        testErrorCases(pestoClient, getVerifier());
        testMFAFlow(pestoClient, getVerifier());
        testRefreshFlow(pestoClient, getVerifier(), restIdps);

        for(RESTIdPServer server:restServers){
            server.stop();
        }
    }



    @Test
    public void testPabcREST() throws Exception{
        logger.info("Starting testPabcREST");
        int serverCount = 3;
        List<CombinedIdP> idps = setupCombinedIdPs(serverCount);
        List<RESTIdPServer> restServers = new ArrayList<>();
        List<String> servlets=new LinkedList<>();
        servlets.add(CombinedIdPServlet.class.getCanonicalName());
        for(int i = 0; i< serverCount; i++) {
            try {
                RESTIdPServer restServer = new RESTIdPServer();
                restServer.setIdP(idps.get(i));
                restServer.start(configuration[i].getPort(), servlets, 0, null, null, null);
                restServers.add(restServer);
            } catch (Exception e) {
                fail("Failed to start IdP");
            }
        }
        List<CombinedIdPRESTConnection> restIdps = new ArrayList<>();
        for(int i = 0; i< serverCount; i++) {
            try {
                CombinedIdPRESTConnection restConnection = new CombinedIdPRESTConnection("http://127.0.0.1:"+(configuration[i].getPort()),
                    getAdminCookie(), i, 100000);
                List<IdPRESTWrapper> others = new ArrayList<>();
                for(int j = 0; j< serverCount; j++) {
                    if (j != i) {
                        others.add(new PestoIdP2IdPRESTConnection("http://127.0.0.1:" + (configuration[j].getPort()), j,
                            configuration[i].getMyAuthorizationCookie()));
                    }
                }
                for(String cookie: configuration[i].getAuthorizationCookies().keySet()) {
                    idps.get(i).addSession(cookie, configuration[i].getAuthorizationCookies().get(cookie));
                }
                boolean res = idps.get(i).setup("setup", configuration[i], others);
                assertTrue(res);
                restIdps.add(restConnection);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
        }

        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        for (Integer j = 0; j< serverCount; j++){
            publicKeys.put(j, restIdps.get(j).getPabcPublicKeyShare());
        }
        PabcPublicParameters publicParam= restIdps.get(0).getPabcPublicParam();

        CredentialManagement credentialManagement=new PSCredentialManagement(true, new InMemoryCredentialStorage());
        ((PSCredentialManagement)credentialManagement).setup(publicParam,publicKeys,seed);

        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus());

        UserClient client = new PabcClient(restIdps, credentialManagement, cryptoModule);
        PSPABCVerifier verifier = new PSPABCVerifier();
        verifier.setup(idps,seed);
        testSimpleFlowPabc(client, verifier);
        testRefreshFlowPabc(client, verifier, restIdps);
        CredentialManagement credentialManagementWithoutStorage=new PSCredentialManagement(false, null);
        ((PSCredentialManagement)credentialManagementWithoutStorage).setup(publicParam,publicKeys,seed);
        testMFAFlowPabc(new PabcClient(restIdps, credentialManagementWithoutStorage, cryptoModule), verifier);
        for(RESTIdPServer server:restServers){
            server.stop();
        }
    }


    @Test
    public void testPestoREST() throws Exception{
        logger.info("Starting testPestoREST");
        int serverCount = 3;
        List<CombinedIdP> idps = setupCombinedIdPs(serverCount);
        List<RESTIdPServer> restServers = new ArrayList<>();
        List<String> servlets=new LinkedList<>();
        servlets.add(CombinedIdPServlet.class.getCanonicalName());
        for(int i = 0; i< serverCount; i++) {
            try {
                RESTIdPServer restServer = new RESTIdPServer();
                restServer.setIdP(idps.get(i));
                restServer.start(configuration[i].getPort(), servlets, 0, null, null, null);
                restServers.add(restServer);
            } catch (Exception e) {
                fail("Failed to start IdP");
            }
        }
        List<CombinedIdPRESTConnection> restIdps = new ArrayList<>();
        for(int i = 0; i< serverCount; i++) {
            try {
                CombinedIdPRESTConnection restConnection = new CombinedIdPRESTConnection("http://127.0.0.1:"+(configuration[i].getPort()),
                    getAdminCookie(), i, 100000);
                List<IdPRESTWrapper> others = new ArrayList<>();
                for(int j = 0; j< serverCount; j++) {
                    if (j != i) {
                        others.add(new PestoIdP2IdPRESTConnection("http://127.0.0.1:" + (configuration[j].getPort()), j,
                            configuration[i].getMyAuthorizationCookie()));
                    }
                }
                for(String cookie: configuration[i].getAuthorizationCookies().keySet()) {
                    idps.get(i).addSession(cookie, configuration[i].getAuthorizationCookies().get(cookie));
                }
                boolean res = idps.get(i).setup("setup", configuration[i], others);
                assertTrue(res);
                restIdps.add(restConnection);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
        }

        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus());

        UserClient pestoClient = new PestoClient(restIdps, cryptoModule);

        testSimpleFlow(pestoClient, getVerifier());
        testAccManagement(pestoClient, getVerifier());
        testErrorCases(pestoClient, getVerifier());
        testRefreshFlow(pestoClient, getVerifier(), restIdps);
        testMFAFlow(pestoClient, getVerifier());

        for(RESTIdPServer server:restServers){
            server.stop();
        }
    }




    private List<CombinedIdP> setupCombinedIdPs(int amount) {
        if (amount != getServerCount()) {
            throw new IllegalArgumentException("Configuration only supports " + getServerCount() + " servers");
        }
        List<CombinedIdP> idps = new ArrayList<CombinedIdP>();
        databases = new HashMap<>();
        for(int i = 0; i< amount; i++) {
            databases.put(i,  new InMemoryPestoDatabase());
            CombinedIdP idp = null;
            List<IdentityProver> provers = new LinkedList<IdentityProver>();
            provers.add(new TestIdentityProver(databases.get(i)));
            SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(i));
            try {
                Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
                mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
                mfaAuthenticators.put("dummy", new DummyAuthenticator());
                idp = new CombinedIdP(databases.get(i), provers, mfaAuthenticators, crypto, 100000);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
            idps.add(idp);
        }
        return idps;
    }


}
