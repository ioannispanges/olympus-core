package eu.olympus.completeFlow;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.client.PestoClient;
import eu.olympus.client.PestoIdPRESTConnection;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdPRESTWrapper;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.PestoIdP2IdPRESTConnection;
import eu.olympus.server.rest.PestoIdPServlet;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.unit.server.TestIdentityProver;
import eu.olympus.verifier.JWTVerifier;
import eu.olympus.verifier.interfaces.Verifier;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.Test;

public class TestPestoCompleteFlow extends CommonCompleteTests{

    private static Map<Integer, PestoDatabase> databases = new HashMap<Integer, PestoDatabase>();

    @Test
    public void testPestoDirect() throws Exception{
        logger.info("Starting testPestoDirect");
        int serverAmount = 3;
        List<PestoIdP> idps = setupPestoIdps( serverAmount);
        for(int i = 0; i< serverAmount; i++) {
            try {
                PestoIdPImpl idp = (PestoIdPImpl) idps.get(i);
                for(String cookie: configuration[i].getAuthorizationCookies().keySet()) {
                    idp.addSession(cookie, configuration[i].getAuthorizationCookies().get(cookie));
                }
                List<PestoIdP> others = new ArrayList<PestoIdP>();
                others.addAll(idps);
                others.remove(idp);
                boolean complete = idp.setup("setup", configuration[i], others);
                assertTrue(complete);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
        }

        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate().getPublicKey()).getModulus());
        UserClient client = new PestoClient(idps, cryptoModule);

        Verifier verifier = new JWTVerifier(idps.get(0).getCertificate().getPublicKey());
        logger.info(":testPestoDirect - starting simpleFlow");
        testSimpleFlow(client, verifier);
        logger.info(":testPestoDirect - starting test acc management");
        testAccManagement(client, verifier);
        logger.info(":testPestoDirect - starting test error cases");
        testErrorCases(client, verifier);
        logger.info(":testPestoDirect - starting refresh flow");
        testRefreshFlow(client, verifier, idps);
        logger.info(":testPestoDirect - starting mfa flow");
        testMFAFlow(client, verifier);
    }


    @Test
    public void testPestoREST() throws Exception{
        logger.info("Starting testPestoREST");
        int serverCount = 3;
        List<PestoIdP> idps = setupPestoIdps(serverCount);
        List<RESTIdPServer> restServers = new ArrayList<>();
        List<String> servlets=new LinkedList<>();
        servlets.add(PestoIdPServlet.class.getCanonicalName());
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
        List<PestoIdP> restIdps = new ArrayList<>();
        for(int i = 0; i< serverCount; i++) {
            try {
                PestoIdPRESTConnection restConnection = new PestoIdPRESTConnection("http://127.0.0.1:"+(configuration[i].getPort()),
                    getAdminCookie(), i, 100);
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
                boolean res = ((PestoIdPImpl) idps.get(i)).setup("setup", configuration[i], others);
                assertTrue(res);
                restIdps.add(restConnection);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
        }
        UserClient client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(3), configuration[0].getKeyMaterial().getModulus()));
        logger.info(":testPestoREST - starting simpleFlow");
        testSimpleFlow(client, getVerifier());
        logger.info(":testPestoREST - starting accManagement");
        testAccManagement(client, getVerifier());
        client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(3), configuration[0].getKeyMaterial().getModulus()));
        logger.info(":testPestoREST - starting errorCases");
        testErrorCases(client, getVerifier());
        client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(3), configuration[0].getKeyMaterial().getModulus()));
        logger.info(":testPestoREST - starting refreshFlow");
        testRefreshFlow(client, getVerifier(), restIdps);
        client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(3), configuration[0].getKeyMaterial().getModulus()));
        logger.info(":testPestoREST - starting MFAFlow");
        testMFAFlow(client, getVerifier());
        for(RESTIdPServer server:restServers){
            server.stop();
        }
    }


    @Test
    public void testPestoRESTWithTLS() throws Exception{
        logger.info("Starting testPestoREST-TLS");
        int serverCount = 3;
        List<PestoIdP> idps = setupPestoIdps(serverCount);
        List<RESTIdPServer> restServers = new ArrayList<>();
        List<String> servlets=new LinkedList<>();
        servlets.add(PestoIdPServlet.class.getCanonicalName());
        for(int i = 0; i< serverCount; i++) {
            try {
                RESTIdPServer restServer = new RESTIdPServer();
                restServer.setIdP(idps.get(i));
                restServer.start(configuration[i].getPort(), servlets, configuration[i].getTlsPort(), configuration[i].getKeyStorePath(), configuration[i].getKeyStorePassword(), configuration[i].getKeyStorePassword());
                restServers.add(restServer);
            } catch (Exception e) {
                fail("Failed to start IdP");
            }
        }
        List<PestoIdP> restIdps = new ArrayList<>();
        for(int i = 0; i< serverCount; i++) {
            try {
                PestoIdPRESTConnection restConnection = new PestoIdPRESTConnection("https://localhost:"+(configuration[i].getTlsPort()),
                    getAdminCookie(), i, 100);
                List<IdPRESTWrapper> others = new ArrayList<>();
                for(int j = 0; j< serverCount; j++) {
                    if (j != i) {
                        others.add(new PestoIdP2IdPRESTConnection("https://localhost:" + (configuration[j].getTlsPort()), j,
                            configuration[i].getKeyStorePath(), configuration[i].getKeyStorePassword(),
                            configuration[i].getTrustStorePath(), configuration[i].getTrustStorePassword(),
                            configuration[i].getMyAuthorizationCookie()));
                    }
                }
                for(String cookie: configuration[i].getAuthorizationCookies().keySet()) {
                    ((PestoIdPImpl) idps.get(i)).addSession(cookie, configuration[i].getAuthorizationCookies().get(cookie));
                }
                boolean res = ((PestoIdPImpl) idps.get(i)).setup("setup", configuration[i], others);
                assertTrue(res);
                restIdps.add(restConnection);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
        }

        UserClient client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus()));
        testSimpleFlow(client, getVerifier());
        logger.info(":testPestoREST-TLS - starting accManagement");
        testAccManagement(client, getVerifier());
        client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus()));
        logger.info(":testPestoREST-TLS - starting errorCases");
        testErrorCases(client, getVerifier());
        client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus()));
        logger.info(":testPestoREST-TLS - starting refreshFlow");
        testRefreshFlow(client, getVerifier(), restIdps);
        client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus()));
        logger.info(":testPestoREST-TLS - starting MFAFlow");
        testMFAFlow(client, getVerifier());
        for(RESTIdPServer server:restServers){
            server.stop();
        }
    }

    private List<PestoIdP> setupPestoIdps( int amount) {
        if (amount != getServerCount()) {
            throw new IllegalArgumentException("Configuration only supports " + getServerCount() + " servers");
        }
        List<PestoIdP> idps = new ArrayList<PestoIdP>();
        databases = new HashMap<>();
        for(int i = 0; i< amount; i++) {
            databases.put(i,  new InMemoryPestoDatabase());
            PestoIdPImpl idp = null;
            List<IdentityProver> provers = new LinkedList<IdentityProver>();
            provers.add(new TestIdentityProver(databases.get(i)));
            SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(i));
            try {
                Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
                mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
                mfaAuthenticators.put("dummy", new DummyAuthenticator());
                idp = new PestoIdPImpl(databases.get(i), provers, mfaAuthenticators, crypto, 100000);

            } catch(Exception e) {
                fail("Failed to start IdP");
            }
            idps.add(idp);
        }
        return idps;
    }
}
