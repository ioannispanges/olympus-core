package eu.olympus.completeFlow;

import static org.junit.Assert.fail;

import eu.olympus.TestParameters;
import eu.olympus.client.PasswordIdPRESTConnection;
import eu.olympus.client.PasswordJWTClient;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.PasswordJWTIdP;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.UserPasswordDatabase;
import eu.olympus.server.rest.PasswordIdPServlet;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import eu.olympus.unit.server.TestIdentityProver;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.Test;

public class TestPasswordIdpCompleteFlow extends CommonCompleteTests {


    @Test
    public void testPasswordJWTDirect() throws AuthenticationFailedException, TokenGenerationException {
        logger.info("Starting testPasswordJWTDirect");
        UserPasswordDatabase db = new InMemoryUserPasswordDatabase();
        PasswordJWTIdP idp = null;
        List<IdentityProver> provers = new LinkedList<IdentityProver>();
        provers.add(new TestIdentityProver(db));
        try {
            idp = new PasswordJWTIdP(db, provers, new HashMap<>());
        } catch(Exception e) {
            fail("Failed to start IdP");
        }
        List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
        idps.add(idp);
        UserClient client = new PasswordJWTClient(idps);
        try{
            idp.setup(TestParameters.getRSAPrivateKey2(), TestParameters.getRSA2Cert());
        } catch(Exception e) {
            fail("Failed to generate key");
        }
        testSimpleFlow(client, getVerifier());
    }


    @Test
    public void testPasswordJWTREST() throws Exception {
        logger.info("Starting testPasswordJWTREST");
        InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
        PasswordJWTIdP idp = null;
        List<IdentityProver> provers = new LinkedList<IdentityProver>();
        provers.add(new TestIdentityProver(db));
        RESTIdPServer restServer = RESTIdPServer.getInstance();
        List<String> servlets=new LinkedList<>();
        servlets.add(PasswordIdPServlet.class.getCanonicalName());
        try {
            SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(0));
            Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
            mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
            mfaAuthenticators.put("dummy", new DummyAuthenticator());
            idp = new PasswordJWTIdP(db, provers, mfaAuthenticators);

            restServer.setIdP(idp);
            restServer.start(configuration[0].getPort(), servlets, 0, null, null, null);
        } catch(Exception e) {
            fail("Failed to start IdP" + e);
        }

        List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
        PasswordJWTIdP rest = new PasswordIdPRESTConnection("http://127.0.0.1:"+configuration[0].getPort());
        rest.setup(TestParameters.getRSAPrivateKey2(), TestParameters.getRSA2Cert());
        idps.add(rest);

        UserClient client = new PasswordJWTClient(idps);
        testSimpleFlow(client, getVerifier());
        testAccManagement(client, getVerifier());
        testErrorCases(client, getVerifier());
        testMFAFlow(client, getVerifier());

        try {
            restServer.stop();
        } catch (Exception e) {
        }
    }


}
