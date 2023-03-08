package eu.olympus.completeFlow;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.client.PSCredentialManagement;
import eu.olympus.client.PabcClient;
import eu.olympus.client.PestoClient;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.server.CombinedOIDCIdP;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
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
import org.junit.Test;

public class TestCombinedOIDCIdPCompleteFlow extends TestOIDCCompleteFlow{

    private static Map<Integer, PestoDatabase> databases = new HashMap<Integer, PestoDatabase>();


    @Test
    public void testOIDCFlowAndPabcFlow() throws Exception {
        int serverAmount = 3;
        List<CombinedOIDCIdP> idps = setupCombinedIdPs(serverAmount);

        for(int i = 0; i< serverAmount; i++) {
            try {
                CombinedOIDCIdP idp = idps.get(i);
                List<PestoIdP> others = new ArrayList<PestoIdP>();
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
        simpleOIDCFlow(pestoClient, verifier);
        testPestoCreateAndAddAttributes(pestoClient);
    }


    private List<CombinedOIDCIdP> setupCombinedIdPs(int amount) {
        if (amount != getServerCount()) {
            throw new IllegalArgumentException("Configuration only supports " + getServerCount() + " servers");
        }
        List<CombinedOIDCIdP> idps = new ArrayList<CombinedOIDCIdP>();
        databases = new HashMap<>();
        for(int i = 0; i< amount; i++) {
            databases.put(i,  new InMemoryPestoDatabase());
            CombinedOIDCIdP idp = null;
            List<IdentityProver> provers = new LinkedList<IdentityProver>();
            provers.add(new TestIdentityProver(databases.get(i)));
            SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(i));
            try {
                Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
                mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
                mfaAuthenticators.put("dummy", new DummyAuthenticator());
                idp = new CombinedOIDCIdP(databases.get(i), provers, mfaAuthenticators, crypto,configuration[i].getIssuerId(), 100000);
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
            idps.add(idp);
        }
        return idps;
    }

}
