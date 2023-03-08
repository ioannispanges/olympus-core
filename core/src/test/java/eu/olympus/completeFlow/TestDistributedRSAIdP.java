package eu.olympus.completeFlow;

import static org.junit.Assert.fail;

import eu.olympus.TestParameters;
import eu.olympus.client.DistributedRSAClient;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.KeyShares;
import eu.olympus.model.RSASharedKey;
import eu.olympus.server.DistributedRSAIdP;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.UserPasswordDatabase;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import eu.olympus.unit.server.TestIdentityProver;
import eu.olympus.util.CommonCrypto;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.Test;

public class TestDistributedRSAIdP extends CommonCompleteTests{



    @Test
    public void testDistributedRSADirect() throws Exception{
        logger.info("Starting testDistributedRSADirect");
        List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
        int serverCount = 2;
        RSAPrivateCrtKey pk = (RSAPrivateCrtKey) TestParameters.getRSAPrivateKey2();
        BigInteger d = pk.getPrivateExponent();

        Random rnd = new Random(1);
        BigInteger[] keyShares = new BigInteger[serverCount];
        BigInteger sum = BigInteger.ZERO;
        for(int i=0; i< serverCount-1; i++) {
            keyShares[i]= new BigInteger(pk.getModulus().bitLength()+8* CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(pk.getModulus());
            sum = sum.add(keyShares[i]);
        }
        keyShares[serverCount-1] = d.subtract(sum).mod(pk.getModulus());
        //keyShares[2] = d.subtract(keyShares[0].add(keyShares[1])); works for 3 party
        for(int i = 0; i< serverCount; i++) {
            UserPasswordDatabase db = new InMemoryUserPasswordDatabase();
            DistributedRSAIdP idp = null;
            List<IdentityProver> provers = new LinkedList<IdentityProver>();
            provers.add(new TestIdentityProver(db));
            try {
                ServerCryptoModule cryptoModule = new SoftwareServerCryptoModule(new Random(i));
                cryptoModule.setupServer(new KeyShares(new RSASharedKey(pk.getModulus(), keyShares[i], pk.getPublicExponent()), null, null, null));
                // Note that since the signing is the only distributed aspect of this authentication scheme,
                // we need the authenticator to be initialized with the same randomness on all servers
                Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
                mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(new SoftwareClientCryptoModule(new Random(42), pk.getModulus())));
                mfaAuthenticators.put("dummy", new DummyAuthenticator());
                idp = new DistributedRSAIdP(db, i, provers, cryptoModule, mfaAuthenticators, TestParameters.getRSA2Cert());
            } catch(Exception e) {
                fail("Failed to start IdP");
            }
            idps.add(idp);
        }
        UserClient client = new DistributedRSAClient(idps);

        testSimpleFlow(client, getVerifier());
        testAccManagement(client, getVerifier());
        testErrorCases(client, getVerifier());
        testMFAFlow(client, getVerifier());
    }

}
