package eu.olympus.completeFlow;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.client.PestoClient;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.OIDCPestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.unit.server.TestIdentityProof;
import eu.olympus.unit.server.TestIdentityProver;
import eu.olympus.util.Util;
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

public class TestOIDCCompleteFlow extends CommonCompleteTests{

    @Test
    public void testOIDCFlow() throws Exception {
        int serverAmount = 3;
        List<OIDCPestoIdPImpl> idps = new ArrayList<>();

        for(int i = 0; i< serverAmount; i++) {
            PestoDatabase db = new InMemoryPestoDatabase();
            OIDCPestoIdPImpl idp = null;
            List<IdentityProver> provers = new LinkedList<IdentityProver>();
            provers.add(new TestIdentityProver(db));
            try {
                SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(i));
                Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
                mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
                idp = new OIDCPestoIdPImpl(db, provers, mfaAuthenticators, crypto, configuration[i].getIssuerId(), 100);
            } catch(Exception e) {
                e.printStackTrace();

                fail("Failed to start IdP");
            }
            idps.add(idp);
        }
        for(int i = 0; i< serverAmount; i++) {
            try {
                OIDCPestoIdPImpl idp = idps.get(i);
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
        simpleOIDCFlow(client, verifier);
        testPestoCreateAndAddAttributes(client);
    }

    //Policies for OIDC differ slightly, so we use a custom testflow
    public void simpleOIDCFlow(UserClient client, Verifier verifier) throws AuthenticationFailedException, TokenGenerationException {
        try{
            client.createUser("user_1_pesto", "password");
        } catch(UserCreationFailedException e) {
            e.printStackTrace();
            fail("Failed to create user");
        }
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("Name", new Attribute("John Doe"));
        attributes.put("Nationality", new Attribute("DK"));
        attributes.put("Age",new Attribute(22));

        try {

            // Prove identity using the key cache
            client.addAttributes("user_1_pesto", "password",  new TestIdentityProof("proof",attributes), null, "NONE");
        } catch(OperationFailedException e) {
            fail("Failed to prove identity: " + e);
        }
        client.clearSession();

        Map<String, Attribute> attributes2 = new HashMap<>();
        attributes2.put("Name", new Attribute("Jane Doe"));
        attributes2.put("Nationality", new Attribute("Se"));
        attributes2.put("Age",new Attribute(30));
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
        predicate = new Predicate("audience", Operation.REVEAL, new Attribute("test-service-provider"));
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

    public void testPestoCreateAndAddAttributes(UserClient client){
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

}
