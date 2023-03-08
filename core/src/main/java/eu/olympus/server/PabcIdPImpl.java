package eu.olympus.server;

import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.server.interfaces.IdPRESTWrapper;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PABCConfiguration;
import eu.olympus.server.interfaces.PESTOConfiguration;
import eu.olympus.server.interfaces.PabcIdP;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.rest.Role;
import eu.olympus.util.multisign.MSverfKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class PabcIdPImpl extends AbstractPestoIdP implements PabcIdP {
    protected ThresholdPSSharesGenerator sharesGenerator;

    public PabcIdPImpl(PestoDatabase database, List<IdentityProver> identityProvers, Map<String,
        MFAAuthenticator> authenticators, ServerCryptoModule cryptoModule, int rateLimit) throws SetupException {
        super(database, identityProvers, authenticators, cryptoModule, rateLimit);
        sharesGenerator = new ThresholdPSSharesGenerator(database, cryptoModule.getBytes(57));
    }

    @Override
    public boolean setup(String ssid, PESTOConfiguration configuration, List<? extends IdPRESTWrapper> servers){
        sharesGenerator.setup((PABCConfiguration) configuration);
        return super.setup(ssid, configuration,servers);
    }

    @Override
    public String getCredentialShare(String username, byte[] cookie, long salt, byte[] signature, long timestamp) throws Exception {
        validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
        boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.AUTHENTICATE);
        if(authenticated) {
            return sharesGenerator.createCredentialShare(username,timestamp).getEncoded();
        }
        throw new AuthenticationFailedException("Failed : User failed authentication");
    }

    public MSverfKey getPabcPublicKeyShare(){
        return sharesGenerator.getVerificationKeyShare();
    }

    public PabcPublicParameters getPabcPublicParam(){
        return sharesGenerator.getPublicParam();
    }

}
