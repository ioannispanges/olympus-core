package eu.olympus.server;

import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.PolicyUnfulfilledException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.rest.Role;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class CombinedIdP extends PabcIdPImpl implements PestoIdP {

  public CombinedIdP(PestoDatabase database, List<IdentityProver> identityProvers, Map<String, MFAAuthenticator> authenticators, ServerCryptoModule cryptoModule, int rateLimit) throws SetupException {
    super(database, identityProvers, authenticators, cryptoModule, rateLimit);
  }

  @Override
  public String authenticate(String username, byte[] cookie, long salt, byte[] signature,
      Policy policy) throws Exception {
    validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
    boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.AUTHENTICATE);
    if(authenticated) {
      try{
        Map<String, Attribute> assertions = authenticationHandler
            .validateAssertions(username, policy);
        return tokenGenerator.generateToken(assertions);
      } catch(PolicyUnfulfilledException | TokenGenerationException e) {
        throw new AuthenticationFailedException("Failed : Could not produce a token", e);
      }
    }
    throw new AuthenticationFailedException("Failed : User failed authentication");
  }
}
