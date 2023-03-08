package eu.olympus.server.interfaces;

import eu.olympus.model.PSCredential;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.util.multisign.MSpublicParam;
import java.security.PublicKey;

public interface CredentialGenerator {

    /**
     * Setup the credential generator.
     * @param configuration The configuration to use
     * @return Public parameters of the signing scheme
     */
    MSpublicParam setup(PABCConfiguration configuration);

    /**
     * @return The share of the verification key corresponding to this credential generator (IdP).
     */
    PublicKey getVerificationKeyShare();

    /**
     * @return Public parameters of the signing scheme
     */
    PabcPublicParameters getPublicParam();

    /**
     * Create a credential share for a specific user (using his attributes).
     * @param username User that requested the credential (it is assumed that he correctly authenticated).
     * @param timestamp Timestamp for setting the expiration time (epoch)
     * @return A credential share.
     */
    PSCredential createCredentialShare(String username, long timestamp) throws OperationFailedException;

}
