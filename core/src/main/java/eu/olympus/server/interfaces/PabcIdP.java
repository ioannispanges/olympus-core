package eu.olympus.server.interfaces;

import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.util.multisign.MSverfKey;

public interface PabcIdP extends PestoBasedIdP {

    public String getCredentialShare(String username, byte[] cookie, long salt, byte[] signature, long timestamp) throws Exception;

    public MSverfKey getPabcPublicKeyShare() throws OperationFailedException;

    public PabcPublicParameters getPabcPublicParam() throws OperationFailedException;

}
