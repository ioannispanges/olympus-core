package eu.olympus.client;

import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.SerializedKey;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.server.rest.SignatureAndTimestamp;
import eu.olympus.server.interfaces.PabcIdP;
import eu.olympus.server.rest.PestoRESTEndpoints;
import eu.olympus.util.KeySerializer;
import eu.olympus.util.multisign.MSverfKey;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import org.apache.commons.codec.binary.Base64;

public class PabcIdPRESTConnection extends IdPRESTConnection implements PabcIdP {
    /**
     * Create a new rest connections to an IdP
     * @param url includes port, eg. http://127.0.0.1:9090
     */
    public PabcIdPRESTConnection(String url, String accessToken, int id, int rateLimit) {
        super(url, accessToken, id, rateLimit);
    }

    @Override
    public String getCredentialShare(String username, byte[] cookie, long salt, byte[] signature, long timestamp) {
        SignatureAndTimestamp data = new SignatureAndTimestamp(username, Base64.encodeBase64String(
            cookie), salt, Base64.encodeBase64String(signature), timestamp);
        return client.target(host+PestoRESTEndpoints.GET_CREDENTIAL_SHARE).request()
            .post(Entity.entity(data, MediaType.APPLICATION_JSON), String.class);
    }

    @Override
    public MSverfKey getPabcPublicKeyShare() throws OperationFailedException {
        try {
            SerializedKey serializedKey = client.target(host+PestoRESTEndpoints.GET_PABC_PUBLIC_KEY_SHARE).request().get(SerializedKey.class);
            return (MSverfKey) KeySerializer.deSerialize(serializedKey);
        } catch(Exception e) {
            throw new OperationFailedException("Failed to retrieve public key share",e);
        }
    }

    @Override
    public PabcPublicParameters getPabcPublicParam() throws OperationFailedException {
        try {
            return client.target(host + PestoRESTEndpoints.GET_PABC_PUBLIC_PARAMETERS).request().get(PabcPublicParameters.class);
        } catch (Exception e){
            throw new OperationFailedException("Failed to get parameters", e);
        }
    }
}
