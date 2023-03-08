package eu.olympus.server.rest;

import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.SerializedKey;
import eu.olympus.model.server.rest.SignatureAndTimestamp;
import eu.olympus.server.PabcIdPImpl;
import eu.olympus.util.KeySerializer;
import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/idp")
public class PabcIdPServlet extends AbstractIdpServlet{

    @Context
    ServletContext context;
    private static final Logger logger = LoggerFactory.getLogger(PabcIdPServlet.class);

    @Path(PestoRESTEndpoints.GET_CREDENTIAL_SHARE)
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public String getCredentialShare(SignatureAndTimestamp request) throws Exception {
        logger.info("idp/"+PestoRESTEndpoints.GET_CREDENTIAL_SHARE);
        logger.trace(getJson(request));
        PabcIdPImpl idp = (PabcIdPImpl) context.getAttribute("idp");
        return idp.getCredentialShare(request.getUsername(),
            Base64.decodeBase64(request.getSessionCookie()), request.getSaltIndex(), Base64.decodeBase64(request.getSignature()),request.getTimestamp());
    }

    @Path(PestoRESTEndpoints.GET_PABC_PUBLIC_KEY_SHARE)
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public SerializedKey getPABCPublicKeyShare() {
        logger.info("idp/"+PestoRESTEndpoints.GET_PABC_PUBLIC_KEY_SHARE);
        PabcIdPImpl idp = (PabcIdPImpl) context.getAttribute("idp");
        return KeySerializer.serialize(idp.getPabcPublicKeyShare());
    }

    @Path(PestoRESTEndpoints.GET_PABC_PUBLIC_PARAMETERS)
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public PabcPublicParameters getPABCPublicParam() {
        logger.info("idp/"+PestoRESTEndpoints.GET_PABC_PUBLIC_PARAMETERS);
        PabcIdPImpl idp = (PabcIdPImpl) context.getAttribute("idp");
        return idp.getPabcPublicParam();
    }
}
