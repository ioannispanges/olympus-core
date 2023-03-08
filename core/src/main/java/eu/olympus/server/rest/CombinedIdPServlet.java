package eu.olympus.server.rest;

import eu.olympus.model.server.rest.SignatureAndPolicy;
import eu.olympus.server.interfaces.PestoIdP;
import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CombinedIdPServlet extends PabcIdPServlet{
    @Context
    ServletContext context;
    private static final Logger logger = LoggerFactory.getLogger(CombinedIdPServlet.class);

    @Path(PestoRESTEndpoints.AUTHENTICATE)
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public String authenticate(SignatureAndPolicy request) throws Exception {
        logger.info("idp/"+PestoRESTEndpoints.AUTHENTICATE);
        logger.trace(getJson(request));
        PestoIdP idp = (PestoIdP) context.getAttribute("idp");
        return idp.authenticate(request.getUsername(), Base64.decodeBase64(request.getSessionCookie()),
            request.getSaltIndex(), Base64.decodeBase64(request.getSignature()),
            request.getPolicy());
    }
}
