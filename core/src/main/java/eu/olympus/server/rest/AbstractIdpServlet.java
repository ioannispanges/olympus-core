package eu.olympus.server.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.AddAttributesRequest;
import eu.olympus.model.server.rest.AddMasterShare;
import eu.olympus.model.server.rest.AddPartialMFARequest;
import eu.olympus.model.server.rest.AddPartialSignatureRequest;
import eu.olympus.model.server.rest.AttributeMap;
import eu.olympus.model.server.rest.ChangePasswordRequest;
import eu.olympus.model.server.rest.DeleteAccountRequest;
import eu.olympus.model.server.rest.DeleteAttributesRequest;
import eu.olympus.model.server.rest.FinishRegistrationRequest;
import eu.olympus.model.server.rest.GetAllAttributesRequest;
import eu.olympus.model.server.rest.OPRFRequest;
import eu.olympus.model.server.rest.OPRFRestResponse;
import eu.olympus.model.server.rest.SecondFactorConfirmation;
import eu.olympus.model.server.rest.SecondFactorDelete;
import eu.olympus.model.server.rest.SecondFactorRequest;
import eu.olympus.model.server.rest.SetKeyShare;
import eu.olympus.server.AbstractPestoIdP;
import eu.olympus.util.KeySerializer;
import eu.olympus.util.keyManagement.PemUtil;
import java.security.PublicKey;
import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.miracl.core.BLS12461.CONFIG_BIG;
import org.miracl.core.BLS12461.ECP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractIdpServlet {

    private final String BEARERTOKENSTRING = "Bearer ";

    @Context
    ServletContext context;
    private static final Logger logger = LoggerFactory.getLogger(AbstractIdpServlet.class);

    @Path(PestoRESTEndpoints.REQUEST_OPRF)
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public OPRFRestResponse requestOPRF(OPRFRequest request) throws UserCreationFailedException, AuthenticationFailedException, OperationFailedException {
        logger.info("idp/"+PestoRESTEndpoints.REQUEST_OPRF);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        ECP element = ECP.fromBytes(Base64.decodeBase64(request.getElement()));
        OPRFResponse resp = idp.performOPRF(request.getSsid(),
            request.getUsername(), element, request.getMfaToken(), request.getMfaType());
        byte[] fp12Bytes = new byte[12* CONFIG_BIG.MODBYTES];
        resp.getY().toBytes(fp12Bytes);
        return new OPRFRestResponse(resp.getSsid(), Base64.encodeBase64String(fp12Bytes), resp.getSessionCookie());
    }

    @Path(PestoRESTEndpoints.REQUEST_MFA)
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public String requestMFA(SecondFactorRequest request) throws AuthenticationFailedException, OperationFailedException {
        logger.info("idp/"+PestoRESTEndpoints.REQUEST_MFA);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return idp.requestMFA(request.getUsername(), Base64.decodeBase64(request.getSessionCookie()), request.getSaltIndex(), request.getType(), Base64.decodeBase64(request.getSignature()));
    }

    @Path(PestoRESTEndpoints.CONFIRM_MFA)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Boolean confirmMFA(SecondFactorConfirmation request) throws AuthenticationFailedException, OperationFailedException {
        logger.info("idp/"+PestoRESTEndpoints.CONFIRM_MFA);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return idp.confirmMFA(request.getUsername(), Base64.decodeBase64(request.getSessionCookie()), request.getSaltIndex(), request.getToken(), request.getType(), Base64.decodeBase64(request.getSignature()));
    }

    @Path(PestoRESTEndpoints.REMOVE_MFA)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Boolean removeMFA(SecondFactorDelete request) throws AuthenticationFailedException, OperationFailedException {
        logger.info("idp/"+PestoRESTEndpoints.REMOVE_MFA);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return idp.removeMFA(request.getUsername(), Base64.decodeBase64(request.getSessionCookie()), request.getSaltIndex(), request.getToken(), request.getType(), Base64.decodeBase64(request.getSignature()));
    }

    @Secured({Role.ADMIN})
    @Path(PestoRESTEndpoints.START_REFRESH)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Boolean startRefresh() {
        logger.info("idp/"+PestoRESTEndpoints.START_REFRESH);
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return idp.startRefresh();
    }

    @Secured({Role.SERVER})
    @Path(PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addPartialSignature(AddPartialSignatureRequest request) {
        logger.info("idp/"+PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        idp.addPartialServerSignature(request.getSsid(), Base64.decodeBase64(request.getString()));
        logger.info("idp/"+PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE+" completed");
    }

    @Secured({Role.SERVER})
    @Path(PestoRESTEndpoints.ADD_PARTIAL_MFA_SECRET)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addMFASecret(AddPartialMFARequest request) {
        logger.info("idp/"+PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        idp.addPartialMFASecret(request.getSsid(), request.getString(), request.getType());
    }

    @Secured({Role.SERVER})
    @Path(PestoRESTEndpoints.SET_KEY_SHARE)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void setKeyShare(SetKeyShare request) throws OperationFailedException {
        logger.info("idp/"+PestoRESTEndpoints.SET_KEY_SHARE);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        idp.setKeyShare(request.getId(), Base64.decodeBase64(request.getShares()));
    }

    @Secured({Role.SERVER})
    @Path(PestoRESTEndpoints.ADD_MASTER_SHARE)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addMasterShare(AddMasterShare request, @HeaderParam(value = "Authorization") String authorization) {
        logger.info("idp/"+PestoRESTEndpoints.ADD_MASTER_SHARE);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        String newCookie = idp.refreshCookie(authorization.substring(BEARERTOKENSTRING.length()));
        try {
            idp.addMasterShare(request.getNewSsid(), Base64.decodeBase64(request.getNewShare()));
        } catch(Exception e) {
            logger.info("addMasterShare failed.", e);
            return Response.serverError().header("Authorization", "Authorization "+newCookie).build();
        }
        return Response.noContent().header("Authorization", BEARERTOKENSTRING+newCookie).build();
    }

    @Path(PestoRESTEndpoints.FINISH_REGISTRATION)
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public String finishRegistration(FinishRegistrationRequest request) throws Exception {
        logger.info("idp/"+PestoRESTEndpoints.FINISH_REGISTRATION);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return Base64.encodeBase64String(idp.finishRegistration(request.getUsername(),
            Base64.decodeBase64(request.getSessionCookie()), (PublicKey) KeySerializer.deSerialize(request.getPublicKey()), Base64.decodeBase64(request.getSignature()),
            request.getSalt(), request.getIdProof()));
    }


    @Path(PestoRESTEndpoints.GET_PUBLIC_KEY)
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public String getCertificate() throws Exception {
        logger.info("idp/getcertificate");
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return PemUtil.encodeDerToPem(idp.getCertificate().getEncoded(), "CERTIFICATE");
    }

    @Path(PestoRESTEndpoints.ADD_ATTRIBUTES)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Boolean addAttributes(AddAttributesRequest request) throws Exception {
        logger.info("idp/"+PestoRESTEndpoints.ADD_ATTRIBUTES);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return idp.addAttributes(request.getUsername(), Base64.decodeBase64(request.getSessionCookie()), request.getSaltIndex(),
            Base64.decodeBase64(request.getSignature()), request.getIdProof());
    }

    @Path(PestoRESTEndpoints.GET_ALL_ATTRIBUTES)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public AttributeMap getAllAttributes(GetAllAttributesRequest request) throws Exception {
        logger.info("idp/"+PestoRESTEndpoints.GET_ALL_ATTRIBUTES);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return new AttributeMap(idp.getAllAttributes(request.getUsername(), Base64.decodeBase64(request.getSessionCookie()), request.getSaltIndex(),
            Base64.decodeBase64(request.getSignature())));
    }

    @Path(PestoRESTEndpoints.DELETE_ATTRIBUTES)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Boolean deleteAttributes(DeleteAttributesRequest request) throws Exception {
        logger.info("idp/"+PestoRESTEndpoints.DELETE_ATTRIBUTES);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return idp.deleteAttributes(request.getUsername(), Base64.decodeBase64(request.getSessionCookie()), request.getSaltIndex(),
            Base64.decodeBase64(request.getSignature()), request.getAttributes());
    }

    @Path(PestoRESTEndpoints.CHANGE_PASSWORD)
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public String changePassword(ChangePasswordRequest request) throws Exception {
        logger.info("idp/"+PestoRESTEndpoints.CHANGE_PASSWORD);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return Base64.encodeBase64String(idp.changePassword(request.getUsername(),
            Base64.decodeBase64(request.getSessionCookie()), (PublicKey)KeySerializer.deSerialize(request.getPublicKey()), Base64.decodeBase64(request.getOldSignature()),
            Base64.decodeBase64(request.getNewSignature()), request.getSalt()));
    }

    @Path(PestoRESTEndpoints.DELETE_ACCOUNT)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Boolean deleteAccount(DeleteAccountRequest request) throws Exception {
        logger.info("idp/"+PestoRESTEndpoints.DELETE_ACCOUNT);
        logger.trace(getJson(request));
        AbstractPestoIdP idp = (AbstractPestoIdP) context.getAttribute("idp");
        return idp.deleteAccount(request.getUsername(), Base64.decodeBase64(request.getSessionCookie()), request.getSaltIndex(),
            Base64.decodeBase64(request.getSignature()));
    }

    protected String getJson(Object obj) {
        try {
            return new ObjectMapper().writeValueAsString(obj);
        } catch(Exception e) {
            return "Could not convert "+obj+": "+e.getLocalizedMessage();
        }
    }
}
