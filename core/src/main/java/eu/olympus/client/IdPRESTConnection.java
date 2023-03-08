package eu.olympus.client;

import eu.olympus.model.Attribute;
import eu.olympus.model.Authorization;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.AddAttributesRequest;
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
import eu.olympus.server.interfaces.PestoBasedIdP;
import eu.olympus.server.rest.PestoRESTEndpoints;
import eu.olympus.server.rest.Role;
import eu.olympus.util.KeySerializer;
import eu.olympus.util.keyManagement.CertificateUtil;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import org.apache.commons.codec.binary.Base64;
import org.miracl.core.BLS12461.CONFIG_BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class IdPRESTConnection implements PestoBasedIdP {


    private final int rateLimit;
    protected String host;
    protected Client client;
    private String authentication;
    private int id;
    private static Logger logger = LoggerFactory.getLogger(PestoIdPRESTConnection.class);

    /**
     * Create a new rest connections to an IdP
     * @param url includes port, eg. http://127.0.0.1:9090
     */
    public IdPRESTConnection(String url, String accessToken, int id, int rateLimit) {
        this.rateLimit = rateLimit;
        this.host = url+"/idp/";
        this.client = ClientBuilder.newClient();
        this.authentication = "Bearer "+accessToken;
        this.id = id;
    }

    @Override
    public int getRateLimit() {
        return rateLimit;
    }

    @Override
    public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType) {
        byte[] rawBytes = new byte[CONFIG_BIG.MODBYTES*12];
        x.toBytes(rawBytes, false);
        OPRFRequest request = new OPRFRequest(ssid, username, Base64.encodeBase64String(rawBytes));
        request.setMfaToken(mfaToken);
        request.setMfaType(mfaType);
        OPRFRestResponse response = client.target(host+ PestoRESTEndpoints.REQUEST_OPRF).request().post(Entity.entity(request, MediaType.APPLICATION_JSON), OPRFRestResponse.class);
        FP12 y = OPRFRestResponse.getAsElement(Base64.decodeBase64(response.getElement()));
        OPRFResponse resp = new OPRFResponse(y, response.getSsid(), response.getSessionCookie());
        return resp;
    }

    @Override
    public boolean startRefresh() {
        try {
            return client.target(host+PestoRESTEndpoints.START_REFRESH).request()
                .header("Authorization", authentication)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON), Boolean.class);
        } catch(NotAuthorizedException e) {
            logger.info("Start refresh failed", e);
            return false;
        }
    }

    @Override
    public void addMasterShare(String newSsid, byte[] share) {
        throw new UnsupportedOperationException("Not supported for clients");
    }

    @Override
    public void setKeyShare(int id, byte[] newShares) {
        throw new UnsupportedOperationException("Not supported for clients");
    }

    @Override
    public void addPartialServerSignature(String ssid, byte[] signature) {
        throw new UnsupportedOperationException("Not supported for clients");
    }

    @Override
    public void addPartialMFASecret(String ssid, String secret, String type) {
        throw new UnsupportedOperationException("Not supported for clients");
    }

    @Override
    public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) throws UserCreationFailedException {
        try{
            FinishRegistrationRequest request = new FinishRegistrationRequest(username, Base64.encodeBase64String(
                cookie), KeySerializer.serialize(publicKey), Base64.encodeBase64String(signature), salt, idProof);
            String response = client.target(host+PestoRESTEndpoints.FINISH_REGISTRATION).request().post(Entity.entity(request, MediaType.APPLICATION_JSON), String.class);
            return Base64.decodeBase64(response);
        } catch (RuntimeException e){
            throw new UserCreationFailedException("Failed to finish registration",e);
        }

    }

    @Override
    public boolean addAttributes(String username, byte[] cookie, long salt, byte[] signature, String idProof) {
        AddAttributesRequest signatureAndProof = new AddAttributesRequest(username, Base64.encodeBase64String(
            cookie), salt, Base64.encodeBase64String(signature), idProof);
        return client.target(host+PestoRESTEndpoints.ADD_ATTRIBUTES).request()
            .post(Entity.entity(signatureAndProof, MediaType.APPLICATION_JSON), Boolean.class);
    }

    @Override
    public Certificate getCertificate() {
        try {
            String output = client.target(host+PestoRESTEndpoints.GET_PUBLIC_KEY).request().get(String.class);
            logger.info("Getting certificate from: " + host+PestoRESTEndpoints.GET_PUBLIC_KEY);
            return CertificateUtil.decodePemCert(output);
        } catch(Exception e) {
            logger.error("IDP could not provide certificate");
            throw new RuntimeException(e);
        }
    }

    @Override
    public int getId() {
        return id;
    }

    @Override
    public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) {
        GetAllAttributesRequest data = new GetAllAttributesRequest(username, Base64.encodeBase64String(
            cookie), salt, Base64.encodeBase64String(signature));
        AttributeMap attributes = client.target(host+PestoRESTEndpoints.GET_ALL_ATTRIBUTES).request()
            .post(Entity.entity(data, MediaType.APPLICATION_JSON), AttributeMap.class);
        return attributes.getAttributes();
    }

    @Override
    public boolean deleteAttributes(String username, byte[] cookie, long salt, byte[] signature, List<String> attributes) {
        DeleteAttributesRequest data = new DeleteAttributesRequest(username, Base64.encodeBase64String(
            cookie), salt, Base64.encodeBase64String(signature), attributes);
        return client.target(host+PestoRESTEndpoints.DELETE_ATTRIBUTES).request()
            .post(Entity.entity(data, MediaType.APPLICATION_JSON), Boolean.class);
    }

    @Override
    public boolean deleteAccount(String username, byte[] cookie, long salt, byte[] signature) {
        DeleteAccountRequest data = new DeleteAccountRequest(username, Base64.encodeBase64String(cookie), salt, Base64.encodeBase64String(signature));
        return client.target(host+PestoRESTEndpoints.DELETE_ACCOUNT).request()
            .post(Entity.entity(data, MediaType.APPLICATION_JSON), Boolean.class);
    }

    @Override
    public byte[] changePassword(String username, byte[] cookie, PublicKey publicKey, byte[] oldSignature, byte[] newSignature, long salt) throws OperationFailedException {
        ChangePasswordRequest request = new ChangePasswordRequest(username, Base64.encodeBase64String(
            cookie), KeySerializer.serialize(publicKey), Base64.encodeBase64String(oldSignature), Base64.encodeBase64String(newSignature), salt);
        String response = client.target(host+PestoRESTEndpoints.CHANGE_PASSWORD).request()
            .post(Entity.entity(request, MediaType.APPLICATION_JSON), String.class);
        return Base64.decodeBase64(response);
    }

    @Override
    public boolean confirmMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) {
        SecondFactorConfirmation message = new SecondFactorConfirmation(username, Base64.encodeBase64String(
            cookie), salt, Base64.encodeBase64String(signature), token, type);
        return client.target(host+PestoRESTEndpoints.CONFIRM_MFA).request().post(Entity.entity(message, MediaType.APPLICATION_JSON), Boolean.class);
    }

    @Override
    public String requestMFA(String username, byte[] cookie, long salt, String type, byte[] signature) {
        SecondFactorRequest message = new SecondFactorRequest(username, Base64.encodeBase64String(
            cookie), salt, Base64.encodeBase64String(signature), type);
        return client.target(host+PestoRESTEndpoints.REQUEST_MFA).request().post(Entity.entity(message, MediaType.APPLICATION_JSON), String.class);
    }

    @Override
    public boolean removeMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) {
        SecondFactorDelete message = new SecondFactorDelete(username, Base64.encodeBase64String(
            cookie), salt, Base64.encodeBase64String(signature), token, type);
        return client.target(host+PestoRESTEndpoints.REMOVE_MFA).request().post(Entity.entity(message, MediaType.APPLICATION_JSON), Boolean.class);
    }

    @Override
    public void addSession(String cookie, Authorization authorization) {
        throw new UnsupportedOperationException("Not supported for clients");
    }

    @Override
    public void validateSession(String cookie, List<Role> requestedRoles) throws AuthenticationFailedException {
        throw new UnsupportedOperationException("Not supported for clients");
    }

    @Override
    public String refreshCookie(String cookie) {
        throw new UnsupportedOperationException("Not supported for clients");
    }
}
