package eu.olympus.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.Attribute;
import eu.olympus.model.Authorization;
import eu.olympus.model.KeyShares;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.interfaces.IdPRESTWrapper;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PESTOConfiguration;
import eu.olympus.server.interfaces.PestoBasedIdP;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.TokenGenerator;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryKeyDB;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;
import org.miracl.core.BLS12461.ECP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractPestoIdP implements PestoBasedIdP {

    private static final Logger logger = LoggerFactory.getLogger(PestoIdPImpl.class);
    private final ObjectMapper objectMapper;
    private final int rateLimit;
    private int id;
    protected ServerCryptoModule cryptoModule;
    protected PestoAuthenticationHandler authenticationHandler;
    protected TokenGenerator tokenGenerator;
    private Certificate cert;
    int nServers;

    public AbstractPestoIdP(PestoDatabase database, List<IdentityProver> identityProvers, Map<String, MFAAuthenticator> authenticators, ServerCryptoModule cryptoModule, int rateLimit) {
        this.rateLimit = rateLimit;
        this.cryptoModule = cryptoModule;
        this.objectMapper = new ObjectMapper();
        authenticationHandler = new PestoAuthenticationHandler(database, cryptoModule, new InMemoryKeyDB(), authenticators);
        tokenGenerator = new ThresholdRSAJWTTokenGenerator(cryptoModule);
        if (identityProvers != null) {
            for (IdentityProver idProver : identityProvers) {
                authenticationHandler.addIdentityProver(idProver);
            }
        }
    }

    public boolean setup(String ssid,
        PESTOConfiguration pestoConfiguration,
        List<? extends IdPRESTWrapper> servers) {
        try {

            KeyShares master = new KeyShares(pestoConfiguration.getKeyMaterial(), pestoConfiguration.getRsaBlindings(),
                pestoConfiguration.getOprfKey(),pestoConfiguration.getOprfBlindings());
            boolean res = authenticationHandler.setup(ssid, master, pestoConfiguration.getLocalKeyShare(), pestoConfiguration.getRemoteShares(), pestoConfiguration.getId(),
                pestoConfiguration.getAllowedTimeDifference(), pestoConfiguration.getWaitTime(), pestoConfiguration.getSessionLength(), servers);
            id = pestoConfiguration.getId();
            tokenGenerator.setup(pestoConfiguration);
            cert = pestoConfiguration.getCert();
            nServers=servers.size()+1;

            return res;
        } catch(Exception e) {
            return false;
        }
    }

    @Override
    public int getRateLimit(){
        return rateLimit;
    }

    @Override
    public void addSession(String cookie, Authorization authorization) {
        this.authenticationHandler.storeAuthorization(cookie, authorization);;
    }

    @Override
    public void validateSession(String cookie, List<Role> requestedRole) throws AuthenticationFailedException {
        this.authenticationHandler.validateSession(cookie, requestedRole);
    }

    @Override
    public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType) throws UserCreationFailedException, AuthenticationFailedException, OperationFailedException {
        return authenticationHandler.performOPRF(ssid, username, x, mfaToken, mfaType);
    }

    public boolean startRefresh() {
        return authenticationHandler.startRefresh();
    }

    public void addMasterShare(String newSsid, byte[] share) {
        authenticationHandler.addMasterShare(newSsid, share);
    }

    public void setKeyShare(int id, byte[] newShare) throws OperationFailedException {
        authenticationHandler.setKeyShare(id, newShare);
    }

    public void addPartialServerSignature(String ssid, byte[] signature) {
        authenticationHandler.addPartialServerSignature(ssid, signature);
    }

    public void addPartialMFASecret(String ssid, String secret, String type) {
        authenticationHandler.addPartialMFASecret(ssid, secret, type);
    }

    @Override
    public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) throws UserCreationFailedException {
        try {
            validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
            return authenticationHandler.finishRegistration(username, cookie, publicKey, signature, salt, idProof);
        } catch (AuthenticationFailedException | UserCreationFailedException | OperationFailedException e){
            throw new UserCreationFailedException("Failed to finish registration",e);
        }
    }

    @Override
    public Certificate getCertificate() {
        return cert;
    }

    @Override
    public int getId() {
        return id;
    }

    @Override
    public boolean addAttributes(String username, byte[] cookie, long salt, byte[] signature, String idProof) throws OperationFailedException {
        try {
            validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
            boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.ADD_ATTRIBUTES+idProof);
            if(!authenticated) {
                logger.info("addAttributes: Failed to authenticate user "+username);
                return false;
            }
            this.authenticationHandler.addAttributes(username, idProof);
            return true;
        } catch(AuthenticationFailedException e) {
            logger.info("addAttributes: Failed to add attributes "+username, e);
            return false;
        }
    }

    @Override
    public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) throws AuthenticationFailedException, OperationFailedException {
        validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
        boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.GET_ALL_ATTRIBUTES);
        if(authenticated) {
            Map<String, Attribute> assertions = authenticationHandler
                .getAllAssertions(username);
            return assertions;
        }
        throw new AuthenticationFailedException("Failed : User failed authentication");
    }

    @Override
    public boolean deleteAttributes(String username, byte[] cookie, long salt, byte[] signature, List<String> attributes) throws AuthenticationFailedException, OperationFailedException {
        validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
        try {
            boolean authenticated = authenticationHandler
                .validateUsernameAndSignature(username, cookie, salt, signature,
                    CommonRESTEndpoints.DELETE_ATTRIBUTES + objectMapper
                        .writeValueAsString(attributes));
            if (!authenticated) {
                logger.info("deleteAttributes: Failed to authenticate user " + username);
                return false;
            }
            authenticationHandler.deleteAttributes(username, attributes);
            return true;
        } catch (JsonProcessingException e){
            throw new OperationFailedException("Failed to parse attributes", e);
        }
    }

    @Override
    public boolean deleteAccount(String username, byte[] cookie, long salt, byte[] signature) throws AuthenticationFailedException, OperationFailedException {
        validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
        boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.DELETE_ACCOUNT);
        if(!authenticated) {
            logger.info("deleteAccount: Failed to authenticate user "+username);
            return false;
        }
        authenticationHandler.deleteAccount(username);
        return true;
    }

    @Override
    public byte[] changePassword(String username, byte[] cookie, PublicKey publicKey, byte[] oldSignature, byte[] newSignature, long salt) throws Exception {
        validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
        return authenticationHandler.changePassword(username, cookie, publicKey, oldSignature, newSignature, salt);
    }

    @Override
    public String requestMFA(String username, byte[] cookie, long salt, String type, byte[] signature) throws OperationFailedException {
        try {
            validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
            boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.REQUEST_MFA  + type);
            if(authenticated) {
                return authenticationHandler.requestMFASecret(username, type);
            }
            throw new OperationFailedException("Authentication failed");
        }catch (AuthenticationFailedException | OperationFailedException e) {
            throw new OperationFailedException("Failed to request MFA",e);
        }
    }

    @Override
    public boolean confirmMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) throws AuthenticationFailedException, OperationFailedException {
        validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
        boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.CONFIRM_MFA  + type);
        if(!authenticated) {
            logger.info("confirmMFA: Failed to authenticate user "+username);
            return false;
        }
        if(!authenticationHandler.activateMFA(username, token, type)){
            logger.info("confirmMFA: Failed to activate MFA");
            return false;
        }
        return true;
    }

    @Override
    public boolean removeMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) throws AuthenticationFailedException, OperationFailedException {
       	validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));

        boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.REMOVE_MFA  + type);
        if(!authenticated) {
            logger.info("removeMFA: Failed to authenticate user "+username);
            return false;
        }
        if(!authenticationHandler.deleteMFA(username, token, type)){
            logger.info("removeMFA: Failed to remove MFA");
            return false;
        } 
        return true;
    }

    @Override
    public String refreshCookie(String cookie) {
        return authenticationHandler.refreshCookie(cookie);
    }

}
