package eu.olympus.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.SigningFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.server.interfaces.PestoBasedIdP;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.rest.PestoRESTEndpoints;
import eu.olympus.util.KeySerializer;
import eu.olympus.util.Util;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.CONFIG_BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;
import org.miracl.core.BLS12461.ROM;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class PestoAuthClient implements UserClient {

    private static Logger logger = LoggerFactory.getLogger(PestoAuthClient.class);

    protected ClientCryptoModule cryptoModule;
    protected Map<Integer, PestoBasedIdP> servers;
    protected ExecutorService executorService;
    protected Map<Integer, byte[]> cookies;
    protected Map<Integer, Long> sessionStartedTimes;
    protected long lastUsedSalt;
    public static final long sessionLength = 6000000;
    private static final String NO_MFA = "NONE";
    private KeyPair signingKeys = null;
    private final ObjectMapper objectMapper;
    protected String savedUsername = null;


    public PestoAuthClient(List<? extends PestoBasedIdP> servers, ClientCryptoModule cryptoModule) {
        this.objectMapper = new ObjectMapper();
        this.servers = new HashMap<>();
        this.cookies = new HashMap<>();
        this.sessionStartedTimes = new HashMap<>();
        this.cryptoModule = cryptoModule;
        Integer i = 0;
        for (PestoBasedIdP server : servers) {
            this.servers.put(i, server);
            sessionStartedTimes.put(i, 0l);
            i++;
        }
        this.executorService = Executors.newFixedThreadPool(servers.size());
    }

    protected long getFreshSalt() {
        long currentTime = System.currentTimeMillis();
        if (currentTime <= lastUsedSalt) {
            try {
                Thread.sleep(1 + lastUsedSalt - currentTime);
                lastUsedSalt = System.currentTimeMillis();
            } catch (InterruptedException e) {
                // In case there is a thread interruption just try again
                return getFreshSalt();
            }
        } else {
            lastUsedSalt = currentTime;
        }
        return lastUsedSalt;
    }

    @Override
    public void createUser(String username, String password) throws UserCreationFailedException {
        createUserAndAddAttributes(username, password, null);
    }

    @Override
    public void addAttributes(IdentityProof identityProof) throws OperationFailedException {
        checkActiveSession();
        performAddAttributes(getSavedUsername(), identityProof);
    }

    @Override
    public void addAttributes(String username, String password, IdentityProof identityProof, String token, String type) throws OperationFailedException {
        ensureActiveSession(username, password, token, type);
        performAddAttributes(username, identityProof);
    }

    private void performAddAttributes(String username, IdentityProof identityProof) throws OperationFailedException {
        try {
            long salt = getFreshSalt();
            List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();
            byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.ADD_ATTRIBUTES + identityProof.getStringRepresentation());
            for (PestoBasedIdP server : servers.values()) {
                authentications
                    .add(executorService.submit(() -> server.addAttributes(username, cookies.get(server.getId()), salt, signature[server.getId()], identityProof.getStringRepresentation())));
            }
            for (Future<Boolean> future : authentications) {
                if (!future.get()) {
                    throw new AuthenticationFailedException("vIdP failed to prove identity");
                }
            }
            updateCurrentSessionTimes();
        } catch (Exception e) {
            signingKeys = null;
            throw new OperationFailedException("Failed to add attributes", e);
        }
    }

    @Override
    public void createUserAndAddAttributes(String username, String password, IdentityProof identityProof) throws UserCreationFailedException {
        try {
            final String idProof = identityProof != null ? identityProof.getStringRepresentation() : "";
            ensureActiveSession(username, password, null, NO_MFA);
            long salt = getFreshSalt();
            byte[][] signatures = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES + idProof);
            int approvedCount = 0;
            List<Future<byte[]>> futures = new ArrayList<Future<byte[]>>();
            for (PestoBasedIdP server : servers.values()) {
                futures.add(executorService.submit(() -> server.finishRegistration(username, cookies.get(server.getId()), signingKeys.getPublic(), signatures[server.getId()], salt, idProof)));
            }
            byte[][] responseSignatures = new byte[servers.size()][];
            int it = 0;
            for (Future<byte[]> bytes : futures) {
                responseSignatures[it] = bytes.get();
                it++;
            }
            for (int i = 0; i < servers.size(); i++) {
                //Verify combined signature
                PublicKey combKey = cryptoModule.getStandardRSAkey();
                byte[] input = (KeySerializer.serialize(signingKeys.getPublic()).getBytes());
                if (cryptoModule.verifySignature(combKey, input, responseSignatures[i])) {
                    approvedCount++;
                }
            }
            if (approvedCount != servers.size()) {
                throw new UserCreationFailedException("Not all IdPs finished registration");
            }
            savedUsername = username;
        } catch (Exception e) {
            signingKeys = null;
            throw new UserCreationFailedException("Failed to create user and add attributes", e);
        }
    }

    @Override
    public Map<String, Attribute> getAllAttributes() throws OperationFailedException {
        checkActiveSession();
        return performGetAllAttributes(getSavedUsername());
    }

    @Override
    public Map<String, Attribute> getAllAttributes(String username, String password, String token, String type) throws OperationFailedException {
        ensureActiveSession(username, password, token, type);
        return performGetAllAttributes(username);
    }

    private Map<String, Attribute> performGetAllAttributes(String username) throws OperationFailedException {
        try {
            long salt = getFreshSalt();
            byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.GET_ALL_ATTRIBUTES);

            List<Future<Map<String, Attribute>>> authentications = new ArrayList<Future<Map<String, Attribute>>>();

            for (PestoBasedIdP server : servers.values()) {
                authentications.add(executorService.submit(() -> server.getAllAttributes(username, cookies.get(server.getId()), salt, signature[server.getId()])));
            }
            List<Map<String, Attribute>> maps = new ArrayList<>();
            for (Future<Map<String, Attribute>> future : authentications) {
                maps.add(future.get());
            }
            if (!Util.verifyIdenticalMaps(maps)) {
                throw new AuthenticationFailedException("Differing output from vIdP");
            }
            updateCurrentSessionTimes();
            return maps.get(0);
        } catch (Exception e) {
            signingKeys = null;
            throw new OperationFailedException("Failed to get attributes", e);
        }
    }

    @Override
    public void deleteAttributes(List<String> attributes) throws OperationFailedException {
        checkActiveSession();
        performDeleteAttributes(getSavedUsername(), attributes);
    }

    @Override
    public void deleteAttributes(String username, String password, List<String> attributes, String token, String type) throws OperationFailedException {
        ensureActiveSession(username, password, token, type);
        performDeleteAttributes(username, attributes);
    }

    private void performDeleteAttributes(String username, List<String> attributes) throws OperationFailedException {
        try {
            long salt = getFreshSalt();
            byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.DELETE_ATTRIBUTES + objectMapper.writeValueAsString(attributes));

            List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();

            for (PestoBasedIdP server : servers.values()) {
                authentications.add(executorService.submit(() -> server.deleteAttributes(username, cookies.get(server.getId()), salt, signature[server.getId()], attributes)));
            }
            for (Future<Boolean> future : authentications) {
                if (!future.get()) {
                    throw new AuthenticationFailedException("vIdP failed to delete attribute");
                }
            }
            updateCurrentSessionTimes();
        } catch (Exception e) {
            signingKeys = null;
            throw new OperationFailedException("Failed to delete attributes", e);
        }
    }

    /**
     * Deletes the users account on the vIdP
     *
     * @param password The users password
     * @throws OperationFailedException
     */
    @Override
    public void deleteAccount(String username, String password, String token, String type) throws OperationFailedException {
        try {
            getFreshKeys(username, password, token, type);
            long salt = getFreshSalt();
            byte[][] signature = getSignedNonceAndUid(username, salt, PestoRESTEndpoints.DELETE_ACCOUNT);

            List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();

            for (PestoBasedIdP server : servers.values()) {
                authentications.add(executorService.submit(() -> server.deleteAccount(username, cookies.get(server.getId()), salt, signature[server.getId()])));
            }
            for (Future<Boolean> future : authentications) {
                if (!future.get()) {
                    throw new AuthenticationFailedException("Server failed to delete account");
                }
            }
            updateCurrentSessionTimes();
        } catch (Exception e) {
            signingKeys = null;
            throw new OperationFailedException("Failed to delete account", e);
        }
    }

    /**
     * Changes the users password, without changing other stored attributed on the vIdP. This requires the user to enter her old password, her new password and using a fresh MFA token (creating a new
     * session cookie under the new key).
     *
     * @param oldPassword The users existing password
     * @param newPassword The password to use in the future
     * @param token       The MFA token
     * @param type        The type of MFA token used
     */
    @Override
    public void changePassword(String username, String oldPassword, String newPassword, String token, String type) throws OperationFailedException {
        try {
            getFreshKeys(username, oldPassword, token, type);
            byte[] newPw = newPassword.getBytes(Charsets.UTF_8);
            long salt = getFreshSalt();
            KeyPair newKeyPair = performOPRF(username, newPw, String.valueOf(salt), token, type);
            byte[] nonce = this.cryptoModule.constructNonce(username, salt);
            List<byte[]> message = new ArrayList<byte[]>();
            message.add(username.getBytes(Charsets.UTF_8));
            message.add(nonce);
            message.add(newKeyPair.getPublic().getEncoded());
            message.add(CommonRESTEndpoints.CHANGE_PASSWORD.getBytes(Charsets.UTF_8));
            int approvedCount = 0;
            List<Future<byte[]>> futures = new ArrayList<Future<byte[]>>();
            for (PestoBasedIdP server : servers.values()) {
                List<byte[]> currentMessage = new ArrayList<>();
                currentMessage.addAll(message);
                currentMessage.add(cookies.get(server.getId()));
                byte[] newSignature = this.cryptoModule.signECDSA(newKeyPair.getPrivate(), currentMessage);
                byte[] oldSignature = this.cryptoModule.signECDSA(signingKeys.getPrivate(), newSignature);
                futures.add(executorService.submit(() -> server.changePassword(username, cookies.get(server.getId()), newKeyPair.getPublic(), oldSignature, newSignature, salt)));
            }
            byte[][] signatures = new byte[servers.size()][];
            int it = 0;
            for (Future<byte[]> bytes : futures) {
                signatures[it] = bytes.get();
                it++;
            }
            for (int i = 0; i < servers.size(); i++) {
                //Verify combined signature
                PublicKey combKey = cryptoModule.getStandardRSAkey();
                byte[] input = (KeySerializer.serialize(newKeyPair.getPublic()).getBytes());
                if (cryptoModule.verifySignature(combKey, input, signatures[i])) {
                    approvedCount++;
                }
            }
            if (approvedCount != servers.size()) {
                throw new UserCreationFailedException("Not all servers finished registration");
            }
            signingKeys = newKeyPair;
        } catch (Exception e) {
            signingKeys = null;
            throw new OperationFailedException("Failed to change password", e);
        }
    }

    @Override
    public String requestMFAChallenge(String username, String password, String type) throws OperationFailedException {
        try {
            ensureActiveSession(username, password, null, "NO_MFA");
            long salt = getFreshSalt();
            byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.REQUEST_MFA + type);

            List<Future<String>> futures = new ArrayList<Future<String>>();

            for (PestoBasedIdP server : servers.values()) {
                futures.add(executorService.submit(() -> server.requestMFA(username, cookies.get(server.getId()), salt, type, signature[server.getId()])));
            }
            List<String> challenges = new ArrayList<String>();
            for (Future<String> future : futures) {
                challenges.add(future.get());
            }
            if (!Util.verifyIdenticalStrings(challenges)) {
                throw new AuthenticationFailedException("Differing output from vIdP");
            }
            updateCurrentSessionTimes();
            return challenges.get(0);
        } catch (Exception e) {
            signingKeys = null;
            throw new OperationFailedException("Failed to request MFA", e);
        }
    }

    @Override
    public void confirmMFA(String username, String password, String token, String type) throws OperationFailedException {
        try {
            getFreshKeys(username, password, null, "NO_MFA");
            long salt = getFreshSalt();
            byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.CONFIRM_MFA + type);

            List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();
            for (PestoBasedIdP server : servers.values()) {
                authentications.add(executorService.submit(() -> server.confirmMFA(username, cookies.get(server.getId()), salt, token, type, signature[server.getId()])));
            }
            for (Future<Boolean> future : authentications) {
                if (!future.get()) {
                    throw new AuthenticationFailedException("vIdP failed to confirm MFA token");
                }
            }
        } catch (Exception e) {
            signingKeys = null;
            throw new OperationFailedException("Failed to confirm MFA", e);
        }
    }

    @Override
    public void removeMFA(String username, String password, String token, String type) throws OperationFailedException {
        try {
            getFreshKeys(username, password, token, type);
            long salt = getFreshSalt();
            List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();
            byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.REMOVE_MFA + type);
            for (PestoBasedIdP server : servers.values()) {
                authentications.add(executorService.submit(() -> server.removeMFA(username, cookies.get(server.getId()), salt, token, type, signature[server.getId()])));
            }
            for (Future<Boolean> future : authentications) {
                if (!future.get()) {
                    throw new AuthenticationFailedException("Server failed to remove MFA token");
                }
            }
            updateCurrentSessionTimes();
        } catch (Exception e) {
            signingKeys = null;
            logger.info("PestoAuthClient: Failed to remove MFA: ", e);
            throw new OperationFailedException("Failed to remove MFA", e);
        }
    }

    protected byte[][] getSignedNonceAndUid(String username, long salt, String operation) throws SigningFailedException {
        byte[] nonce = this.cryptoModule.constructNonce(username, salt);
        return signRequest(signingKeys.getPrivate(), username.getBytes(Charsets.UTF_8), nonce, operation.getBytes(StandardCharsets.UTF_8));
    }

    protected KeyPair performOPRF(String username, byte[] pw, String ssid, String mfaToken, String mfaType) throws OperationFailedException {
        try {
            BIG r = cryptoModule.getRandomNumber();
            ECP xMark = cryptoModule.hashAndMultiply(r, pw);

            Map<Integer, Future<OPRFResponse>> futures = new HashMap<>();
            for (PestoBasedIdP server : servers.values()) {
                futures.put(server.getId(), executorService.submit(() -> server.performOPRF(ssid, username, xMark, mfaToken, mfaType)));
            }
            List<FP12> responses = new ArrayList<>();
            for (int counter : futures.keySet()) {
                OPRFResponse resp = futures.get(counter).get();
                if (!ssid.equals(resp.getSsid())) {
                    throw new UserCreationFailedException("Invalid server response");
                }
                responses.add(resp.getY());
                cookies.put(counter, Base64.decodeBase64(resp.getSessionCookie()));
            }

            byte[] privateBytes = processReplies(responses, r, username.getBytes(Charsets.UTF_8), pw);
            KeyPair keys = cryptoModule.generateKeysFromBytes(privateBytes);
            updateCurrentSessionTimes();
            return keys;
        } catch (Exception e) {
            logger.info("PestoAuthClient: Failed to perform OPRF: ", e);
            throw new OperationFailedException("Failed to perform OPRF", e);
        }
    }

    @Override
    public void clearSession() {
        this.cookies.clear();
        this.sessionStartedTimes.clear();
        for (int i = 0; i < servers.size(); i++) {
            sessionStartedTimes.put(i, 0l);
        }
        signingKeys = null;
        savedUsername = null;
    }

    public String getSavedUsername() throws OperationFailedException {
        if (savedUsername != null) {
            return savedUsername;
        }
        throw new OperationFailedException("No user is logged in");
    }

    protected void setSavedUsername(String savedUsername) {
        this.savedUsername = savedUsername;
    }

    protected void ensureActiveSession(String username, String password, String token, String type) throws OperationFailedException {
        long largestSessionTime = sessionStartedTimes.values().stream().mapToLong(v -> v).max().getAsLong();
        if (System.currentTimeMillis() >= (largestSessionTime + sessionLength) || signingKeys == null) {
            getFreshKeys(username, password, token, type);
        }
    }

    protected void checkActiveSession() throws OperationFailedException {
        long largestSessionTime = sessionStartedTimes.values().stream().mapToLong(v -> v).max().getAsLong();
        if (System.currentTimeMillis() >= (largestSessionTime + sessionLength) || signingKeys == null) {
            throw new OperationFailedException("User has no active session");
        }
    }

    protected void getFreshKeys(String username, String password, String token, String type) throws OperationFailedException {
        try {
            long salt = getFreshSalt();
            signingKeys = performOPRF(username, password.getBytes(StandardCharsets.UTF_8), String.valueOf(salt), token, type);
        } catch (OperationFailedException e) {
            throw new OperationFailedException("Failed to retrieve signing keys", e);
        }
    }

    protected void updateCurrentSessionTimes() {
        for (PestoBasedIdP server : servers.values()) {
            sessionStartedTimes.put(server.getId(), System.currentTimeMillis());
        }
    }

    protected byte[] processReplies(List<FP12> responses, BIG r, byte[] username, byte[] password) {
        List<byte[]> toHash = new ArrayList<byte[]>();
        toHash.add(password);
        toHash.add(username);

        BIG rModInv = new BIG();
        rModInv.copy(r);
        rModInv.invmodp(new BIG(ROM.CURVE_Order));
        FP12 yMark = new FP12();
        yMark.one();
        for (FP12 current : responses) {
            yMark.mul(current);
        }
        FP12 receivedY = yMark.pow(rModInv);
        byte[] rawBytes = new byte[12 * CONFIG_BIG.MODBYTES];
        receivedY.toBytes(rawBytes);
        toHash.add(rawBytes);

        return cryptoModule.hashList(toHash);
    }

    protected byte[][] signRequest(PrivateKey privateKey, byte[] uid, byte[] nonce, byte[] operation) throws SigningFailedException {
        byte[][] output = new byte[cookies.size()][];
        for (int i = 0; i < cookies.size(); i++) {
            List<byte[]> listToSign = Arrays.asList(nonce, uid, operation, cookies.get(i));
            output[i] = cryptoModule.signECDSA(privateKey, listToSign);
        }
        return output;
    }
}
