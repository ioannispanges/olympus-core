package eu.olympus.server.interfaces;

import eu.olympus.model.Attribute;
import eu.olympus.model.Authorization;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.rest.Role;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import org.miracl.core.BLS12461.ECP;

public interface PestoBasedIdP extends IdPRESTWrapper{

    /**
     * The maximum number of operations the IDP will handle.
     */
    public int getRateLimit();

    public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType) throws UserCreationFailedException, AuthenticationFailedException, OperationFailedException;

    public boolean startRefresh();

    public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) throws Exception;

    public boolean addAttributes(String username, byte[] cookie, long salt, byte[] signature, String idProof) throws AuthenticationFailedException, OperationFailedException;

    public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) throws AuthenticationFailedException, OperationFailedException;

    public boolean deleteAttributes(String username, byte[] cookie, long salt, byte[] signature, List<String> attributes) throws AuthenticationFailedException, OperationFailedException;

    public boolean deleteAccount(String username, byte[] cookie, long salt, byte[] signature) throws AuthenticationFailedException, OperationFailedException;

    public byte[] changePassword(String username, byte[] cookie, PublicKey publicKey, byte[] oldSignature, byte[] newSignature, long salt) throws Exception;

    public boolean confirmMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) throws AuthenticationFailedException, OperationFailedException;

    public String requestMFA(String username, byte[] cookie, long salt, String type, byte[] signature) throws AuthenticationFailedException, OperationFailedException;

    /**
     * Removes a MFA type. The MFA MUST exist and be active for the removal to be successful.
     * Furthermore, this can only be done after MFA authentication and requires a new MFA token be verified.
     * Returns true if successful and otherwise false. In case false is returned, the MFA remains active.
     * @param username The username for which the MFA must be removed
     * @param cookie The active cookie for the given server
     * @param salt The nonce used in the signature that authenticates the user's password
     * @param token A MFA token valid for the MFA to be removed
     * @param type The type of MFA to remove
     * @param signature A signature on the request
     */
    public boolean removeMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) throws AuthenticationFailedException, OperationFailedException;

    /**
     * Add a session cookie to storage. This is an administrative method, used to manually
     * grant access to other partial-IdP instances during configuration.
     * @param cookie The cookie to add
     * @param authorization The attached Authorization
     */
    public void addSession(String cookie, Authorization authorization);

    /**
     * Verifies that AT LEAST ONE of the requestedRoles are granted to the user with the given cookie.
     * @param cookie
     * @param requestedRoles
     * @throws AuthenticationFailedException
     */
    public void validateSession(String cookie, List<Role> requestedRoles) throws AuthenticationFailedException;

    /**
     * Replaces an existing session with a fresh generated one. Roles are transfered from the
     * existing cookie.
     * @param cookie The existing cookie
     * @return A new cookie
     */
    public String refreshCookie(String cookie);
}
