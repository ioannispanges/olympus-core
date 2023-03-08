package eu.olympus.unit.server;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.NonExistingUserException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.AbstractPasswordIdP;
import eu.olympus.server.PasswordHandler;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;

public class TestAbstractPasswordIdP {

    private static final byte[] validCookie = Base64.decodeBase64("cookie".getBytes(StandardCharsets.UTF_8));

    @Test(expected = OperationFailedException.class)
    public void testChangePasswordFailingWithBadCookie() throws AuthenticationFailedException, UserCreationFailedException, OperationFailedException {
        AbstractPasswordIdP idp = new TestIdP(mockHandler());
        idp.changePassword(new UsernameAndPassword("user", "bad_password"), "password2", "cookie".getBytes());
    }

    @Test(expected = OperationFailedException.class)
    public void testRequestMFANullPointer() throws AuthenticationFailedException, NonExistingUserException, OperationFailedException {
        PasswordHandler passwordHandler = mockHandler();
        doThrow(NonExistingUserException.class).when(passwordHandler).requestMFASecret(anyString(), any());
        AbstractPasswordIdP idp = new TestIdP(passwordHandler);
        idp.requestMFA(new UsernameAndPassword("user", "password"), validCookie, null);
    }

    @Test(expected = OperationFailedException.class)
    public void testGetAllAttributesFailingWithBadCookie() throws AuthenticationFailedException, OperationFailedException {
        AbstractPasswordIdP idp = new TestIdP(mockHandler());
        idp.getAllAttributes("user", "badCookie".getBytes());
    }

    @Test(expected = OperationFailedException.class)
    public void testDeleteAttributeFailingWithBadCookie() throws AuthenticationFailedException, OperationFailedException {
        AbstractPasswordIdP idp = new TestIdP(mockHandler());
        idp.deleteAttribute("user", "badCookie".getBytes(), Arrays.asList("item"));
    }

    @Test(expected = UserCreationFailedException.class)
    public void testCreateUserAndAddAttributesUserAlreadyExists() throws UserCreationFailedException {
        AbstractPasswordIdP idp = new TestIdP(mockHandler());
        idp.createUserAndAddAttributes(new UsernameAndPassword("user", "password"), null);
    }

    @Test(expected = OperationFailedException.class)
    public void testDeleteAccountInvalidSession() throws AuthenticationFailedException, OperationFailedException {
        AbstractPasswordIdP idp = new TestIdP(mockHandler());
        idp.deleteAccount(new UsernameAndPassword("user", "password"), "invalidCookie".getBytes());
    }

    @Test(expected = OperationFailedException.class)
    public void testDeleteAccountInvalidPassword() throws AuthenticationFailedException, OperationFailedException {
        PasswordHandler passwordHandler = mockHandler();
        doReturn(false).when(passwordHandler).validateUsernameAndPassword(any());
        AbstractPasswordIdP idp = new TestIdP(passwordHandler);
        idp.deleteAccount(new UsernameAndPassword("user", "badPassword"), validCookie);
    }

    @Test(expected = OperationFailedException.class)
    public void testConfirmMFAInvalidSession() throws OperationFailedException {
        AbstractPasswordIdP idp = new TestIdP(mockHandler());
        idp.confirmMFA(new UsernameAndPassword("user", "password"), "invalidCookie".getBytes(), "token", null);
    }

    @Test(expected = OperationFailedException.class)
    public void testConfirmMFAInvalidPassword() throws OperationFailedException {
        PasswordHandler authHandler = mock(PasswordHandler.class);
        doReturn(false).when(authHandler).validateUsernameAndPassword(any());
        AbstractPasswordIdP idp = new TestIdP(authHandler);
        idp.confirmMFA(new UsernameAndPassword("user", "badPassword"), validCookie, "token", "type");
    }

    @Test(expected = OperationFailedException.class)
    public void testConfirmMFAInvalidMFAToken() throws OperationFailedException {
        PasswordHandler authHandler = mock(PasswordHandler.class);
        doReturn(true).when(authHandler).validateUsernameAndPassword(any());
        doReturn(false).when(authHandler).validateMFAToken(anyString(), anyString(), anyString());
        AbstractPasswordIdP idp = new TestIdP(authHandler);
        idp.confirmMFA(new UsernameAndPassword("user", "password"), validCookie, "token", "type");
    }

    @Test(expected = OperationFailedException.class)
    public void testRemoveMFAInvalidSession() throws OperationFailedException {
        AbstractPasswordIdP idp = new TestIdP(mockHandler());
        idp.removeMFA(new UsernameAndPassword("user", "password"), "invalidCookie".getBytes(), "token", null);
    }

    @Test(expected = OperationFailedException.class)
    public void testRemoveMFAInvalidPassword() throws OperationFailedException {
        PasswordHandler authHandler = mock(PasswordHandler.class);
        doReturn(false).when(authHandler).validateUsernameAndPassword(any());
        AbstractPasswordIdP idp = new TestIdP(authHandler);
        idp.removeMFA(new UsernameAndPassword("user", "badPassword"), validCookie, "token", "type");
    }

    @Test(expected = OperationFailedException.class)
    public void testRequestMFAInvalidSession() throws AuthenticationFailedException, OperationFailedException {
        AbstractPasswordIdP idp = new TestIdP(mockHandler());
        idp.requestMFA(new UsernameAndPassword("user", "badPassword"), new byte[256], "type");
    }

    @Test(expected = OperationFailedException.class)
    public void testRequestMFAInvalidPassword() throws AuthenticationFailedException, OperationFailedException {
        PasswordHandler authHandler = mock(PasswordHandler.class);
        doReturn(false).when(authHandler).validateUsernameAndPassword(any());
        AbstractPasswordIdP idp = new TestIdP(authHandler);
        idp.requestMFA(new UsernameAndPassword("user", "badPassword"), validCookie, "type");
    }

    private PasswordHandler mockHandler() {
        PasswordHandler authHandler = mock(PasswordHandler.class);
        doReturn(true).when(authHandler).validateUsernameAndPassword(any());
        return authHandler;
    }

    private static class TestIdP extends AbstractPasswordIdP {

        public TestIdP(PasswordHandler handler) {
            this.authenticationHandler = handler;
        }

        @Override
        public Certificate getCertificate() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public int getId() {
            // TODO Auto-generated method stub
            return 0;
        }

        @Override
        public String authenticate(String username, byte[] cookie, Policy policy) throws AuthenticationFailedException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public boolean validateSession(String cookie) {
            return cookie.equals("cookiQ==");
        }
    }
}
