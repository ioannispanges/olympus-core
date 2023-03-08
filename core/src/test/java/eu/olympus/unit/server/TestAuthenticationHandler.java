package eu.olympus.unit.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import eu.olympus.model.Attribute;
import eu.olympus.model.Authorization;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.AuthenticationHandler;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.UserAuthorizationDatabase;
import eu.olympus.server.storage.InMemoryKeyDB;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.stubbing.Answer;

public class TestAuthenticationHandler {

    ArgumentCaptor<String> usernameCaptor;
    ArgumentCaptor<String> attributeCaptor;

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    @Test
    public void testAddAttributes() throws Exception {
        PestoDatabase db = mockDb();
        doReturn(true).when(db).hasUser(anyString());

        IdentityProver idProver = mockIdProver();
        Answer<Boolean> isValidAnswer = invocationOnMock -> {
            String idProof = invocationOnMock.getArgument(0);
            return "idProof".equals(idProof);
        };
        doAnswer(isValidAnswer).when(idProver).isValid(anyString(), anyString());

        AuthenticationHandler authHandler = new AuthenticationHandler(db, new InMemoryKeyDB(), new HashMap<>(), null) {

            @Override
            public String requestMFASecret(String username, String type) throws Exception {
                // TODO Auto-generated method stub
                return null;
            }

            @Override
            public String generateSessionCookie(String username) {
                // TODO Auto-genermated method stub
                return null;
            }
        };
        authHandler.addIdentityProver(idProver);
        authHandler.addAttributes("username", "idProof");
        verify(idProver, times(1)).isValid(anyString(), anyString());
        verify(idProver, times(1)).addAttributes(anyString(), anyString());
    }

    @Test(expected = OperationFailedException.class)
    public void testAddAttributesNoUser() throws Exception {
        PestoDatabase db = mockDb();


        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));

        authHandler.addAttributes("username", "idProof");
        fail();
    }

    @Test(expected = OperationFailedException.class)
    public void testAddBadIdentityProver() throws Exception {
        PestoDatabase db = mockDb();
        doReturn(true).when(db).hasUser(anyString());

        IdentityProver idProver = mockIdProver();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        authHandler.addIdentityProver(idProver);
        authHandler.addAttributes("username", "idProof");
    }

    @Test(expected = OperationFailedException.class)
    public void testAddBadIdentityProof() throws Exception {
        PestoDatabase db = mockDb();
        doReturn(true).when(db).hasUser(anyString());

        IdentityProver idProver = mockIdProver();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        authHandler.addIdentityProver(idProver);
        authHandler.addAttributes("username", "idProof");
    }

    @Test
    public void testDeleteAccount() throws OperationFailedException {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        authHandler.deleteAccount("username");
        ArgumentCaptor<String> stringCaptor = ArgumentCaptor.forClass(String.class);
        verify(db, times(1)).deleteUser(stringCaptor.capture());
        assertEquals("username", stringCaptor.getValue());
    }

    @Test
    public void testDeleteAttributes() throws OperationFailedException {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        List<String> attributes = new ArrayList<String>(1);
        attributes.add("attribute");
        authHandler.deleteAttributes("username", attributes);
        authHandler.deleteAccount("username");
        verify(db, times(1)).deleteAttribute(usernameCaptor.capture(), attributeCaptor.capture());
        assertEquals("username", usernameCaptor.getValue());
        assertEquals("attribute", attributeCaptor.getValue());
    }

    @Test
    public void testGetAllAttributes() throws OperationFailedException {
        PestoDatabase db = mockDb();
        Map<String, Attribute> map = new HashMap<String, Attribute>();
        map.put("attribute1", new Attribute("value1"));
        map.put("attribute2", new Attribute("value2"));
        doReturn(map).when(db).getAttributes(anyString());

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        Map<String, Attribute> attributes = authHandler.getAllAssertions("username");
        verify(db, times(1)).getAttributes(usernameCaptor.capture());
        assertEquals("username", usernameCaptor.getValue());
        assertEquals(2, attributes.size());
        assertEquals(new Attribute("value1"), attributes.get("attribute1"));
        assertEquals(new Attribute("value2"), attributes.get("attribute2"));
    }


    @Test
    public void testValidateAssertionsEQ() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute1", Operation.EQ, new Attribute("13"));
        predicates.add(predicate);
        predicate = new Predicate("attribute2", Operation.EQ, new Attribute(15));
        predicates.add(predicate);
        predicate = new Predicate("attribute3", Operation.EQ, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("1.1.1980")));
        predicates.add(predicate);
        policy.setPredicates(predicates);

        Map<String, Attribute> response = authHandler.validateAssertions("username", policy);
        assertEquals(3, response.size());
        assertEquals(new Attribute(true), response.get("attribute1EQUALS13"));
        assertEquals(new Attribute(true), response.get("attribute2EQUALS15"));
        assertEquals(new Attribute(true), response.get("attribute3EQUALS01.01.80"));
    }

    @Test
    public void testValidateAssertionsBadEQ() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        Policy policy = new Policy();
        Predicate predicate = new Predicate("attribute1", Operation.EQ, new Attribute("some other string"));
        List<Predicate> predicates = new LinkedList<>();
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }
        predicate = new Predicate("attribute2", Operation.EQ, new Attribute(10));
        predicates = new LinkedList<>();
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }

        predicate = new Predicate("attribute3", Operation.EQ, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("10.10.1999")));
        predicates = new LinkedList<>();
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }
    }

    @Test
    public void testValidateAssertionsLT() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute2", Operation.LESSTHANOREQUAL, new Attribute(16));
        predicates.add(predicate);
        predicate = new Predicate("attribute3", Operation.LESSTHANOREQUAL, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("1.8.1981")));
        predicates.add(predicate);
        policy.setPredicates(predicates);

        Map<String, Attribute> response = authHandler.validateAssertions("username", policy);
        assertEquals(2, response.size());
        assertEquals(new Attribute(true), response.get("attribute2LT16"));
        assertEquals(new Attribute(true), response.get("attribute3LT01.08.81"));
    }

    @Test
    public void testValidateAssertionsBadLT() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));

        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute2", Operation.LESSTHANOREQUAL, new Attribute(14));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }
        predicates = new LinkedList<>();
        predicate = new Predicate("attribute3", Operation.LESSTHANOREQUAL, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("8.1.1979")));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }

        predicates = new LinkedList<>();
        predicate = new Predicate("attribute1", Operation.LESSTHANOREQUAL, new Attribute("25"));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }
    }

    @Test
    public void testValidateAssertionsGT() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute2", Operation.GREATERTHANOREQUAL, new Attribute(14));
        predicates.add(predicate);
        predicate = new Predicate("attribute3", Operation.GREATERTHANOREQUAL, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("8.1.1970")));
        predicates.add(predicate);
        policy.setPredicates(predicates);

        Map<String, Attribute> response = authHandler.validateAssertions("username", policy);
        assertEquals(2, response.size());
        assertEquals(new Attribute(true), response.get("attribute2GT14"));
        assertEquals(new Attribute(true), response.get("attribute3GT08.01.70"));
    }

    @Test
    public void testValidateAssertionsBadGT() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));

        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute2", Operation.GREATERTHANOREQUAL, new Attribute(16));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }
        predicates = new LinkedList<>();
        predicate = new Predicate("attribute3", Operation.GREATERTHANOREQUAL, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("02.01.1980")));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }

        predicates = new LinkedList<>();
        predicate = new Predicate("attribute1", Operation.GREATERTHANOREQUAL, new Attribute("25"));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }
    }

    @Test
    public void testValidateAssertionsIR() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute2", Operation.INRANGE, new Attribute(14), new Attribute(16));
        predicates.add(predicate);
        policy.setPredicates(predicates);

        Map<String, Attribute> response = authHandler.validateAssertions("username", policy);
        assertEquals(1, response.size());
        assertEquals(new Attribute(true), response.get("attribute2INRANGE14-16"));
    }


    @Test
    public void testValidateAssertionsIRDate() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));
        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute3", Operation.INRANGE, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("02.01.1979")),
            new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("02.01.1982")));
        predicates.add(predicate);
        policy.setPredicates(predicates);

        Map<String, Attribute> response = authHandler.validateAssertions("username", policy);
        assertEquals(1, response.size());
        assertEquals(new Attribute(true), response.get("attribute3INRANGE02.01.79-02.01.82"));
    }

    @Test
    public void testValidateAssertionsBadIR() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));

        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute2", Operation.INRANGE, new Attribute(16));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }
        predicates = new LinkedList<>();
        predicate = new Predicate("attribute3", Operation.INRANGE, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("02.01.1980")));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }

        predicates = new LinkedList<>();
        predicate = new Predicate("attribute1", Operation.GREATERTHANOREQUAL, new Attribute("25"));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        try {
            authHandler.validateAssertions("username", policy);
            fail();
        } catch (Exception e) {
        }
    }

    @Test(expected = Exception.class)
    public void testValidateAssertionsOutsideRangeInteger() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));

        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute3", Operation.INRANGE, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("02.01.2000")));
        predicate.setExtraValue(new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("02.01.3000")));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        authHandler.validateAssertions("username", policy);
        fail();
    }


    @Test(expected = Exception.class)
    public void testValidateAssertionsOutsideRangeDate() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));

        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute2", Operation.INRANGE, new Attribute(200));
        predicate.setExtraValue(new Attribute(201));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        authHandler.validateAssertions("username", policy);
        fail();
    }

    @Test(expected = Exception.class)
    public void testValidateAssertionsInRangeBoolean() throws Exception {
        PestoDatabase db = mockDb();

        AuthenticationHandler authHandler = testAuthenticationHandler(db,mock(UserAuthorizationDatabase.class));

        Policy policy = new Policy();
        List<Predicate> predicates = new LinkedList<>();
        Predicate predicate = new Predicate("attribute4", Operation.INRANGE, new Attribute(true));
        predicate.setExtraValue(new Attribute(false));
        predicates.add(predicate);
        policy.setPredicates(predicates);
        authHandler.validateAssertions("username", policy);
        fail();
    }

    @Test
    public void testRefreshCookieLookupFails() throws OperationFailedException {
        PestoDatabase db = mockDb();
        UserAuthorizationDatabase sessions = mock(UserAuthorizationDatabase.class);
        doThrow(new RuntimeException()).when(sessions).lookupCookie(anyString());
        AuthenticationHandler authHandler = testAuthenticationHandler(db,sessions);
        Assert.assertEquals("cookie",authHandler.refreshCookie("cookie"));
    }

    @Test
    public void testRefreshCookieStoreFails() throws OperationFailedException {
        PestoDatabase db = mockDb();
        UserAuthorizationDatabase sessions = mock(UserAuthorizationDatabase.class);
        doReturn(new Authorization()).when(sessions).lookupCookie(anyString());
        doThrow(new RuntimeException()).when(sessions).storeCookie(any(),any());
        AuthenticationHandler authHandler = testAuthenticationHandler(db,sessions);
        Assert.assertEquals("cookie",authHandler.refreshCookie("cookie"));
    }

    @Test
    public void testRefreshCookieDeleteCookieFails() throws OperationFailedException {
        PestoDatabase db = mockDb();
        UserAuthorizationDatabase sessions = mock(UserAuthorizationDatabase.class);
        doReturn(new Authorization()).when(sessions).lookupCookie(anyString());
        doThrow(new RuntimeException()).when(sessions).deleteCookie(any());
        AuthenticationHandler authHandler = testAuthenticationHandler(db,sessions);
        Assert.assertNotEquals("cookie",authHandler.refreshCookie("cookie"));
    }

    @Test(expected = AuthenticationFailedException.class)
    public void testValidateSession() throws AuthenticationFailedException, OperationFailedException {
        PestoDatabase db = mockDb();
        Authorization auth = mock(Authorization.class);
        doReturn(-1L).when(auth).getExpiration();
        UserAuthorizationDatabase sessions = mock(UserAuthorizationDatabase.class);
        doReturn(auth).when(sessions).lookupCookie(anyString());
        AuthenticationHandler authHandler = testAuthenticationHandler(db,sessions);
        authHandler.validateSession("",new ArrayList<>());
    }

    private AuthenticationHandler testAuthenticationHandler(PestoDatabase db, UserAuthorizationDatabase sessions) {
        ServerCryptoModule mockCrypto = mock(ServerCryptoModule.class);
        doReturn(new byte[256]).when(mockCrypto).getBytes(anyInt());
        return new AuthenticationHandler(db, sessions, new HashMap<>(), mockCrypto) {

            @Override
            public String requestMFASecret(String username, String type) throws Exception {
                // TODO Auto-generated method stub
                return null;
            }

            @Override
            public String generateSessionCookie(String username) {
                // TODO Auto-generated method stub
                return null;
            }

        };
    }


    @Test
    public void calculateTimeout() {
        assertEquals(120L,AuthenticationHandler.calculateTimeout(100,2,10L));
        assertEquals(140L,AuthenticationHandler.calculateTimeout(100,3,10L));
        assertEquals(1800,AuthenticationHandler.calculateTimeout(1000,4,100L));
    }

    private IdentityProver mockIdProver() {
        IdentityProver ip = mock(IdentityProver.class);
        doReturn(false).when(ip).isValid(anyString(), anyString());
        return ip;
    }

    private PestoDatabase mockDb() throws OperationFailedException {
        PestoDatabase db = mock(PestoDatabase.class);
        Map<String, Attribute> map = new HashMap<String, Attribute>();
        map.put("attribute1", new Attribute("13"));
        map.put("attribute2", new Attribute(15));
        map.put("attribute4", new Attribute(true));
        try {
            map.put("attribute3", new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("01.01.1980")));
        } catch (ParseException ignored) {
        }

        doReturn(false).when(db).hasUser(anyString());
        doReturn(map).when(db).getAttributes(anyString());
        doReturn(true).when(db).deleteAttribute(anyString(), anyString());
        doReturn(true).when(db).deleteUser(anyString());
        return db;
    }

    @Before
    public void beforeEach() {
        usernameCaptor = ArgumentCaptor.forClass(String.class);
        attributeCaptor = ArgumentCaptor.forClass(String.class);
    }
}
