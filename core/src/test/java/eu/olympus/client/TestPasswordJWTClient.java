package eu.olympus.client;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.PasswordJWTIdP;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import eu.olympus.unit.server.TestIdentityProof;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

public class TestPasswordJWTClient {

	private final static String user = "username";
	private final static String password = "password";
	private final static String signature = "signature";
	private final static String challenge = "challenge";
	private final static Map<String, Attribute> attributes = new HashMap<>();
	private final static List<String> claims = new LinkedList<String>();

	private static ArgumentCaptor<UsernameAndPassword> unameAndPwCaptor;
	private static ArgumentCaptor<TestIdentityProof> proofCaptor;
	private static ArgumentCaptor<String> stringCaptor;
	private static ArgumentCaptor<byte[]> cookieCaptor;
	private static ArgumentCaptor<Policy> policyCaptor;
	private static ArgumentCaptor<List<String>> attrCaptor;

	static PasswordJWTIdP dummyIdP;

	@Test
	public void testCreateUser() throws UserCreationFailedException, AuthenticationFailedException, OperationFailedException {
		dummyIdP = mockJWTIdp();
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.createUser(user, password);

		Mockito.verify(dummyIdP, times(1)).createUser(unameAndPwCaptor.capture());
		assertEquals(unameAndPwCaptor.getValue().getUsername(), user);
		assertEquals(unameAndPwCaptor.getValue().getPassword(), password);
	}
	
	@Test
	public void testCreateUserAndAddAttributes() throws UserCreationFailedException {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.createUserAndAddAttributes(user, password, new TestIdentityProof(signature, attributes));

		Mockito.verify(dummyIdP, times(1)).createUserAndAddAttributes(unameAndPwCaptor.capture(), proofCaptor.capture());
		assertEquals(unameAndPwCaptor.getValue().getUsername(), user);
		assertEquals(unameAndPwCaptor.getValue().getPassword(), password);
	}
	
	@Test
	public void testAddAttributes() throws AuthenticationFailedException, OperationFailedException, UserCreationFailedException {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.createUser("username", "password");
		client.addAttributes("username", password, new TestIdentityProof(signature, attributes), null, "NONE");
		Mockito.verify(dummyIdP, times(1)).addAttributes(stringCaptor.capture(), any(), proofCaptor.capture());
		assertEquals(stringCaptor.getValue(), user);
	}
	
	@Test
	public void testAuthenticate() throws AuthenticationFailedException {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		Policy policy = new Policy();
		List<Predicate> predicates = new ArrayList<>();
		for(String s: claims) {
			Predicate predicate = new Predicate();
			predicate.setAttributeName(s);
			predicate.setOperation(Operation.REVEAL);
			predicates.add(predicate);
		}
		policy.setPredicates(predicates);
		String reply = client.authenticate(user, password, policy, null, "NONE");
		assertThat(reply, is("Dummy-Authenticate"));
		Mockito.verify(dummyIdP, times(1)).authenticate(stringCaptor.capture(), any(), policyCaptor.capture());
		assertEquals(stringCaptor.getValue(), user);
		assertEquals(policyCaptor.getValue().getPredicates().size(), claims.size());
		for (Predicate p : policyCaptor.getValue().getPredicates()) {
			assertThat(claims, hasItem(p.getAttributeName()));
		}
	}
	
	@Test
	public void testRequestMFAChallenge() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.requestMFAChallenge(user, password, GoogleAuthenticator.TYPE);

		Mockito.verify(dummyIdP, times(1)).requestMFA(unameAndPwCaptor.capture(),any(),stringCaptor.capture());
		assertEquals(unameAndPwCaptor.getValue().getUsername(), user);
		assertEquals(unameAndPwCaptor.getValue().getPassword(), password);
		assertEquals(stringCaptor.getValue(), "GOOGLE_AUTHENTICATOR");
	}
	
	@Test(expected = OperationFailedException.class)
	public void testMissingConfirmMFA() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);

		client.confirmMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testMissingRemoveMFA() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);

		client.removeMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test
	public void testMissingUser() {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		try {
			client.removeMFA("otherUser", password, "none", GoogleAuthenticator.TYPE);
			fail();
		} catch (Exception e) {
			// correct behaviour
		}
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testFailedAuthentication() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		PasswordJWTIdP idp = mockJWTIdp();
		doReturn(null).when(idp).authenticate(anyString(),any(),any());
		servers.add(idp);
		PasswordJWTClient client = new PasswordJWTClient(servers);

		client.authenticate(user, "wrong-password", new Policy(), null, "NONE");
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testFailedDeleteAttributes() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		PasswordJWTIdP idp = mockJWTIdp();
		doReturn(false).when(idp).deleteAttribute(anyString(),any(),anyList());
		servers.add(idp);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.deleteAttributes("username", "wrong-password", Arrays.asList("name"), null, "NONE");
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testFailedDeleteAccount() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.deleteAccount("username", "wrong-password", null, "NONE");
		fail();
	}
	
	@Test
	public void testGetAllAttributes() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		PasswordJWTIdP idp = mockJWTIdp();
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);
		authClient.createUser("username", "password");
		Map<String, Attribute> attributes = authClient.getAllAttributes("username","password", null, "NONE");
		assertEquals(2, attributes.size());
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(new Attribute("John2"), attributes.get("name2"));
	}


	@Test
	public void testGetAllAttributesWithMFA() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		PasswordJWTIdP idp = mockJWTIdp();
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);
		authClient.createUser("username", "password");
		Map<String, Attribute> attributes = authClient.getAllAttributes("username","password", "TOKEN", GoogleAuthenticator.TYPE);
		assertEquals(2, attributes.size());
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(new Attribute("John2"), attributes.get("name2"));
	}

	@Test(expected = OperationFailedException.class)
	public void testGetAllAttributesServerFailure() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		PasswordJWTIdP idp = mockJWTIdp();
		doThrow(new OperationFailedException()).when(idp).getAllAttributes(anyString(),any());
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);
		authClient.getAllAttributes("username","password", null, "NONE");
		fail();
	}

	@Test
	public void testDeleteAttributes() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		PasswordJWTIdP idp = mockJWTIdp();
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);
		authClient.createUser("username", "password");
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username","password", toDelete, null, "NONE");

		verify(idp, times(1)).deleteAttribute(stringCaptor.capture(),cookieCaptor.capture(),attrCaptor.capture());
		assertArrayEquals(Base64.decodeBase64("cookie"), cookieCaptor.getValue());
		assertEquals("username", stringCaptor.getValue());
		assertEquals(1, attrCaptor.getValue().size());
		assertEquals("John", attrCaptor.getValue().get(0));
	}

	@Test
	public void testDeleteAttributesWithMFA() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		PasswordJWTIdP idp = mockJWTIdp();
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);
		authClient.createUser("username", "password");
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username","password", toDelete, "TOKEN", GoogleAuthenticator.TYPE);


		verify(idp, times(1)).deleteAttribute(stringCaptor.capture(),cookieCaptor.capture(),any());
		assertArrayEquals(Base64.decodeBase64("cookie"), cookieCaptor.getValue());
		assertEquals("username", stringCaptor.getValue());
	}

	@Test(expected = OperationFailedException.class)
	public void testDeleteAttributesServerFailure() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		PasswordJWTIdP idp = mockJWTIdp();
		doThrow(new OperationFailedException()).when(idp).deleteAttribute(anyString(),any(),anyList());
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username","password", toDelete, null, "NONE");
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testDeleteAttributesServerNegativeAnswer() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		PasswordJWTIdP idp = mockJWTIdp();
		doReturn(false).when(idp).deleteAttribute(anyString(),any(),anyList());
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);

		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username","password", toDelete, null, "NONE");
		fail();
	}

	@Test
	public void testDeleteAccountWithMFA() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();

		PasswordJWTIdP idp = mockJWTIdp();
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);

		authClient.createUser("username", "password");
		authClient.deleteAccount("username","password", "TOKEN", GoogleAuthenticator.TYPE);
		verify(idp, times(1)).deleteAccount(unameAndPwCaptor.capture(),cookieCaptor.capture());
		assertArrayEquals(Base64.decodeBase64("cookie"), cookieCaptor.getValue());
		assertEquals("username", unameAndPwCaptor.getValue().getUsername());
		assertEquals("username","password", unameAndPwCaptor.getValue().getPassword());
	}

	@Test(expected = OperationFailedException.class)
	public void testDeleteAccountServerFailure() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		PasswordJWTIdP idp = mockJWTIdp();
		doThrow(new OperationFailedException()).when(idp).deleteAccount(any(),any());
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);

		authClient.deleteAccount("username","password", null, "NONE");
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testDeleteAccountServerFailureNice() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		PasswordJWTIdP idp = mockJWTIdp();
		doReturn(false).when(idp).deleteAccount(any(),any());
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);

		authClient.deleteAccount("username","password", null, "NONE");
		fail();
	}

	@Test
	public void testChangePasswordWithMFA() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		PasswordJWTIdP idp = mockJWTIdp();
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);
		authClient.createUser("username", "password");
		authClient.changePassword("username","password", "password2", "TOKEN", GoogleAuthenticator.TYPE);

		verify(idp, times(1)).changePassword(unameAndPwCaptor.capture(),stringCaptor.capture(),cookieCaptor.capture());

		assertArrayEquals(Base64.decodeBase64("cookie"), cookieCaptor.getValue());
		assertEquals("username", unameAndPwCaptor.getValue().getUsername());
		assertEquals("password2", stringCaptor.getValue());
	}

	@Test(expected=OperationFailedException.class)
	public void testChangePasswordBadServerSignature() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();

		PasswordJWTIdP idp = mockJWTIdp();
		doThrow(new OperationFailedException()).when(idp).changePassword(any(),anyString(),any());
		idps.add(idp);
		PasswordJWTClient authClient = testPasswordJWTClient(idps);
		authClient.changePassword("username","password", "password2", null, "NONE");
		fail();
	}



	private class TestIdP extends PasswordJWTIdP {

		public TestIdP() throws Exception {
			super(new InMemoryUserPasswordDatabase(), new ArrayList<>(), new HashMap<String, MFAAuthenticator>());
		}

		@Override
		public String startSession(UsernameAndPassword authentication, String token, String type)
				throws AuthenticationFailedException {
			if("NONE".equals(type)) {
				return "Y29va2ll";
			}
			assertEquals("TOKEN", token);
			assertEquals(GoogleAuthenticator.TYPE, type);
			return "Y29va2ll";
		}

		@Override
		public Certificate getCertificate() {
			return TestParameters.getRSA1Cert();
		}

		@Override
		public Map<String, Attribute> getAllAttributes(String username, byte[] cookie) {
			assertEquals("username", username);
			assertEquals("cookie", new String(cookie));

			Map<String, Attribute> attributes = new HashMap<String, Attribute>();
			attributes.put("name", new Attribute("John"));
			attributes.put("name2", new Attribute("John2"));
			return attributes;
		}

		public boolean deleteAttributeReached = false;
		@Override
		public boolean deleteAttribute(String username, byte[] cookie, List<String> attributes) {
			assertEquals("username", username);
			assertEquals("cookie", new String(cookie));
			assertEquals(1, attributes.size());
			assertEquals("John", attributes.get(0));
			deleteAttributeReached = true;
			return true;
		}

		public boolean deleteAccountReached = false;
		@Override
		public boolean deleteAccount(UsernameAndPassword authentication, byte[] cookie) {
			assertEquals("username", authentication.getUsername());
			assertEquals("password", authentication.getPassword());
			assertEquals("cookie", new String(cookie));
			deleteAccountReached = true;
			return true;
		}

		public boolean changePWReached = false;

		@Override
		public void changePassword(
				UsernameAndPassword oldAuthenticationData, String newPassword, byte[] cookie) {
			assertEquals("cookie", new String(cookie));
			assertEquals("username", oldAuthenticationData.getUsername());
			assertEquals("password2", newPassword);
			changePWReached = true;
		}
	}

	private static PasswordJWTIdP mockJWTIdp() throws AuthenticationFailedException, OperationFailedException {
		PasswordJWTIdP idp = mock(PasswordJWTIdP.class);
		doReturn("cookie").when(idp).startSession(any(UsernameAndPassword.class),any(),anyString());
		doReturn(TestParameters.getRSA1Cert()).when(idp).getCertificate();
		doAnswer(invocationOnMock -> {
			if (!(invocationOnMock.getArgument(0,String.class)).equals(user)) {
				return null;
			} else {
				return "Dummy-Authenticate";
			}
		}).when(idp).authenticate(anyString(),any(),any());
		doAnswer(invocationOnMock -> {
			Map<String, Attribute> attributes = new HashMap<String, Attribute>();
			attributes.put("name", new Attribute("John"));
			attributes.put("name2", new Attribute("John2"));
			return attributes;
		}).when(idp).getAllAttributes(anyString(),any());

		doReturn(true).when(idp).deleteAttribute(anyString(),any(),anyList());
		doAnswer(invocationOnMock ->
			(invocationOnMock.getArgument(0, UsernameAndPassword.class)).getUsername().equals(user) && (invocationOnMock.getArgument(0, UsernameAndPassword.class)).getPassword().equals(password)).when(idp).deleteAccount(any(UsernameAndPassword.class),any());
		return idp;
	}


	private PasswordJWTClient testPasswordJWTClient(List<PasswordJWTIdP> idps) {
		return new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
	}

	@BeforeClass
	public static void setup() throws AuthenticationFailedException, UserCreationFailedException, OperationFailedException {
		claims.add("name");
		claims.add("age");
		attributes.put("name", new Attribute("John"));
		attributes.put("age", new Attribute(22));
		dummyIdP = mockJWTIdp();
	}

	@Before
	public void beforeEach() {
		unameAndPwCaptor = ArgumentCaptor.forClass(UsernameAndPassword.class);
		proofCaptor = ArgumentCaptor.forClass(TestIdentityProof.class);
		stringCaptor = ArgumentCaptor.forClass(String.class);
		policyCaptor = ArgumentCaptor.forClass(Policy.class);
		attrCaptor = ArgumentCaptor.forClass(List.class);
		cookieCaptor = ArgumentCaptor.forClass(byte[].class);
	}
}
