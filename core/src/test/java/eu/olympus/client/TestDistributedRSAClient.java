package eu.olympus.client;

import static org.junit.Assert.assertEquals;
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
import static org.mockito.Mockito.when;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.DistributedRSAIdP;
import eu.olympus.server.GoogleAuthenticator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.mockito.ArgumentMatchers;

public class TestDistributedRSAClient {
	private final static String user = "username";
	private final static String password = "password";

	@Test(expected = OperationFailedException.class)
	public void testMissingUserMFAChallenge() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();
		DistributedRSAIdP idp1 = stubIdp(new HashMap<>(),"request1");
		DistributedRSAIdP idp2 = stubIdp(new HashMap<>(),"request2");
		idps.add(idp1);
		idps.add(idp2);
		DistributedRSAClient authClient = new DistributedRSAClient(idps);
		authClient.requestMFAChallenge(user, password, GoogleAuthenticator.TYPE);
		fail();
	}
	
	@Test(expected = OperationFailedException.class)
	public void testMissingConfirmMFA() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps);
		authClient.confirmMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testMissingRemoveMFA() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps);
		authClient.removeMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test
	public void testMissingUser() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		idps.add(idp);
		DistributedRSAClient client = new DistributedRSAClient(idps);
		try {
			client.removeMFA("otherUser", password, "none", GoogleAuthenticator.TYPE);
			fail();
		} catch (Exception e) {
			// correct behaviour
		}
	}

	@Test(expected = OperationFailedException.class)
	public void testFailedDeleteAccount() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		doAnswer(i -> {
			UsernameAndPassword auth = i.getArgument(0);
			if (!auth.getUsername().equals(user) || !auth.getPassword().equals(password) ) {
				return "not-cookie";
			}
			return "cookie";
		}).when(idp).startSession(any(UsernameAndPassword.class),anyString(),anyString());
		doAnswer(i -> {
			UsernameAndPassword auth = i.getArgument(0);
			byte[] cookie = i.getArgument(1);
			return auth.getUsername().equals(user) && Arrays.equals("cookie".getBytes(), cookie);
		}).when(idp).deleteAccount(any(UsernameAndPassword.class),ArgumentMatchers.any());

		idps.add(idp);
		DistributedRSAClient client = new DistributedRSAClient(idps);
		client.deleteAccount(user,"wrong-password", null,  "NONE");
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testFailedDeleteAttributes() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();


		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		doAnswer(i -> {
			UsernameAndPassword auth = i.getArgument(0);
			if (!auth.getUsername().equals(user) || !auth.getPassword().equals(password) ) {
				return "not-cookie";
			}
			return "cookie";
		}).when(idp).startSession(any(UsernameAndPassword.class),anyString(),anyString());
		doAnswer(i -> {
			String username = i.getArgument(0);
			byte[] cookie = i.getArgument(1);
			return username.equals(user) && Arrays.equals("cookie".getBytes(), cookie);
		}).when(idp).deleteAttribute(anyString(),ArgumentMatchers.any(),anyList());

		idps.add(idp);
		DistributedRSAClient client = new DistributedRSAClient(idps);
		client.deleteAttributes(user,"wrong-password", Arrays.asList("name"), null,  "NONE");
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testFailedGetAllAttributes() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		Map<String, Attribute> map1 = new HashMap<>();
		map1.put("name", new Attribute("Marge Simpson"));
		Map<String, Attribute> map2 = new HashMap<>();
		map2.put("name", new Attribute("Homer Simpson"));

		DistributedRSAIdP idp = stubIdp(map1,"request1");
		DistributedRSAIdP idp2 = stubIdp(map2,"request1");
		idps.add(idp);
		idps.add(idp2);
		DistributedRSAClient client = new DistributedRSAClient(idps);
		client.getAllAttributes(user,"wrong-password",null,  "NONE");
		fail();
	}

	@Test
	public void testGetAllAttributesWithMFA() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		Map<String, Attribute> map1 = new HashMap<>();
		map1.put("name", new Attribute("John"));
		map1.put("age", new Attribute("26"));
		DistributedRSAIdP idp = stubIdp(map1, "request1");
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		authClient.createUser("username","password");
		Map<String, Attribute> attributes = authClient.getAllAttributes( user,"password", "TOKEN", GoogleAuthenticator.TYPE);
		assertEquals(2, attributes.size());
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(new Attribute("26"), attributes.get("age"));
	}
	
	@Test(expected = OperationFailedException.class)
	public void testGetAllAttributesServerFailure() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		DistributedRSAIdP idp = stubIdp(new HashMap<>(), "request1");
		doThrow(new RuntimeException()).when(idp).getAllAttributes(anyString(),any());
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		authClient.getAllAttributes( user,"password", null, "NONE");
		fail();
	}

	@Test(expected = OperationFailedException.class)
	public void testGetAllAttributesDifferingServerOutputs() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();

		Map<String, Attribute> map1 = new HashMap<>();
		map1.put("name", new Attribute("John"));
		Map<String, Attribute> map2 = new HashMap<>();
		map2.put("name", new Attribute("Bob"));

		DistributedRSAIdP idp = stubIdp(map1,"request1");
		DistributedRSAIdP idp2 = stubIdp(map2,"request1");
		idps.add(idp);
		idps.add(idp2);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		authClient.getAllAttributes(user,"password", null, "NONE");
		fail();
	}

	@Test
	public void testDeleteAttributesWithMFA() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		authClient.createUser(user,"password");
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes(user, "password", toDelete, "TOKEN", GoogleAuthenticator.TYPE);
		verify(idp, times(1)).deleteAttribute(any(), any(),anyList());
	}
	
	@Test(expected = OperationFailedException.class)
	public void testDeleteAttributesServerFailure() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		doThrow(new OperationFailedException()).when(idp).deleteAttribute(any(),any(),any());
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes(user,"password", toDelete, null, "NONE");
		fail();
	}
	
	@Test(expected = OperationFailedException.class)
	public void testDeleteAttributesServerNegativeAnswer() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		doReturn(false).when(idp).deleteAttribute(anyString(),any(),anyList());
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};

		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes(user, "password", toDelete, null, "NONE");
		fail();
	}
	
	@Test
	public void testDeleteAccountWithMFA() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};

		authClient.createUser("username","password");
		authClient.deleteAccount(user, "password", "TOKEN", GoogleAuthenticator.TYPE);
		verify(idp, times(1)).deleteAccount(any(), any());

	}

	@Test(expected = OperationFailedException.class)
	public void testDeleteAccountServerFailure() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		doThrow(new OperationFailedException()).when(idp).deleteAccount(any(), any());
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};

		authClient.deleteAccount(user, "password", null, "NONE");
		fail();
	}
	
	@Test(expected = OperationFailedException.class)
	public void testDeleteAccountServerFailureNice() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		doReturn(false).when(idp).deleteAccount(any(), any());
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};

		authClient.deleteAccount(user, "password", null, "NONE");
		fail();
	}
	
	@Test
	public void testChangePasswordWithMFA() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		authClient.createUser("username","password");
		authClient.changePassword(user, "password", "password2", "TOKEN", GoogleAuthenticator.TYPE);
		verify(idp, times(1)).changePassword(any(), any(),any());
	}
	
	@Test(expected=OperationFailedException.class)
	public void testChangePasswordBadServerSignature() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		DistributedRSAIdP idp = stubIdp(new HashMap<>(),"request1");
		doThrow(new OperationFailedException()).when(idp).changePassword(any(), any(),any());
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		authClient.changePassword(user, "password", "password2", null, "NONE");
		fail();
	}

	private DistributedRSAIdP stubIdp(Map<String, Attribute> attributeMap, String requestString) throws Exception {
		DistributedRSAIdP idp = mock(DistributedRSAIdP.class);
		when(idp.getAllAttributes(anyString(),any())).thenReturn(attributeMap);
		when(idp.getCertificate()).thenReturn(TestParameters.getRSA1Cert());
		when(idp.startSession(any(UsernameAndPassword.class), anyString(), anyString())).thenReturn("cookie");
		when(idp.deleteAttribute(anyString(),any(),anyList())).then(invocationOnMock -> (invocationOnMock.getArgument(0).equals(user)));
		when(idp.deleteAccount(any(UsernameAndPassword.class),any(byte[].class))).then(invocationOnMock -> (invocationOnMock.getArgument(0, UsernameAndPassword.class).getUsername().equals(user)));
		doReturn(requestString).when(idp).requestMFA(any(UsernameAndPassword.class), ArgumentMatchers.any(),anyString());
		//when(idp.requestMFA(any(UsernameAndPassword.class),any(byte[].class),anyString())).thenReturn(requestString);
		return idp;
	}

	private Map<String,Attribute> nameAttrMap(String attribute){
		Map<String, Attribute> mockMap = new HashMap<>();
		mockMap.put("name", new Attribute(attribute));
		return mockMap;
	}

}
