package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.Authorization;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.Operation;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.rest.AuthenticationFilter;
import eu.olympus.server.rest.PestoIdPServlet;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.rest.Role;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.psmultisign.PSverfKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.codec.binary.Base64;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;
import org.mockito.ArgumentCaptor;

public class TestPestoIdPRESTConnection {

	private static RESTIdPServer server = new RESTIdPServer();
	private static final String url = "http://127.0.0.1:8666";
	private static final String fp12String = "CCX3MY6l5x691jSy"
			+ "NJKM8Q3BKGPiWJQt8zYkhATkkYNT7of"
			+ "4OBnhQJdGxU3Tf1gQ+pprdhTI57mMHQ0rcnrycDqG8QuDYc11oh0+cu"
			+ "KFR01XWojvSGGcU+FLzM7wpWNmKG1qI4iVW/vyUzoK6Xxj1c5po+kG7"
			+ "hMZe3NEeAzzXhbTZUUjydnQaTGG2iKo2/rwMM3EvbcX3HVG8VlK2mqq"
			+ "usVYyKKRIRNdbLdJLmK/EFwGMFAOIsJR8hlk8dZQS5dUdjC4uUk1dCT"
			+ "dkieiII21MBSoTzwavllqooJ0ITnWJBXtdxJpnoU1lBQJIzSQT+gIq5"
			+ "PxLYcmuANfxEv8Tpf9ayqDjTr0GWHNAxMYYV5gP0RrLv96gEOYc98W7"
			+ "rS8GE6HrKUJqrkW+JTAUzHbgCd5+a61sDT+M/qUExZxrINT+JPVXaio"
			+ "TUwvHs6PiykYsnJUJV6jHpdty0skbJ0rC4vWxPlcX8pB6MVhqeokKd0"
			+ "0Q6on125OUtq5LgV5RgSFO9i2c8PbCvakUx/UFr8fdD/Jrf3JWOmfYQ"
			+ "gf/Cxv86hovCepIs9rvs0wbprmEKvsdLJlVnjRnhtvfSKTjQnUnMph9"
			+ "KX6Y2y6OFy02aNfjt0J7REB0VidQJKK/74gEHMB3mbmi3ChqqVaRU5l"
			+ "a2J5OHzhSFhoZyIF/5VckCpyJiiV8vlLNDVKzglIJ1LyCepVeJO3rYj"
			+ "tK+bqSSTs4pxE5C8n2TzPpHcv4ZO3crP4qIzWbSEAdRde+YXQUw3fOc"
			+ "tSrgmBd+mPnwwgDotTsuOCztaMFHjttwHYvFUWVbYWwQEIWDW9qVaDM"
			+ "in/IB0AjklFyzHr7w9gN2GBS0vQOS4Zn0gMlTbLbdHc+aVxVDp28zo7"
			+ "Yz4zsNM9z3XeWm6/1L7wawqxQhM7FdSiZInyDzqU0kRubYGXva2e5CZ"
			+ "i";
	private static final FP12 fp12 = FP12.fromBytes(Base64.decodeBase64(fp12String));

	private static PestoIdPImpl idp;


	private static ArgumentCaptor<String> userCaptor;
	private static ArgumentCaptor<String> stringCaptor;
	private static ArgumentCaptor<byte[]> oldSigCaptor;
	private static ArgumentCaptor<byte[]> sigCaptor;
	private static ArgumentCaptor<Long> longCaptor;
	private static ArgumentCaptor<Long> saltCaptor;
	private static ArgumentCaptor<PublicKey> publickeyCaptor;


	private static PestoIdPImpl mockIdp() throws Exception {
		PestoIdPImpl idp = mock(PestoIdPImpl.class);
		HashMap<String, Attribute> attr = new HashMap<String, Attribute>();
		attr.put("name", new Attribute("John"));
		AttributeDefinition def=new AttributeDefinitionString("Name","Name",1,16);
		Set<AttributeDefinition> defs=new HashSet<>();
		defs.add(def);

		doReturn(true).when(idp).startRefresh();
		doReturn(new OPRFResponse(fp12, "ssid", "session")).when(idp).performOPRF(anyString(), anyString(), any(), anyString(), anyString());
		doReturn("reply".getBytes()).when(idp).finishRegistration(anyString(), any(), any(), any(), anyLong(), anyString());
		doReturn("token").when(idp).authenticate(anyString(), any(), anyLong(), any(), any());
    doReturn(TestParameters.getRSA1Cert()).when(idp).getCertificate();
		doReturn(true).when(idp).addAttributes(anyString(), any(), anyLong(), any(), anyString());
		doReturn(attr).when(idp).getAllAttributes(anyString(), any(), anyLong(), any());
		doReturn(true).when(idp).deleteAttributes(anyString(), any(), anyLong(), any(), any());
		doReturn(true).when(idp).deleteAccount(anyString(), any(), anyLong(), any());
		doReturn("response".getBytes()).when(idp).changePassword(anyString(), any(), any(), any(), any(), anyLong());
		doReturn(10000).when(idp).getRateLimit();

		return idp;
	}

	@BeforeClass
	public static void startServer() throws Exception {
		idp = mockIdp();

		server.setIdP(idp);

		List<String> types = new ArrayList<String>();
		types.add(PestoIdPServlet.class.getCanonicalName());
		types.add(AuthenticationFilter.class.getCanonicalName());

		server.start(8666, types, 8667, null, null, null);
	}

	@AfterClass
	public static void stopServer() throws Exception {
		server.stop();
	}

	@Test
	public void testPerformOPRFMFA() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		OPRFResponse response = connection.performOPRF("ssid", "username", ECP.generator(), "", "NONE");
		verify(idp, times(1)).performOPRF(anyString(), anyString(), any(), anyString(), anyString());
		assertEquals("ssid", response.getSsid());
		byte[] bytes = new byte[696]; 
		response.getY().toBytes(bytes);
		assertEquals(fp12String, Base64.encodeBase64String(bytes));
	}

	@Test
	public void testStartRefresh()  {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		boolean response = connection.startRefresh();
		verify(idp, times(1)).startRefresh();
		assertTrue(response);
		connection = new PestoIdPRESTConnection(url, "admin", 0,10000);
		doReturn(false).when(idp).startRefresh();
		response = connection.startRefresh();
		assertFalse(response);
	}

	@Test (expected = RuntimeException.class)
	public void testAddPartialSignature()  {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		connection.addPartialServerSignature("ssid", "username".getBytes());
		fail();
	}

	@Test (expected = RuntimeException.class)
	public void testAddPartialMFASecret()  {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		connection.addPartialMFASecret("ssid", "username", "authenticator_type");
		fail();
	}
	
	@Test (expected = RuntimeException.class)
	public void testAddMasterShare()  {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		connection.addMasterShare("ssid", "some-pretty-long-and-winding-share".getBytes());
		fail();
	}

	@Test (expected = RuntimeException.class)
	public void TestSetKeyShare()  {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		connection.setKeyShare(0, "some-pretty-long-and-winding-share".getBytes());
		fail();
	}

	@Test
	public void TestGetId() {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		assertEquals(0, connection.getId());
	}

	@Test
	public void testFinishRegistration() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		byte[] response = connection.finishRegistration("username", "session".getBytes(), TestParameters.getRSAPublicKey1(), "signature".getBytes(), 1000, "idProof");
		verify(idp, times(1)).finishRegistration(userCaptor.capture(), any(), publickeyCaptor.capture(), sigCaptor.capture(), saltCaptor.capture(), stringCaptor.capture());

		assertEquals("username", userCaptor.getValue());
		assertEquals(TestParameters.getRSAPublicKey1(), publickeyCaptor.getValue());
		assertEquals("signature", new String(sigCaptor.getValue()));
		assertEquals(Long.valueOf(1000), saltCaptor.getValue());
		assertEquals("idProof", stringCaptor.getValue());
		assertEquals("reply", new String(response));
	}

	@Test (expected = UserCreationFailedException.class)
	public void testFinishRegistrationException() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		doThrow(UserCreationFailedException.class).when(idp).finishRegistration(anyString(), any(), any(), any(), anyLong(), anyString());
		connection.finishRegistration("user2", "session".getBytes(), TestParameters.getRSAPublicKey1(), "signature".getBytes(), 1000, "idProof");
		fail();
	}

	@Test
	public void testAuthenticate() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		Policy policy = new Policy();
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		policy.setPredicates(predicates);
		String reply = connection.authenticate("username", "session".getBytes(), 1000, "signature".getBytes(), policy);
		verify(idp, times(1)).authenticate(userCaptor.capture(), any(), longCaptor.capture(), sigCaptor.capture(), any());
		assertEquals("username", userCaptor.getValue());
		assertEquals("name", policy.getPredicates().get(0).getAttributeName());
		assertEquals(1, policy.getPredicates().size());
		assertEquals("signature", new String(sigCaptor.getValue()));
		assertEquals(Long.valueOf(1000), longCaptor.getValue());
		assertEquals("token", reply);

	}

	@Test
	public void testAddAttributes() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		assertTrue(connection.addAttributes("username", "session".getBytes(), 1000, "signature".getBytes(), "idProof"));
		verify(idp, times(1)).addAttributes(userCaptor.capture(), any(), saltCaptor.capture(), sigCaptor.capture(), stringCaptor.capture());
		assertEquals("username", userCaptor.getValue());
		assertEquals("signature", new String(sigCaptor.getValue()));
		assertEquals(Long.valueOf(1000), saltCaptor.getValue());
		assertEquals("idProof", stringCaptor.getValue());
	}


	@Test
	public void testGetPublicKey() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		Certificate cert = connection.getCertificate();
		verify(idp, times(1)).getCertificate();
		assertEquals(cert, TestParameters.getRSA1Cert());
		doThrow(new RuntimeException()).when(idp).getCertificate();
		try {
			connection.getCertificate();
			fail();
		} catch (Exception e){
			assertTrue(e instanceof RuntimeException);
		}
	}

	@Test
	public void testGetAllAttributes() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		Map<String, Attribute> attributes = connection.getAllAttributes("username", "session".getBytes(), 200, "sig".getBytes());
		verify(idp, times(1)).getAllAttributes(userCaptor.capture(), any(), saltCaptor.capture(), sigCaptor.capture());
		assertEquals("username", userCaptor.getValue());
		assertEquals("sig", new String(sigCaptor.getValue()));
		assertEquals(Long.valueOf(200), saltCaptor.getValue());
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(1, attributes.size());
	}

	@Test
	public void testDeleteAttributes() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		List<String> attributes = new ArrayList<String>();
		attributes.add("name");
		assertTrue(connection.deleteAttributes("username", "session".getBytes(), 300, "signature".getBytes(), attributes));
		verify(idp, times(1)).deleteAttributes(userCaptor.capture(), any(), saltCaptor.capture(), sigCaptor.capture(), any());
		assertEquals("username", userCaptor.getValue());
		assertEquals("signature", new String(sigCaptor.getValue()));
		assertEquals(Long.valueOf(300), saltCaptor.getValue());
		assertEquals("name", attributes.get(0));
		assertEquals(1, attributes.size());
	}

	@Test
	public void testDeleteAccount() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		assertTrue(connection.deleteAccount("user", "session".getBytes(), 10, "signature".getBytes()));
		verify(idp, times(1)).deleteAccount(userCaptor.capture(), any(), saltCaptor.capture(), sigCaptor.capture());
		assertEquals("user", userCaptor.getValue());
		assertEquals("signature", new String(sigCaptor.getValue()));
		assertEquals(Long.valueOf(10), saltCaptor.getValue());
	}

	@Test
	public void testChangePassword() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		byte[] response = connection.changePassword("username", "session".getBytes(), TestParameters.getECPublicKey2(), "oldsignature".getBytes(), "newsignature".getBytes(), 100);
		verify(idp, times(1)).changePassword(userCaptor.capture(), any(), publickeyCaptor.capture(), sigCaptor.capture(), oldSigCaptor.capture(), anyLong());
		assertEquals("username", userCaptor.getValue());
		assertEquals(TestParameters.getECPublicKey2(), publickeyCaptor.getValue());
		assertEquals("oldsignature", new String(sigCaptor.getValue()));
		assertEquals("newsignature", new String(oldSigCaptor.getValue()));
		assertEquals("response", new String(response));
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testAddSession() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		connection.addSession("cookie", new Authorization());
		fail();
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testValidateSession() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		connection.validateSession("cookie", Arrays.asList(Role.USER));
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testRefreshCookie()  {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
		connection.refreshCookie("cookie");
		fail();
	}

	@Before
	public void beforeEach() {
		stringCaptor = ArgumentCaptor.forClass(String.class);
		userCaptor = ArgumentCaptor.forClass(String.class);
		saltCaptor = ArgumentCaptor.forClass(Long.class);
		longCaptor = ArgumentCaptor.forClass(Long.class);
		sigCaptor = ArgumentCaptor.forClass(byte[].class);
		oldSigCaptor = ArgumentCaptor.forClass(byte[].class);
		publickeyCaptor = ArgumentCaptor.forClass(PublicKey.class);
	}
}
