package eu.olympus.unit.server;

import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import eu.olympus.model.Attribute;
import eu.olympus.model.exceptions.NonExistingUserException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.PasswordHandler;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.storage.InMemoryKeyDB;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

public class TestPasswordHandler {
	@Rule
	public final ExpectedException exception = ExpectedException.none();

	PasswordHandler pwHandler;
	
	@Before
	public void setup() throws Exception{
		Map<String, MFAAuthenticator> authenticators = new HashMap<>();
		MFAAuthenticator mfaAuthenticator = mock(MFAAuthenticator.class);
		doReturn("secret").when(mfaAuthenticator).generateSecret();
		authenticators.put("dummy", mfaAuthenticator);
		pwHandler = new PasswordHandler(new InMemoryUserPasswordDatabase(), new SoftwareServerCryptoModule(new Random(1)), new InMemoryKeyDB(), authenticators );
		UsernameAndPassword userAndPassword = new UsernameAndPassword("User1", "test1234");
		pwHandler.createUser(userAndPassword);
	}

	@Test(expected=Exception.class)
	public void testBadConstructor() throws Exception {
		Storage mockDb = mock(Storage.class);
		when(mockDb.hasUser(anyString())).thenReturn(false);
		when(mockDb.deleteUser(anyString())).thenReturn(true);
		when(mockDb.deleteAttribute(anyString(), anyString())).thenReturn(true);
		new PasswordHandler(mockDb, new SoftwareServerCryptoModule(new Random(1)), new InMemoryKeyDB(), new HashMap<>());
		fail();
	}
	
	@Test
	public void testChangePassword() throws Exception {
		String user = "User5";
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		PasswordHandler pwh = new PasswordHandler(db, new SoftwareServerCryptoModule(new Random(1)),
				new InMemoryKeyDB(), new HashMap<>());

		UsernameAndPassword userAndPassword = new UsernameAndPassword(user, "test1234");
		pwh.createUser(userAndPassword);
		UsernameAndPassword newData = new UsernameAndPassword(user, "newPassword");
		pwh.changePassword(userAndPassword, newData.getPassword());

		boolean t = pwh.validateUsernameAndPassword(userAndPassword);
		assertFalse(t);
		t = pwh.validateUsernameAndPassword(newData);
		assertTrue(t);

	}
	
	@Test(expected = UserCreationFailedException.class)
	public void testChangePasswordBadPassword() throws Exception {
		String user = "User5";
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		PasswordHandler pwh = new PasswordHandler(db, new SoftwareServerCryptoModule(new Random(1)),
				new InMemoryKeyDB(), new HashMap<>());

		UsernameAndPassword userAndPassword = new UsernameAndPassword(user, "test1234");
		pwh.createUser(userAndPassword);
		UsernameAndPassword badPW = new UsernameAndPassword(user, "badPassword");
		pwh.changePassword(badPW, "newPassword");
		fail();
	}
	
	@Test
	public void testSimpleCreation() throws Exception{
		String user = "User5";
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		PasswordHandler pwh = new PasswordHandler(db, new SoftwareServerCryptoModule(new Random(1)),
				new InMemoryKeyDB(), new HashMap<>() );


		UsernameAndPassword userAndPassword = new UsernameAndPassword(user, "test1234");
		pwh.createUser(userAndPassword);
		assertThat(db.getPassword(user), isA(String.class));
		assertThat(db.getSalt(user), isA(String.class));
	}
	
	@Test
	public void testCreateAndAddAttributes() throws Exception{
		String user = "User6";
		InMemoryUserPasswordDatabase db = mock(InMemoryUserPasswordDatabase.class);
		when(db.hasUser(anyString())).thenReturn(false).thenReturn(true);

		PasswordHandler pwh = new PasswordHandler(db, new SoftwareServerCryptoModule(new Random(1)),
			new InMemoryKeyDB(), new HashMap<>() );
		pwh.addIdentityProver(TestIdentityProver.getMock(db));

		UsernameAndPassword userAndPassword = new UsernameAndPassword(user, "test1234");
		TestIdentityProof testIdProof = new TestIdentityProof();
		testIdProof.setSignature("sig");
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		testIdProof.setAttributes(attributes);

		pwh.createUserAndAddAttributes(userAndPassword, testIdProof.getStringRepresentation());
		ArgumentCaptor<Map<String, Attribute>> attributeCaptor = ArgumentCaptor.forClass(Map.class);
		verify(db).addAttributes(anyString(),attributeCaptor.capture());
		assertEquals(1,attributeCaptor.getValue().size());
		assertEquals(new Attribute("John"),attributeCaptor.getValue().get("name"));
		verify(db,times(2)).hasUser(anyString());
	}
	
	
	@Test
	public void testSimpleAuthentication(){

		UsernameAndPassword userAndPassword = new UsernameAndPassword("User1", "test1234");
		boolean t = pwHandler.validateUsernameAndPassword(userAndPassword);
		assertTrue(t);
	}
	
	@Test
	public void testBadUserAndPassword(){
		UsernameAndPassword userAndPassword = new UsernameAndPassword("User2", "password");
		boolean t = pwHandler.validateUsernameAndPassword(userAndPassword);
		assertFalse(t);
	}
	
	@Test
	public void testBadUser(){
		UsernameAndPassword userAndPassword = new UsernameAndPassword("User2", "test1234");
		boolean t = pwHandler.validateUsernameAndPassword(userAndPassword);
		assertFalse(t);
	}

	@Test
	public void testBadPassword(){
		UsernameAndPassword userAndPassword = new UsernameAndPassword("User1", "password");
		boolean t = pwHandler.validateUsernameAndPassword(userAndPassword);
		assertFalse(t);
	}
	
	@Test(expected=Exception.class)
	public void testDuplicateUserSamePW() throws Exception{
		String user = "User1";
		UsernameAndPassword userAndPassword = new UsernameAndPassword(user, "test1234");
		pwHandler.createUser(userAndPassword);
		fail();
	}
	
	@Test(expected=Exception.class)
	public void testDuplicateUserDifferentPW() throws Exception{
		String user = "User1";
		UsernameAndPassword userAndPassword = new UsernameAndPassword(user, "Password2");
		pwHandler.createUser(userAndPassword);
		fail();
	}
	
	@Test(expected = NonExistingUserException.class)
	public void testRequestMFASecret() throws NonExistingUserException, OperationFailedException {
		assertEquals("secret", pwHandler.requestMFASecret("User1", "dummy"));
		pwHandler.requestMFASecret("no_such_user", "dummy");
		fail();
	}
}
