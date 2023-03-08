package eu.olympus.unit.server.storage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import eu.olympus.model.Attribute;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.interfaces.UserPasswordDatabase;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class TestInMemoryUserPasswordDatabase {
	
	@Test
	public void testBasics() throws OperationFailedException {
		UserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user1", "salt", "password");
		assertTrue(db.hasUser("user1"));
		assertEquals("salt", db.getSalt("user1"));
		assertEquals("password", db.getPassword("user1"));
		db.setSalt("user1", "100000");
		assertEquals("100000", db.getSalt("user1"));
		db.setPassword("user1", "new");
		assertEquals("new", db.getPassword("user1"));
		
		boolean successfulDelete = db.deleteUser("user1");
		assertTrue(successfulDelete);
		assertFalse(db.hasUser("user1"));
		assertFalse(db.deleteUser("user1"));
	}
	
	@Test
	public void testAttributes() throws OperationFailedException {
		UserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user1", "salt", "password");
		assertEquals(0, db.getAttributes("user1").size());
		
		db.addAttribute("user1", "name", new Attribute("John"));
		assertEquals(1, db.getAttributes("user1").size());
		assertEquals(new Attribute("John"), db.getAttributes("user1").get("name"));
		
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("age", new Attribute(25));
		attributes.put("nationality", new Attribute("US"));
		db.addAttributes("user1", attributes);
		
		assertEquals(3, db.getAttributes("user1").size());
		assertEquals(new Attribute("John"), db.getAttributes("user1").get("name"));
		assertEquals(new Attribute(25), db.getAttributes("user1").get("age"));
		assertEquals(new Attribute("US"), db.getAttributes("user1").get("nationality"));

		assertTrue(db.deleteAttribute("user1", "name"));
		assertEquals(2, db.getAttributes("user1").size());
		
		assertFalse(db.deleteAttribute("user1", "name"));
		
		assertFalse(db.deleteAttribute("user2", "age"));
	}
	
	// Not the most useful test, but needed for coverage
	@Test
	public void testMFAMethods() throws OperationFailedException {
		UserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user1", "salt", "password");
		

		db.assignMFASecret("user2", GoogleAuthenticator.TYPE, "newsecret");
		assertEquals("newsecret", db.getMFAInformation("user2").get(GoogleAuthenticator.TYPE).getSecret());
		
		db.activateMFA("user2", "NONE");
		assertFalse(db.getMFAInformation("user2").get(GoogleAuthenticator.TYPE).isActivated());

		db.activateMFA("user2", GoogleAuthenticator.TYPE);
		assertTrue(db.getMFAInformation("user2").get(GoogleAuthenticator.TYPE).isActivated());

		db.deleteMFA("user2", "NONE");
		assertTrue(db.getMFAInformation("user2").get(GoogleAuthenticator.TYPE).isActivated());

		db.deleteMFA("user2", GoogleAuthenticator.TYPE);
		assertFalse(db.getMFAInformation("user2").get(GoogleAuthenticator.TYPE).isActivated());

		db.assignMFASecret("user2", "NONE", "secret");
	}

	@Test
	public void testThrottling() throws OperationFailedException {
		UserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user1", "salt", "password");
		db.assignMFASecret("user2", GoogleAuthenticator.TYPE, "newsecret");

		// MFA
		assertEquals(0,db.getNumberOfFailedMFAAttempts("user1"));
		assertEquals(0,db.getLastMFAAttempt("user1"));

		db.failedMFAAttempt("user1");
		assertEquals(1,db.getNumberOfFailedMFAAttempts("user1"));
		assertNotEquals(0,db.getLastMFAAttempt("user1"));

		db.clearFailedMFAAttempts("user1");
		assertEquals(0,db.getNumberOfFailedMFAAttempts("user1"));

		// Auth
		assertEquals(0,db.getNumberOfFailedAuthAttempts("user1"));
		assertEquals(0,db.getLastAuthAttempt("user1"));

		db.failedAuthAttempt("user1");
		assertEquals(1,db.getNumberOfFailedAuthAttempts("user1"));
		assertNotEquals(0,db.getLastAuthAttempt("user1"));

		db.clearFailedAuthAttempts("user1");
		assertEquals(0,db.getNumberOfFailedAuthAttempts("user1"));
	}
	
}
