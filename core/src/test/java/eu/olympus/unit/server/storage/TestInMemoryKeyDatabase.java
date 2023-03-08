package eu.olympus.unit.server.storage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Arrays;

import org.junit.Test;

import eu.olympus.model.Authorization;
import eu.olympus.server.interfaces.UserAuthorizationDatabase;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryKeyDB;

public class TestInMemoryKeyDatabase {
	
	@Test
	public void testPartialSignatures() {
		InMemoryKeyDB db = new InMemoryKeyDB();
		db.addPartialSignature("user", "sig1".getBytes());
		db.addPartialSignature("user", "sig2".getBytes());
		db.addPartialSignature("user", "sig3".getBytes());
		assertEquals(3, db.getPartialSignatures("user").size());
		db.deletePartialSignatures("user");
		assertEquals(db.getPartialSignatures("user").size(), 0);
	}
	
	@Test
	public void testTokens() {
		UserAuthorizationDatabase db = new InMemoryKeyDB();
		db.storeCookie("token", new Authorization("id", Arrays.asList(new Role[] {Role.ADMIN}), System.currentTimeMillis()+10000l));

		assertEquals("id", db.lookupCookie("token").getId());
		assertEquals(Role.ADMIN, db.lookupCookie("token").getRoles().get(0));
		
		db.deleteCookie("token");
		assertNull(db.lookupCookie("token"));
	}
}
