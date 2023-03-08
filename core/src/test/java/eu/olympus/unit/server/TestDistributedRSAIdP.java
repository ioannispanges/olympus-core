package eu.olympus.unit.server;

import static org.junit.Assert.assertEquals;

import eu.olympus.TestParameters;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.server.DistributedRSAIdP;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import java.util.HashMap;
import java.util.LinkedList;
import org.junit.Test;

public class TestDistributedRSAIdP {

	@Test
	public void testGetId() throws Exception {
		// Dummy test for code coverage
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		DistributedRSAIdP idp = new DistributedRSAIdP(db, 0, new LinkedList<IdentityProver>(), null, new HashMap<>(), null);
		assertEquals(0, idp.getId());
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testAuthenticateFailingWithBadCookie() throws Exception {
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user", "salt", "password");
		DistributedRSAIdP idp = new DistributedRSAIdP(db, 0, new LinkedList<IdentityProver>(), null, new HashMap<>(),  TestParameters
				.getRSA1Cert());
		idp.authenticate("user", "cookie".getBytes(), new Policy());
	}
}
