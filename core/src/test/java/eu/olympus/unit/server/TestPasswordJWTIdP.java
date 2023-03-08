package eu.olympus.unit.server;

import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.PasswordJWTIdP;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;

public class TestPasswordJWTIdP {
	
	PasswordJWTIdP idp;
	InMemoryUserPasswordDatabase db;
	
	@Before
	public void setup() throws Exception {
		db = new InMemoryUserPasswordDatabase();
		List<IdentityProver> provers = new LinkedList<IdentityProver>();
		provers.add(TestIdentityProver.getMock(db));
		idp = new PasswordJWTIdP(db, provers, null);
		idp.setup(TestParameters.getRSAPrivateKey1(), TestParameters.getRSA1Cert());
	}

	@Test
	public void testSetup() throws Exception {
		// Dummy test for code coverage 
		PasswordJWTIdP idp2 = new PasswordJWTIdP(db, new LinkedList<IdentityProver>(), null);
		idp2.setup(TestParameters.getRSAPrivateKey2(), TestParameters.getRSA2Cert());
		assertEquals(0, idp2.getId());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetupWithException() throws Exception {
		// Dummy test for code coverage
		Storage db = new InMemoryPestoDatabase();
		new PasswordJWTIdP(db, new LinkedList<IdentityProver>(), null);
		fail();
	}
	
	@Test
	public void testSimpleCreation() throws Exception{
		String user = "User";
		UsernameAndPassword userAndPassword = new UsernameAndPassword(user, "test1234");
		idp.createUser(userAndPassword);
		assertThat(db.getPassword(user), instanceOf(String.class));
		assertThat(db.getSalt(user), instanceOf(String.class));
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testVerificationNoAssertions() throws Exception{
		UsernameAndPassword userAndPassword = new UsernameAndPassword("User1", "test1234");
		idp.createUser(userAndPassword);
		idp.authenticate(userAndPassword.getUsername(), "noCookie".getBytes(), new Policy());
		fail();
	}

	
	@Test(expected = AuthenticationFailedException.class)
	public void testVerificationNoKeyGeneration() throws Exception{
		List<IdentityProver> provers = new LinkedList<IdentityProver>();
		provers.add(TestIdentityProver.getMock(db));
		PasswordJWTIdP idp2 = new PasswordJWTIdP(db, provers, null);

		UsernameAndPassword userAndPassword = new UsernameAndPassword("User1", "test1234");
		idp2.createUser(userAndPassword);
		idp2.authenticate(userAndPassword.getUsername(), "noCookie".getBytes(), new Policy());
		fail();
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testVerificationBadVerification() throws Exception{
		UsernameAndPassword userAndPassword = new UsernameAndPassword("User1", "test1234");
		idp.createUser(userAndPassword);
		
		UsernameAndPassword badCredential = new UsernameAndPassword("User1", "password");
		idp.authenticate(badCredential.getUsername(), "noCookie".getBytes(), new Policy());
		fail();
	}

	@Test
	public void testCreateAndProve() throws Exception{
		String user = "User";
		UsernameAndPassword userAndPassword = new UsernameAndPassword(user, "test1234");

		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("name", new Attribute("John"));
		attributes.put("country", new Attribute("dk"));
		attributes.put("age", new Attribute(10));
		attributes.put("height", new Attribute(180));

		IdentityProof idProof = new TestIdentityProof("signature", attributes);

		idp.createUserAndAddAttributes(userAndPassword, idProof);

		Map<String, Attribute> result = db.getAttributes(user);
		assertEquals(4, result.size());
		for(String s: result.keySet()) {
			assertEquals(attributes.get(s), result.get(s));
		}
	}

	@Test
	public void testAddAtrtibutes() throws Exception {

		UsernameAndPassword userAndPassword = new UsernameAndPassword("UserX", "test1234");
		idp.createUser(userAndPassword);
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("name", new Attribute("John"));
		attributes.put("country", new Attribute("dk"));

		
		IdentityProof idProof = new TestIdentityProof("signature", attributes);
		String cookie = idp.startSession(userAndPassword, null, "NONE");
		idp.addAttributes(userAndPassword.getUsername(), Base64.decodeBase64(cookie), idProof);

		Map<String, Attribute> result = db.getAttributes("UserX");
		assertEquals(2,result.size());
		for(String s: result.keySet()) {
			assertEquals(attributes.get(s), result.get(s));
		}
	}
	
	@Test(expected= OperationFailedException.class)
	public void testAddAttributesBadUser() throws Exception {
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("name", new Attribute("John"));
		attributes.put("country", new Attribute("dk"));
		attributes.put("age", new Attribute(10));
		attributes.put("height", new Attribute(180));

		IdentityProof idProof = new TestIdentityProof("signature", attributes);
		
		idp.addAttributes("UserX", "noCookie".getBytes(), idProof);
		fail();
	}
	
	@Test
	public void testVerificationWithAssertions() throws Exception{
		UsernameAndPassword userAndPassword = new UsernameAndPassword("UserX", "test1234");

		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("name", new Attribute("John"));
		attributes.put("country", new Attribute("dk"));

		IdentityProof idProof = new TestIdentityProof("signature", attributes);
		idp.createUserAndAddAttributes(userAndPassword, idProof);
		
		Policy policy = new Policy();
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		policy.setPredicates(predicates);
		String cookie = idp.startSession(userAndPassword, null, "NONE");
		String token = idp.authenticate(userAndPassword.getUsername(), Base64.decodeBase64(cookie), policy);
		
		assertNotEquals("Failed", token);
	}

}
