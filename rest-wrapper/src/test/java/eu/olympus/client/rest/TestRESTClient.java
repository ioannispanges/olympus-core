package eu.olympus.client.rest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.AttributeMap;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.server.rest.CommonRESTEndpoints;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Feature;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.glassfish.jersey.logging.LoggingFeature;
import org.junit.Test;


public class TestRESTClient {
	
	@Test
	public void testPestoREST() throws Exception{
			
		UserClient client = new DummyClient();
		int restClientPort = 9070;
		RESTUserClient restClient = new RESTUserClient();
		restClient.setClient(client);
		try{
			restClient.setClient(client);
			restClient.start(restClientPort, 0, null, null, null);
		} catch(Exception e){
			e.printStackTrace();
			fail("Failed to start client");
		}

		TestRestClient testClient = new TestRestClient();

		testClient.createUser();
		testClient.createUserAndAddAttributes();
		testClient.addAttributes();
		testClient.authenticate();
		testClient.getAllAttributes();
		testClient.deleteAttributes();
		testClient.deleteAccount();
		testClient.changePassword();
	}

	/**
	 * Test version of the UserClient.
	 * Validate that the received values are valid inputs that
	 * match what was sent by the test.
	 */
	private class DummyClient implements UserClient{

		@Override
		public void createUser(String username, String password) throws UserCreationFailedException {
			assertEquals("user_1", username);
			assertEquals("password", password);
		}

		@Override
		public void createUserAndAddAttributes(String username, String password, IdentityProof identityProof)
				throws UserCreationFailedException {
			assertEquals("user_1", username);
			assertEquals("password", password);
			TestIdentityProof id = (TestIdentityProof)identityProof;
			
			assertEquals("proof", id.getSignature());
			assertEquals(2, id.getAttributes().size());
			assertEquals(new Attribute("Michael"), id.getAttributes().get("Name"));
			assertEquals(new Attribute("DK"), id.getAttributes().get("Nationality"));
		}

		@Override
		public void addAttributes(IdentityProof identityProof) throws OperationFailedException {
			TestIdentityProof id = (TestIdentityProof)identityProof;
			assertEquals("proof", id.getSignature());
			assertEquals(2, id.getAttributes().size());
			assertEquals(new Attribute("Michael"), id.getAttributes().get("Name"));
			assertEquals(new Attribute("DK"), id.getAttributes().get("Nationality"));
		}

		@Override
		public void addAttributes(String username, String password, IdentityProof identityProof, String token, String type) {
			assertEquals("password", password);
			TestIdentityProof id = (TestIdentityProof)identityProof;
			assertEquals("proof", id.getSignature());
			assertEquals(2, id.getAttributes().size());
			assertEquals(new Attribute("Michael"), id.getAttributes().get("Name"));
			assertEquals(new Attribute("DK"), id.getAttributes().get("Nationality"));
		}

		@Override
		public String authenticate(String username, String password, Policy policy, String token, String type) {
			assertEquals("user_1", username);
			assertEquals("password", password);

			assertEquals(2, policy.getPredicates().size());
			assertEquals("Name", policy.getPredicates().get(0).getAttributeName());
			assertEquals(Operation.REVEAL, policy.getPredicates().get(0).getOperation());
			assertEquals("Age", policy.getPredicates().get(1).getAttributeName());
			return "ok";
		}

		@Override
		public Map<String, Attribute> getAllAttributes(String username, String password, String token, String type) {
			assertEquals("password", password);
			Map<String, Attribute> map = new HashMap<String, Attribute>();
			map.put("Name", new Attribute("John"));
			return map;
		}

		@Override
		public Map<String, Attribute> getAllAttributes() throws OperationFailedException {
			Map<String, Attribute> map = new HashMap<String, Attribute>();
			map.put("Name", new Attribute("John"));
			return map;
		}

		@Override
		public void deleteAttributes(String username, String password, List<String> attributes, String token, String type) {
			assertEquals("password", password);
			assertEquals("Name", attributes.get(0));
			assertEquals(1, attributes.size());
			
		}

		@Override
		public void deleteAttributes(List<String> attributes) throws OperationFailedException {
			assertEquals("Name", attributes.get(0));
			assertEquals(1, attributes.size());
		}

		@Override
		public void deleteAccount(String username, String password, String token, String type) {
			assertEquals("password", password);
		}

		@Override
		public void changePassword(String username, String oldPassword, String newPassword, String token, String type) {
			assertEquals("password", oldPassword);
			assertEquals("newpassword", newPassword);
			
		}

		@Override
		public void clearSession() {

		}

		@Override
		public String requestMFAChallenge(String username, String password, String type)
				throws AuthenticationFailedException {
			return null;
		}

		@Override
		public void confirmMFA(String username, String password, String token, String type)
				throws AuthenticationFailedException {
		}

		@Override
		public void removeMFA(String username, String password, String token, String type)
				throws AuthenticationFailedException {

		}
	}
	
	private class TestRestClient {

		Client client;
		public TestRestClient() {
			this.client = ClientBuilder.newClient();
			Logger logger = Logger.getLogger(getClass().getName());

			Feature feature = new LoggingFeature(logger, Level.INFO, null, null);
	//		client.register(feature);
		}
		
		public void createUser() throws UserCreationFailedException {
			String data = "{\"username\":\"user_1\",\"password\":\"password\"}";
			Response reps = client.target("http://localhost:9070/user/"+CommonRESTEndpoints.CREATE_USER).request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
			assertEquals(204, reps.getStatus());
		}

		public void createUserAndAddAttributes() throws UserCreationFailedException {
			String data = "{\"usernameAndPassword\":{\"username\":\"user_1\",\"password\":\"password\"},\"identityProof\":{\"@class\":\"eu.olympus.client.rest.TestIdentityProof\",\"signature\":\"proof\",\"attributes\":{\"Name\":{\"class\":\"eu.olympus.model.Attribute\",\"attr\":\"Michael\", \"type\":\"STRING\"},\"Nationality\":{\"class\":\"eu.olympus.model.Attribute\",\"attr\":\"DK\", \"type\":\"STRING\"}}}}";
			Response reps = client.target("http://localhost:9070/user/"+CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES).request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
			assertEquals(204, reps.getStatus());
		}

		public void addAttributes()	throws AuthenticationFailedException {
			String data = "{\"usernameAndPassword\":{\"username\":\"user_1\",\"password\":\"password\"},\"identityProof\":{\"@class\":\"eu.olympus.client.rest.TestIdentityProof\",\"signature\":\"proof\",\"attributes\":{\"Name\":{\"class\":\"eu.olympus.model.Attribute\",\"attr\":\"Michael\", \"type\":\"STRING\"},\"Nationality\":{\"class\":\"eu.olympus.model.Attribute\",\"attr\":\"DK\", \"type\":\"STRING\"}}}}";
			Response reps = client.target("http://localhost:9070/user/"+CommonRESTEndpoints.ADD_ATTRIBUTES).request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
			assertEquals(204, reps.getStatus());
		}

		public void authenticate() {
			String data = "{\"usernameAndPassword\":{\"username\":\"user_1\",\"password\":\"password\"},\"policy\":{\"predicates\":[{\"attributeName\":\"Name\",\"operation\":\"REVEAL\",\"value\":null},{\"attributeName\":\"Age\",\"operation\":\"REVEAL\",\"value\":null}]}, \"cookie\":\"Y29va2ll\"}";
			Response reps = client.target("http://localhost:9070/user/"+CommonRESTEndpoints.AUTHENTICATE).request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
			assertEquals(200, reps.getStatus());
			assertEquals("ok", reps.readEntity(String.class));
		}
		
		public void getAllAttributes() {
			String data = "{\"username\":\"user_1\",\"password\":\"password\"}";
			Response reps = client.target("http://localhost:9070/user/"+CommonRESTEndpoints.GET_ALL_ATTRIBUTES).request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
			assertEquals(200, reps.getStatus());
			Map<String, Attribute> attributes = reps.readEntity(AttributeMap.class).getAttributes();
			assertEquals(attributes.get("Name"), new Attribute("John"));
			assertEquals(1, attributes.size());
		}
		
		public void deleteAttributes() {
			String data = "{\"usernameAndPassword\":{\"username\":\"user_1\",\"password\":\"password\"},\"cookie\":\"Y29va2ll\",\"attributes\":[\"Name\"]}";
			Response reps = client.target("http://localhost:9070/user/"+CommonRESTEndpoints.DELETE_ATTRIBUTES).request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
			assertEquals(204, reps.getStatus());
		}
		
		public void deleteAccount() {
			String data = "{\"usernameAndPassword\":{\"username\":\"user_1\",\"password\":\"password\"}}";
			Response reps = client.target("http://localhost:9070/user/"+CommonRESTEndpoints.DELETE_ACCOUNT).request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
			assertEquals(204, reps.getStatus());
		}
		
		public void changePassword() {
			String data = "{\"usernameAndPassword\":{\"username\":\"user_1\",\"password\":\"password\"},\"cookie\":\"Y29va2ll\",\"newPassword\":\"newpassword\"}";
			Response reps = client.target("http://localhost:9070/user/"+CommonRESTEndpoints.CHANGE_PASSWORD).request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
			assertEquals(204, reps.getStatus());
		}
	}
}
