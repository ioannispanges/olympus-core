package eu.olympus.unit.server.rest;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import eu.olympus.model.Authorization;
import eu.olympus.model.server.rest.AddPartialSignatureRequest;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.PestoIdPServlet;
import eu.olympus.server.rest.PestoRESTEndpoints;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryPestoDatabase;

public class TestUsernameAndCookieFilter {

	@Test
	public void testBasic() throws Exception {
		RESTIdPServer server = new RESTIdPServer();
		PestoDatabase acl = new InMemoryPestoDatabase();
		PestoIdP testIdP = new PestoIdPImpl(acl,  new ArrayList<>(), new HashMap<String, MFAAuthenticator>(), new SoftwareServerCryptoModule(new Random(1)), 100000);
		server.setIdP(testIdP);
		
		List<String> types = new ArrayList<String>();
		types.add(PestoIdPServlet.class.getCanonicalName());

		testIdP.addSession("server1", new Authorization("server",  Arrays.asList(new Role[]{Role.SERVER}), System.currentTimeMillis()+10000l));
		testIdP.addSession("admin1", new Authorization("administrator",  Arrays.asList(new Role[]{Role.ADMIN}), System.currentTimeMillis()+10000l));
		testIdP.addSession("god", new Authorization("god",  Arrays.asList(new Role[]{Role.ADMIN, Role.SERVER}), System.currentTimeMillis()+10000l));
		
		server.start(10666, types, 10667, null, null, null);
		
		String host = "http://localhost:10666/idp/";
	    Client client = ClientBuilder.newClient();
	    
	    AddPartialSignatureRequest request = new AddPartialSignatureRequest("ssid", Base64.encodeBase64String("signature".getBytes()));
	    
	    
		Response response = client.target(host+ PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request()
				.header("Authorization", "Bearer server1")
				.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		assertEquals(204, response.getStatus());
		
		response = client.target(host+PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request()
				.header("Authorization", "Bearer god")
				.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		assertEquals(204, response.getStatus());
		
		response = client.target(host+PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request()
				.header("Authorization", "Bearer admin1")
				.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		assertEquals(401, response.getStatus());

		response = client.target(host+PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request()
				.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		assertEquals(401, response.getStatus());
		
		response = client.target(host+PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request()
				.header("Authorization", "Bearer no-such-user")
				.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		assertEquals(401, response.getStatus());
		
		server.stop();
	}
}
