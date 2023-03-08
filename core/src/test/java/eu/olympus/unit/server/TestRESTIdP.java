package eu.olympus.unit.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import eu.olympus.TestParameters;
import eu.olympus.model.Authorization;
import eu.olympus.model.server.rest.AddPartialSignatureRequest;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.PestoIdPServlet;
import eu.olympus.server.rest.PestoRESTEndpoints;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.rest.Role;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.eclipse.jetty.http.HttpStatus;
import org.junit.Test;

public class TestRESTIdP {

    @Test
    public void testBasic() throws Exception {
        RESTIdPServer server = new RESTIdPServer();
        PestoIdP testIdP = mock(PestoIdPImpl.class);
        doReturn(1000).when(testIdP).getRateLimit();
        server.setIdP(testIdP);

        testIdP.addSession("authToken", new Authorization("user", Arrays.asList(new Role[]{Role.SERVER}), System.currentTimeMillis() + 10000l));
        List<String> types = new ArrayList<String>();
        types.add(PestoIdPServlet.class.getCanonicalName());

        server.start(10666, types, 10667, null, null, null);

        Client client = ClientBuilder.newClient();

        AddPartialSignatureRequest request = new AddPartialSignatureRequest("ssid", "signature");
        Response response = client.target("http://localhost:10666/idp/" + PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request().header("Authorization", "Bearer authToken")
            .post(Entity.entity(request, MediaType.APPLICATION_JSON));

        server.stop();
        verify(testIdP, times(1)).addPartialServerSignature(anyString(), any());
        assertEquals(204, response.getStatus());
    }
    @Test
    public void testThrottle() throws Exception {
        RESTIdPServer server = new RESTIdPServer();
        PestoIdP testIdP = mock(PestoIdPImpl.class);
        // Set rate limit to 1.
        doReturn(1).when(testIdP).getRateLimit();
        server.setIdP(testIdP);

        testIdP.addSession("authToken", new Authorization("user", Arrays.asList(new Role[]{Role.SERVER}), System.currentTimeMillis() + 10000l));
        List<String> types = new ArrayList<String>();
        types.add(PestoIdPServlet.class.getCanonicalName());

        server.start(10666, types, 10667, null, null, null);

        Client clientOne = ClientBuilder.newClient();
        Client clientTwo = ClientBuilder.newClient();

        Response response = executeSimultaneousRequests(clientOne, 10666);
        Response responseTwo = executeSimultaneousRequests(clientTwo, 10666);

        server.stop();

        //Ensure both clients were blocked by the rate limit
        assertNotNull(response);
        assertNotNull(responseTwo);
    }

    /**
     * Executes a number of requests very quickly, to try and reach the rate limit of the idp
     */
    public Response executeSimultaneousRequests(Client client, int port) throws ExecutionException, InterruptedException {

        AddPartialSignatureRequest request = new AddPartialSignatureRequest("ssid", "signature");
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        List<Future<Response>> responses = new ArrayList<>();
        for(int i = 0; i < 100; i++){
            responses.add(executor.submit(() -> client.target("http://localhost:" + port + "/idp/" + PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request().header("Authorization", "Bearer authToken")
                .post(Entity.entity(request, MediaType.APPLICATION_JSON))));
        }

        Response result = null;
        for (Future<Response> responseFuture: responses) {
            Response response = responseFuture.get();
            if(response.getStatus() == HttpStatus.NOT_ACCEPTABLE_406){
                // Rate limit is reached
                result = response;
            }
        }
        return result;
    }

    @Test
    public void testTLS() throws Exception {
        RESTIdPServer server = new RESTIdPServer();
        PestoIdPImpl testIdP = mock(PestoIdPImpl.class);
        doReturn(1000).when(testIdP).getRateLimit();
        server.setIdP(testIdP);

        testIdP.addSession("authToken", new Authorization("user", Arrays.asList(new Role[]{Role.SERVER}), System.currentTimeMillis() + 10000l));

        List<String> types = new ArrayList<String>();
        types.add(PestoIdPServlet.class.getCanonicalName());

        server.start(10666, types, 10667, TestParameters.TEST_KEY_STORE_LOCATION, TestParameters.TEST_KEY_STORE_PWD, TestParameters.TEST_KEY_STORE_PWD);


        Client client = ClientBuilder.newClient();
        AddPartialSignatureRequest request = new AddPartialSignatureRequest("ssid", "signature");
        Response response = client.target("http://localhost:10666/idp/" + PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request().header("Authorization", "Bearer authToken")
            .post(Entity.entity(request, MediaType.APPLICATION_JSON));

        server.stop();
        verify(testIdP, times(1)).addPartialServerSignature(anyString(), any());
        assertEquals(204, response.getStatus());
    }
}
