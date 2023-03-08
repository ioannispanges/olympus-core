package eu.olympus.unit.server.rest;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

import eu.olympus.model.server.rest.OPRFRequest;
import eu.olympus.model.server.rest.OPRFRestResponse;
import eu.olympus.server.rest.PestoIdPServlet;

/**
 * Mainly for test coverage
 */
public class TestPestoIdPServlet {
	
	@Test
	public void testGetJsonException() throws Exception {
		PestoIdPServlet servlet = new PestoIdPServlet() {
			@Override
			public OPRFRestResponse requestOPRF(OPRFRequest request) {
				String response = getJson(System.out);
				assertEquals("Could not convert", response.substring(0, 17));
				return null;
			}
		};
		servlet.requestOPRF(null);
	}
}
