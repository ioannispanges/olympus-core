package eu.olympus.cfp.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.cfp.server.identityprovers.TestIdentityProver;
import eu.olympus.cfp.server.identityprovers.TokenIdentityProver;
import eu.olympus.cfp.server.storage.InMemoryPestoDatabase;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.server.CombinedIdP;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdPRESTWrapper;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.rest.CombinedIdPServlet;
import eu.olympus.server.rest.PabcIdPServlet;
import eu.olympus.server.rest.PestoIdP2IdPRESTConnection;
import eu.olympus.server.rest.RESTIdPServer;
import java.io.File;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

public class RunCFPServer {

	public static void main(String[] args) throws Exception {
		
		ObjectMapper mapper = new ObjectMapper();
		PABCConfigurationImpl configuration = mapper.readValue(new File(args[0]), PABCConfigurationImpl.class);
		
		List<IdPRESTWrapper> others = new ArrayList<>();
		for (String s: configuration.getServers()) {
			others.add(new PestoIdP2IdPRESTConnection(s, configuration.getId(),
					configuration.getKeyStorePath(), configuration.getKeyStorePassword(),
					configuration.getTrustStorePath(), configuration.getTrustStorePassword(),
					configuration.getMyAuthorizationCookie()));

		}
		//Setup databases
		//Currently uses a simple in memory database
		PestoDatabase db = new InMemoryPestoDatabase();

		//Setup identity provers
		//Currently uses
		// a TokenIdentityProver for adding a unid to a user
		// a UserCredentialIdentityProver for adding a certificate to a user
		// a CreditFileIdentityProver for adding a credit file to a user
		List<IdentityProver> identityProvers = new LinkedList<IdentityProver>();
		identityProvers.add(new TokenIdentityProver(db));
		identityProvers.add(new TestIdentityProver(db));
	//  identityProvers.add(new UserCredentialIdentityProver("", db));
	//	identityProvers.add(new CreditFileIdentityProver("", db));

		ServerCryptoModule cryptoModule = new SoftwareServerCryptoModule(new SecureRandom());

		// list of servlets (one for each technology (PESTO/pABC)
		List<String> types = new ArrayList<>(1);
      	types.add(CombinedIdPServlet.class.getCanonicalName());


		//Setup the IdP.
		CombinedIdP idp = null;
		idp = new CombinedIdP(db, identityProvers, new HashMap<>(), cryptoModule, 100000);
		idp.setup("ssid", configuration, others);
		//And also an in memory database for authorization of servers and admins
		for(String cookie: configuration.getAuthorizationCookies().keySet()) {
			idp.addSession(cookie, configuration.getAuthorizationCookies().get(cookie));
		}
		
		RESTIdPServer restServer = new RESTIdPServer();
		restServer.setIdP(idp);
		restServer.start(configuration.getPort(), types,
				configuration.getTlsPort(), 
				configuration.getKeyStorePath(), 
				configuration.getKeyStorePassword(), 
				configuration.getKeyStorePassword());
	}
}
