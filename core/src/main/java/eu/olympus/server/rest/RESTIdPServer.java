package eu.olympus.server.rest;

import eu.olympus.server.interfaces.VirtualIdP;
import java.util.List;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class RESTIdPServer {
	private Server server;
	private ServerConnector plainConnector = null;
	private ServerConnector sslConnector = null;
	
	private static RESTIdPServer myself = null;
	
	private VirtualIdP idp;
	
	private static final Logger logger = LoggerFactory.getLogger(RESTIdPServer.class);
	
	public RESTIdPServer(){
	}
	
	public void setIdP(VirtualIdP idp){
		this.idp = idp; 
		
	}

	public VirtualIdP getIdP(){
		return this.idp; 
	}
	
	public static RESTIdPServer getInstance() {
		if(myself == null) {
			myself = new RESTIdPServer();
			return myself;
		} else {
			return myself;
		}
	}
	
    public void start(int port, List<String> types, int tlsPort, String keyStorePath, String ksPassword, String kmPassword) throws Exception {
    	logger.info("STARTING REST IdP SERVER : " +port +" - " +idp.getClass().getSimpleName());
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        context.setAttribute("idp", idp);
       
        server = new Server();
        plainConnector = new ServerConnector(server);
        plainConnector.setPort(port);
			ServerConnector[] connectors = new ServerConnector[1];
  		connectors[0] = plainConnector;
  		if(keyStorePath != null) {
  			connectors = new ServerConnector[2];
  			connectors[0] = plainConnector;
  			HttpConfiguration https = new HttpConfiguration();

  			https.addCustomizer(new SecureRequestCustomizer());

  			SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();

  			sslContextFactory.setKeyStorePath(keyStorePath);
  			sslContextFactory.setKeyStorePassword(ksPassword);
  			sslContextFactory.setKeyManagerPassword(kmPassword);

  			sslConnector = new ServerConnector(server,
  					new SslConnectionFactory(sslContextFactory, "http/1.1"),
  					new HttpConnectionFactory(https));

  			sslConnector.setPort(tlsPort);
  			connectors[1] = sslConnector;
  		}
 		server.setConnectors(connectors);
         //*/
        
    
        server.setHandler(context);
        types.add("eu.olympus.server.rest.AuthenticationFilter");
        types.add("eu.olympus.server.rest.RateLimitFilter");

        ServletHolder jerseyServlet = context.addServlet(
        		org.glassfish.jersey.servlet.ServletContainer.class, "/*");
        jerseyServlet.setInitOrder(0);
        // Tells the Jersey Servlet which REST service/class to load.
		jerseyServlet.setInitParameter(
				"jersey.config.server.provider.classnames",
				String.join(",",types));

        //jerseyServlet.setInitParameter(
        //        "jersey.config.server.provider.classnames",
        //        FullPestoIdPServlet.class.getCanonicalName());
        //PasswordIdPServlet.class.getCanonicalName()
        
        server.start();
    }
    	
    public void stop() throws Exception {
    	logger.info("STOPPING REST IdP SERVER");
    	this.plainConnector.close();
    	if (this.sslConnector != null) {
    		this.sslConnector.close();
    	}
    	server.stop();
    }


}
