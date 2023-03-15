package eu.olympus.client.rest;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import eu.olympus.client.interfaces.UserClient;


public class RESTUserClient {
	
	private Server server;
	
	private static RESTUserClient myself = null;
	
	private UserClient user;
	
	public RESTUserClient(){
	}

	public void setClient(UserClient user){
		this.user = user;
	}
	
	public UserClient getUser(){
		return this.user;
	}
	
	
	public static RESTUserClient getInstance(){
		if(myself == null) {
			myself = new RESTUserClient();
			return myself;
		} else {
			return myself;
		}
	}
	
	public void start(int port, int tlsPort, String certPath, String ksPassword, String kmPassword) throws Exception{
		System.out.println("STARTING REST User Client :" +port +"-" +user);
		ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
		context.setContextPath("/");
		context.setAttribute("user", user);
		
		server = new Server();
        ServerConnector connector = new ServerConnector(server);
        
        connector.setPort(port);
  		Connector[] connectors = new Connector[1]; 
  		connectors[0] = connector;
  		if(certPath != null){
  			connectors = new Connector[2];
  			connectors[0] = connector;
  			HttpConfiguration https = new HttpConfiguration();
  			
  			https.addCustomizer(new SecureRequestCustomizer());
  			
  			SslContextFactory sslContextFactory = new SslContextFactory();
  			
  			sslContextFactory.setKeyStorePath(certPath);
  			
  			sslContextFactory.setKeyStorePassword(ksPassword);
  			
  			sslContextFactory.setKeyManagerPassword(kmPassword);
  			
  			ServerConnector sslConnector = new ServerConnector(server,
  					new SslConnectionFactory(sslContextFactory, "http/1.1"),
  					new HttpConnectionFactory(https));
  			
  			sslConnector.setPort(tlsPort);
  			connectors[1] = sslConnector;
  		}
  		
  		server.setConnectors(connectors);
  		
  		server.setHandler(context);
  		
  		ServletHolder jerseyServlet = context.addServlet(
  	             org.glassfish.jersey.servlet.ServletContainer.class, "/*");
  	        jerseyServlet.setInitOrder(0);
  	        
  	    // Tells the Jersey Servlet which REST service/class to load.

  	    jerseyServlet.setInitParameter(
               "jersey.config.server.provider.classnames",
               UserClientServlet.class.getCanonicalName());
  	    
  	    server.start();
	}
	
    public void stop() throws Exception{
    	System.out.println("STOPPING REST User Client");
    	server.stop();
    }

}
