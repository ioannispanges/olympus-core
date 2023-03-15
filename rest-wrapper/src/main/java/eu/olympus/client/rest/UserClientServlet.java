package eu.olympus.client.rest;

import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.server.rest.AttributeMap;
import eu.olympus.model.server.rest.PasswordAuthentication;
import eu.olympus.model.server.rest.PasswordAuthenticationAndAttributes;
import eu.olympus.model.server.rest.PasswordAuthenticationAndIDProof;
import eu.olympus.model.server.rest.PasswordAuthenticationAndPassword;
import eu.olympus.model.server.rest.PasswordAuthenticationAndPolicy;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.rest.CommonRESTEndpoints;
import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

@Path("/user")
public class UserClientServlet {
	
	@Context ServletContext context;
	
	@Path(CommonRESTEndpoints.CREATE_USER)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public void createUser(UsernameAndPassword request) throws Exception {
		System.out.println("Got a createUser request");
		UserClient user = (UserClient) context.getAttribute("user");
		user.createUser(request.getUsername(), request.getPassword());
		System.out.println("Finished creating user");
	}
	
	@Path(CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public void createUserAndAddAttributes(PasswordAuthenticationAndIDProof request) throws Exception {
		System.out.println("Got a createUserAndAddAttributes request");
		UserClient user = (UserClient) context.getAttribute("user");
		UsernameAndPassword rq = request.getUsernameAndPassword();
		user.createUserAndAddAttributes(rq.getUsername(), rq.getPassword(), request.getIdentityProof());
		System.out.println("Finished creating user and proving identity");
	}
	
	@Path(CommonRESTEndpoints.ADD_ATTRIBUTES)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public void addAttributes(PasswordAuthenticationAndIDProof request) throws Exception {
		System.out.println("Got a add Attributes request");
		UserClient user = (UserClient) context.getAttribute("user");
		UsernameAndPassword rq = request.getUsernameAndPassword();
		user.addAttributes(rq.getUsername(), rq.getPassword(), request.getIdentityProof(), null, "NONE");
		System.out.println("Finished proving identity");
	}
	
	
	@Path(CommonRESTEndpoints.AUTHENTICATE)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public String authenticate(PasswordAuthenticationAndPolicy request) throws Exception {
		System.out.println("Got an authenticate request");
		UserClient user = (UserClient) context.getAttribute("user");
		UsernameAndPassword auth = request.getUsernameAndPassword();
		return user.authenticate(auth.getUsername(), auth.getPassword(), request.getPolicy(), null, "NONE");
	}

	@Path(CommonRESTEndpoints.GET_ALL_ATTRIBUTES)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public AttributeMap getAllAttributes(UsernameAndPassword request) throws Exception {
		System.out.println("Got an getAllAttributes request");
		UserClient user = (UserClient) context.getAttribute("user");
		return new AttributeMap(user.getAllAttributes(request.getUsername(), request.getPassword(), null, "NONE"));
	}

	@Path(CommonRESTEndpoints.DELETE_ATTRIBUTES)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public void deleteAttributes(PasswordAuthenticationAndAttributes request) throws Exception {
		System.out.println("Got an deleteAttributes request");
		UserClient user = (UserClient) context.getAttribute("user");
		user.deleteAttributes(request.getUsernameAndPassword().getUsername(), request.getUsernameAndPassword().getPassword(), request.getAttributes(), null, "NONE");
		System.out.println("Attributes deleted");
	}
	

	@Path(CommonRESTEndpoints.DELETE_ACCOUNT)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public void deleteAccount(PasswordAuthentication request) throws Exception {
		System.out.println("Got an deleteAccount request");
		UserClient user = (UserClient) context.getAttribute("user");
		user.deleteAccount(request.getUsernameAndPassword().getUsername(),request.getUsernameAndPassword().getPassword(), null, "NONE");
		System.out.println("Account deleted");
	}
	
	@Path(CommonRESTEndpoints.CHANGE_PASSWORD)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public void changePassword(PasswordAuthenticationAndPassword request) throws Exception {
		System.out.println("Got an change password request");
		UserClient user = (UserClient) context.getAttribute("user");
		user.changePassword(request.getUsernameAndPassword().getUsername(), request.getUsernameAndPassword().getPassword(), request.getNewPassword(), null, "NONE");
		System.out.println("Password changed");
	}
}
