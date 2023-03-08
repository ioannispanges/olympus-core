package eu.olympus.server.rest;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.AttributeMap;
import eu.olympus.model.server.rest.AuthenticationAndAttributes;
import eu.olympus.model.server.rest.AuthenticationAndIDProof;
import eu.olympus.model.server.rest.AuthenticationAndPolicy;
import eu.olympus.model.server.rest.PasswordAuthentication;
import eu.olympus.model.server.rest.KeyAndCert;
import eu.olympus.model.server.rest.PasswordAuthenticationAndIDProof;
import eu.olympus.model.server.rest.PasswordAuthenticationAndMFAToken;
import eu.olympus.model.server.rest.PasswordAuthenticationAndMFATokenNoCookie;
import eu.olympus.model.server.rest.PasswordAuthenticationAndMFAType;
import eu.olympus.model.server.rest.PasswordAuthenticationAndPassword;
import eu.olympus.model.server.rest.UsernameAndCookie;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.PasswordJWTIdP;
import eu.olympus.util.KeySerializer;
import eu.olympus.util.keyManagement.CertificateUtil;
import eu.olympus.util.keyManagement.PemUtil;
import java.security.interfaces.RSAPrivateKey;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import org.apache.commons.codec.binary.Base64;

@Path("/idp")
public class PasswordIdPServlet {

	private final PasswordJWTIdP idp = (PasswordJWTIdP) RESTIdPServer.getInstance().getIdP();

	@Path(CommonRESTEndpoints.SETUP)
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public void setup(KeyAndCert keyPair) throws Exception {
		idp.setup((RSAPrivateKey)KeySerializer.deSerialize(keyPair.getPrivKey()),
				CertificateUtil.decodePemCert(keyPair.getCertificate()));
	}

	@Path(CommonRESTEndpoints.GET_PUBLIC_KEY)
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public String getCertificate() throws Exception {
			return PemUtil.encodeDerToPem(idp.getCertificate().getEncoded(), "CERTIFICATE");
	}


	@Path(CommonRESTEndpoints.CREATE_USER)
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public void createUser(UsernameAndPassword creationData) throws UserCreationFailedException, OperationFailedException {
		idp.createUser(creationData);
	}

	@Path(CommonRESTEndpoints.ADD_ATTRIBUTES)
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public void addAttributes(AuthenticationAndIDProof creationData) throws AuthenticationFailedException, InvalidProtocolBufferException, OperationFailedException {
		idp.addAttributes(creationData.getUsername(), Base64.decodeBase64(creationData.getCookie()), creationData.getIdentityProof());
	}


	@Path(CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES)
	@POST	
	public void createUserAndAddAttributes(PasswordAuthenticationAndIDProof creationData)
			throws UserCreationFailedException {
		idp.createUserAndAddAttributes(creationData.getUsernameAndPassword(), creationData.getIdentityProof());

	}

	@Path(CommonRESTEndpoints.AUTHENTICATE)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public String authenticate(AuthenticationAndPolicy authenticationData) throws Exception {
		return idp.authenticate(authenticationData.getUsername(), Base64.decodeBase64(authenticationData.getCookie()), authenticationData.getPolicy());
	}
	
	@Path(CommonRESTEndpoints.DELETE_ATTRIBUTES)
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Boolean deleteAttributes(AuthenticationAndAttributes authenticationData) throws Exception {
		return idp.deleteAttribute(authenticationData.getUsername(), Base64.decodeBase64(authenticationData.getCookie()), authenticationData.getAttributes());
	}
	
	@Path(CommonRESTEndpoints.DELETE_ACCOUNT)
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Boolean deleteAccount(PasswordAuthentication authenticationData) throws Exception {
		return idp.deleteAccount(authenticationData.getUsernameAndPassword(), Base64.decodeBase64(authenticationData.getCookie()));
	}
	
	@Path(CommonRESTEndpoints.GET_ALL_ATTRIBUTES)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public AttributeMap getAllAttributes(UsernameAndCookie authenticationData) throws AuthenticationFailedException, OperationFailedException {
		return new AttributeMap(idp.getAllAttributes(authenticationData.getUsername(), Base64.decodeBase64(authenticationData.getCookie())));
	}
	
	@Path(CommonRESTEndpoints.CHANGE_PASSWORD)
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public void changePassword(PasswordAuthenticationAndPassword passwordData) throws UserCreationFailedException, AuthenticationFailedException, OperationFailedException {
		idp.changePassword(passwordData.getUsernameAndPassword(), passwordData.getNewPassword(),
				Base64.decodeBase64(passwordData.getCookie()));
	}
		
	@Path(CommonRESTEndpoints.REQUEST_MFA)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public String requestMFA(PasswordAuthenticationAndMFAType request) throws AuthenticationFailedException, OperationFailedException {
		return idp
				.requestMFA(request.getUsernameAndPassword(), Base64.decodeBase64(request.getCookie()),
						request.getType());
	}
	
	@Path(CommonRESTEndpoints.CONFIRM_MFA)
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public boolean confirmMFA(PasswordAuthenticationAndMFAToken request) throws AuthenticationFailedException, OperationFailedException {
		return idp
				.confirmMFA(request.getUsernameAndPassword(), Base64.decodeBase64(request.getCookie()),
						request.getToken(),
						request.getType());
	}

	@Path(CommonRESTEndpoints.REMOVE_MFA)
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public boolean removeMFA(PasswordAuthenticationAndMFAToken request) throws AuthenticationFailedException, OperationFailedException {
		return idp.removeMFA(request.getUsernameAndPassword(), Base64.decodeBase64(request.getCookie()),
				request.getToken(), request.getType());
	}

	@Path(PasswordRESTEndpoints.START_SESSION)
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public String startSession(PasswordAuthenticationAndMFATokenNoCookie request) throws AuthenticationFailedException, OperationFailedException {
		return idp
				.startSession(request.getUsernameAndPassword(), request.getToken(), request.getType());
	}
}
