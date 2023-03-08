package eu.olympus.model;

import eu.olympus.server.interfaces.ServerConfiguration;
import eu.olympus.util.keyManagement.CertificateSerializer;
import eu.olympus.util.keyManagement.CertificateUtil;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

public class ServerConfigurationImpl implements ServerConfiguration {

	private int port;
	private List<String> servers;
	private Map<String, Authorization> authorizationCookies;
	private String myAuthorizationCookie;
	private int tlsPort;
	private String keyStorePath;
	private String trustStorePath;
	private String keyStorePassword;
	private String trustStorePassword;
	@JsonSerialize(using = CertificateSerializer.class)
	private Certificate cert;
	private String issuerId;

	public ServerConfigurationImpl() {
	}

	public ServerConfigurationImpl(int port, int tlsPort, List<String> servers, String keyStorePath,
			String keyStorePassword, String trustStorePath, String trustStorePassword, Certificate cert,
			Map<String, Authorization> cookies, String authorizationCookie, String issuerId) {
		this.port = port;
		this.tlsPort = tlsPort;
		this.servers = servers;
		this.keyStorePath = keyStorePath;
		this.keyStorePassword = keyStorePassword;
		this.trustStorePath = trustStorePath;
		this.trustStorePassword = trustStorePassword;
		this.cert = cert;
		this.authorizationCookies = cookies;
		this.myAuthorizationCookie = authorizationCookie;
		this.issuerId = issuerId;
	}

	@Override
	public String getKeyStorePath() {
		return keyStorePath;
	}

	public void setKeyStorePath(String keyStorePath) {
		this.keyStorePath = keyStorePath;
	}
	
	@Override
	public String getTrustStorePath() {
		return trustStorePath;
	}

	public void setTrustStorePath(String trustStorePath) {
		this.trustStorePath = trustStorePath;
	}
	
	@Override
	public String getKeyStorePassword() {
		return keyStorePassword;
	}

	public void setKeyStorePassword(String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}

	@Override
	public String getTrustStorePassword() {
		return trustStorePassword;
	}

	public void setTrustStorePassword(String trustStorePassword) {
		this.trustStorePassword = trustStorePassword;
	}

	@Override
	public int getPort() {
		return port;
	}
	
	public void setPort(int port) {
		this.port = port;
	}
	
	@Override
	public List<String> getServers() {
		return servers;
	}
	
	public void setServers(List<String> servers) {
		this.servers = servers;
	}
		
	@Override
	public int getTlsPort() {
		return tlsPort;
	}

	@Override
	public Certificate getCert() {
		return cert;
	}

	public void setCert(String cert) {
		try {
			this.cert = CertificateUtil.decodePemCert(cert);
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}
	
	public void setCert(Certificate cert) {
		this.cert = cert;
	}

	public void setTlsPort(int tlsPort) {
		this.tlsPort = tlsPort;
	}

	public Map<String, Authorization> getAuthorizationCookies() {
		return authorizationCookies;
	}

	public void setAuthorizationCookies(Map<String, Authorization> authorizationCookies) {
		this.authorizationCookies = authorizationCookies;
	}

	public String getMyAuthorizationCookie() {
		return myAuthorizationCookie;
	}

	public void setMyAuthorizationCookie(String myAuthorizationCookie) {
		this.myAuthorizationCookie = myAuthorizationCookie;
	}

	public String getIssuerId() {
		return issuerId;
	}

	public void setIssuerId(String issuerId) {
		this.issuerId = issuerId;
	}
}
