package eu.olympus.model;

import java.util.List;

import eu.olympus.server.rest.Role;

public class Authorization {
	
	private String id;
	private List<Role> roles;
	private long expiration;

	public Authorization() {
	}
	
	public Authorization(String id, List<Role> roles, long expires) {
		this.id = id;
		this.roles = roles;
		this.setExpiration(expires);
	}

	public List<Role> getRoles() {
		return roles;
	}
	
	public void setRoles(List<Role> roles) {
		this.roles = roles;
	}
	
	public String getId() {
		return id;
	}
	
	public void setId(String id) {
		this.id = id;
	}

	public long getExpiration() {
		return expiration;
	}

	public void setExpiration(long expiration) {
		this.expiration = expiration;
	}
}
