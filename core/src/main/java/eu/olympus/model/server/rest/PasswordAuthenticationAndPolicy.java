package eu.olympus.model.server.rest;

import eu.olympus.model.Policy;

public class PasswordAuthenticationAndPolicy extends PasswordAuthentication{

  private Policy policy;

  public PasswordAuthenticationAndPolicy(UsernameAndPassword authentication, String cookie, Policy policy) {
    super(authentication, cookie);
    this.policy = policy;
  }

  public PasswordAuthenticationAndPolicy() {
  }

  public Policy getPolicy() {
    return policy;
  }

  public void setPolicy(Policy policy) {
    this.policy = policy;
  }
}
