package eu.olympus.model.server.rest;

public class PasswordAuthentication {
  private UsernameAndPassword usernameAndPassword;
  private String cookie;

  public PasswordAuthentication(UsernameAndPassword usernameAndPassword, String cookie) {
    this.usernameAndPassword = usernameAndPassword;
    this.cookie = cookie;
  }

  public PasswordAuthentication() {
  }

  public UsernameAndPassword getUsernameAndPassword() {
    return usernameAndPassword;
  }

  public void setUsernameAndPassword(UsernameAndPassword usernameAndPassword) {
    this.usernameAndPassword = usernameAndPassword;
  }

  public String getCookie() {
    return cookie;
  }

  public void setCookie(String cookie) {
    this.cookie = cookie;
  }
}
