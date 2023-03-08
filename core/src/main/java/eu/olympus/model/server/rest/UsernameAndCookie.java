package eu.olympus.model.server.rest;

public class UsernameAndCookie {

  private String username;
  private String cookie;


  public UsernameAndCookie(String username, String cookie) {
    this.username = username;
    this.cookie = cookie;
  }

  public UsernameAndCookie() {
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getCookie() {
    return cookie;
  }

  public void setCookie(String cookie) {
    this.cookie = cookie;
  }

}
