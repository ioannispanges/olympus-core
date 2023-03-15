package oidc.model;

import lombok.Getter;
import lombok.Setter;

/**
 * A container for a login request
 */
@Getter
@Setter
public class LoginRequest {

    private String username;
    private String password;
}
