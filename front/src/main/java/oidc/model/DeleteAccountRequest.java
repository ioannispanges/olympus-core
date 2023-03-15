package oidc.model;


import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * A container for a delete account request
 */
@Getter
@Setter
public class DeleteAccountRequest {
    @NotBlank(message = "Can't be empty")
    private String username;
    @NotBlank(message = "Can't be empty")
    private String password;

    private String passwordCheck;
    private boolean passwordsEqual;


    @AssertTrue(message = "Passwords should match")
    public boolean isPasswordsEqual() {
        if(password != null){
            return password.equals(passwordCheck);
        }
        return false;
    }
}
