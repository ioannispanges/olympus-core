package oidc.model;

import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * A container for a change password request
 */
@Getter
@Setter
public class ChangePasswordRequest {

    @NotBlank(message = "Can't be empty")
    private String username;
    @NotBlank(message = "Can't be empty")
    private String oldPassword;

    @Size(min = 4, message = "Must have more than 4 symbols")
    private String newPassword;

    private String passwordCheck;
    private boolean passwordsEqual;


    @AssertTrue(message = "Passwords should match")
    public boolean isPasswordsEqual() {
        if(newPassword != null){
            return newPassword.equals(passwordCheck);
        }
        return false;
    }
}
