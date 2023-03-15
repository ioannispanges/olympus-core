package oidc.model;


import java.util.Date;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.springframework.format.annotation.DateTimeFormat;

/**
 * A container for a login request
 */
@Getter
@Setter
public class ChangeAttributesRequest implements AttributeContainer {

    @NotBlank(message = "Can't be empty")
    @Size(min=1, message = "Must not be empty")
    private String name;

    @NotNull(message = "Can't be empty")
    @Size(min=1, message = "Must not be empty")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date birthdate;

    @NotNull(message = "Can't be empty")
    @Size(min=1, message = "Must not be empty")
    private String email;

    public Date getDateBirthdate(){
        return birthdate;
    }
}
