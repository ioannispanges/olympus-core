package oidc.controller;

import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeIdentityProof;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.ExistingUserException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import oidc.model.AttributeContainer;
import oidc.model.ChangeAttributesRequest;
import oidc.model.ChangePasswordRequest;
import oidc.model.CreateUserRequest;
import oidc.model.DeleteAccountRequest;
import oidc.model.LoginRequest;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class OidcController {

    private static final Logger logger = LoggerFactory.getLogger(OidcController.class);

    @Autowired
    UserClient userClient;

    @Autowired
    Policy policy;

    // Login
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(Model model, @RequestParam String redirect_uri, @RequestParam String state, @RequestParam String nonce, HttpServletRequest request) {
        request.getSession().setAttribute("redirectUrl", redirect_uri);
        request.getSession().setAttribute("state", state);
        request.getSession().setAttribute("nonce", nonce);
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        policy.setPolicyId(nonce);
        return "/login";
    }

    @RequestMapping(value = "/loginFailed", method = RequestMethod.GET)
    public String login(Model model) {
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        model.addAttribute("loginError", true);
        return "/login";
    }

    @RequestMapping(value = "/loginPage", method = RequestMethod.GET)
    public String loginPage(Model model) {
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        model.addAttribute("hasCreated", false);
        return "/login";
    }

    @PostMapping("/authenticate")
    public RedirectView authenticate(LoginRequest loginRequest, Model model, HttpServletRequest request) throws AuthenticationFailedException, TokenGenerationException {
        try {
            policy.getPredicates().add(new Predicate("audience", Operation.REVEAL, new Attribute("olympus-service-provider")));
            String token = userClient.authenticate(loginRequest.getUsername(), loginRequest.getPassword(), policy, null, "NONE");
            model.addAttribute("username", loginRequest.getUsername());
            model.addAttribute("token", token);
            
            String redirectUrl = (String) request.getSession().getAttribute("redirectUrl");
            String state = (String) request.getSession().getAttribute("state");
            return new RedirectView(redirectUrl + "#state=" + state + "&id_token=" + token + "&token_type=bearer");
        } catch (Exception e) {
            if (ExceptionUtils.indexOfThrowable(e, AuthenticationFailedException.class) != -1) {
                return new RedirectView("/loginFailed", true);
            } else {
                throw e;
            }
        } finally {
            userClient.clearSession();
        }
    }

    // Logout

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout(Model model, HttpServletRequest request) throws ServletException {
        userClient.clearSession();
        request.getSession().removeAttribute("name");
        request.getSession().removeAttribute("email");
        request.getSession().removeAttribute("birthdate");
        request.getSession().setAttribute("loggedIn", false);
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        model.addAttribute("hasCreated", false);
        return "/login";
    }

    // Create User
    @RequestMapping(value = "/createUser", method = RequestMethod.GET)
    public String createNewUser(Model model) {
        model.addAttribute("userExists", false);
        CreateUserRequest createUserRequest = new CreateUserRequest();
        model.addAttribute("createUserRequest", createUserRequest);
        return "/createUser";
    }

    @RequestMapping(value = "/createUser", method = RequestMethod.POST)
    public String postUser(@Valid @ModelAttribute("createUserRequest")CreateUserRequest createUserRequest, BindingResult bindingResult, Model model) {
        if (bindingResult.hasErrors()) {
            return "/createUser";
        }
        try {
            IdentityProof identityProof = constructIdentityProof(createUserRequest);
            userClient.createUserAndAddAttributes(createUserRequest.getUsername(), createUserRequest.getPassword(), identityProof);
        } catch (Exception exception) {
            if (ExceptionUtils.indexOfThrowable(exception, ExistingUserException.class) != -1) {
                model.addAttribute("userExists", true);
            } else if (ExceptionUtils.indexOfThrowable(exception, AuthenticationFailedException.class) != -1) {
                model.addAttribute("userExists", true);
            } else if (ExceptionUtils.indexOfThrowable(exception, UserCreationFailedException.class) != -1) {
                model.addAttribute("userExists", true);
            } else {
                model.addAttribute("unknownError", true);
            }
            logger.warn("Create user failed: " + exception);
            return "/createUser";
        }
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        model.addAttribute("hasCreated", true);
        userClient.clearSession();
        return "/login";
    }

    private AttributeIdentityProof constructIdentityProof(CreateUserRequest createUserRequest) {
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("name", new Attribute(createUserRequest.getName()));
        attributes.put("given_name", new Attribute(createUserRequest.getFirstname()));
        attributes.put("family_name", new Attribute(createUserRequest.getLastname()));
        attributes.put("birthdate",new Attribute(createUserRequest.getBirthdate()));
        attributes.put("vaccinationDate",new Attribute(createUserRequest.getVaccinationDate()));
        attributes.put("email", new Attribute(createUserRequest.getEmail()));
        return new AttributeIdentityProof(attributes);
    }

    @RequestMapping(value = "manageAccountPage", method = RequestMethod.GET)
    public String manageAccountPage(Model model, HttpServletRequest request) {
        if (request.getSession().getAttribute("loggedIn") == null || !(boolean) request.getSession().getAttribute("loggedIn")) {
            return getFrontpage(model);
        }
        model.addAttribute("name", request.getSession().getAttribute("name"));
        return "/manageAccount";
    }

    @RequestMapping(value = "manageAccountLogin", method = RequestMethod.GET)
    public String manageAccountLogin(Model model) {
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        return "/manageAccountLogin";
    }

    @PostMapping("/manageAccountAuthenticate")
    public RedirectView manageAccountAuthenticate(LoginRequest loginRequest, Model model, HttpServletRequest request) throws AuthenticationFailedException, OperationFailedException {
        try {
            String token = userClient.authenticate(loginRequest.getUsername(), loginRequest.getPassword(), policy, null, "NONE");
            Map<String, Attribute> attributes = userClient.getAllAttributes();
            request.getSession().setAttribute("loggedIn", true);
            request.getSession().setAttribute("name", attributes.get("name").getAttr());
            request.getSession().setAttribute("email", attributes.get("email").getAttr());
            request.getSession().setAttribute("birthdate", attributes.get("birthdate").getAttr());
            model.addAttribute("name", attributes.get("name"));
            model.addAttribute("token", token);
            return new RedirectView("/manageAccountPage", true);
        } catch (Exception e) {
            userClient.clearSession();
            if (ExceptionUtils.indexOfThrowable(e, AuthenticationFailedException.class) != -1) {
                model.addAttribute("loginError", true);
                return new RedirectView("/manageAccountLogin", true);
            } else {
                throw e;
            }
        }
    }


    // Change password

    @RequestMapping(value = "/changePassword", method = RequestMethod.GET)
    public String changePassword(Model model, HttpServletRequest request) {
        if(request.getSession().getAttribute("loggedIn") == null || !(boolean) request.getSession().getAttribute("loggedIn")){
            return getFrontpage(model);
        }
        ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
        model.addAttribute("changePasswordRequest", changePasswordRequest);
        return "/changePassword";
    }


    @PostMapping("/changePassword")
    public String postChangePassword(@Valid ChangePasswordRequest changePasswordRequest, BindingResult bindingResult, Model model) {
        if (bindingResult.hasErrors()) {
            return "/changePassword";
        }
        try {
            userClient.changePassword(changePasswordRequest.getUsername(), changePasswordRequest.getOldPassword(), changePasswordRequest.getNewPassword(), null, "NONE");
        } catch (Exception exception) {
            if (ExceptionUtils.indexOfThrowable(exception, UserCreationFailedException.class) != -1) {
                model.addAttribute("passwordChangeError", true);
            } else if (ExceptionUtils.indexOfThrowable(exception, AuthenticationFailedException.class) != -1) {
                model.addAttribute("usernameWrongError", true);
            } else {
                model.addAttribute("unknownError", true);
            }
            logger.warn("Change password failed: " + exception);
            return "/changePassword";
        }

        model.addAttribute("hasChanged", true);
        return "/manageAccount";
    }

    // Delete account

    @RequestMapping(value = "/deleteAccount", method = RequestMethod.GET)
    public String deleteAccount(Model model, HttpServletRequest request) {
        if(request.getSession().getAttribute("loggedIn") == null || !(boolean) request.getSession().getAttribute("loggedIn")){
            return getFrontpage(model);
        }
        DeleteAccountRequest deleteRequest = new DeleteAccountRequest();
        model.addAttribute("deleteRequest", deleteRequest);
        return "/deleteAccount";
    }


    @PostMapping("/deleteAccount")
    public String postDeleteAccount(DeleteAccountRequest deleteRequest, Model model) {
        try {
            userClient.deleteAccount(deleteRequest.getUsername(),deleteRequest.getPassword(), null, "NONE");
        } catch (Exception exception) {
            if (ExceptionUtils.indexOfThrowable(exception, AuthenticationFailedException.class) != -1) {
                model.addAttribute("userDeletionError", true);
            } else {
                model.addAttribute("unknownError", true);
            }
            model.addAttribute("deleteRequest", deleteRequest);
            return "/deleteAccount";
        }
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        model.addAttribute("hasDeletedAccount", true);
        return "/login";
    }

    // Change attributes

    @RequestMapping(value = "changeAttributes", method = RequestMethod.GET)
    public String changeAttributesPage(Model model, HttpServletRequest request) {
        if(request.getSession().getAttribute("loggedIn") == null || !(boolean) request.getSession().getAttribute("loggedIn")){
            return getFrontpage(model);
        }
        ChangeAttributesRequest changeAttributesRequest = new ChangeAttributesRequest();
        String name = (String) (request.getSession().getAttribute("name"));
        String email = (String) (request.getSession().getAttribute("email"));
        Date birthdate = (Date) (request.getSession().getAttribute("birthdate"));

        changeAttributesRequest.setName(name);
        changeAttributesRequest.setBirthdate(birthdate);
        changeAttributesRequest.setEmail(email);

        model.addAttribute("changeAttributesRequest", changeAttributesRequest);
        return "/changeAttributes";
    }

    @PostMapping("changeAttributes")
    public String postChangeAttributes(ChangeAttributesRequest changeAttributesRequest, Model model, HttpServletRequest request) {
        try {
            IdentityProof identityProof = constructIdentityProof(changeAttributesRequest);
            userClient.addAttributes(identityProof);
        } catch (Exception exception) {
            if (ExceptionUtils.indexOfThrowable(exception, ExistingUserException.class) != -1) {
                model.addAttribute("userExists", true);
            } else if (ExceptionUtils.indexOfThrowable(exception, AuthenticationFailedException.class) != -1) {
                model.addAttribute("userExists", true);
            } else {
                model.addAttribute("unknownError", true);
            }
            logger.warn("Changing attributes failed: " + exception);
            logger.warn(exception.getCause().toString());
            return "/changeAttributes";
        }
        model.addAttribute("name", changeAttributesRequest.getName());
        model.addAttribute("hasChanged", true);

        request.getSession().setAttribute("name", changeAttributesRequest.getName());
        request.getSession().setAttribute("email", changeAttributesRequest.getEmail());
        request.getSession().setAttribute("birthdate", changeAttributesRequest.getBirthdate());
        return "/manageAccount";
    }


    private AttributeIdentityProof constructIdentityProof(AttributeContainer createUserRequest) {
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("name", new Attribute(createUserRequest.getName()));
        attributes.put("birthdate", new Attribute(createUserRequest.getBirthdate()));
        attributes.put("email", new Attribute(createUserRequest.getEmail()));
        return new AttributeIdentityProof(attributes);
    }

    private String getFrontpage(Model model) {
        LoginRequest loginRequest = new LoginRequest();
        model.addAttribute("loginRequest", loginRequest);
        return "/login";
    }

}
