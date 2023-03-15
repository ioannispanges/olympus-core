package oidc.controller;

import com.nimbusds.jose.jwk.RSAKey;
import oidc.model.DiscoveryLoader;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OidcRestController {

    @Autowired
    DiscoveryLoader discoveryLoader;

    @Autowired
    RSAKey certs;

    @CrossOrigin(origins = "http://localhost:3000")
    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<JSONObject> getDiscovery() {
        return new ResponseEntity<>(discoveryLoader.out(), HttpStatus.OK);
    }

    @CrossOrigin(origins = "http://localhost:3000")
    @GetMapping("/certs")
    public ResponseEntity<JSONObject> getCerts() throws ParseException {
        JSONParser parser = new JSONParser();
        JSONObject certsJson = (JSONObject) parser.parse(certs.toString());
        JSONArray keysArray = new JSONArray();
        keysArray.add(certsJson);
        JSONObject keys = new JSONObject();
        keys.put("keys", keysArray);
        return new ResponseEntity<>(keys, HttpStatus.OK);
    }

}
