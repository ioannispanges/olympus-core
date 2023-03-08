package eu.olympus.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.AttributeIdentityProof;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.Storage;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AttributeIdentityProver implements IdentityProver {

    private static Logger logger = LoggerFactory.getLogger(AttributeIdentityProver.class);

    private final Storage storage;

    public AttributeIdentityProver(Storage storage) {
        this.storage = storage;
    }

    //Only validates that the proof is a AttributeIdentityProof
    @Override
    public boolean isValid(String input, String username) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            mapper.readValue(input, AttributeIdentityProof.class);
        } catch (IOException | IllegalArgumentException e) {
            logger.info("Could not read input, and cast to AttributeIdentityProof",e);
            return false;
        }
        return true;
    }


    @Override
    public void addAttributes(String input, String username) {
        ObjectMapper mapper = new ObjectMapper();
        AttributeIdentityProof proof;
        try {
            proof = mapper.readValue(input, AttributeIdentityProof.class);
            storage.addAttributes(username, proof.getAttributes());
        } catch (IOException | OperationFailedException e) {
            logger.error("Could not add attributes", e);
            throw new RuntimeException("Failed to add attributes.",e);
        }

    }
}
