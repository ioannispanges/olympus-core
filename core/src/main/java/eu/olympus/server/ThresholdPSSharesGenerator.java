package eu.olympus.server;

import eu.olympus.model.*;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.server.interfaces.CredentialGenerator;
import eu.olympus.server.interfaces.PABCConfiguration;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.util.Pair;
import eu.olympus.util.multisign.*;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.*;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ThresholdPSSharesGenerator implements CredentialGenerator {

    private static final String PAIRING_NAME="eu.olympus.util.pairingBLS461.PairingBuilderBLS461";
    private long timestampLeeway;
    private PSms multiSignatureScheme;
    private MSprivateKey privateKey;
    private MSverfKey publicKey;
    private Storage database;
    private long lifetime;
    private PairingBuilder builder;
    private Set<AttributeDefinition> attributeDefinitions;
    MSpublicParam publicParameters;

    public ThresholdPSSharesGenerator(Storage database,byte[] seed) throws SetupException {
        this.database = database;
        multiSignatureScheme = new PSms();
        try {
        	builder=(PairingBuilder) Class.forName(PAIRING_NAME).newInstance();
        	builder.seedRandom(seed);
        } catch (Exception e) {
              throw new SetupException("Could not initialize builder with name "+ PAIRING_NAME, e);
        }
    }

    public void setLifetime(long lifetime) {
        this.lifetime = lifetime;
    }

    @Override
    public MSpublicParam setup(PABCConfiguration configuration) {
        attributeDefinitions=configuration.getAttrDefinitions();
        MSauxArg schemeAuxArg=new PSauxArg(PAIRING_NAME,attributeDefinitions.stream().map(e->e.getId().toLowerCase()).collect(Collectors.toSet()));
        try {
            publicParameters=multiSignatureScheme.setup(configuration.getServers().size()+1, schemeAuxArg, configuration.getSeed());
        } catch (MSSetupException e) {
            throw new RuntimeException("Could not setup Pabc scheme");
        }
        Pair<MSprivateKey,MSverfKey> keys= multiSignatureScheme.kg();
        privateKey=keys.getFirst();
        publicKey=keys.getSecond();
        lifetime = configuration.getLifetime();
        this.timestampLeeway = configuration.getAllowedTimeDifference();
        return publicParameters;
    }

    @Override
    public MSverfKey getVerificationKeyShare() {
        if(!multiSignatureScheme.isSetup()){
            throw new IllegalStateException("It is necessary to run setup before using this method");
        }
        return publicKey;
    }

    @Override
    public PabcPublicParameters getPublicParam() {
        return new PabcPublicParameters(attributeDefinitions,publicParameters.getEncoded());
    }

    @Override
    public PSCredential createCredentialShare(String username, long timestamp) throws OperationFailedException {
        if(!multiSignatureScheme.isSetup()){
            throw new IllegalStateException("It is necessary to run setup before using this method");
        }
        if(!checkTimestamp(timestamp))
            throw new IllegalArgumentException("Current time not compatible with timestamp");
        long epoch=setExpirationTime(timestamp);
        Map<String, Attribute> userAttributes=database.getAttributes(username); //Check if this is not null (the user is in the database)? It is assumed the user already authenticated.
        Map<String, ZpElement> attributesZpValues=new HashMap<>();
        Map<String,Attribute> attributeValues=new HashMap<>();
        for(AttributeDefinition attrDef: attributeDefinitions){
            Attribute attributeValue = userAttributes.get(attrDef.getId().toLowerCase());
            if(attributeValue!=null && attrDef.checkValidValue(attributeValue)){
                //TODO If we later decide to incorporate "Definition" into storage/idProving checkValidValue will not be necessary. For now if it is not valid we treat it as if it was not stored
                attributeValues.put(attrDef.getId().toLowerCase(),valueForCredential(attributeValue,attrDef));
                attributesZpValues.put(attrDef.getId().toLowerCase(),builder.getZpElementFromAttribute(attributeValue,attrDef));
            }
            else{
                attributesZpValues.put(attrDef.getId().toLowerCase(),builder.getZpElementZero());
            }
        }
        MSsignature signature= multiSignatureScheme.sign(privateKey,new PSmessage(attributesZpValues,builder.getZpElementFromEpoch(epoch)));
        return new PSCredential(epoch,attributeValues,signature);
    }

    private long setExpirationTime(long timestamp){
        return timestamp+lifetime;
    }

    private boolean checkTimestamp(long timestamp){
        long current=System.currentTimeMillis();
        return (timestamp<(current+timestampLeeway)) && (timestamp>(current-timestampLeeway));
    }

    private Attribute valueForCredential(Attribute attributeValue,AttributeDefinition definition) {
        if(attributeValue.getType()==AttributeType.DATE){
            //Truncating to the time scale that is actually considered for computations to reflect what is actually signed
            Instant i= ((Date) attributeValue.getAttr()).toInstant();
            return new Attribute(Date.from(i.truncatedTo(((AttributeDefinitionDate)definition).getGranularity().getUnit())));
        }
        else
            return attributeValue;
    }

}
