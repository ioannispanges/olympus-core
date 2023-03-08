package eu.olympus.client;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.CredentialStorage;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.Operation;
import eu.olympus.model.PSCredential;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.PresentationToken;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.PolicyUnfulfilledException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.model.exceptions.TokenGenerationException;
import eu.olympus.server.interfaces.PabcIdP;
import eu.olympus.util.Pair;
import eu.olympus.util.multisign.MS;
import eu.olympus.util.multisign.MSmessage;
import eu.olympus.util.multisign.MSpublicParam;
import eu.olympus.util.multisign.MSsignature;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.multisign.MSzkToken;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSauxArg;
import eu.olympus.util.psmultisign.PSmessage;
import eu.olympus.util.psmultisign.PSms;
import eu.olympus.util.psmultisign.PSpublicParam;
import eu.olympus.util.psmultisign.PSverfKey;
import eu.olympus.util.rangeProof.RangePredicateToken;
import eu.olympus.util.rangeProof.RangeProver;
import eu.olympus.util.rangeProof.model.PedersenBase;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

//TODO For exceptions, add at least three types: SetupException, PolicyUnfulfilledException, TokenGenerationException (for when combination fails)
public class PSCredentialManagement implements CredentialManagement {

	private CredentialStorage credentialStorage;
    private MS multiSignatureScheme;
    private Set<AttributeDefinition> attributeDefinitions;
    private Map<String,AttributeDefinition> attrDefMap; // Key will have the AttrDefId in lower case
    private MSpublicParam schemePublicParameters;
    private MSverfKey olympusVerificationKey;
    private PairingBuilder builder;
    private Map<Integer,MSverfKey> verfKeysIdPs;
    private boolean storage;
    int numberOfIdPs;
    
    public PSCredentialManagement(boolean storage, CredentialStorage credentialStorage) {
    	this.storage = storage;
    	if(storage && credentialStorage==null)
    		throw new IllegalArgumentException("If credentials are going to be stored a Credential Storage must be provided");
    	this.credentialStorage=credentialStorage;
	}

	public void setup(List<? extends PabcIdP> servers, byte[] seed) throws OperationFailedException, SetupException {
		numberOfIdPs=servers.size();
		PabcPublicParameters pp=servers.get(0).getPabcPublicParam();
		try {
			schemePublicParameters = new PSpublicParam(pp.getEncodedSchemePublicParam());
		} catch (InvalidProtocolBufferException e) {
			throw new SetupException("Could not retrieve scheme public param",e);
		}
		attributeDefinitions=pp.getAttributeDefinitions();
		if(!checkAttributeDefinitions())
			throw new SetupException("Conflicting sets of attribute names");
		multiSignatureScheme = new PSms();
		PSauxArg auxArg = (PSauxArg) schemePublicParameters.getAuxArg();
		try {
			multiSignatureScheme.setup(schemePublicParameters.getN(), auxArg, seed);
			builder = (PairingBuilder) Class.forName(auxArg.getPairingName()).newInstance();
			builder.seedRandom(seed);
		} catch (Exception e) {
			throw new SetupException("Could not create scheme",e);
		}
		MSverfKey[] verificationKeySharesArray = new MSverfKey[servers.size()];
		verfKeysIdPs=new HashMap<>();
		for (int i = 0; i < servers.size(); i++) {
			verificationKeySharesArray[i] = servers.get(i).getPabcPublicKeyShare(); //TODO Concurrent
			verfKeysIdPs.put(i,verificationKeySharesArray[i]);
		}
		this.olympusVerificationKey = multiSignatureScheme.kAggreg(verificationKeySharesArray);
		this.attrDefMap=attributeDefinitions.stream().collect(Collectors.toMap(e-> e.getId().toLowerCase(),
                Function.identity()));
    }

	public void setup(PabcPublicParameters publicParameters, Map<Integer, MSverfKey> verificationKeyShares, byte[] seed) throws SetupException {
    	attributeDefinitions=publicParameters.getAttributeDefinitions();
		try {
			schemePublicParameters = new PSpublicParam(publicParameters.getEncodedSchemePublicParam());
		} catch (InvalidProtocolBufferException e) {
			throw new SetupException("Could not retrieve scheme public param", e);
		}
		if(!checkAttributeDefinitions())
			throw new SetupException("Conflicting sets of attribute names");
		multiSignatureScheme = new PSms();
		this.numberOfIdPs = schemePublicParameters.getN();
		PSauxArg auxArg = (PSauxArg) schemePublicParameters.getAuxArg();
		try {
			multiSignatureScheme.setup(numberOfIdPs, auxArg, seed);
		} catch (MSSetupException e) {
			throw new SetupException("Wrong public parameters", e);
		}
		if (verificationKeyShares.keySet().size() != numberOfIdPs)
			throw new IllegalArgumentException("Incorrect number of verification key shares");
		this.verfKeysIdPs = verificationKeyShares;
		try {
			builder = (PairingBuilder) Class.forName(auxArg.getPairingName()).newInstance();
			builder.seedRandom(seed);
		} catch (Exception e) {
			// Should never get here as setup of the scheme requires being able to do this instruction successfully
			throw new SetupException("Failed to retrieve Pairing Builder", e);
		}
		MSverfKey[] verificationKeySharesArray = new MSverfKey[verificationKeyShares.keySet().size()];
		int i = 0;
		for (MSverfKey vk : verificationKeyShares.values()) {
			verificationKeySharesArray[i] = vk;
			i++;
		}
		this.olympusVerificationKey = multiSignatureScheme.kAggreg(verificationKeySharesArray);
        this.attrDefMap=attributeDefinitions.stream().collect(Collectors.toMap(e-> e.getId().toLowerCase(),
                Function.identity()));
	}

	public void setupForOffline(PabcPublicParameters publicParameters, MSverfKey olympusVerificationKey, byte[] seed) throws SetupException {
		attributeDefinitions=publicParameters.getAttributeDefinitions();
		try {
			schemePublicParameters = new PSpublicParam(publicParameters.getEncodedSchemePublicParam());
		} catch (InvalidProtocolBufferException e) {
			throw new SetupException("Could not retrieve scheme public param",e);
		}
		if(!checkAttributeDefinitions())
			throw new IllegalArgumentException("Conflicting sets of attribute names");
		multiSignatureScheme = new PSms();
		this.numberOfIdPs = schemePublicParameters.getN();
		PSauxArg auxArg = (PSauxArg) schemePublicParameters.getAuxArg();
		try {
			multiSignatureScheme.setup(numberOfIdPs, auxArg, seed);
		} catch (MSSetupException e) {
			throw new SetupException("Wrong public parameters");
		}
		try {
			builder = (PairingBuilder) Class.forName(auxArg.getPairingName()).newInstance();
			builder.seedRandom(seed);
		} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
			throw new SetupException("Failed to retrieve Pairing Builder",e);
			// Should never get here as setup of the scheme requires being able to do this instruction successfully
		}
		this.olympusVerificationKey = olympusVerificationKey;
        this.attrDefMap=attributeDefinitions.stream().collect(Collectors.toMap(e-> e.getId().toLowerCase(),
                Function.identity()));
	}

	private boolean checkAttributeDefinitions() {
    	Set<String> attrIds=attributeDefinitions.stream().map(e-> e.getId().toLowerCase()).collect(Collectors.toSet());
		return attrIds.equals(((PSauxArg) schemePublicParameters.getAuxArg()).getAttributes());
	}

	public Pair<PabcPublicParameters,Map<Integer,MSverfKey>> getPublicParams(){
    	if(schemePublicParameters ==null || verfKeysIdPs==null)
    		throw new IllegalStateException("No setup was performed");
		return new Pair<>(new PabcPublicParameters(attributeDefinitions,schemePublicParameters.getEncoded()),verfKeysIdPs);
	}

	public Pair<PabcPublicParameters,MSverfKey> getPublicParamsForOffline(){
		if(schemePublicParameters ==null || olympusVerificationKey==null)
			throw new IllegalStateException("No setup was performed");
		return new Pair<>(new PabcPublicParameters(attributeDefinitions,schemePublicParameters.getEncoded()),olympusVerificationKey);
	}

	@Override
	public PresentationToken generatePresentationToken(Policy policy) throws TokenGenerationException {
		if (multiSignatureScheme == null) {
			throw new IllegalStateException("It is necessary to run setup (or offlineSetup) before using this method");
		}
		if (credentialStorage==null || !credentialStorage.checkCredential()) {
			throw new IllegalStateException("No credential available to derive the presentation token");
		}
		try {
			return tokenFromPolicyAndCredential(policy, credentialStorage.getCredential());
		} catch (PolicyUnfulfilledException e){
			throw new TokenGenerationException("Failed to produce token", e);
		}
	}

	@Override
	public PresentationToken combineAndGeneratePresentationToken(Map<Integer, PSCredential> credentialShares,
			Policy policy) throws TokenGenerationException {
		if (verfKeysIdPs == null)
			throw new IllegalStateException("It is necessary to run setup before using this method");
		if (numberOfIdPs != credentialShares.keySet().size())
			throw new IllegalArgumentException("Incorrect number of credentialShares");
		MSverfKey[] verificationKeys = new MSverfKey[numberOfIdPs];
		MSsignature[] psCredentialShares = new MSsignature[numberOfIdPs];
		int i = 0;
		for (Integer id : verfKeysIdPs.keySet()) {
			verificationKeys[i] = verfKeysIdPs.get(id); // instead of i use id
			PSCredential aux = credentialShares.get(id);
			if (aux == null)
				throw new TokenGenerationException("No credential share from required IdP");
			psCredentialShares[i] = aux.getSignature();
			i++;
		}
		PSCredential anyCredential = credentialShares.values().iterator().next();
		long epoch = anyCredential.getEpoch();
		Map<String, Attribute> attributes = anyCredential.getAttributes();
		MSsignature aggSign = null;
		try {
			aggSign = multiSignatureScheme.comb(verificationKeys, psCredentialShares);
			Map<String, ZpElement> attributeZpValues = new HashMap<>();
			for (AttributeDefinition attr : attributeDefinitions) {
				Attribute val = attributes.get(attr.getId().toLowerCase());
				ZpElement valTransform = val == null ? builder.getZpElementZero() : builder.getZpElementFromAttribute(val, attr);
				attributeZpValues.put(attr.getId().toLowerCase(), valTransform);
			}
			if(!multiSignatureScheme.verf(olympusVerificationKey,new PSmessage(attributeZpValues,builder.getZpElementFromEpoch(epoch)),aggSign))
				throw new TokenGenerationException("Failed to generate token");
		} catch (Exception e) {
			throw new TokenGenerationException("Failed to generate token",e);
		}
		PSCredential temporalCredential = new PSCredential(epoch, attributes, aggSign);
		if (storage) {
			credentialStorage.storeCredential(temporalCredential);
		}
			try {
				return tokenFromPolicyAndCredential(policy, temporalCredential);
			} catch (PolicyUnfulfilledException e){
				throw new TokenGenerationException("Failed to produce token", e);
			}
    }

    private PresentationToken tokenFromPolicyAndCredential(Policy policy, PSCredential temporalCredential) throws PolicyUnfulfilledException {
        Map<String, ZpElement> attributeZpValues = new HashMap<>();
        for (AttributeDefinition attr : attributeDefinitions) {
            Attribute val = temporalCredential.getElement(attr.getId().toLowerCase());
            ZpElement valTransform = val == null ? builder.getZpElementZero() : builder.getZpElementFromAttribute(val, attr);
            attributeZpValues.put(attr.getId().toLowerCase(), valTransform);
        }
        Set<String> attributesToReveal = new HashSet<>();
        Set<String> attributesForRange = new HashSet<>();
        List<Predicate> rangePredicates = new LinkedList<>();
        for (Predicate p : policy.getPredicates()) {
        	if (p.getOperation() == Operation.REVEAL) {
                //TODO It should be possible to support "equals" operation (crypto would be the same as reveal, but verifier would use the "requested value" when verifying instead of a value "revealed" by the user within the presentation
            	attributesToReveal.add(p.getAttributeName().toLowerCase());
            } else if (p.getOperation() == Operation.INRANGE || p.getOperation() == Operation.GREATERTHANOREQUAL || p.getOperation() == Operation.LESSTHANOREQUAL) {
                rangePredicates.add(p);
                attributesForRange.add(p.getAttributeName().toLowerCase());
            } else {
                throw new PolicyUnfulfilledException("Could not satisfy policy: " + p.getOperation() + " is not supported for dp-ABC");
            }
        }
        if (!temporalCredential.getAttributes().keySet().containsAll(attributesToReveal))
            throw new PolicyUnfulfilledException("Could not satisfy policy: credential does not contain every requested attribute");
        if (!temporalCredential.getAttributes().keySet().containsAll(attributesForRange))
            throw new PolicyUnfulfilledException("Could not satisfy policy: credential does not contain every requested attribute for range predicate");
        if (attributesForRange.size() != rangePredicates.size())
            throw new PolicyUnfulfilledException("Repeated attribute ID in different range predicates");
        Map<String, Attribute> revealedAttributes = temporalCredential.getAttributes().entrySet().stream()
                .filter(e -> attributesToReveal.contains(e.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        MSmessage signedAttributes = new PSmessage(attributeZpValues,
                builder.getZpElementFromEpoch(temporalCredential.getEpoch()));
        if (rangePredicates.isEmpty()) {
            MSzkToken token = multiSignatureScheme.presentZKtoken(olympusVerificationKey, attributesToReveal,
                    signedAttributes, policy.getPolicyId(), temporalCredential.getSignature());
            return new PresentationToken(temporalCredential.getEpoch(), revealedAttributes, token, null);
        } else {
            Map<String, RangePredicateToken> rangePredicateTokenMap = new HashMap<>();
            RangeProver prover = new RangeProver(policy.getPolicyId(), builder);
            PSverfKey key = (PSverfKey) olympusVerificationKey;
            for (Predicate p : rangePredicates) {
//We know definitions/keys are present because we checked that the attribute is in the credential (only those that are "defined" would be included in a cred)
                String attrId = p.getAttributeName().toLowerCase();
                AttributeDefinition definition = attrDefMap.get(attrId);
                PedersenBase base = new PedersenBase(key.getVY().get(attrId), key.getVX()); //Base has to be g=Y_j h=X
                rangePredicateTokenMap.put(attrId, prover.generateRangePredicateToken(base, temporalCredential.getElement(attrId), definition, p));
            }
            MSzkToken token = multiSignatureScheme.presentZKtokenModified(olympusVerificationKey, attributesToReveal,
                    prover.getGeneratedCommitments(), signedAttributes, policy.getPolicyId(), temporalCredential.getSignature());
            return new PresentationToken(temporalCredential.getEpoch(), revealedAttributes, token, rangePredicateTokenMap);
        }
    }

	@Override
	public void clearCredential() {
		credentialStorage.deleteCredential();
	}

	@Override
	public boolean checkStoredCredential() {
		if (!storage) {
			return false;
		}
		return credentialStorage.checkCredential();
	}
}
