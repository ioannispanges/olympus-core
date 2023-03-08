package eu.olympus.util.rangeProof;

import eu.olympus.model.*;
import eu.olympus.util.Util;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.rangeProof.model.PedersenBase;
import eu.olympus.util.rangeProof.model.RangeProofBase;
import eu.olympus.util.rangeProof.tools.RangeProofVerifier;
import eu.olympus.util.rangeProof.tools.Utils;

import java.util.Date;

/**
 * Exposes high level abstraction of Range Proofs to be used by the OL verifier. Idea is to create a new RangeVerifier for each presentation process
 * (mimicking the behaviour of the prover, though in this case it is not really necessary to do so)
 */
public class RangeVerifier {

    private PairingBuilder builder;
    private String salt;
    private ZpElement one;
    private ZpElement two;

    public RangeVerifier(String salt, PairingBuilder builder) {
        this.builder = builder;
        this.salt = salt;
        one=builder.getZpElementOne();
        two=one.add(one);
    }


    /**
     * Verify the validity of a token for a range predicate proof.
     * @param base Base used for the Pedersen commitment (for use in PSPABCVerifier it will be h=X, g=Y_{attrDefId}).
     * @param token Token we want to check
     * @param definition The corresponding attribute definition. It has to be "numerical" (Integer or Date)
     * @param predicate The predicate we want to test
     * @return
     */
    public RangePredicateVerificationResult verifyRangePredicate(PedersenBase base,RangePredicateToken token, AttributeDefinition definition, Predicate predicate){
        if(!(definition instanceof AttributeDefinitionInteger || definition instanceof AttributeDefinitionDate))
            throw new IllegalArgumentException("Must be a supported 'numerical' attribute definition for a range proof");
        if(!definition.getId().equalsIgnoreCase(predicate.getAttributeName())){
            throw new IllegalArgumentException("Not corresponding");
        }
        if(predicate.getValue()==null || !definition.checkValidValue(predicate.getValue()))
            throw new IllegalArgumentException("Predicate value not valid for definition");
        switch (predicate.getOperation()){
            case LESSTHANOREQUAL:
                return verifyRangePredicateLessThan(base,token,definition,predicate.getValue());
            case GREATERTHANOREQUAL:
                return verifyRangePredicateGreaterThan(base,token,definition,predicate.getValue());
            case INRANGE:
                if(predicate.getExtraValue()==null || !definition.checkValidValue(predicate.getExtraValue()))
                    throw new IllegalArgumentException("Predicate extra value not valid for definition");
                checkRange(predicate.getValue(),predicate.getExtraValue());
                return verifyRangePredicateInRange(base,token,definition,predicate.getValue(),predicate.getExtraValue()); //We could perform check/choose the lower and upper bound from predicate instead of relying on definition
            default:
                throw new IllegalArgumentException("Predicate operation not for range proof: "+predicate.getOperation());
        }
    }

    private RangePredicateVerificationResult verifyRangePredicateLessThan(PedersenBase base,RangePredicateToken token, AttributeDefinition definition, Attribute upperBound) {
        int m= Util.nextPowerOfPowerOfTwo(definition.toBigIntegerRepresentation(upperBound));
        RangeProofBase rangeProofBase= Utils.generateRangeProofBase(m,salt,builder);
        RangeProofVerifier verifier=new RangeProofVerifier(builder);
        ZpElement offset= two.pow(m).sub(one).sub(builder.getZpElementFromAttribute(upperBound,definition));
        Group1Element v=token.getCommitV();    //V
        Group1Element vPrime=v.mul(base.getG().exp(offset)); //V'=V · Y^(offset)
        boolean resultLower=verifier.verify(rangeProofBase,base,v,token.getProofLowerBound()); //Check x>=0 (i.e., no trick with modular arithmetic)
        boolean resultUpper=verifier.verify(rangeProofBase,base,vPrime,token.getProofUpperBound()); //Check x<=upperBound
        return (resultLower&&resultUpper? RangePredicateVerificationResult.VALID : RangePredicateVerificationResult.INVALID);
    }

    private RangePredicateVerificationResult verifyRangePredicateGreaterThan(PedersenBase base,RangePredicateToken token, AttributeDefinition definition, Attribute lowerBound) {
        Attribute upperBound;
        if(definition instanceof AttributeDefinitionInteger){
            upperBound=new Attribute(((AttributeDefinitionInteger) definition).getMaximumValue());
        }else {
            upperBound=new Attribute(((AttributeDefinitionDate) definition).getMaxDate());
        }
        int m= Util.nextPowerOfPowerOfTwo(definition.toBigIntegerRepresentation(upperBound));
        RangeProofBase rangeProofBase= Utils.generateRangeProofBase(m,salt,builder);
        RangeProofVerifier verifier=new RangeProofVerifier(builder);
        ZpElement a= builder.getZpElementFromAttribute(lowerBound,definition);
        Group1Element v=token.getCommitV();    //V
        Group1Element vPrime=v.mul(base.getG().invExp(a)); //V'=V · Y^(-a)
        boolean resultLower=verifier.verify(rangeProofBase,base,vPrime,token.getProofLowerBound()); //Check x>=lowerBound
        boolean resultUpper=verifier.verify(rangeProofBase,base,v,token.getProofUpperBound()); //Check x<=MAX_VALUE (i.e. no trick with modular arithmetic)
        return (resultLower&&resultUpper? RangePredicateVerificationResult.VALID : RangePredicateVerificationResult.INVALID);
    }

    private RangePredicateVerificationResult verifyRangePredicateInRange(PedersenBase base,RangePredicateToken token, AttributeDefinition definition, Attribute lowerBound, Attribute upperBound) {
        int m= Util.nextPowerOfPowerOfTwo(definition.toBigIntegerRepresentation(upperBound));
        RangeProofBase rangeProofBase= Utils.generateRangeProofBase(m,salt,builder);
        RangeProofVerifier verifier=new RangeProofVerifier(builder);
        ZpElement offset= two.pow(m).sub(one).sub(builder.getZpElementFromAttribute(upperBound,definition));
        ZpElement a= builder.getZpElementFromAttribute(lowerBound,definition);
        Group1Element vPrimePrime=token.getCommitV().mul(base.getG().invExp(a));    //V''=V · Y^(-a)
        Group1Element vPrime=token.getCommitV().mul(base.getG().exp(offset));  //V'=V · Y^(offset)
        boolean resultLower=verifier.verify(rangeProofBase,base,vPrimePrime,token.getProofLowerBound()); //Check x>=lowerBound
        boolean resultUpper=verifier.verify(rangeProofBase,base,vPrime,token.getProofUpperBound()); //Check x<=upperBound
        return (resultLower&&resultUpper? RangePredicateVerificationResult.VALID : RangePredicateVerificationResult.INVALID);
    }


    protected void checkRange(Attribute value, Attribute extraValue) {
        switch (value.getType()){
            case INTEGER:
                Integer x1=(Integer)value.getAttr();
                Integer x2=(Integer)extraValue.getAttr();
                if (x1>=x2)
                    throw new IllegalArgumentException("Invalid range lowerBound>=upperBound");
                break;
            case DATE:
                Date d1=(Date)value.getAttr();
                Date d2=(Date)extraValue.getAttr();
                if(d1.after(d2))
                    throw new IllegalArgumentException("Invalid range lowerBound>=upperBound");
                break;
            default:
                throw new IllegalArgumentException("Incompatible type");
        }
    }
}
