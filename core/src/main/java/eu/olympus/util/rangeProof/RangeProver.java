package eu.olympus.util.rangeProof;

import eu.olympus.model.*;
import eu.olympus.util.Util;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.rangeProof.model.PedersenBase;
import eu.olympus.util.rangeProof.model.PedersenCommitment;
import eu.olympus.util.rangeProof.model.RangeProof;
import eu.olympus.util.rangeProof.model.RangeProofBase;
import eu.olympus.util.rangeProof.tools.RangeProofProver;
import eu.olympus.util.rangeProof.tools.Utils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;



/**
 * Exposes high level abstraction of Range Proofs to be used by the OL prover (credMngmnt). Idea is to create a new RangeProver for each presentation process,
 * which generates all the necessary range proofs (and uses the same salt for base generation, for example the policy ID).
 */
public class RangeProver {
    // Need to think how we want to check date ranges (in the sense of "pretty" Age predicates). As it is right now it
    // could be enough (users of the library simply must be aware of how to create the predicate, e.g., check dateOfBirth<=now-18years)
    //TODO For grater_than and less_than we could probably use only one proof (as they are later linked to the credential, which we can
    // trust contains only attribute values in the range set by the attribute definition)
    private Map<String, PedersenCommitment> generatedCommitments;
    private String salt;
    private PairingBuilder builder;
    private ZpElement one;
    private ZpElement two;

    public RangeProver(String salt, PairingBuilder builder){
        generatedCommitments=new HashMap<>();
        this.salt=salt;
        this.builder=builder;
        one=builder.getZpElementOne();
        two=one.add(one);
    }

    //If the range needed corresponds exactly to a [0,2^(2^n)-1] range we could avoid using two proofs (it is a fringe case, but could be "optimized")
    /**
     * Generates a token for a range predicate (lt,gt,inRange), for the attribute value "value" and the corresponding attribute definition.
     * @param base Pedersen base for the proof (for use in PSCredentialManager it will be h=X, g=Y_{attrDefId})
     * @param value The attribute value that we want to prove it fulfils the predicate
     * @param attributeDefinition The corresponding attribute definition. It has to be "numerical" (Integer or Date)
     * @param pred Predicate we want to prove
     * @return
     */
    public RangePredicateToken generateRangePredicateToken(PedersenBase base, Attribute value, AttributeDefinition attributeDefinition, Predicate pred){
        if(!(attributeDefinition instanceof AttributeDefinitionInteger || attributeDefinition instanceof AttributeDefinitionDate))
            throw new IllegalArgumentException("Must be a supported 'numerical' attribute definition for a range proof");
        if(!attributeDefinition.getId().equalsIgnoreCase(pred.getAttributeName())){
            throw new IllegalArgumentException("Not corresponding");
        }
        if(!attributeDefinition.checkValidValue(value))
            throw new IllegalArgumentException("Attribute value not valid for definition");
        if(pred.getValue()==null || !attributeDefinition.checkValidValue(pred.getValue()))
            throw new IllegalArgumentException("Predicate value not valid for definition");
        switch (pred.getOperation()){
            case LESSTHANOREQUAL:
                return generateRangePredicateTokenLessThan(base,value,attributeDefinition,pred.getValue());
            case GREATERTHANOREQUAL:
                return generateRangePredicateTokenGreaterThan(base,value,attributeDefinition,pred.getValue());
            case INRANGE:
                if(pred.getExtraValue()==null || !attributeDefinition.checkValidValue(pred.getExtraValue()))
                    throw new IllegalArgumentException("Predicate extra value not valid for definition");
                checkRange(pred.getValue(),pred.getExtraValue());
                return generateRangePredicateTokenInRange(base,value,attributeDefinition,pred.getValue(),pred.getExtraValue());
            default:
                throw new IllegalArgumentException("Predicate operation not for range proof: "+pred.getOperation());
        }
    }


    private RangePredicateToken generateRangePredicateTokenLessThan(PedersenBase base, Attribute value, AttributeDefinition attributeDefinition, Attribute upperBound) {
        int m= Util.nextPowerOfPowerOfTwo(attributeDefinition.toBigIntegerRepresentation(upperBound));
        RangeProofBase rangeProofBase=Utils.generateRangeProofBase(m,salt,builder);
        RangeProofProver prover=new RangeProofProver(builder);
        ZpElement x=builder.getZpElementFromAttribute(value,attributeDefinition);
        ZpElement gamma=builder.getRandomZpElement();
        ZpElement offset= two.pow(m).sub(one).sub(builder.getZpElementFromAttribute(upperBound,attributeDefinition));
        PedersenCommitment witness=new PedersenCommitment(base.getG(),base.getH(), x, gamma);     //V=X^gamma Y^x
        PedersenCommitment witnessPrime=new PedersenCommitment(base.getG(),base.getH(), x.add(offset), gamma); //V'=X^gamma Y^(x+offset)
        RangeProof proofLowerBound=prover.generateProof(rangeProofBase,witness); //Prove x>=0 (i.e., no trick with modular arithmetic)
        RangeProof proofUpperBound=prover.generateProof(rangeProofBase,witnessPrime); //Prove x<=upperBound
        generatedCommitments.put(attributeDefinition.getId().toLowerCase(),witness);
        return new RangePredicateToken(proofLowerBound,proofUpperBound,witness.getV());
    }

    private RangePredicateToken generateRangePredicateTokenGreaterThan(PedersenBase base, Attribute value, AttributeDefinition attributeDefinition, Attribute lowerBound) {
        Attribute upperBound;
        if(attributeDefinition instanceof AttributeDefinitionInteger){
            upperBound=new Attribute(((AttributeDefinitionInteger) attributeDefinition).getMaximumValue());
        }else { //For now we only support Integer and Date
            upperBound=new Attribute(((AttributeDefinitionDate) attributeDefinition).getMaxDate());
        }
        int m= Util.nextPowerOfPowerOfTwo(attributeDefinition.toBigIntegerRepresentation(upperBound));
        RangeProofBase rangeProofBase=Utils.generateRangeProofBase(m,salt,builder);
        RangeProofProver prover=new RangeProofProver(builder);
        ZpElement x=builder.getZpElementFromAttribute(value,attributeDefinition);
        ZpElement gamma=builder.getRandomZpElement();
        ZpElement a= builder.getZpElementFromAttribute(lowerBound,attributeDefinition);
        PedersenCommitment witness=new PedersenCommitment(base.getG(),base.getH(), x, gamma);     //V=X^gamma Y^x
        PedersenCommitment witnessPrime=new PedersenCommitment(base.getG(),base.getH(), x.sub(a), gamma); //V'=X^gamma Y^(x-a)
        RangeProof proofLowerBound=prover.generateProof(rangeProofBase,witnessPrime); //Prove x>=lowerBound
        RangeProof proofUpperBound=prover.generateProof(rangeProofBase,witness); //Prove x<=MAX_VALUE (i.e. no trick with modular arithmetic)
        generatedCommitments.put(attributeDefinition.getId().toLowerCase(),witness);
        return new RangePredicateToken(proofLowerBound,proofUpperBound,witness.getV());
    }

    private RangePredicateToken generateRangePredicateTokenInRange(PedersenBase base, Attribute value, AttributeDefinition attributeDefinition, Attribute lowerBound, Attribute upperBound) {
        int m= Util.nextPowerOfPowerOfTwo(attributeDefinition.toBigIntegerRepresentation(upperBound));
        RangeProofBase rangeProofBase=Utils.generateRangeProofBase(m,salt,builder);
        RangeProofProver prover=new RangeProofProver(builder);
        ZpElement x=builder.getZpElementFromAttribute(value,attributeDefinition);
        ZpElement gamma=builder.getRandomZpElement();
        ZpElement offset= two.pow(m).sub(one).sub(builder.getZpElementFromAttribute(upperBound,attributeDefinition));
        ZpElement a= builder.getZpElementFromAttribute(lowerBound,attributeDefinition);
        PedersenCommitment witnessA=new PedersenCommitment(base.getG(),base.getH(), x.sub(a), gamma);     //V=X^gamma Y^(x-a)
        PedersenCommitment witnessO=new PedersenCommitment(base.getG(),base.getH(), x.add(offset), gamma); //V'=X^gamma Y^(x+offset)
        RangeProof proofLowerBound=prover.generateProof(rangeProofBase,witnessA); //Prove x>=lowerBound
        RangeProof proofUpperBound=prover.generateProof(rangeProofBase,witnessO); //Prove x<=upperBound
        PedersenCommitment witness=new PedersenCommitment(base.getG(),base.getH(), x, gamma);
        generatedCommitments.put(attributeDefinition.getId().toLowerCase(),witness);
        return new RangePredicateToken(proofLowerBound,proofUpperBound,witness.getV());
    }

    private void checkRange(Attribute value, Attribute extraValue) {
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
        }
    }

    /**
     * After all the necessary range proofs have been executed with this Prover instance, you can retrieve the commitments (one for each attribute ID) so you can use them as
     * needed (e.g., randomness for linking proof...). Note that for a single "proving session" using a RangeProver, multiple proofs for a single attr ID will NOT be supported
     * @return
     */
    public Map<String, PedersenCommitment> getGeneratedCommitments() {
        return generatedCommitments;
    }
}
