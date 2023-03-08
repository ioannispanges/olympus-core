package eu.olympus.util.rangeProof.tools;

import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.rangeProof.model.*;

public class RangeProofVerifier {

    PairingBuilder builder;

    public RangeProofVerifier(PairingBuilder builder) {
        this.builder = builder;
    }

    public boolean verify(RangeProofBase base, PedersenBase commitmentBase, Group1Element v, RangeProof proof){
        int n=base.getG().size();
        if(!((n & (n - 1)) == 0)){
            return false;
        }
        Group1Element a=proof.getA();
        Group1Element s=proof.getS();
        Group1Element t1commit=proof.getT1();
        Group1Element t2commit=proof.getT2();
        ZpElement tauX=proof.getTauX();
        ZpElement mu=proof.getMu();
        ZpElement y=Utils.newChallenge(v,a,s,builder);
        ZpElement z=Utils.newChallenge(y,a,s,builder);
        ZpElement zSquared=z.pow(2);
        ZpElement x=Utils.newChallenge(z,t1commit,t2commit,builder);
        ZpElement xSquared=x.pow(2);
        ZpElement uChallenge=Utils.newChallenge(x,tauX,mu,builder);
        ZpVector ys=ZpVector.expandExpN(y,n,builder);
        ZpElement two=builder.getZpElementOne().add(builder.getZpElementOne());
        ZpVector twos_n=ZpVector.expandExpN(two,n,builder);
        ZpElement delta_yz=z.sub(zSquared).mul(ys.sumComponents()).sub(z.pow(3).mul(twos_n.sumComponents()));
        ZpElement expForComparison=proof.gettHat().sub(delta_yz); //One less exponentiation
        Group1Element left=commitmentBase.getG().exp(expForComparison).mul(commitmentBase.getH().exp(tauX));
        Group1Element right=v.exp(zSquared).mul(t1commit.exp(x)).mul(t2commit.exp(xSquared));
        if(!left.equals(right))
            return false;
        GroupVector hPrime=base.getH().exp(ZpVector.expandExpN(y.inverse(),n,builder));
        Group1Element u=commitmentBase.getG().exp(uChallenge);
        InnerProductBase innerProductBase=new InnerProductBase(base.getG(),hPrime,u);
        InnerProductVerifier iPverifier=new InnerProductVerifier(builder);
        ZpVector hPrimeExponent=ys.mulScalar(z).add(twos_n.mulScalar(zSquared));
        Group1Element p=a.mul(s.exp(x)).mul(base.getG().mulComponents().invExp(z)).mul(hPrime.expMult(hPrimeExponent)).mul(commitmentBase.getH().invExp(mu)).mul(u.exp(proof.gettHat()));
        return iPverifier.verify(innerProductBase,p,proof.getInnerProductProof(),uChallenge);
    }
}
