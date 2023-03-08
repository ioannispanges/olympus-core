package eu.olympus.util.rangeProof.tools;

import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.rangeProof.model.*;

public class RangeProofProver {

    PairingBuilder builder;

    public RangeProofProver(PairingBuilder builder) {
        this.builder = builder;
    }

    // n used for proving range [0,2^n-1] is implicit in base length.
    // Number we want to use for the proof, randomness and commitment base are within the witness
    public RangeProof generateProof(RangeProofBase base, PedersenCommitment witness){
        int n=base.getG().size();
        if(!((n & (n - 1)) == 0)){
            throw new IllegalArgumentException("Length has to be a power of 2");
        }
        ZpVector ones=new ZpVector(builder.getZpElementOne(),n);
        ZpVector aL=ZpVector.bitRepresentation(witness.getNumber(),n);
        ZpVector aR=aL.sub(ones);
        ZpElement alpha=builder.getRandomZpElement();
        GroupVector ghBase=GroupVector.concat(base.getG(),base.getH());
        Group1Element a=ghBase.expMult(ZpVector.concat(aL,aR)).mul(witness.getH().exp(alpha));
        //Group1Element a=base.getG().expMult(aL).mul(base.getH().expMult(aR)).mul(witness.getH().exp(alpha));
        ZpVector sL=ZpVector.randomVector(n,builder);
        ZpVector sR=ZpVector.randomVector(n,builder);
        ZpElement rho=builder.getRandomZpElement();
        Group1Element s=ghBase.expMult(ZpVector.concat(sL,sR)).mul(witness.getH().exp(rho));
        ///Group1Element s=base.getG().expMult(sL).mul(base.getH().expMult(sR)).mul(witness.getH().exp(rho));
        ZpElement y=Utils.newChallenge(witness.getV(),a,s,builder);
        ZpElement z=Utils.newChallenge(y,a,s,builder);
        ZpElement zSquared=z.pow(2);
        ZpVector l0=aL.sub(ones.mulScalar(z));
        ZpVector l1=sL;
        ZpVectorPolynomial l=new ZpVectorPolynomial(l0,l1);
        ZpVector ys=ZpVector.expandExpN(y,n,builder);
        ZpElement two=builder.getZpElementOne().add(builder.getZpElementOne());
        ZpVector twos_n=ZpVector.expandExpN(two,n,builder);
        ZpVector r0=ys.hadamardProduct(aR.add(ones.mulScalar(z))).add(twos_n.mulScalar(zSquared));
        ZpVector r1=ys.hadamardProduct(sR);
        ZpVectorPolynomial r=new ZpVectorPolynomial(r0,r1);
        //ZpElement t0=l0.innerProduct(r0); Not needed
        ZpElement t1=l0.innerProduct(r1).add(l1.innerProduct(r0));
        ZpElement t2=l1.innerProduct(r1);
        ZpElement tau1=builder.getRandomZpElement();
        ZpElement tau2=builder.getRandomZpElement();
        Group1Element t1Commit=witness.getG().exp(t1).mul(witness.getH().exp(tau1));
        Group1Element t2Commit=witness.getG().exp(t2).mul(witness.getH().exp(tau2));
        ZpElement x=Utils.newChallenge(z,t1Commit,t2Commit,builder);
        ZpVector l_x=l.eval(x);
        ZpVector r_x=r.eval(x);
        ZpElement tHat=l_x.innerProduct(r_x);
        ZpElement tauX=tau2.mul(x.pow(2)).add(tau1.mul(x)).add(zSquared.mul(witness.getGamma()));
        ZpElement mu=alpha.add(rho.mul(x));
        InnerProductWitness innerProductWitness=new InnerProductWitness(l_x,r_x);
        InnerProductProver iPprover=new InnerProductProver(builder);
        GroupVector hPrime=base.getH().exp(ZpVector.expandExpN(y.inverse(),n,builder));
        ZpElement uChallenge=Utils.newChallenge(x,tauX,mu,builder);
        Group1Element u=witness.getG().exp(uChallenge);
        InnerProductBase innerProductBase=new InnerProductBase(base.getG(),hPrime,u);
        InnerProductProof innerProductProof=iPprover.generateProof(innerProductBase,innerProductWitness,uChallenge);
        return new RangeProof(t1Commit,t2Commit,tauX,mu,tHat,a,s,innerProductProof);
    }


}
