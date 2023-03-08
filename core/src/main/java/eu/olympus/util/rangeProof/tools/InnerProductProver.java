package eu.olympus.util.rangeProof.tools;

import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.rangeProof.model.GroupVector;
import eu.olympus.util.rangeProof.model.InnerProductBase;
import eu.olympus.util.rangeProof.model.InnerProductProof;
import eu.olympus.util.rangeProof.model.InnerProductWitness;
import eu.olympus.util.rangeProof.model.ZpVector;
import java.util.LinkedList;
import java.util.List;
public class InnerProductProver {

    private PairingBuilder builder;

    public InnerProductProver(PairingBuilder builder){
        this.builder=builder;
    }

    public InnerProductProof generateProof(InnerProductBase base, InnerProductWitness witness, ZpElement challengeSalt){
        if(base.getG().size()!=witness.getA().size())
            throw new IllegalArgumentException("Base and witness length must be the same");
        if(!((base.getG().size() & (base.getG().size() - 1)) == 0)){
            throw new IllegalArgumentException("Length has to be a power of 2");
        }
        ZpElement salt=challengeSalt!=null ? challengeSalt : builder.getZpElementZero();
        return recurrentProof(base,witness,new LinkedList<>(),new LinkedList<>(),salt);
    }

    private InnerProductProof recurrentProof(InnerProductBase base, InnerProductWitness ab, List<Group1Element> listL, List<Group1Element> listR, ZpElement previousChallenge){
        ZpVector a=ab.getA();
        ZpVector b=ab.getB();
        int n=a.size();
        if (n==1){
            return new InnerProductProof(listL,listR,a.getComponent(1),b.getComponent(1));
        }
        int nPrime=n/2;
        ZpVector aLeft=a.subvector(1,nPrime);
        ZpVector aRight=a.subvector(nPrime+1,n);
        ZpVector bLeft=b.subvector(1,nPrime);
        ZpVector bRight=b.subvector(nPrime+1,n);
        GroupVector g=base.getG();
        GroupVector h=base.getH();
        GroupVector gLeft=g.subVector(1,nPrime);
        GroupVector gRight=g.subVector(nPrime+1,n);
        GroupVector hLeft=h.subVector(1,nPrime);
        GroupVector hRight=h.subVector(nPrime+1,n);
        ZpElement cL=aLeft.innerProduct(bRight);
        ZpElement cR=aRight.innerProduct(bLeft);
        Group1Element l=GroupVector.concat(gRight,hLeft).expMult(ZpVector.concat(aLeft,bRight)).mul(base.getU().exp(cL));
        //Group1Element l=gRight.expMult(aLeft).mul(hLeft.expMult(bRight)).mul(base.getU().exp(cL));
        Group1Element r=GroupVector.concat(gLeft,hRight).expMult(ZpVector.concat(aRight,bLeft)).mul(base.getU().exp(cR));
        //Group1Element r=gLeft.expMult(aRight).mul(hRight.expMult(bLeft)).mul(base.getU().exp(cR));
        listL.add(l);
        listR.add(r);
        ZpElement x=Utils.newChallenge(previousChallenge,l,r,builder);
        ZpElement xInv=x.inverse();
        GroupVector gPrime=gLeft.expScalar(xInv).hadamardProduct(gRight.expScalar(x));
        GroupVector hPrime=hLeft.expScalar(x).hadamardProduct(hRight.expScalar(xInv));
        ZpVector aPrime=aLeft.mulScalar(x).add(aRight.mulScalar(xInv));
        ZpVector bPrime=bLeft.mulScalar(xInv).add(bRight.mulScalar(x));
        InnerProductBase newBase=new InnerProductBase(gPrime,hPrime,base.getU());
        InnerProductWitness newAB=new InnerProductWitness(aPrime,bPrime);
        return recurrentProof(newBase,newAB,listL,listR,x);
    }



}
