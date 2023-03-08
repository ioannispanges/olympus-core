package eu.olympus.util.rangeProof.tools;

import eu.olympus.util.Pair;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.rangeProof.model.GroupVector;
import eu.olympus.util.rangeProof.model.InnerProductBase;
import eu.olympus.util.rangeProof.model.InnerProductProof;
import eu.olympus.util.rangeProof.model.ZpVector;

public class InnerProductVerifier {

    PairingBuilder builder;

    public InnerProductVerifier(PairingBuilder builder) {
        this.builder = builder;
    }

    public boolean verify(InnerProductBase base, Group1Element p, InnerProductProof proof, ZpElement challengeSalt){
        ZpElement previousChallenge=challengeSalt!=null ? challengeSalt : builder.getZpElementZero();
        int n=base.getG().size();
        if(!((n & (n - 1)) == 0)){
            return false;
        }
        int lsize=proof.getL().size();
        ZpElement[] xs=new ZpElement[lsize];
        ZpElement[] xsInv=new ZpElement[lsize];
        ZpElement[] xsSquared=new ZpElement[lsize];
        ZpElement[] xsInvSquared=new ZpElement[lsize];
        ZpElement[] xsSquaredNeg=new ZpElement[lsize];
        ZpElement[] xsInvSquaredNeg=new ZpElement[lsize];
        Group1Element[] l=new Group1Element[lsize];
        Group1Element[] r=new Group1Element[lsize];
        for(int i=0;i<lsize;i++){
            l[i]=proof.getL().get(i);
            r[i]=proof.getR().get(i);
            ZpElement x=Utils.newChallenge(previousChallenge,l[i],r[i],builder);
            ZpElement xInv=x.inverse();
            ZpElement xSquared=x.pow(2);
            ZpElement xInvSquared=xInv.pow(2);
            // Lists of xsSquared/Neg and xsInvSquared/Neg need to be in order for L and R exponentiations
            // Lists of x and xInv need to be reversed for computing ss
            //Paper (at least version I was consulting) fails describe this
            xsSquared[i]=xSquared;
            xsInvSquared[i]=xInvSquared;
            xsSquaredNeg[i]=xSquared.neg();
            xsInvSquaredNeg[i]=xInvSquared.neg();
            xs[lsize-i-1]=x;
            xsInv[lsize-i-1]=xInv;
            previousChallenge=x;
        }
        Pair<ZpVector,ZpVector> ss=computeS(xs,xsInv,n);
        ZpVector aS=ss.getFirst().mulScalar(proof.getA());
        ZpVector bSinv=ss.getSecond().mulScalar(proof.getB());
        ZpElement c=proof.getA().mul(proof.getB());
        ZpVector negX2=new ZpVector(xsSquaredNeg);
        ZpVector negXInv2=new ZpVector(xsInvSquaredNeg);
        ZpVector exponents=ZpVector.concat(aS,bSinv,negX2,negXInv2);
        GroupVector ghlr=GroupVector.concat(base.getG(),base.getH(),new GroupVector(l),new GroupVector(r));
        Group1Element reconstructedP=ghlr.expMult(exponents).mul(base.getU().exp(c));
        return p.equals(reconstructedP);
    }

    private Pair<ZpVector, ZpVector> computeS(ZpElement[] xs, ZpElement[] xsInv, int n) {
        ZpElement[] s=new ZpElement[n];
        ZpElement[] sInv=new ZpElement[n];
        for(int i=0;i<n;i++){
            s[i]=builder.getZpElementOne();
            for(int j=0;j<xs.length;j++){
                if(bit(i,j))
                    s[i]=s[i].mul(xs[j]);
                else
                    s[i]=s[i].mul(xsInv[j]);
            }
            sInv[i]=s[i].inverse();
        }
        return new Pair<>(new ZpVector(s),new ZpVector(sInv));
    }

    private boolean bit(int i, int j) {
        return ((i>>j) & 1) != 0;
    }

}
