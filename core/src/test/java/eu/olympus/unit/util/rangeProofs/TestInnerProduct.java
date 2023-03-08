package eu.olympus.unit.util.rangeProofs;

import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.rangeProof.model.*;
import eu.olympus.util.rangeProof.tools.InnerProductProver;
import eu.olympus.util.rangeProof.tools.InnerProductVerifier;
import org.junit.Test;
import org.miracl.core.BLS12461.BIG;

import java.util.LinkedList;
import java.util.List;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestInnerProduct {
    private static final byte[] seed="RandomSeedForTestsblablablalbalalblabla".getBytes();
    private static final int n=16;


    @Test
    public void testCorrectVerificationWithSalt() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpElement salt=builder.getRandomZpElement();
        InnerProductProver prover=new InnerProductProver(builder);
        InnerProductBase base=generateTestBase(builder);
        InnerProductWitness witness=generateTestWitness(builder);
        ZpElement c=witness.getA().innerProduct(witness.getB());
        Group1Element p=base.getG().expMult(witness.getA()).mul(base.getH().expMult(witness.getB())).mul(base.getU().exp(c));
        InnerProductProof proof=prover.generateProof(base,witness,salt);
        InnerProductVerifier verifier=new InnerProductVerifier(builder);
        assertThat(verifier.verify(base,p,proof,salt),is(true));
    }

    @Test
    public void testCorrectVerificationWithoutSalt() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        InnerProductProver prover=new InnerProductProver(builder);
        InnerProductBase base=generateTestBase(builder);
        InnerProductWitness witness=generateTestWitness(builder);
        ZpElement c=witness.getA().innerProduct(witness.getB());
        Group1Element p=base.getG().expMult(witness.getA()).mul(base.getH().expMult(witness.getB())).mul(base.getU().exp(c));
        InnerProductProof proof=prover.generateProof(base,witness,null);
        InnerProductVerifier verifier=new InnerProductVerifier(builder);
        assertThat(verifier.verify(base,p,proof,null),is(true));
    }

    @Test
    public void testWrongP() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        InnerProductProver prover=new InnerProductProver(builder);
        InnerProductBase base=generateTestBase(builder);
        InnerProductWitness witness=generateTestWitness(builder);
        ZpElement c=witness.getA().innerProduct(witness.getB());
        ZpElement modifiedC=witness.getA().innerProduct(witness.getB()).add(builder.getRandomZpElement());
        Group1Element p=base.getG().expMult(witness.getA()).mul(base.getH().expMult(witness.getB())).mul(base.getU().exp(c));
        Group1Element wrongP1=p.exp(new ZpElementBLS461(new BIG(2)));
        Group1Element wrongP2=base.getG().expMult(witness.getB()).mul(base.getH().expMult(witness.getB())).mul(base.getU().exp(c));
        Group1Element wrongP3=base.getG().expMult(witness.getA().mulScalar(new ZpElementBLS461(new BIG(2)))).mul(base.getH().expMult(witness.getB())).mul(base.getU().exp(c));
        Group1Element wrongP4=base.getG().expMult(witness.getA()).mul(base.getH().expMult(witness.getB())).mul(base.getU().exp(modifiedC));
        Group1Element wrongP5=base.getG().expScalar(new ZpElementBLS461(new BIG(2))).expMult(witness.getA()).mul(base.getH().expMult(witness.getB())).mul(base.getU().exp(c));
        Group1Element wrongP6=base.getG().expMult(witness.getA()).mul(base.getH().expScalar(new ZpElementBLS461(new BIG(2))).expMult(witness.getB())).mul(base.getU().exp(c));
        Group1Element wrongP7=base.getG().expMult(witness.getA()).mul(base.getH().expMult(witness.getB())).mul(base.getU().exp(new ZpElementBLS461(new BIG(2))).exp(c));
        InnerProductProof proof=prover.generateProof(base,witness,null);
        InnerProductVerifier verifier=new InnerProductVerifier(builder);
        assertThat(verifier.verify(base,p,proof,null),is(true));
        assertThat(verifier.verify(base,wrongP1,proof,null),is(false));
        assertThat(verifier.verify(base,wrongP2,proof,null),is(false));
        assertThat(verifier.verify(base,wrongP3,proof,null),is(false));
        assertThat(verifier.verify(base,wrongP4,proof,null),is(false));
        assertThat(verifier.verify(base,wrongP5,proof,null),is(false));
        assertThat(verifier.verify(base,wrongP6,proof,null),is(false));
        assertThat(verifier.verify(base,wrongP7,proof,null),is(false));
    }

    @Test
    public void testWrongModifiedProof() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        InnerProductProver prover=new InnerProductProver(builder);
        InnerProductBase base=generateTestBase(builder);
        InnerProductWitness witness=generateTestWitness(builder);
        ZpElement c=witness.getA().innerProduct(witness.getB());
        Group1Element p=base.getG().expMult(witness.getA()).mul(base.getH().expMult(witness.getB())).mul(base.getU().exp(c));
        InnerProductProof proof=prover.generateProof(base,witness,null);
        InnerProductProof wrongProof1=new InnerProductProof(proof.getL(),proof.getR(),proof.getA(),proof.getB().add(builder.getRandomZpElement()));
        InnerProductProof wrongProof2=new InnerProductProof(proof.getL(),proof.getR(),proof.getA().add(builder.getRandomZpElement()),proof.getB());
        InnerProductProof wrongProof3=new InnerProductProof(proof.getR(),proof.getL(),proof.getA(),proof.getB());
        List<Group1Element> wrongL=new LinkedList<>(proof.getL());
        wrongL.set(0,wrongL.get(0).mul(wrongL.get(0)));
        InnerProductProof wrongProof4=new InnerProductProof(wrongL,proof.getR(),proof.getA(),proof.getB());
        List<Group1Element> wrongL2=new LinkedList<>(proof.getL());
        List<Group1Element> wrongR2=new LinkedList<>(proof.getR());
        wrongR2.remove(0);
        wrongL2.remove(0);
        InnerProductProof wrongProof5=new InnerProductProof(wrongL2,wrongR2,proof.getA(),proof.getB());
        InnerProductVerifier verifier=new InnerProductVerifier(builder);
        assertThat(verifier.verify(base,p,proof,null),is(true));
        assertThat(verifier.verify(base,p,wrongProof1,null),is(false));
        assertThat(verifier.verify(base,p,wrongProof2,null),is(false));
        assertThat(verifier.verify(base,p,wrongProof3,null),is(false));
        assertThat(verifier.verify(base,p,wrongProof4,null),is(false));
        assertThat(verifier.verify(base,p,wrongProof5,null),is(false));
    }

    @Test
    public void testWrongProofsForDifferentBaseOrWitness() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        InnerProductProver prover=new InnerProductProver(builder);
        InnerProductVerifier verifier=new InnerProductVerifier(builder);
        InnerProductBase[] bases=new InnerProductBase[2];
        bases[0]=generateTestBase(builder);
        bases[1]=generateTestBase(builder);
        assertThat(bases[0].equals(bases[1]),is(false));
        InnerProductWitness[] witnesses=new InnerProductWitness[2];
        witnesses[0]=generateTestWitness(builder);
        witnesses[1]=generateTestWitness(builder);
        assertThat(witnesses[0].equals(witnesses[1]),is(false));
        InnerProductProof[] proofs=new InnerProductProof[4];
        Group1Element[] ps=new Group1Element[4];
        int count=0;
        for(int i=0;i<2;i++)
            for(int j=0;j<2;j++){
                ZpElement c=witnesses[i].getA().innerProduct(witnesses[i].getB());
                ps[count]=bases[j].getG().expMult(witnesses[i].getA()).mul(bases[j].getH().expMult(witnesses[i].getB())).mul(bases[j].getU().exp(c));
                proofs[count]=prover.generateProof(bases[j],witnesses[i],null);
                count++;
            }
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                if(j!=i){ //Proof and p do not match
                    assertThat(verifier.verify(bases[0],ps[i],proofs[j],null),is(false));
                    assertThat(verifier.verify(bases[1],ps[i],proofs[j],null),is(false));
                }
            }
        }
    }

    private InnerProductWitness generateTestWitness(PairingBuilder builder) {
        ZpElement[] aComponents=new ZpElement[n];
        for(int i=0;i<n;i++)
            aComponents[i]=builder.getRandomZpElement();
        ZpVector a=new ZpVector(aComponents);
        ZpElement[] bComponents=new ZpElement[n];
        for(int i=0;i<n;i++)
            bComponents[i]=builder.getRandomZpElement();
        ZpVector b=new ZpVector(bComponents);
        return new InnerProductWitness(a,b);
    }

    private InnerProductBase generateTestBase(PairingBuilder builder) {
        Group1Element[] gComponents=new Group1Element[n];
        for(int i=0;i<n;i++)
            gComponents[i]=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        GroupVector g=new GroupVector(gComponents);
        Group1Element[] hComponents=new Group1Element[n];
        for(int i=0;i<n;i++)
            hComponents[i]=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        GroupVector h=new GroupVector(hComponents);
        Group1Element u=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        return new InnerProductBase(g,h,u);
    }


    @Test
    public void testWrongLengthVerification() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpElement salt=builder.getRandomZpElement();
        InnerProductProver prover=new InnerProductProver(builder);
        InnerProductBase base=generateTestBase(builder);
        InnerProductWitness witness=generateTestWitness(builder);
        ZpElement c=witness.getA().innerProduct(witness.getB());
        Group1Element p=base.getG().expMult(witness.getA()).mul(base.getH().expMult(witness.getB())).mul(base.getU().exp(c));
        InnerProductProof proof=prover.generateProof(base,witness,salt);
        InnerProductVerifier verifier=new InnerProductVerifier(builder);
        GroupVector wrongG=new GroupVector(p,p,p);
        GroupVector wrongH=new GroupVector(p,p,p);
        InnerProductBase wrongBase=new InnerProductBase(wrongG,wrongH,base.getU());
        assertThat(verifier.verify(wrongBase,p,proof,salt),is(false));
    }
    //-------- Exceptions ---------
    @Test
    public void testIllegalArgumentExceptionsProver() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        InnerProductProver prover=new InnerProductProver(builder);
        Group1Element g=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        ZpElement z=(builder.getRandomZpElement());
        GroupVector v1Element=new GroupVector(g);
        GroupVector v2Elements=new GroupVector(g,g);
        GroupVector v3Elements=new GroupVector(g,g,g);
        ZpVector z1Element=new ZpVector(z);
        ZpVector z2Elements=new ZpVector(z,z);
        ZpVector z3Elements=new ZpVector(z,z,z);
        try{
            InnerProductBase wrongBase=new InnerProductBase(v1Element,v2Elements,g);
            fail("InnerProductBase should fail");
        }catch (IllegalArgumentException e){
        }
        try{
            InnerProductWitness wrongWitness=new InnerProductWitness(z1Element,z2Elements);
            fail("InnerProductWitness should fail");
        }catch (IllegalArgumentException e){
        }
        try{
            InnerProductBase base=new InnerProductBase(v1Element,v1Element,g);
            InnerProductWitness witness=new InnerProductWitness(z2Elements,z2Elements);
            prover.generateProof(base,witness,null);
            fail("InnerProductProver should fail wrong lengths");
        }catch (IllegalArgumentException e){
        }
        try{
            InnerProductBase base=new InnerProductBase(v3Elements,v3Elements,g);
            InnerProductWitness witness=new InnerProductWitness(z3Elements,z3Elements);
            prover.generateProof(base,witness,null);
            fail("InnerProductProver should fail not power of 2");
        }catch (IllegalArgumentException e){
        }
        try{
            InnerProductBase base=new InnerProductBase(v3Elements,v3Elements,g);
            List<Group1Element> l=new LinkedList<>();
            l.add(g);
            l.add(g);
            List<Group1Element> r=new LinkedList<>();
            r.add(g);
            InnerProductProof wrongProof=new InnerProductProof(l,r,z,z);
            fail("InnerProductProver should fail not matching lengths");
        }catch (IllegalArgumentException e){
        }
    }

}
