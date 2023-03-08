package eu.olympus.unit.util.rangeProofs;

import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.rangeProof.model.*;
import eu.olympus.util.rangeProof.tools.*;
import org.junit.Test;
import org.miracl.core.BLS12461.BIG;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class TestRangeProofProtocol {
    private static final byte[] seed="RandomSeedForTestsblablablalbalalblabla".getBytes();


    @Test
    public void testCorrectVerification() {
        int n=16;
        ZpElement number=new ZpElementBLS461(new BIG(65000));
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpElement blindingGamma=builder.getRandomZpElement();
        RangeProofProver prover=new RangeProofProver(builder);
        PedersenBase pedersenBase=generateTestPedersenBase(builder);
        RangeProofBase base=generateTestBase(builder,n);
        PedersenCommitment commitment=new PedersenCommitment(pedersenBase.getG(),pedersenBase.getH(), number, blindingGamma);
        Group1Element v=commitment.getV();
        RangeProof proof=prover.generateProof(base,commitment);
        RangeProofVerifier verifier=new RangeProofVerifier(builder);
        assertThat(verifier.verify(base,pedersenBase,v,proof),is(true));
    }


    @Test
    public void testFalseVerificationNumberBiggerThanN() {
        int n=8;
        ZpElement number=new ZpElementBLS461(new BIG(300));
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpElement blindingGamma=builder.getRandomZpElement();
        RangeProofProver prover=new RangeProofProver(builder);
        PedersenBase pedersenBase=generateTestPedersenBase(builder);
        RangeProofBase base=generateTestBase(builder,n);
        PedersenCommitment commitment=new PedersenCommitment(pedersenBase.getG(),pedersenBase.getH(), number, blindingGamma);
        Group1Element v=commitment.getV();
        RangeProof proof=prover.generateProof(base,commitment);
        RangeProofVerifier verifier=new RangeProofVerifier(builder);
        assertThat(verifier.verify(base,pedersenBase,v,proof),is(false));
    }

    @Test
    public void testFalseVerificationModifiedCommitment() {
        int n=8;
        ZpElement realNumberForCommitment=new ZpElementBLS461(new BIG(300));
        ZpElement fakeNumberForProof=new ZpElementBLS461(new BIG(100));
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpElement blindingGamma=builder.getRandomZpElement();
        ZpElement fakeBlindingGamma=builder.getRandomZpElement();
        RangeProofProver prover=new RangeProofProver(builder);
        PedersenBase pedersenBase=generateTestPedersenBase(builder);
        RangeProofBase base=generateTestBase(builder,n);
        PedersenCommitment commitmentReal=new PedersenCommitment(pedersenBase.getG(),pedersenBase.getH(), realNumberForCommitment, blindingGamma);
        PedersenCommitment commitment2=new PedersenCommitment(pedersenBase.getG(),pedersenBase.getH(), fakeNumberForProof, blindingGamma);
        PedersenCommitment commitment3=new PedersenCommitment(pedersenBase.getG(),pedersenBase.getH(), realNumberForCommitment, fakeBlindingGamma);
        PedersenCommitment commitment4=new PedersenCommitment(pedersenBase.getG(),pedersenBase.getH(), fakeNumberForProof, fakeBlindingGamma);
        Group1Element v=commitmentReal.getV();
        RangeProof proof=prover.generateProof(base,commitmentReal);
        RangeProof proof2=prover.generateProof(base,commitment2);
        RangeProof proof3=prover.generateProof(base,commitment3);
        RangeProof proof4=prover.generateProof(base,commitment4);
        RangeProofVerifier verifier=new RangeProofVerifier(builder);
        assertThat(verifier.verify(base,pedersenBase,v,proof),is(false));
        assertThat(verifier.verify(base,pedersenBase,v,proof2),is(false));
        assertThat(verifier.verify(base,pedersenBase,v,proof3),is(false));
        assertThat(verifier.verify(base,pedersenBase,v,proof4),is(false));
    }

    @Test()
    public void testNotPowerOfTwoVerify() {
        int n=8;
        ZpElement number=new ZpElementBLS461(new BIG(15));
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpElement blindingGamma=builder.getRandomZpElement();
        RangeProofProver prover=new RangeProofProver(builder);
        PedersenBase pedersenBase=generateTestPedersenBase(builder);
        RangeProofBase base=generateTestBase(builder,n);
        PedersenCommitment commitment=new PedersenCommitment(pedersenBase.getG(),pedersenBase.getH(), number, blindingGamma);
        Group1Element v=commitment.getV();
        RangeProof proof=prover.generateProof(base,commitment);
        RangeProofVerifier verifier=new RangeProofVerifier(builder);
        RangeProofBase base2=new RangeProofBase(base.getG().subVector(1,n-1),base.getH().subVector(1,n-1));
        assertThat(verifier.verify(base2,pedersenBase,v,proof),is(false));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNotPowerOfTwo() {
        int n=9;
        ZpElement number=new ZpElementBLS461(new BIG(15));
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpElement blindingGamma=builder.getRandomZpElement();
        RangeProofProver prover=new RangeProofProver(builder);
        PedersenBase pedersenBase=generateTestPedersenBase(builder);
        RangeProofBase base=generateTestBase(builder,n);
        PedersenCommitment commitment=new PedersenCommitment(pedersenBase.getG(),pedersenBase.getH(), number, blindingGamma);
        Group1Element v=commitment.getV();
        prover.generateProof(base,commitment);
    }

    private RangeProofBase generateTestBase(PairingBuilder builder, int n) {
        return Utils.generateRangeProofBase(n,"salt",builder);
    }

    private PedersenBase generateTestPedersenBase(PairingBuilder builder) {
        Group1Element g=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Group1Element h=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        return new PedersenBase(g,h);
    }
}
