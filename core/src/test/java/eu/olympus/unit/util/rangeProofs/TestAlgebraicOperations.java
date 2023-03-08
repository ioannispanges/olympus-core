package eu.olympus.unit.util.rangeProofs;

import eu.olympus.util.Util;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.rangeProof.model.GroupVector;
import eu.olympus.util.rangeProof.model.ZpVector;
import eu.olympus.util.rangeProof.tools.Utils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.miracl.core.BLS12461.BIG;

import java.math.BigInteger;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAlgebraicOperations {
    private static final byte[] seed="RandomSeedForTestsblablablalbalalblabla".getBytes();
    private static ZpElement z2;
    private static ZpElement z3;
    private static ZpElement z5;
    private static ZpElement z7;
    private static Group1Element generator;
    private static Group1Element g2;
    private static Group1Element g3;
    private static Group1Element g5;
    private static Group1Element g7;

    @BeforeClass
    public static void initializeConstants(){
        PairingBuilder builder=new PairingBuilderBLS461();
        z2=new ZpElementBLS461(new BIG(2));
        z3=new ZpElementBLS461(new BIG(3));
        z5=new ZpElementBLS461(new BIG(5));
        z7=new ZpElementBLS461(new BIG(7));
        generator=builder.getGroup1Generator();
        g2=generator.exp(z2);
        g3=generator.exp(z3);
        g5=generator.exp(z5);
        g7=generator.exp(z7);
    }

    @Test
    public void testNextPowerOfPowerOfTwo(){
        BigInteger val1=new BigInteger("16");
        int result1=Util.nextPowerOfPowerOfTwo(val1);
        BigInteger val2=new BigInteger("7");
        int result2=Util.nextPowerOfPowerOfTwo(val2);
        BigInteger val3=new BigInteger("66000");
        int result3=Util.nextPowerOfPowerOfTwo(val3);
        assertThat(result1,is(8));
        assertThat(result2,is(4));
        assertThat(result3,is(32));
    }

    @Test
    public void testSubVector(){
        ZpVector zpv1=new ZpVector(z2,z3,z5,z7);
        ZpVector zpv2=new ZpVector(z2,z3);
        ZpVector zpv3=new ZpVector(z5,z7);
        assertThat(zpv1.subvector(1,2).equals(zpv2),is(true));
        assertThat(zpv1.subvector(3,4).equals(zpv3),is(true));
        GroupVector gv1=new GroupVector(g2,g3,g5,g7);
        GroupVector gv2=new GroupVector(g2,g3);
        GroupVector gv3=new GroupVector(g5,g7);
        assertThat(gv1.subVector(1,2).equals(gv2),is(true));
        assertThat(gv1.subVector(3,4).equals(gv3),is(true));
    }

    @Test
    public void testGetComponent(){
        ZpVector zpv1=new ZpVector(z2,z3,z5,z7);
        assertThat(zpv1.getComponent(1).equals(z2),is(true));
        assertThat(zpv1.getComponent(2).equals(z3),is(true));
        assertThat(zpv1.getComponent(3).equals(z5),is(true));
        assertThat(zpv1.getComponent(4).equals(z7),is(true));
        GroupVector gv1=new GroupVector(g2,g3,g5,g7);
        assertThat(gv1.getComponent(1).equals(g2),is(true));
        assertThat(gv1.getComponent(2).equals(g3),is(true));
        assertThat(gv1.getComponent(3).equals(g5),is(true));
        assertThat(gv1.getComponent(4).equals(g7),is(true));
    }

    @Test
    public void testZpVectorInnerProduct(){
        ZpVector zpv1=new ZpVector(z7,z2,z5);
        ZpVector zpv2=new ZpVector(z2,z3,z5);
        ZpElement expectedResult=new ZpElementBLS461(new BIG(45));
        assertThat(zpv1.innerProduct(zpv2).equals(expectedResult),is(true));
    }

    @Test
    public void testZpVectorAddition(){
        ZpVector zpv1=new ZpVector(z7,z2,z5);
        ZpVector zpv2=new ZpVector(z2,z3,z5);
        ZpVector expectedResult=new ZpVector(new ZpElementBLS461(new BIG(9)),new ZpElementBLS461(new BIG(5)),new ZpElementBLS461(new BIG(10)));
        assertThat(zpv1.add(zpv2).equals(expectedResult),is(true));
    }

    @Test
    public void testZpVectorSubtraction(){
        ZpVector zpv1=new ZpVector(z7,z3,z5);
        ZpVector zpv2=new ZpVector(z2,z2,z5);
        ZpVector expectedResult=new ZpVector(new ZpElementBLS461(new BIG(5)),new ZpElementBLS461(new BIG(1)),new ZpElementBLS461(new BIG(0)));
        assertThat(zpv1.sub(zpv2).equals(expectedResult),is(true));
    }

    @Test
    public void testZpVectorSumComponents(){
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpElement zEx1=builder.getRandomZpElement();
        ZpElement zEx2=builder.getRandomZpElement();
        ZpElement zEx3=builder.getRandomZpElement();
        ZpVector zpv1=new ZpVector(zEx1,zEx2,zEx3);
        ZpElement expectedResult=zEx1.add(zEx2).add(zEx3);
        assertThat(zpv1.sumComponents().equals(expectedResult),is(true));
    }

    @Test
    public void testZpVectorHadamardProduct(){
        ZpVector zpv1=new ZpVector(z7,z2,z5);
        ZpVector zpv2=new ZpVector(z2,z3,z5);
        ZpVector expectedResult=new ZpVector(new ZpElementBLS461(new BIG(14)),new ZpElementBLS461(new BIG(6)),new ZpElementBLS461(new BIG(25)));
        assertThat(zpv1.hadamardProduct(zpv2).equals(expectedResult),is(true));
    }

    @Test
    public void testZpVectorMulScalar(){
        ZpVector zpv1=new ZpVector(z7,z2,z5);
        ZpElement scalar=new ZpElementBLS461(new BIG(8));
        ZpVector expectedResult=new ZpVector(new ZpElementBLS461(new BIG(56)),new ZpElementBLS461(new BIG(16)),new ZpElementBLS461(new BIG(40)));
        assertThat(zpv1.mulScalar(scalar).equals(expectedResult),is(true));
    }

    @Test
    public void testZpVectorExpandExp(){
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpVector zpv1=ZpVector.expandExpN(z3,4,builder);
        ZpVector expectedResult=new ZpVector(new ZpElementBLS461(new BIG(1)),new ZpElementBLS461(new BIG(3)),new ZpElementBLS461(new BIG(9)),new ZpElementBLS461(new BIG(27)));
        assertThat(zpv1.equals(expectedResult),is(true));
    }

    @Test
    public void testZpVectorConcat(){
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpVector zpv1=new ZpVector(z2);
        ZpVector zpv2=new ZpVector(z3,z5);
        ZpVector expectedResult= new ZpVector(z2,z3,z5);
        assertThat(ZpVector.concat(zpv1,zpv2).equals(expectedResult),is(true));
    }

    @Test
    public void testGroupVectorConcat(){
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        GroupVector zpv1=new GroupVector(g2);
        GroupVector zpv2=new GroupVector(g5,g7);
        GroupVector expectedResult= new GroupVector(g2,g5,g7);
        assertThat(GroupVector.concat(zpv1,zpv2).equals(expectedResult),is(true));
    }

    @Test
    public void testGroupVectorMulComponents(){
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        Group1Element gEx1=generator.exp(builder.getRandomZpElement());
        Group1Element gEx2=generator.exp(builder.getRandomZpElement());
        Group1Element gEx3=generator.exp(builder.getRandomZpElement());
        GroupVector zpv1=new GroupVector(gEx1,gEx2,gEx3);
        Group1Element expectedResult=gEx1.mul(gEx2).mul(gEx3);
        assertThat(zpv1.mulComponents().equals(expectedResult),is(true));
    }

    @Test
    public void testGroupVectorExpMult(){
        GroupVector gv=new GroupVector(g2,g7,g5);
        ZpVector zv=new ZpVector(z7,z2,z5);
        Group1Element expectedResult=generator.exp(new ZpElementBLS461(new BIG(53)));
        assertThat(gv.expMult(zv).equals(expectedResult),is(true));
    }

    @Test
    public void testGroupVectorExp(){
        GroupVector gv=new GroupVector(g2,g7,g5);
        ZpVector zv=new ZpVector(z7,z2,z5);
        GroupVector expectedResult=new GroupVector(g2.exp(z7),g7.exp(z2),g5.exp(z5));
        assertThat(gv.exp(zv).equals(expectedResult),is(true));
    }

    @Test
    public void testGroupVectorExpScalar(){
        GroupVector gv=new GroupVector(g2,g7,g5);
        ZpElement zcomp=z3;
        ZpVector zv=new ZpVector(z3,z3,z3);
        assertThat(gv.exp(zv).equals(gv.expScalar(zcomp)),is(true));
    }

    @Test
    public void testGroupVectorHadamardProduct(){
        GroupVector gv1=new GroupVector(g2,g7,g5);
        GroupVector gv2=new GroupVector(g3,g7,g2);
        GroupVector expectedResult=new GroupVector(generator.exp(new ZpElementBLS461(new BIG(5))),generator.exp(new ZpElementBLS461(new BIG(14))),generator.exp(new ZpElementBLS461(new BIG(7))));
        assertThat(gv1.hadamardProduct(gv2).equals(expectedResult),is(true));
    }

    @Test
    public void testGenerateNewChallenge(){
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        int length=2;
        Group1Element[] l=new Group1Element[length];
        for(int i=0;i<length;i++)
            l[i]=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Group1Element[] r=new Group1Element[length];
        for(int i=0;i<length;i++)
            r[i]=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        ZpElement[] z=new ZpElement[length];
        for(int i=0;i<length;i++)
            z[i]=builder.getRandomZpElement();
        ZpElement[][][] hashes=new ZpElement[length][length][length];
        for(int i=0;i<length;i++)
            for(int j=0;j<length;j++)
                for(int k=0;k<length;k++)
                    hashes[i][j][k]= Utils.newChallenge(z[i],l[j],r[k],builder);
        for(int a=0;a<length;a++)
            for(int i=0;i<length;i++)
                for(int j=0;j<length;j++)
                    for(int k=0;k<length;k++){
                        boolean expectedResult=(a==i&&a==j&&a==k);
                        assertThat(hashes[a][a][a].equals(hashes[i][j][k]),is(expectedResult));
                    }

    }

    @Test
    public void testZpElementToBits() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpElement z=builder.getRandomZpElement();
       // ZpElement z=z2.mul(z3).mul(z5).mul(z7).mul(z7).mul(z5);
        int n=z.getNBits();
        String result="";
        for(int i=0;i<n;i++){
            String currentBit=z.getBit(i).toString();
            currentBit=currentBit.substring(currentBit.length()-1);
            result+=currentBit;
        }
        ZpElement reconvert=builder.getZpElementZero();
        for(int i=0;i<n;i++){
            char bit=result.charAt(i);
            ZpElement addition= (bit=='1') ? z2.pow(i) : builder.getZpElementZero();
            reconvert=reconvert.add(addition);
        }
        assertThat(z.equals(reconvert),is(true));
        //System.out.println(result);
    }


    @Test
    public void testZpVectorToStringAndEquals() {
        ZpVector zv=new ZpVector(z7,z2);
        ZpVector zpv1=new ZpVector(z3,z2);
        ZpVector zpv2=new ZpVector(z2);
        zv.toString();
        assertThat(zv.equals(zv),is(true));
        assertThat(zv.equals(null),is(false));
        assertThat(zv.equals(g2),is(false));
        assertThat(zv.equals(zpv2),is(false));
        assertThat(zv.equals(zpv1),is(false));
    }

    @Test
    public void testGroupVectorEquals() {
        GroupVector zv=new GroupVector(g7,g2);
        GroupVector zpv1=new GroupVector(g3,g2);
        GroupVector zpv2=new GroupVector(g2);
        assertThat(zv.equals(zv),is(true));
        assertThat(zv.equals(null),is(false));
        assertThat(zv.equals(g2),is(false));
        assertThat(zv.equals(zpv2),is(false));
        assertThat(zv.equals(zpv1),is(false));
    }

    //-------- Exceptions ---------
    @Test
    public void testGroupVectorIllegalArgumentExceptions() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        Group1Element g=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        ZpElement z=(builder.getRandomZpElement());
        GroupVector v1Element=new GroupVector(g);
        GroupVector v2Elements=new GroupVector(g,g);
        ZpVector z1Element=new ZpVector(z);
        ZpVector z2Elements=new ZpVector(z,z);
        try{
            v1Element.hadamardProduct(v2Elements);
            fail("hadamardProduct should fail");
        }catch (IllegalArgumentException e){
        }
        try{
            v1Element.expMult(z2Elements);
            fail("expMult should fail");
        }catch (IllegalArgumentException e){
        }
        try{
            v2Elements.exp(z1Element);
            fail("exp should fail");
        }catch (IllegalArgumentException e){
        }
    }

    @Test
    public void testZpVectorIllegalArgumentExceptions() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        ZpVector z1Element=new ZpVector(builder.getRandomZpElement());
        ZpVector z2Elements=new ZpVector(builder.getRandomZpElement(),builder.getRandomZpElement());
        try{
            z1Element.hadamardProduct(z2Elements);
            fail("hadamardProduct should fail");
        }catch (IllegalArgumentException e){
        }
        try{
            z1Element.add(z2Elements);
            fail("add should fail");
        }catch (IllegalArgumentException e){
        }
        try{
            z1Element.innerProduct(z2Elements);
            fail("innerProduct should fail");
        }catch (IllegalArgumentException e){
        }
    }

}
