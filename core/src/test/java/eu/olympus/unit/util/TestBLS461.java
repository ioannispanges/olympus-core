package eu.olympus.unit.util;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.util.Pair;
import eu.olympus.util.multisign.MS;
import eu.olympus.util.multisign.MSauxArg;
import eu.olympus.util.multisign.MSprivateKey;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.pairingBLS461.Hash0BLS461;
import eu.olympus.util.pairingBLS461.Hash1BLS461;
import eu.olympus.util.pairingBLS461.Hash2BLS461;
import eu.olympus.util.pairingBLS461.PairingBLS461;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.Group3Element;
import eu.olympus.util.pairingInterfaces.Hash0;
import eu.olympus.util.pairingInterfaces.Hash1;
import eu.olympus.util.pairingInterfaces.Hash2;
import eu.olympus.util.pairingInterfaces.Hash2Modified;
import eu.olympus.util.pairingInterfaces.Pairing;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSauxArg;
import eu.olympus.util.psmultisign.PSms;
import eu.olympus.util.psmultisign.PSverfKey;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.Test;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.CONFIG_BIG;
import org.miracl.core.BLS12461.ROM;
import org.miracl.core.RAND;

public class TestBLS461 {
	private static final BIG p=new BIG(ROM.CURVE_Order);
	private static final int FIELD_BYTES= CONFIG_BIG.MODBYTES;
    private static final String PAIRING_NAME="eu.olympus.util.pairingBLS461.PairingBuilderBLS461";

    private Set<String> attrNames=new HashSet<>(Arrays.asList("name","age"));
    private final byte[] seed = "random value random value random value random value random".getBytes();
    private int nServers=3;

	@Test
	public void testHash0(){
		int tamMessage=3;
		Hash0 h=new Hash0BLS461();
        List<ZpElement> m1=new LinkedList<>();
        List<ZpElement> m2=new LinkedList<>();
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte)(i);
		rng.seed(seedLength,raw);
		//Generate messages that will be hashed as random ZpElements.
		for(int i=0;i< tamMessage;i++){
			m1.add(new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		for(int i=0;i< tamMessage;i++){
			m2.add(new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		//Hashing
		Pair<ZpElement, Group2Element> hashM1_1=h.hash(m1);
        Pair<ZpElement, Group2Element> hashM2=h.hash(m2);
        Pair<ZpElement, Group2Element> hashM1_2=h.hash(m1);
        //Check hashes
        assertThat(hashM1_1.getFirst().equals(hashM1_2.getFirst()),is(true));
        assertThat(hashM1_1.getSecond().equals(hashM1_2.getSecond()),is(true));
        assertThat(hashM1_1.getFirst().equals(hashM2.getFirst()),is(false));
        assertThat(hashM1_1.getSecond().equals(hashM2.getSecond()),is(false));
	}

    @Test
    public void testHash1() throws MSSetupException {
//Create a PS-scheme instantiation
        MS psScheme=new PSms();
        //Generate auxArg and setup
        MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
        psScheme.setup(nServers,auxArg, seed);
        //KeyGeneration for three servers
        PSverfKey[] serverVK1=new PSverfKey[nServers];
        for(int i=0;i<nServers;i++){
            Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
            serverVK1[i]=(PSverfKey)keys.getSecond();
        }
        //KeyGeneration for other three servers
        PSverfKey[] serverVK2=new PSverfKey[nServers];
        for(int i=0;i<nServers;i++){
            Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
            serverVK2[i]=(PSverfKey)keys.getSecond();
        }
        //Check hashing
        Hash1 h1=new Hash1BLS461();
        ZpElement[] t1_1=h1.hash(serverVK1);
        ZpElement[] t2=h1.hash(serverVK2);
        ZpElement[] t1_2=h1.hash(serverVK1);
        for(int i=0;i<nServers;i++){
            assertThat(t1_1[i].equals(t1_2[i]),is(true));
            assertThat(t1_1[i].equals(t2[i]),is(false));
        }
    }

    @Test
    public void testPow() {
//Create a PS-scheme instantiation
        PairingBuilder builder=new PairingBuilderBLS461();
        ZpElement z=builder.getRandomZpElement();
        assertThat(z.pow(2).equals(z.mul(z)),is(true));
        assertThat(z.pow(3).equals(z.mul(z).mul(z)),is(true));
    }

    @Test
    public void testHash2() throws MSSetupException {
        //Create a PS-scheme instantiation
        MS psScheme=new PSms();
        //Generate auxArg and setup
        MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
        psScheme.setup(nServers,auxArg, seed);
        //KeyGeneration for three servers
        PSverfKey[] serverVK1=new PSverfKey[nServers];
        for(int i=0;i<nServers;i++){
            Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
            serverVK1[i]=(PSverfKey)keys.getSecond();
        }
        PSverfKey avk1=(PSverfKey)psScheme.kAggreg(serverVK1);
        //KeyGeneration for other three servers
        PSverfKey[] serverVK2=new PSverfKey[nServers];
        for(int i=0;i<nServers;i++){
            Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
            serverVK2[i]=(PSverfKey)keys.getSecond();
        }
        PSverfKey avk2=(PSverfKey)psScheme.kAggreg(serverVK2);
        //Create message
        String m="Test";
        //Create dummy Group2 and 3 elements
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        PairingBLS461 pair=new PairingBLS461();
        Group2Element sig1=builder.getGroup2Generator().exp(builder.getRandomZpElement());
        Group2Element sig2=builder.getGroup2Generator().exp(builder.getRandomZpElement());
        Group3Element prodT=pair.pair(builder.getGroup2Generator().exp(builder.getRandomZpElement()),builder.getGroup1Generator());
        Group3Element prodT2=pair.pair(builder.getGroup2Generator().exp(builder.getRandomZpElement()),builder.getGroup1Generator());
        //Check hashing
        Hash2 h2=new Hash2BLS461();
        ZpElement res1_1=h2.hash(m,avk1,sig1,sig2,prodT);
        ZpElement res2=h2.hash(m,avk2,sig1,sig2,prodT);
        ZpElement res1_2=h2.hash(m,avk1,sig1,sig2,prodT);
        ZpElement res3=h2.hash(m,avk1,sig1,sig2,prodT2);
        ZpElement res4=h2.hash(m,avk1,sig1,sig1,prodT);
        ZpElement res5=h2.hash(m,avk1,sig2,sig2,prodT);
        ZpElement res6=h2.hash("Test2",avk1,sig1,sig2,prodT);
        assertThat(res1_1.equals(res1_2),is(true));
        assertThat(res1_1.equals(res2),is(false));
        assertThat(res1_1.equals(res3),is(false));
        assertThat(res1_1.equals(res4),is(false));
        assertThat(res1_1.equals(res5),is(false));
        assertThat(res1_1.equals(res6),is(false));
        //Create dummy message
        String m2="Test2";
        assertThat(h2.hash(m,avk1,sig1,sig2,prodT).equals(h2.hash(m2,avk1,sig1,sig2,prodT)),is(false));

    }

    @Test
    public void testPairing() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
	    PairingBLS461 pair=new PairingBLS461();
	    Group2Element g1=builder.getGroup2Generator();
	    Group1Element g2=builder.getGroup1Generator();
	    ZpElement a=builder.getRandomZpElement();
	    ZpElement b=builder.getRandomZpElement();
        ZpElement c=builder.getRandomZpElement();
        ZpElement d=builder.getRandomZpElement();

        assertThat(pair.pair(g1,g2).equals(pair.pair(g1,g2)),is(true));
        assertThat(pair.pair(g1.exp(a),g2).equals(pair.pair(g1,g2).exp(a)),is(true));
        assertThat(pair.pair(g1,g2.exp(b)).equals(pair.pair(g1,g2).exp(b)),is(true));
	    assertThat(pair.pair(g1.exp(c),g2.exp(d)).equals(pair.pair(g1,g2).exp(c.mul(d))),is(true));
    }

    @Test
    public void testMultiPairing() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        PairingBLS461 pair=new PairingBLS461();
        Group2Element g1=builder.getGroup2Generator();
        Group1Element g2=builder.getGroup1Generator();
        ZpElement a=builder.getRandomZpElement();
        ZpElement b=builder.getRandomZpElement();
        ZpElement c=builder.getRandomZpElement();
        ZpElement d=builder.getRandomZpElement();
        Group2Element el1a=g1.exp(a);
        Group2Element el1c=g1.exp(c);
        Group1Element el2b=g2.exp(b);
        Group1Element el2d=g2.exp(d);
        Group3Element res1=pair.pair(el1a,el2b).mul(pair.pair(el1c,el2d));
        Collection<Pair<Group2Element,Group1Element>> elements=new LinkedList<>();
        elements.add(new Pair<>(el1a,el2b));
        elements.add(new Pair<>(el1c,el2d));
        Group3Element res2=pair.multiPair(elements);
        assertThat(res1.equals(res2),is(true));
    }

    @Test
    public void testMultiExponentiation(){
        PairingBuilder builder=new PairingBuilderBLS461();
        Group1Element g2=builder.getGroup1Generator();
        builder.seedRandom(seed);
	    int n=25;
	    Group1Element[] elements=new Group1Element[n];
	    for(int i=0;i<n;i++)
	        elements[i]=g2.exp(builder.getRandomZpElement());
        ZpElement[] zpElements=new ZpElement[n];
        for(int i=0;i<n;i++)
            zpElements[i]=builder.getRandomZpElement();
        //long start=System.currentTimeMillis();
        Group1Element res1=g2.multiExp(elements,zpElements);
        //long end=System.currentTimeMillis();
        //System.out.println("Multi "+(end-start));
        //start=System.currentTimeMillis();
        Group1Element res2=elements[0].exp(zpElements[0]);
        for(int i=1;i<n;i++)
            res2=res2.mul(elements[i].exp(zpElements[i]));
        //end=System.currentTimeMillis();
        //System.out.println("Normal "+(end-start));
        assertThat(res1.equals(res2),is(true));
    }

    @Test
    public void testInvExpGroup2() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        int numberOfTests=10;
        Group2Element g1=builder.getGroup2Generator();
        ZpElement r=builder.getRandomZpElement();
        g1=g1.exp(r);
        for(int i=0;i<numberOfTests;i++) {
            ZpElement a = builder.getRandomZpElement();
            assertThat(g1.exp(a).mul(g1.invExp(a)).isUnity(), is(true));
        }
    }

    @Test
    public void testInvExpGroup1() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        int numberOfTests=10;
        Group1Element g2=builder.getGroup1Generator();
        ZpElement r=builder.getRandomZpElement();
        g2=g2.exp(r);
        for(int i=0;i<numberOfTests;i++) {
            ZpElement a = builder.getRandomZpElement();
            assertThat(g2.exp(a).mul(g2.invExp(a)).isUnity(), is(true));
        }
    }

    @Test
    public void testInvExpGroup3() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        int numberOfTests=10;
        Group3Element g3=builder.getGroup3Generator();
        ZpElement r=builder.getRandomZpElement();
        g3=g3.exp(r);
        for(int i=0;i<numberOfTests;i++) {
            ZpElement a = builder.getRandomZpElement();
            assertThat(g3.exp(a).mul(g3.invExp(a)).isUnity(), is(true));
        }
    }

    @Test
    public void testInverseOverZp() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        int numberOfTests=10;
        for(int i=0;i<numberOfTests;i++){
            ZpElement r=builder.getRandomZpElement();
            ZpElement rInv=r.inverse();
            assertThat( r.mul(rInv).isUnity(), is(true));
        }
    }

    @Test
    public void testInverseZpWithGroup2() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        Group2Element t=builder.getGroup2Generator().exp(builder.getRandomZpElement());
        int numberOfTests=10;
        for(int i=0;i<numberOfTests;i++){
            ZpElement r=builder.getRandomZpElement();
            ZpElement rInv=r.inverse();
            assertThat( t.exp(r).exp(rInv).equals(t), is(true));
        }
    }

    @Test
    public void testInverseZpWithGroup1() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        Group1Element t=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        int numberOfTests=10;
        for(int i=0;i<numberOfTests;i++){
            ZpElement r=builder.getRandomZpElement();
            ZpElement rInv=r.inverse();
            assertThat( t.exp(r).exp(rInv).equals(t), is(true));
        }
    }

    @Test
    public void testInverseZpWithGroup3() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        Group3Element t=builder.getGroup3Generator().exp(builder.getRandomZpElement());
        int numberOfTests=10;
        for(int i=0;i<numberOfTests;i++){
            ZpElement r=builder.getRandomZpElement();
            ZpElement rInv=r.inverse();
            assertThat( t.exp(r).exp(rInv).equals(t), is(true));
        }
    }


    @Test
    public void testInverseForDOPRF() {
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        Group2Element t=builder.getGroup2Generator().exp(builder.getRandomZpElement());
        Group1Element x=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Pairing p=builder.getPairing();
        Group3Element res=p.pair(t,x);
        int numberOfTests=10;
        for(int i=0;i<numberOfTests;i++){
            ZpElement r=builder.getRandomZpElement();
            ZpElement rInv=r.inverse();
            assertThat( p.pair(t,x.exp(r)).exp(rInv).equals(res) , is(true));
        }
    }

    @Test
    public void testBigIntegerCompatibility() {
	    String number = "0a9245d01cf3bce5c1f94defb51dc348e0b9f9f17e32e158a769b85f88185a20cda66dac4a6b2195b321f178d50c8feb34db13af7686f00fe5cb";
	    BigInteger bigInt = new BigInteger(number, 16);
        BIG big = BIG.fromBytes(bigInt.toByteArray());
        String resString = big.toString();
        assertThat(number.equals(resString), is(true));
    }

    @Test
    public void testArgumentExceptionsGroup2Element(){
	    Group2Element g=(new PairingBuilderBLS461()).getGroup2Generator();
	    Group2Element mockG=MockFactory.mockGroup2Element();
	    ZpElement mockZ=MockFactory.mockZpElement();
	    try{
	        g.mul(mockG);
            fail("Multiplication should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.exp(mockZ);
            fail("Exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.invExp(mockZ);
            fail("Inverse exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testEqualsGroup2Element(){
	    PairingBuilder builder=new PairingBuilderBLS461();
	    Group2Element g1=builder.getGroup2Generator().exp(builder.getRandomZpElement());
        Group2Element g2=g1.mul(g1);
        assertThat(g1.equals(g1), is(true));
        assertThat(g1.equals(g2), is(false));
        assertThat(g1.equals(null), is(false));
        assertThat(g1.equals(MockFactory.mockGroup2Element()), is(false));
    }

    @Test
    public void testArgumentExceptionsGroup1Element(){
        Group1Element g=(new PairingBuilderBLS461()).getGroup1Generator();
        Group1Element mockG=MockFactory.mockGroup1Element();
        ZpElement mockZ=MockFactory.mockZpElement();
        try{
            g.mul(mockG);
            fail("Multiplication should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.exp(mockZ);
            fail("Exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.invExp(mockZ);
            fail("Inverse exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testEqualsGroup1Element(){
        PairingBuilder builder=new PairingBuilderBLS461();
        Group1Element g1=builder.getGroup1Generator().exp(builder.getRandomZpElement());
        Group1Element g2=g1.mul(g1);
        assertThat(g1.equals(g1), is(true));
        assertThat(g1.equals(g2), is(false));
        assertThat(g1.equals(null), is(false));
        assertThat(g1.equals(MockFactory.mockGroup1Element()), is(false));

    }

    @Test
    public void testArgumentExceptionsGroup3Element(){
        Group3Element g=(new PairingBuilderBLS461()).getGroup3Generator();
        Group3Element mockG=MockFactory.mockGroup3Element();
        ZpElement mockZ=MockFactory.mockZpElement();
        try{
            g.mul(mockG);
            fail("Multiplication should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.exp(mockZ);
            fail("Exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            g.invExp(mockZ);
            fail("Inverse exponentiation should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testEqualsGroup3Element(){
        PairingBuilder builder=new PairingBuilderBLS461();
        Group3Element g1=builder.getGroup3Generator().exp(builder.getRandomZpElement());
        Group3Element g2=g1.mul(g1);
        assertThat(g1.equals(g1), is(true));
        assertThat(g1.equals(g2), is(false));
        assertThat(g1.equals(null), is(false));
        assertThat(g1.equals(MockFactory.mockGroup3Element()), is(false));
    }

    @Test
    public void testArgumentExceptionsZpElement(){
        ZpElement z=(new PairingBuilderBLS461()).getRandomZpElement();
        ZpElement mockZ=MockFactory.mockZpElement();
        try{
            z.add(mockZ);
            fail("Addition should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            z.mul(mockZ);
            fail("Multiplication should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
        try{
            z.sub(mockZ);
            fail("Subtraction should throw IllegalArgumentException");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testEqualsZpElement(){
        PairingBuilder builder=new PairingBuilderBLS461();
        ZpElement z1=builder.getRandomZpElement();
        ZpElement z2=z1.add(z1);
        assertThat(z1.equals(z1), is(true));
        assertThat(z1.equals(z2), is(false));
        assertThat(z1.equals(null), is(false));
        assertThat(z1.equals(MockFactory.mockZpElement()), is(false));
    }


    @Test(expected=IllegalArgumentException.class)
    public void testArgumentExceptionsHash0(){
        Hash0 h=(new PairingBuilderBLS461()).getHash0();
        List<ZpElement> elements=new LinkedList<>();
        elements.add(MockFactory.mockZpElement());
        h.hash(elements);
        fail();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testArgumentExceptionsHash1(){
        Hash1 h=(new PairingBuilderBLS461()).getHash1();
        Group1Element mockG=MockFactory.mockGroup1Element();
        PSverfKey vk=new PSverfKey(mockG,null,null,null);
        PSverfKey[] vks=new PSverfKey[1];
        vks[0]=vk;
        h.hash(vks);
        fail();
    }



    @Test
    public void testArgumentExceptionsHash2(){
        Hash2 h=(new PairingBuilderBLS461()).getHash2();
        Group2Element g1=(new PairingBuilderBLS461()).getGroup2Generator();
        Group2Element mockG1=MockFactory.mockGroup2Element();
        Group2Element g2=(new PairingBuilderBLS461()).getGroup2Generator();
        Group2Element mockG2=MockFactory.mockGroup2Element();
        Group3Element g3=(new PairingBuilderBLS461()).getGroup3Generator();
        Group3Element mockG3=MockFactory.mockGroup3Element();
        PSverfKey vk=new PSverfKey(MockFactory.mockGroup1Element(),null,null,null);
        String m="test";
        try{
            h.hash(m,vk,mockG1,g2,g3);
            fail("Should throw IllegalArgumentException, sigma1");
        }catch(IllegalArgumentException e){
        }
        try{
            h.hash(m,vk,g1,mockG2,g3);
            fail("Should throw IllegalArgumentException, sigma2");
        }catch(IllegalArgumentException e){
        }
        try{
            h.hash(m,vk,g1,g2,mockG3);
            fail("Should throw IllegalArgumentException, prodT");
        }catch(IllegalArgumentException e){
        }
        try{
            h.hash(m,vk,g1,g2,g3);
            fail("Should throw IllegalArgumentException, avk");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testArgumentExceptionsHash2Modified(){
	    PairingBuilder builder=new PairingBuilderBLS461();
        Hash2Modified h=builder.getHash2Mod();
        Group2Element g1=builder.getGroup2Generator();
        Group2Element mockG1=MockFactory.mockGroup2Element();
        Group2Element g2=builder.getGroup2Generator();
        Group2Element mockG2=MockFactory.mockGroup2Element();
        Group3Element g3=builder.getGroup3Generator();
        Group3Element mockG3=MockFactory.mockGroup3Element();
        PSverfKey vk=new PSverfKey(MockFactory.mockGroup1Element(),null,null,null);
        Map<String,Group1Element> elementMap=new HashMap<>();
        elementMap.put("testAttr",builder.getGroup1Generator());
        Map<String,Group1Element> elementMapWrong=new HashMap<>();
        elementMapWrong.put("testAttr",MockFactory.mockGroup1Element());
        String m="test";
        try{
            h.hash(m,vk,mockG1,g2,g3,elementMap);
            fail("Should throw IllegalArgumentException, sigma1");
        }catch(IllegalArgumentException e){
        }
        try{
            h.hash(m,vk,g1,mockG2,g3,elementMap);
            fail("Should throw IllegalArgumentException, sigma2");
        }catch(IllegalArgumentException e){
        }
        try{
            h.hash(m,vk,g1,g2,mockG3,elementMap);
            fail("Should throw IllegalArgumentException, prodT");
        }catch(IllegalArgumentException e){
        }
        try{
            h.hash(m,vk,g1,g2,g3,elementMapWrong);
            fail("Should throw IllegalArgumentException, Vp");
        }catch(IllegalArgumentException e){
        }
        try{
            h.hash(m,vk,g1,g2,g3,elementMap);
            fail("Should throw IllegalArgumentException, avk");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testArgumentExceptionsPair(){
        Pairing pairing=(new PairingBuilderBLS461()).getPairing();
        Group2Element g1=(new PairingBuilderBLS461()).getGroup2Generator();
        Group2Element mockG1=MockFactory.mockGroup2Element();
        Group1Element g2=(new PairingBuilderBLS461()).getGroup1Generator();
        Group1Element mockG2=MockFactory.mockGroup1Element();
        try{
            pairing.pair(g1,mockG2);
            fail("Should throw IllegalArgumentException, el2");
        }catch(IllegalArgumentException e){
        }
        try{
            pairing.pair(mockG1,g2);
            fail("Should throw IllegalArgumentException, el1");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testArgumentExceptionsMultiPair(){
        Pairing pairing=(new PairingBuilderBLS461()).getPairing();
        Group2Element g1=(new PairingBuilderBLS461()).getGroup2Generator();
        Group2Element mockG1=MockFactory.mockGroup2Element();
        Group1Element g2=(new PairingBuilderBLS461()).getGroup1Generator();
        Group1Element mockG2=MockFactory.mockGroup1Element();
        Pair<Group2Element,Group1Element> good=new Pair<>(g1,g2);
        Pair<Group2Element,Group1Element> wrongG1=new Pair<>(mockG1,g2);
        Pair<Group2Element,Group1Element> wrongG2=new Pair<>(g1,mockG2);
        Collection<Pair<Group2Element,Group1Element>> wrong1=new LinkedList<>();
        wrong1.add(good);
        wrong1.add(wrongG1);
        Collection<Pair<Group2Element,Group1Element>> wrong2=new LinkedList<>();
        wrong2.add(good);
        wrong2.add(wrongG2);

        try{
            pairing.multiPair(wrong1);
            fail("Should throw IllegalArgumentException, el1");
        }catch(IllegalArgumentException e){
        }
        try{
            pairing.multiPair(wrong2);
            fail("Should throw IllegalArgumentException, el2");
        }catch(IllegalArgumentException e){
        }
    }

    @Test
    public void testMultiExponentiationExceptions(){
        PairingBuilder builder=new PairingBuilderBLS461();
        Group1Element g2=builder.getGroup1Generator();
        builder.seedRandom(seed);
        int n=2;
        Group1Element[] elements=new Group1Element[n];
        for(int i=0;i<n;i++)
            elements[i]=g2.exp(builder.getRandomZpElement());
        ZpElement[] zpElements=new ZpElement[n];
        for(int i=0;i<n;i++)
            zpElements[i]=builder.getRandomZpElement();
        Group1Element[] elementsMock=new Group1Element[n];
        for(int i=0;i<n;i++)
            elementsMock[i]=MockFactory.mockGroup1Element();
        ZpElement[] zpElementsMock=new ZpElement[n];
        for(int i=0;i<n;i++)
            zpElementsMock[i]=MockFactory.mockZpElement();
        try {
            g2.multiExp(elements,new ZpElement[0]);
            fail("Should throw IllegalArgumentException different lengths");
        }catch (IllegalArgumentException e){
        }
        try {
            g2.multiExp(new Group1Element[0],new ZpElement[0]);
            fail("Should throw IllegalArgumentException 0 length");
        }catch (IllegalArgumentException e){
        }
        try {
            g2.multiExp(elementsMock,zpElements);
            fail("Should throw IllegalArgumentException wrong type Group1");
        }catch (IllegalArgumentException e){
        }
        try {
            g2.multiExp(elements,zpElementsMock);
            fail("Should throw IllegalArgumentException wrong type ZpElement");
        }catch (IllegalArgumentException e){
        }

    }

}
