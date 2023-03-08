package eu.olympus.unit.util;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.util.Pair;
import eu.olympus.util.multisign.MS;
import eu.olympus.util.multisign.MSauxArg;
import eu.olympus.util.multisign.MSmessage;
import eu.olympus.util.multisign.MSprivateKey;
import eu.olympus.util.multisign.MSsignature;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.multisign.MSzkToken;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSauxArg;
import eu.olympus.util.psmultisign.PSmessage;
import eu.olympus.util.psmultisign.PSms;
import eu.olympus.util.psmultisign.PSprivateKey;
import eu.olympus.util.psmultisign.PSsignature;
import eu.olympus.util.psmultisign.PSverfKey;
import eu.olympus.util.psmultisign.PSzkToken;
import eu.olympus.util.psmultisign.PSzkTokenModified;
import eu.olympus.util.rangeProof.model.PedersenCommitment;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.CONFIG_BIG;
import org.miracl.core.BLS12461.ROM;
import org.miracl.core.RAND;


public class TestPSsignBLS461 {
	@Rule
	public final ExpectedException exception = ExpectedException.none();

	private static final BIG p=new BIG(ROM.CURVE_Order);
	private static final int FIELD_BYTES= CONFIG_BIG.MODBYTES;
	private static final String PAIRING_NAME="eu.olympus.util.pairingBLS461.PairingBuilderBLS461";
	private final byte[] seed = "random value random value random value random value random".getBytes();

	private Set<String> attrNames=new HashSet<>(Arrays.asList("name","age"));
	private int nServers=3;


	@Test
	public void testCompletePSFlow() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		//Verifying the signature
		assertThat(psScheme.verf(avk,mAttr,signature), is(true));
		//Revealed attributes and signed message
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		Map<String,ZpElement> revAttr=new HashMap<>();
		for(String attr:revealedAttributesNames)
			revAttr.put(attr,attributes.get(attr));
		MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
		String message="TestMessage";
		//Token generation
		//long start=System.currentTimeMillis();
		MSzkToken token=psScheme.presentZKtoken(avk,revealedAttributesNames,mAttr,message,signature);
		//long end=System.currentTimeMillis();
		//System.out.println(end-start);
		//Token verification
		//start=System.currentTimeMillis();
		assertThat(psScheme.verifyZKtoken(token,avk,message,mRevealAttr),is(true));
		//end=System.currentTimeMillis();
		//System.out.println(end-start);
	}

	@Test
	public void testDifferentAttributesVerify() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte)(i*i);
		rng.seed(seedLength,raw);
		//Generate attributes and epoch as random ZpElements.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Constructing the message for signing (attributes)
		MSmessage m=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],m);
		}
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		//Creating new attributes
		Map<String, ZpElement> wrongAttributes=new HashMap<>();
		for(String attr:attrNames){
			wrongAttributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		//Creating message from falsified attributes
		MSmessage wrongM=new PSmessage(wrongAttributes,epoch);
		//Verifying the signature
		assertThat(psScheme.verf(avk,wrongM,signature), is(false));
	}

	@Test(expected=IllegalArgumentException.class)
	public void testNotEnoughServersComb() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte)(i*i);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Constructing the message for signing (attributes)
		MSmessage m=new PSmessage(attributes,epoch);
		//Signature share for each server (except one)
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers-1;i++){
			signShares[i]=psScheme.sign(serverSK[i],m);
		}
		//Combining shares in one signature
		psScheme.comb(serverVK, signShares);
		fail();
	}

	@Test
	public void testWrongEpoch() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte)(i*i);
		rng.seed(seedLength,raw);
		//Generate attributes and epoch as random ZpElements.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Constructing the message for signing (attributes)
		MSmessage m=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],m);
		}
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		//Creating new attributes
		ZpElement wrongEpoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Creating message from falsified attributes
		MSmessage wrongM=new PSmessage(attributes,wrongEpoch);
		//Verifying the signature
		assertThat(psScheme.verf(avk,wrongM,signature), is(false));
	}


	@Test()
	public void testVerfKeyEquals() throws MSSetupException {
		int n=2;
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(n,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[n];
		MSverfKey[] serverVK=new MSverfKey[n];
		for(int i=0;i<n;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		MSverfKey vk0=serverVK[0];
		assertThat(vk0.equals(serverVK[0]), is(true));
		assertThat(vk0.equals(serverVK[1]), is(false));
		assertThat(vk0.equals(serverSK[0]), is(false));
	}

	@Test()
	public void testNoSetup() {
		MS psScheme=new PSms();
		try{
			psScheme.kg();
			fail("Should throw IllegalStateException, keyGen");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.kAggreg(null);
			fail("Should throw IllegalStateException, keyGen");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.sign(null,null);
			fail("Should throw IllegalStateException, keyAggr");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.comb(null, null);
			fail("Should throw IllegalStateException, comb");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.verf(null,null,null);
			fail("Should throw IllegalStateException, comb");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.presentZKtoken(null,null,null,null,null);
			fail("Should throw IllegalStateException, presentZKtoken");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.verifyZKtoken(null,null,null,null);
			fail("Should throw IllegalStateException, verifyZKtoken");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.presentZKtokenModified(null,null,null,null,null,null);
			fail("Should throw IllegalStateException, presentZKtokenModified");
		}catch (IllegalStateException e){
		}
		try{
			psScheme.verifyZKtokenModified(null,null,null,null,null);
			fail("Should throw IllegalStateException, verifyZKtokenModified");
		}catch (IllegalStateException e){
		}
	}


	@Test()
	public void testSetupExceptions() throws MSSetupException {
		MS psScheme=new PSms();
		int n=nServers;
		int wrongN=0;
		PSauxArg correctAux=new PSauxArg(PAIRING_NAME,attrNames);
		PSauxArg wrongPairingName=new PSauxArg("NoName",attrNames);
		PSauxArg wrongAttrNames=new PSauxArg(PAIRING_NAME,new HashSet<>());
		PSauxArg wrongAttrNames2=new PSauxArg(PAIRING_NAME,null);
		try{
			psScheme.setup(n,MockFactory.mockMsAuxArg(),seed);
			fail("Should throw IllegalArgumentException, wrong psauxarg");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.setup(wrongN,correctAux,seed);
			fail("Should throw MSSetupException, wrong N");
		}catch (MSSetupException e){
		}
		try{
			psScheme.setup(n,wrongPairingName,seed);
			fail("Should throw MSSetupException, wrongPairingName");
		}catch (MSSetupException e){
		}
		try{
			psScheme.setup(n,wrongAttrNames,seed);
			fail("Should throw MSSetupException, length0 attrnames");
		}catch (MSSetupException e){
		}
		try{
			psScheme.setup(n,wrongAttrNames2,seed);
			fail("Should throw MSSetupException, null attrnames");
		}catch (MSSetupException e){
		}
		try{
			psScheme.setup(n,correctAux,seed);
			psScheme.setup(n,correctAux,seed);
			fail("Should throw IllegalStateException");
		}catch (IllegalStateException e){
		}
	}

	@Test()
	public void testKAggrExceptions() throws MSSetupException {
		int n1=2;
		int n2=3;
		//Create scheme for 2 severs with attrNames name, age; and get verification key
		MS psScheme1=new PSms();
		PSauxArg auxArg1=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme1.setup(n1,auxArg1,seed);
		PSverfKey vk1=(PSverfKey)psScheme1.kg().getSecond();
		//Create scheme for 3 severs with attrNames test; and get verification key
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(n2,auxArg2,seed);
		PSverfKey vk2=(PSverfKey)psScheme2.kg().getSecond();
		//Create arrays of verfKeys:
		MSverfKey[] wrongType=new MSverfKey[2];
		wrongType[0]=vk1;
		wrongType[1]=MockFactory.mockVerfKey();
		MSverfKey[] wrongFirstVk=new MSverfKey[2];
		wrongFirstVk[0]=vk2;
		wrongFirstVk[1]=vk1;
		MSverfKey[] wrongSecondVk=new MSverfKey[2];
		wrongSecondVk[0]=vk1;
		wrongSecondVk[1]=vk2;
		//Check exceptions for wrong type, wrong number of vks, wrong att of vks
		try{
			psScheme1.kAggreg(wrongType);
			fail("Should throw IllegalArgumentException, type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme2.kAggreg(new MSverfKey[1]);
			fail("Should throw IllegalArgumentException, number of vks");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.kAggreg(wrongFirstVk);
			fail("Should throw MSSetupException,  wrong attr first");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.kAggreg(wrongSecondVk);
			fail("Should throw IllegalStateException, wrong attr second");
		}catch (IllegalArgumentException e){
		}
	}

	@Test()
	public void testSignExceptions() throws MSSetupException {
		//Create scheme with attrNames name, age; and get secret key
		MS psScheme1=new PSms();
		PSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme1.setup(nServers,auxArg,seed);
		PSprivateKey sk1=(PSprivateKey) psScheme1.kg().getFirst();
		
		//Create scheme with attrNames test; and get secret key
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(nServers,auxArg2,seed);
		PSprivateKey sk2=(PSprivateKey) psScheme2.kg().getFirst();
		//Create scheme with attrNames test1,test2; and get secret key
		MS psScheme3=new PSms();
		PSauxArg auxArg3=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test1","test2")));
		psScheme3.setup(nServers,auxArg3,seed);
		PSprivateKey sk3=(PSprivateKey) psScheme3.kg().getFirst();
		//Generate correct message
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		MSmessage correctMsg=new PSmessage(attributes,epoch);
		//Generate wrong messages
		Map<String, ZpElement> attributes2=new HashMap<>();
		attributes2.put("test",new ZpElementBLS461(BIG.randomnum(p, rng)));
		MSmessage wrongNattrMsg=new PSmessage(attributes2,epoch);
		Map<String, ZpElement> attributes3=new HashMap<>();
		attributes3.put("test1",new ZpElementBLS461(BIG.randomnum(p, rng)));
		attributes3.put("test2",new ZpElementBLS461(BIG.randomnum(p, rng)));
		MSmessage wrongAttrNamesMsg=new PSmessage(attributes3,epoch);

		//Check exceptions for wrong types, wrong number number of attr and wrong attrNames for sk and msg
		try{
			psScheme1.sign(new MSprivateKey() {},correctMsg);
			fail("Should throw IllegalArgumentException, type sk");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.sign(sk1,MockFactory.mockMsMessage());
			fail("Should throw IllegalArgumentException, type msg");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.sign(sk2,correctMsg);
			fail("Should throw IllegalArgumentException, type msg");
		}catch (IllegalArgumentException e){
		}try{
			psScheme1.sign(sk3,correctMsg);
			fail("Should throw IllegalArgumentException, type msg");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.sign(sk1,wrongAttrNamesMsg);
			fail("Should throw IllegalArgumentException, attr names msg");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme1.sign(sk1,wrongNattrMsg);
			fail("Should throw IllegalArgumentException, number attr msg");
		}catch (IllegalArgumentException e){
		}
	}

	@Test()
	public void testCombExceptions() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Construct invalid vks and signature share
		MSverfKey[] serverVKWrong1=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			serverVKWrong1[i]=serverVK[i];
		}
		serverVKWrong1[nServers-1]=MockFactory.mockVerfKey();
		MSverfKey[] serverVKWrong2=new MSverfKey[nServers+1];
		MSsignature[] signSharesWrong1=new MSsignature[nServers];
		for(int i=0;i<nServers-1;i++){
			signSharesWrong1[i]=signShares[i];
		}
		signSharesWrong1[nServers-1]=new PSsignature(new PairingBuilderBLS461().getRandomZpElement(),((PSsignature)signShares[nServers-1]).getSigma1(),((PSsignature)signShares[nServers-1]).getSigma2());
		MSsignature[] signSharesWrong2=new MSsignature[nServers];
		for(int i=0;i<nServers-1;i++){
			signSharesWrong2[i]=signShares[i];
		}
		signSharesWrong2[nServers-1]=new PSsignature(((PSsignature)signShares[nServers-1]).getMPrim(),new PairingBuilderBLS461().getGroup2Generator(),((PSsignature)signShares[nServers-1]).getSigma2());
		MSsignature[] signSharesWrong3=new MSsignature[nServers+1];
		MSsignature[] signSharesWrong4=new MSsignature[nServers+1];
		for(int i=0;i<nServers-1;i++){
			signSharesWrong4[i]=signShares[i];
		}
		signSharesWrong4[nServers-1]=MockFactory.mockSig();

		//Check exceptions for wrong types, wrong number of signatures/verification keys and incompatible signs.
		try{
			psScheme.comb(serverVKWrong1, signShares);
			fail("Should throw IllegalArgumentException, vk wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.comb(serverVKWrong2, signShares);
			fail("Should throw IllegalArgumentException, vks wrong length");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.comb(serverVK, signSharesWrong1);
			fail("Should throw IllegalArgumentException, signatures wrong mPrim");
		}catch (IllegalArgumentException e){
		}try{
			psScheme.comb(serverVK, signSharesWrong2);
			fail("Should throw IllegalArgumentException, signatures wrong sigma1");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.comb(serverVK, signSharesWrong3);
			fail("Should throw IllegalArgumentException, signatures wrong length");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.comb(serverVK, signSharesWrong4);
			fail("Should throw IllegalArgumentException, signatures wrong type");
		}catch (IllegalArgumentException e){
		}
	}


	@Test()
	public void testVerfFraudulentUnitySignature() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		PairingBuilder pb=new PairingBuilderBLS461();
		ZpElement a=pb.getRandomZpElement();
		Group2Element unity=pb.getGroup2Generator().exp(a).mul(pb.getGroup2Generator().invExp(a));
		MSsignature signatureWrong=new PSsignature(((PSsignature)signature).getMPrim(),unity,unity);
		assertThat(psScheme.verf(avk,mAttr,signature),is(true));
		assertThat(psScheme.verf(avk,mAttr,signatureWrong),is(false));
	}

	@Test()
	public void testVerfExceptions() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		//Construct invalid avk, message, signature
		Map<String, ZpElement> attributes2=new HashMap<>();
		attributes2.put("test",new ZpElementBLS461(BIG.randomnum(p, rng)));
		MSmessage wrongNattrMsg=new PSmessage(attributes2,epoch);
		Map<String, ZpElement> attributes3=new HashMap<>();
		attributes3.put("test1",new ZpElementBLS461(BIG.randomnum(p, rng)));
		attributes3.put("test2",new ZpElementBLS461(BIG.randomnum(p, rng)));
		MSmessage wrongAttrNamesMsg=new PSmessage(attributes3,epoch);
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(nServers,auxArg2,seed);
		MSverfKey vkWrong1= psScheme2.kg().getSecond();
		MS psScheme3=new PSms();
		PSauxArg auxArg3=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test1","test2")));
		psScheme3.setup(nServers,auxArg3,seed);
		MSverfKey vkWrong2=psScheme3.kg().getSecond();
		//Check exceptions for wrong types, wrong number of signatures/verification keys.
		try{
			psScheme.verf(vkWrong1,mAttr,signature);
			fail("Should throw IllegalArgumentException, vk wrong number of attr");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verf(vkWrong2,mAttr,signature);
			fail("Should throw IllegalArgumentException, vk wrong attr names");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verf(MockFactory.mockVerfKey(),mAttr,signature);
			fail("Should throw IllegalArgumentException, vk wrong type");
		}catch (IllegalArgumentException e){
		}try{
			psScheme.verf(avk,mAttr,MockFactory.mockSig());
			fail("Should throw IllegalArgumentException, signature wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verf(avk,wrongAttrNamesMsg,signature);
			fail("Should throw IllegalArgumentException, message wrong attr names");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verf(avk,wrongNattrMsg,signature);
			fail("Should throw IllegalArgumentException, message wrong attr length");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verf(avk,MockFactory.mockMsMessage(),signature);
			fail("Should throw IllegalArgumentException, message wrong type");
		}catch (IllegalArgumentException e){
		}
	}

	@Test()
	public void testZkPresentExceptions() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		String message="TestMessage";
		//Token generation
		//Construct invalid avk, message, signature
		Map<String, ZpElement> attributes2=new HashMap<>();
		attributes2.put("test",new ZpElementBLS461(BIG.randomnum(p, rng)));
		MSmessage wrongNattrMsg=new PSmessage(attributes2,epoch);
		Map<String, ZpElement> attributes3=new HashMap<>();
		attributes3.put("test1",new ZpElementBLS461(BIG.randomnum(p, rng)));
		attributes3.put("test2",new ZpElementBLS461(BIG.randomnum(p, rng)));
		MSmessage wrongAttrNamesMsg=new PSmessage(attributes3,epoch);
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(nServers,auxArg2,seed);
		MSverfKey vkWrong1= psScheme2.kg().getSecond();
		MS psScheme3=new PSms();
		PSauxArg auxArg3=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test1","test2")));
		psScheme3.setup(nServers,auxArg3,seed);
		MSverfKey vkWrong2=psScheme3.kg().getSecond();
		Set<String> revealedAttributesNamesWrong=new HashSet<>();
		revealedAttributesNamesWrong.add("testWrong");
		//Check exceptions for wrong types, wrong number of signatures/verification keys.
		try{
			psScheme.presentZKtoken(vkWrong1,revealedAttributesNames,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, vk wrong number of attr");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(vkWrong2,revealedAttributesNames,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, vk wrong attr names");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(MockFactory.mockVerfKey(),revealedAttributesNames,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, vk wrong type");
		}catch (IllegalArgumentException e){
		}try{
			psScheme.presentZKtoken(avk,revealedAttributesNames,mAttr,message,MockFactory.mockSig());
			fail("Should throw IllegalArgumentException, signature wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(avk,revealedAttributesNames,wrongAttrNamesMsg,message,signature);
			fail("Should throw IllegalArgumentException, message wrong attr names");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(avk,revealedAttributesNames,wrongNattrMsg,message,signature);
			fail("Should throw IllegalArgumentException, message wrong attr length");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(avk,revealedAttributesNames,MockFactory.mockMsMessage(),message,signature);
			fail("Should throw IllegalArgumentException, message wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtoken(avk,revealedAttributesNamesWrong,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, wrong revealed attributes");
		}catch (IllegalArgumentException e){
		}
	}




	@Test()
	public void testZkVerifyFraudulentTokenRevealedAttributes() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		Map<String,ZpElement> revAttr=new HashMap<>();
		for(String attr:revealedAttributesNames)
			revAttr.put(attr,attributes.get(attr));
		MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
		String message="TestMessage";
		//Token generation
		MSzkToken token=psScheme.presentZKtoken(avk,revealedAttributesNames,mAttr,message,signature);
		//Construct invalid tokens
		PSzkToken psToken=(PSzkToken)token;
		Map<String,ZpElement> map1=new HashMap<>(psToken.getVaj());
		map1.put("age",epoch);
		MSzkToken tokenWrong1=new PSzkToken(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map1,psToken.getVt(),psToken.getVaPrim());
		Map<String,ZpElement> map2=new HashMap<>(psToken.getVaj());
		map2.remove("name");
		MSzkToken tokenWrong2=new PSzkToken(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map2,psToken.getVt(),psToken.getVaPrim());
		assertThat(psScheme.verifyZKtoken(tokenWrong1,avk,message,mRevealAttr),is(false));
		assertThat(psScheme.verifyZKtoken(tokenWrong2,avk,message,mRevealAttr),is(false));
	}


	@Test()
	public void testZkVerifyExceptions() throws MSSetupException {
		//Set specific seed for attribute generation
		int seedLength = FIELD_BYTES;
		RAND rng = new RAND();
		rng.clean();
		byte[] raw=new byte[seedLength];
		for (int i=0;i<seedLength;i++) raw[i]=(byte) (i+1);
		rng.seed(seedLength,raw);
		//Generate attributes as random ZpElements and a random epoch.
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attrNames){
			attributes.put(attr,new ZpElementBLS461(BIG.randomnum(p, rng)));
		}
		ZpElement epoch=new ZpElementBLS461(BIG.randomnum(p, rng));
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attrNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		Map<String,ZpElement> revAttr=new HashMap<>();
		for(String attr:revealedAttributesNames)
			revAttr.put(attr,attributes.get(attr));
		MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
		String message="TestMessage";
		//Token generation
		MSzkToken token=psScheme.presentZKtoken(avk,revealedAttributesNames,mAttr,message,signature);
		//Construct invalid avk, message, signature
		Map<String, ZpElement> attributes3=new HashMap<>();
		attributes3.put("test1",new ZpElementBLS461(BIG.randomnum(p, rng)));
		attributes3.put("test2",new ZpElementBLS461(BIG.randomnum(p, rng)));
		MSmessage wrongAttrNamesMsg=new PSmessage(attributes3,epoch);
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(nServers,auxArg2,seed);
		MSverfKey vkWrong1= psScheme2.kg().getSecond();
		MS psScheme3=new PSms();
		PSauxArg auxArg3=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test1","test2")));
		psScheme3.setup(nServers,auxArg3,seed);
		MSverfKey vkWrong2=psScheme3.kg().getSecond();
		MS psScheme4=new PSms();
		PSauxArg auxArg4=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("name","test2")));
		psScheme4.setup(nServers,auxArg4,seed);
		MSverfKey vkWrong3=psScheme4.kg().getSecond();
		Set<String> revealedAttributesNamesWrong=new HashSet<>();
		revealedAttributesNamesWrong.add("testWrong");
		PSzkToken psToken=(PSzkToken)token;
		Map<String,ZpElement> map1=new HashMap<>(psToken.getVaj());
		map1.put("testWrong",epoch);
		MSzkToken tokenWrong1=new PSzkToken(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map1,psToken.getVt(),psToken.getVaPrim());
		//Check exceptions for wrong types, wrong number of signatures/verification keys.
		try{
			psScheme.verifyZKtoken(token,vkWrong1,message,mRevealAttr);
			fail("Should throw IllegalArgumentException, vk wrong number of attr");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(token,vkWrong2,message,mRevealAttr);
			fail("Should throw IllegalArgumentException, vk wrong attr names hidden");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(token,vkWrong3,message,mRevealAttr);
			fail("Should throw IllegalArgumentException, vk wrong attr names revealed");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(token,MockFactory.mockVerfKey(),message,mRevealAttr);
			fail("Should throw IllegalArgumentException, vk wrong type");
		}catch (IllegalArgumentException e){
		}try{
			psScheme.verifyZKtoken(MockFactory.mockZkToken(),avk,message,mRevealAttr);
			fail("Should throw IllegalArgumentException, token wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(token,avk,message,MockFactory.mockMsMessage());
			fail("Should throw IllegalArgumentException, message type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(token,avk,message,wrongAttrNamesMsg);
			fail("Should throw IllegalArgumentException, message wrong attributes");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.verifyZKtoken(tokenWrong1,avk,message,mRevealAttr);
			fail("Should throw IllegalArgumentException, token invalid attr");
		}catch (IllegalArgumentException e){
		}
	}

    @Test
    public void testCompletePSFlowModified() throws MSSetupException {
        //Set specific seed for attribute generation
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        //Generate attributes as random ZpElements and a random epoch.
        Set<String> attributeNames=new HashSet<>(attrNames);
        attributeNames.add("height");
        Map<String, ZpElement> attributes=new HashMap<>();
        for(String attr:attributeNames){
            attributes.put(attr,builder.getRandomZpElement());
        }
        ZpElement epoch=builder.getRandomZpElement();
        //Create a PS-scheme instantiation
        MS psScheme=new PSms();
        //Generate auxArg and setup
        MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attributeNames);
        psScheme.setup(nServers,auxArg, seed);
        //KeyGeneration for each server
        MSprivateKey[] serverSK=new MSprivateKey[nServers];
        MSverfKey[] serverVK=new MSverfKey[nServers];
        for(int i=0;i<nServers;i++){
            Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
            serverSK[i]=keys.getFirst();
            serverVK[i]=keys.getSecond();
        }
        //Obtaining the aggregated verification key
        MSverfKey avk=psScheme.kAggreg(serverVK);
        //Constructing the message for signing (attributes)
        MSmessage mAttr=new PSmessage(attributes,epoch);
        //Signature share for each server
        MSsignature[] signShares=new MSsignature[nServers];
        for(int i=0;i<nServers;i++){
            signShares[i]=psScheme.sign(serverSK[i],mAttr);
        }
        //Combining shares in one signature
        MSsignature signature=psScheme.comb(serverVK, signShares);
        //Verifying the signature
        assertThat(psScheme.verf(avk,mAttr,signature), is(true));
        //Revealed attributes and signed message
        Set<String> revealedAttributesNames=new HashSet<>();
        revealedAttributesNames.add("age");
        //Create Commitment for link
		String message="TestMessage";
        PedersenCommitment v=new PedersenCommitment(((PSverfKey)avk).getVY().get("height"),((PSverfKey)avk).getVX(), attributes.get("height"), builder.getRandomZpElement());
        Map<String,PedersenCommitment> Vp=new HashMap<>();
        Vp.put("height",v);
        //Token generation
		//long start=System.currentTimeMillis();
        MSzkToken token=psScheme.presentZKtokenModified(avk,revealedAttributesNames,Vp,mAttr,message,signature);
		//long end=System.currentTimeMillis();
		//System.out.println(end-start);
        //Token verification
        Map<String,ZpElement> revAttr=new HashMap<>();
        for(String attr:revealedAttributesNames)
            revAttr.put(attr,attributes.get(attr));
        MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
        Map<String, Group1Element> commitments=new HashMap<>();
        commitments.put("height",v.getV());
		//start=System.currentTimeMillis();
		assertThat(psScheme.verifyZKtokenModified(token,avk,message,mRevealAttr,commitments),is(true));
		//end=System.currentTimeMillis();
		//System.out.println(end-start);
	}

	@Test()
	public void testZkVerifyModifiedFraudulentTokens() throws MSSetupException {
		//Set specific seed for attribute generation
		PairingBuilder builder=new PairingBuilderBLS461();
		builder.seedRandom(seed);
		//Generate attributes as random ZpElements and a random epoch.
		Set<String> attributeNames=new HashSet<>(attrNames);
		attributeNames.add("height");
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attributeNames){
			attributes.put(attr,builder.getRandomZpElement());
		}
		ZpElement epoch=builder.getRandomZpElement();
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attributeNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		//Verifying the signature
		assertThat(psScheme.verf(avk,mAttr,signature), is(true));
		//Revealed attributes and signed message
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		//Create Commitment for link
		String message="TestMessage";
		PedersenCommitment v=new PedersenCommitment(((PSverfKey)avk).getVY().get("height"),((PSverfKey)avk).getVX(), attributes.get("height"), builder.getRandomZpElement());
		Map<String,PedersenCommitment> Vp=new HashMap<>();
		Vp.put("height",v);
		//Token generation
		MSzkToken tokenOrig=psScheme.presentZKtokenModified(avk,revealedAttributesNames,Vp,mAttr,message,signature);
		MSzkToken token=new PSzkTokenModified(((PSzkTokenModified)tokenOrig).toProto());
		//Token verification
		Map<String,ZpElement> revAttr=new HashMap<>();
		for(String attr:revealedAttributesNames)
			revAttr.put(attr,attributes.get(attr));
		MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
		Map<String, Group1Element> commitments=new HashMap<>();
		commitments.put("height",v.getV());
		//Construct invalid tokens
		PSzkTokenModified psToken=(PSzkTokenModified)token;
		Map<String,ZpElement> map1=new HashMap<>(psToken.getVaj());
		map1.put("age",epoch);
		MSzkToken tokenWrong1=new PSzkTokenModified(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map1,psToken.getVt(),psToken.getVaPrim(),psToken.getvGammaj());
		Map<String,ZpElement> map2=new HashMap<>(psToken.getVaj());
		map2.remove("name");
		MSzkToken tokenWrong2=new PSzkTokenModified(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map2,psToken.getVt(),psToken.getVaPrim(),psToken.getvGammaj());
		//Construct wrong Commitment, same gamma different number, both different (trying to forge a "link")
		PedersenCommitment vWrong1=new PedersenCommitment(v.getG(),v.getH(),builder.getRandomZpElement(),v.getGamma());
		Map<String, Group1Element> commitmentsWrong1=new HashMap<>();
		commitmentsWrong1.put("height",vWrong1.getV());
		PedersenCommitment vWrong2=new PedersenCommitment(v.getG(),v.getH(),builder.getRandomZpElement(),builder.getRandomZpElement());
		Map<String, Group1Element> commitmentsWrong2=new HashMap<>();
		commitmentsWrong2.put("height",vWrong2.getV());
        Map<String, Group1Element> commitmentsWrong3=new HashMap<>();
        commitmentsWrong3.put("name",vWrong2.getV());
        Map<String,ZpElement> map3=new HashMap<>(psToken.getVaj());
        map3.remove("name");
        map3.put("height",epoch);
        MSzkToken tokenWrong3=new PSzkTokenModified(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map3,psToken.getVt(),psToken.getVaPrim(),psToken.getvGammaj());
        assertThat(psScheme.verifyZKtokenModified(token,avk,message,mRevealAttr,commitments),is(true));
		assertThat(psScheme.verifyZKtokenModified(tokenWrong1,avk,message,mRevealAttr,commitments),is(false));
		assertThat(psScheme.verifyZKtokenModified(tokenWrong2,avk,message,mRevealAttr,commitments),is(false));
		assertThat(psScheme.verifyZKtokenModified(tokenWrong2,avk,message,mRevealAttr,commitmentsWrong1),is(false));
		assertThat(psScheme.verifyZKtokenModified(token,avk,message,mRevealAttr,commitmentsWrong2),is(false));
		assertThat(psScheme.verifyZKtokenModified(token,avk,message,mRevealAttr,commitmentsWrong3),is(false));
		assertThat(psScheme.verifyZKtokenModified(tokenWrong3,avk,message,mRevealAttr,commitments),is(false));
	}

	@Test()
	public void testZkVerifyModifiedFraudulentCommitmentsInRange() throws MSSetupException {
		//Set specific seed for attribute generation
		PairingBuilder builder=new PairingBuilderBLS461();
		builder.seedRandom(seed);
		//Generate attributes as random ZpElements and a random epoch.
		Set<String> attributeNames=new HashSet<>(attrNames);
		attributeNames.add("height");
		Map<String, AttributeDefinition> definitions=new HashMap<>();
		definitions.put("name",new AttributeDefinitionString("name","name",1,10));
		definitions.put("height",new AttributeDefinitionInteger("height","height",1,300));
		definitions.put("age",new AttributeDefinitionInteger("age","age",0,120));
		Map<String, Attribute> attributeValues=new HashMap<>();
		attributeValues.put("name",new Attribute("John"));
		attributeValues.put("age",new Attribute(35));
		attributeValues.put("height",new Attribute(180));
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attributeNames){
			attributes.put(attr,builder.getZpElementFromAttribute(attributeValues.get(attr),definitions.get(attr)));
		}
		ZpElement epoch=builder.getRandomZpElement();
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attributeNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		//Verifying the signature
		assertThat(psScheme.verf(avk,mAttr,signature), is(true));
		//Revealed attributes and signed message
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("name");
		//Create Commitment for link
		String message="TestMessage";
		PedersenCommitment v=new PedersenCommitment(((PSverfKey)avk).getVY().get("height"),((PSverfKey)avk).getVX(), attributes.get("height"), builder.getRandomZpElement());
		Map<String,PedersenCommitment> Vp=new HashMap<>();
		Vp.put("height",v);
		//Token generation
		MSzkToken token=psScheme.presentZKtokenModified(avk,revealedAttributesNames,Vp,mAttr,message,signature);
		//Token verification
		Map<String,ZpElement> revAttr=new HashMap<>();
		for(String attr:revealedAttributesNames)
			revAttr.put(attr,attributes.get(attr));
		MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
		Map<String, Group1Element> commitments=new HashMap<>();
		commitments.put("height",v.getV());
		//Idea behind this is some "malicious user" trying to link a commitment that shows his age is in some range (20-25) or height in other (200-204) when the attributes
		// in the credential do not fit (35 and 180). This way both a lower and higher attribute than the range are checked.
		// As extra, check what happens if the fake commitment is created using randomness 0 (no other "special" candidate value for the randomness)
		//Changing the commitment after the proof was generated is already tested in other place
		// Fake commitments
		PedersenCommitment vAge20=new PedersenCommitment(((PSverfKey)avk).getVY().get("age"),((PSverfKey)avk).getVX(),
				builder.getZpElementFromAttribute(new Attribute(20),definitions.get("age")), builder.getRandomZpElement());
		PedersenCommitment vAge25=new PedersenCommitment(((PSverfKey)avk).getVY().get("age"),((PSverfKey)avk).getVX(),
				builder.getZpElementFromAttribute(new Attribute(25),definitions.get("age")), builder.getRandomZpElement());
		PedersenCommitment vAge23=new PedersenCommitment(((PSverfKey)avk).getVY().get("age"),((PSverfKey)avk).getVX(),
				builder.getZpElementFromAttribute(new Attribute(23),definitions.get("age")), builder.getRandomZpElement());
		PedersenCommitment vHeight200=new PedersenCommitment(((PSverfKey)avk).getVY().get("height"),((PSverfKey)avk).getVX(),
				builder.getZpElementFromAttribute(new Attribute(200),definitions.get("height")), builder.getRandomZpElement());
		PedersenCommitment vHeight204=new PedersenCommitment(((PSverfKey)avk).getVY().get("height"),((PSverfKey)avk).getVX(),
				builder.getZpElementFromAttribute(new Attribute(204),definitions.get("height")), builder.getRandomZpElement());
		PedersenCommitment vHeight203=new PedersenCommitment(((PSverfKey)avk).getVY().get("height"),((PSverfKey)avk).getVX(),
				builder.getZpElementFromAttribute(new Attribute(203),definitions.get("height")), builder.getRandomZpElement());
		PedersenCommitment vAgeRandomness0=new PedersenCommitment(((PSverfKey)avk).getVY().get("age"),((PSverfKey)avk).getVX(),
				builder.getZpElementFromAttribute(new Attribute(22),definitions.get("age")), builder.getZpElementZero());
		Map<String, PedersenCommitment> VpAge20=new HashMap<>();
		VpAge20.put("age",vAge20);
		Map<String, PedersenCommitment> VpAge25=new HashMap<>();
		VpAge25.put("age",vAge25);
		Map<String, PedersenCommitment> VpAge23=new HashMap<>();
		VpAge23.put("age",vAge23);
		Map<String, PedersenCommitment> VpAgeRandomness0=new HashMap<>();
		VpAgeRandomness0.put("age",vAgeRandomness0);
		Map<String, PedersenCommitment> VpHeight200=new HashMap<>();
		VpHeight200.put("height",vHeight200);
		Map<String, PedersenCommitment> VpHeight204=new HashMap<>();
		VpHeight204.put("height",vHeight204);
		Map<String, PedersenCommitment> VpHeight203=new HashMap<>();
		VpHeight203.put("height",vHeight203);
		Map<String, Group1Element> commitmentsAge20=new HashMap<>();
		commitmentsAge20.put("age",vAge20.getV());
		Map<String, Group1Element> commitmentsAge25=new HashMap<>();
		commitmentsAge25.put("age",vAge25.getV());
		Map<String, Group1Element> commitmentsAge23=new HashMap<>();
		commitmentsAge23.put("age",vAge23.getV());
		Map<String, Group1Element> commitmentsAgeRandomness0=new HashMap<>();
		commitmentsAgeRandomness0.put("age",vAgeRandomness0.getV());
		Map<String, Group1Element> commitmentsHeight200=new HashMap<>();
		commitmentsHeight200.put("height",vHeight200.getV());
		Map<String, Group1Element> commitmentsHeight204=new HashMap<>();
		commitmentsHeight204.put("height",vHeight204.getV());
		Map<String, Group1Element> commitmentsHeight203=new HashMap<>();
		commitmentsHeight203.put("height",vHeight203.getV());
		//Generate proofs
		MSzkToken tokenAge20=psScheme.presentZKtokenModified(avk,revealedAttributesNames,VpAge20,mAttr,message,signature);
		MSzkToken tokenAge25=psScheme.presentZKtokenModified(avk,revealedAttributesNames,VpAge25,mAttr,message,signature);
		MSzkToken tokenAge23=psScheme.presentZKtokenModified(avk,revealedAttributesNames,VpAge23,mAttr,message,signature);
		MSzkToken tokenAgeRandomness0=psScheme.presentZKtokenModified(avk,revealedAttributesNames,VpAgeRandomness0,mAttr,message,signature);
		MSzkToken tokenHeight200=psScheme.presentZKtokenModified(avk,revealedAttributesNames,VpHeight200,mAttr,message,signature);
		MSzkToken tokenHeight204=psScheme.presentZKtokenModified(avk,revealedAttributesNames,VpHeight204,mAttr,message,signature);
		MSzkToken tokenHeight203=psScheme.presentZKtokenModified(avk,revealedAttributesNames,VpHeight203,mAttr,message,signature);
		//Verifications
		assertThat(psScheme.verifyZKtokenModified(token,avk,message,mRevealAttr,commitments),is(true));
		assertThat(psScheme.verifyZKtokenModified(tokenAge20,avk,message,mRevealAttr,commitmentsAge20),is(false));
		assertThat(psScheme.verifyZKtokenModified(tokenAge25,avk,message,mRevealAttr,commitmentsAge25),is(false));
		assertThat(psScheme.verifyZKtokenModified(tokenAge23,avk,message,mRevealAttr,commitmentsAge23),is(false));
		assertThat(psScheme.verifyZKtokenModified(tokenAgeRandomness0,avk,message,mRevealAttr,commitmentsAgeRandomness0),is(false));
		assertThat(psScheme.verifyZKtokenModified(tokenHeight200,avk,message,mRevealAttr,commitmentsHeight200),is(false));
		assertThat(psScheme.verifyZKtokenModified(tokenHeight204,avk,message,mRevealAttr,commitmentsHeight204),is(false));
		assertThat(psScheme.verifyZKtokenModified(tokenHeight203,avk,message,mRevealAttr,commitmentsHeight203),is(false));
	}

	@Test()
	public void testZkPresentModifiedExceptions() throws MSSetupException {
		//Set specific seed for attribute generation
		PairingBuilder builder=new PairingBuilderBLS461();
		builder.seedRandom(seed);
		//Generate attributes as random ZpElements and a random epoch.
		Set<String> attributeNames=new HashSet<>(attrNames);
		attributeNames.add("height");
		Map<String, ZpElement> attributes=new HashMap<>();
		for(String attr:attributeNames){
			attributes.put(attr,builder.getRandomZpElement());
		}
		ZpElement epoch=builder.getRandomZpElement();
		//Create a PS-scheme instantiation
		MS psScheme=new PSms();
		//Generate auxArg and setup
		MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attributeNames);
		psScheme.setup(nServers,auxArg, seed);
		//KeyGeneration for each server
		MSprivateKey[] serverSK=new MSprivateKey[nServers];
		MSverfKey[] serverVK=new MSverfKey[nServers];
		for(int i=0;i<nServers;i++){
			Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
			serverSK[i]=keys.getFirst();
			serverVK[i]=keys.getSecond();
		}
		//Constructing the message for signing (attributes)
		MSmessage mAttr=new PSmessage(attributes,epoch);
		//Signature share for each server
		MSsignature[] signShares=new MSsignature[nServers];
		for(int i=0;i<nServers;i++){
			signShares[i]=psScheme.sign(serverSK[i],mAttr);
		}
		//Obtaining the aggregated verification key
		MSverfKey avk=psScheme.kAggreg(serverVK);
		//Combining shares in one signature
		MSsignature signature=psScheme.comb(serverVK, signShares);
		Set<String> revealedAttributesNames=new HashSet<>();
		revealedAttributesNames.add("age");
		String message="TestMessage";
        PedersenCommitment v=new PedersenCommitment(((PSverfKey)avk).getVY().get("height"),((PSverfKey)avk).getVX(), attributes.get("height"), builder.getRandomZpElement());
        Map<String,PedersenCommitment> Vp=new HashMap<>();
        Vp.put("height",v);
		//Token generation
		//Construct invalid avk, message, signature
		Map<String, ZpElement> attributes2=new HashMap<>();
		attributes2.put("test",builder.getRandomZpElement());
		MSmessage wrongNattrMsg=new PSmessage(attributes2,epoch);
		Map<String, ZpElement> attributes3=new HashMap<>();
		attributes3.put("age",builder.getRandomZpElement());
		attributes3.put("name",builder.getRandomZpElement());
		attributes3.put("test",builder.getRandomZpElement());
		MSmessage wrongAttrNamesMsg=new PSmessage(attributes3,epoch);
        Map<String, ZpElement> attributes4=new HashMap<>();
        attributes4.put("age",builder.getRandomZpElement());
        attributes4.put("height",builder.getRandomZpElement());
        attributes4.put("test",builder.getRandomZpElement());
        MSmessage wrongAttrNamesMsg2=new PSmessage(attributes4,epoch);
		MS psScheme2=new PSms();
		PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
		psScheme2.setup(nServers,auxArg2,seed);
		MSverfKey vkWrong1= psScheme2.kg().getSecond();
		MS psScheme3=new PSms();
		PSauxArg auxArg3=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("age","name","test3")));
		psScheme3.setup(nServers,auxArg3,seed);
		MSverfKey vkWrong2=psScheme3.kg().getSecond();
        MS psScheme4=new PSms();
        PSauxArg auxArg4=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("age","test2","height")));
        psScheme4.setup(nServers,auxArg4,seed);
        MSverfKey vkWrong3=psScheme4.kg().getSecond();
		Set<String> revealedAttributesNamesWrong=new HashSet<>();
		revealedAttributesNamesWrong.add("testWrong");
        Map<String,PedersenCommitment> VpWrongIntersec=new HashMap<>();
        VpWrongIntersec.put("age",v);
        Map<String,PedersenCommitment> VpWrong1=new HashMap<>();
        VpWrong1.put("testWrong",v);
		//Check exceptions for wrong types, wrong number of signatures/verification keys.
		try{
			psScheme.presentZKtokenModified(vkWrong1,revealedAttributesNames,Vp,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, vk wrong number of attr");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtokenModified(vkWrong2,revealedAttributesNames,Vp,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, vk wrong attr names");
		}catch (IllegalArgumentException e){
		}
        try{
            psScheme.presentZKtokenModified(vkWrong3,revealedAttributesNames,Vp,mAttr,message,signature);
            fail("Should throw IllegalArgumentException, vk wrong attr names");
        }catch (IllegalArgumentException e){
        }
		try{
			psScheme.presentZKtokenModified(MockFactory.mockVerfKey(),revealedAttributesNames,Vp,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, vk wrong type");
		}catch (IllegalArgumentException e){
		}try{
			psScheme.presentZKtokenModified(avk,revealedAttributesNames,Vp,mAttr,message,MockFactory.mockSig());
			fail("Should throw IllegalArgumentException, signature wrong type");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtokenModified(avk,revealedAttributesNames,Vp,wrongAttrNamesMsg,message,signature);
			fail("Should throw IllegalArgumentException, message wrong attr names");
		}catch (IllegalArgumentException e){
		}
        try{
            psScheme.presentZKtokenModified(avk,revealedAttributesNames,Vp,wrongAttrNamesMsg2,message,signature);
            fail("Should throw IllegalArgumentException, message wrong attr names");
        }catch (IllegalArgumentException e){
        }
		try{
			psScheme.presentZKtokenModified(avk,revealedAttributesNames,Vp,wrongNattrMsg,message,signature);
			fail("Should throw IllegalArgumentException, message wrong attr length");
		}catch (IllegalArgumentException e){
		}
		try{
			psScheme.presentZKtokenModified(avk,revealedAttributesNames,Vp,MockFactory.mockMsMessage(),message,signature);
			fail("Should throw IllegalArgumentException, message wrong type");
		}catch (IllegalArgumentException e){
		}
        try{
            psScheme.presentZKtokenModified(avk,revealedAttributesNamesWrong,Vp,mAttr,message,signature);
            fail("Should throw IllegalArgumentException, wrong revealed attributes");
        }catch (IllegalArgumentException e){
        }
        try{
            psScheme.presentZKtokenModified(avk,revealedAttributesNames,VpWrong1,mAttr,message,signature);
            fail("Should throw IllegalArgumentException, wrong revealed attributes");
        }catch (IllegalArgumentException e){
        }
		try{
			psScheme.presentZKtokenModified(avk,revealedAttributesNames,VpWrongIntersec,mAttr,message,signature);
			fail("Should throw IllegalArgumentException, wrong revealed attributes");
		}catch (IllegalArgumentException e){
		}
	}


    @Test()
    public void testZkVerifyModifiedExceptions() throws MSSetupException {
        //Set specific seed for attribute generation
        PairingBuilder builder=new PairingBuilderBLS461();
        builder.seedRandom(seed);
        //Generate attributes as random ZpElements and a random epoch.
        Set<String> attributeNames=new HashSet<>(attrNames);
        attributeNames.add("height");
        Map<String, ZpElement> attributes=new HashMap<>();
        for(String attr:attributeNames){
            attributes.put(attr,builder.getRandomZpElement());
        }
        ZpElement epoch=builder.getRandomZpElement();
        //Create a PS-scheme instantiation
        MS psScheme=new PSms();
        //Generate auxArg and setup
        MSauxArg auxArg=new PSauxArg(PAIRING_NAME,attributeNames);
        psScheme.setup(nServers,auxArg, seed);
        //KeyGeneration for each server
        MSprivateKey[] serverSK=new MSprivateKey[nServers];
        MSverfKey[] serverVK=new MSverfKey[nServers];
        for(int i=0;i<nServers;i++){
            Pair<MSprivateKey,MSverfKey> keys=psScheme.kg();
            serverSK[i]=keys.getFirst();
            serverVK[i]=keys.getSecond();
        }
        //Constructing the message for signing (attributes)
        MSmessage mAttr=new PSmessage(attributes,epoch);
        //Signature share for each server
        MSsignature[] signShares=new MSsignature[nServers];
        for(int i=0;i<nServers;i++){
            signShares[i]=psScheme.sign(serverSK[i],mAttr);
        }
        //Obtaining the aggregated verification key
        MSverfKey avk=psScheme.kAggreg(serverVK);
        //Combining shares in one signature
        MSsignature signature=psScheme.comb(serverVK, signShares);
        Set<String> revealedAttributesNames=new HashSet<>();
        revealedAttributesNames.add("age");
        Map<String,ZpElement> revAttr=new HashMap<>();
        for(String attr:revealedAttributesNames)
            revAttr.put(attr,attributes.get(attr));
        MSmessage mRevealAttr=new PSmessage(revAttr,epoch);
        String message="TestMessage";
        PedersenCommitment v=new PedersenCommitment(((PSverfKey)avk).getVY().get("height"),((PSverfKey)avk).getVX(), attributes.get("height"), builder.getRandomZpElement());
        Map<String,PedersenCommitment> Vp=new HashMap<>();
        Vp.put("height",v);
        //Token generation
        MSzkToken token=psScheme.presentZKtokenModified(avk,revealedAttributesNames,Vp,mAttr,message,signature);
        Map<String, Group1Element> commitments=new HashMap<>();
        commitments.put("height",v.getV());
        //Construct invalid avk, message, signature
        Map<String, ZpElement> attributes3=new HashMap<>();
        attributes3.put("test1",builder.getRandomZpElement());
        attributes3.put("test2",builder.getRandomZpElement());
        attributes3.put("test3",builder.getRandomZpElement());
        MSmessage wrongAttrNamesMsg=new PSmessage(attributes3,epoch);
        MS psScheme2=new PSms();
        PSauxArg auxArg2=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("test")));
        psScheme2.setup(nServers,auxArg2,seed);
        MSverfKey vkWrong1= psScheme2.kg().getSecond();
        MS psScheme3=new PSms();
        PSauxArg auxArg3=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("name","height","test3")));
        psScheme3.setup(nServers,auxArg3,seed);
        MSverfKey vkWrong2=psScheme3.kg().getSecond();
        MS psScheme4=new PSms();
        PSauxArg auxArg4=new PSauxArg(PAIRING_NAME,new HashSet<>(Arrays.asList("name","age","test3")));
        psScheme4.setup(nServers,auxArg4,seed);
        MSverfKey vkWrong3=psScheme4.kg().getSecond();
        Set<String> revealedAttributesNamesWrong=new HashSet<>();
        revealedAttributesNamesWrong.add("testWrong");
        PSzkTokenModified psToken=(PSzkTokenModified)token;
        Map<String,ZpElement> map1=new HashMap<>(psToken.getVaj());
        map1.put("testWrong",epoch);
        MSzkToken tokenWrong1=new PSzkTokenModified(psToken.getSigma1(),psToken.getSigma2(),psToken.getC(),map1,psToken.getVt(),psToken.getVaPrim(),psToken.getvGammaj());
        Map<String, Group1Element> wrongCommitments1=new HashMap<>();
        wrongCommitments1.put("testWrong",v.getV());
        Map<String, Group1Element> wrongCommitments2=new HashMap<>();
        wrongCommitments2.put("age",v.getV());
        //Check exceptions for wrong types, wrong number of signatures/verification keys.
        try{
            psScheme.verifyZKtokenModified(token,vkWrong1,message,mRevealAttr,commitments);
            fail("Should throw IllegalArgumentException, vk wrong number of attr");
        }catch (IllegalArgumentException e){
        }
        try{
            psScheme.verifyZKtokenModified(token,vkWrong2,message,mRevealAttr,commitments);
            fail("Should throw IllegalArgumentException, vk wrong attr names hidden");
        }catch (IllegalArgumentException e){
        }
        try{
            psScheme.verifyZKtokenModified(token,vkWrong3,message,mRevealAttr,commitments);
            fail("Should throw IllegalArgumentException, vk wrong attr names revealed");
        }catch (IllegalArgumentException e){
        }
        try{
            psScheme.verifyZKtokenModified(token,MockFactory.mockVerfKey(),message,mRevealAttr,commitments);
            fail("Should throw IllegalArgumentException, vk wrong type");
        }catch (IllegalArgumentException e){
        }try{
            psScheme.verifyZKtokenModified(MockFactory.mockZkToken(),avk,message,mRevealAttr,commitments);
            fail("Should throw IllegalArgumentException, token wrong type");
        }catch (IllegalArgumentException e){
        }
        try{
            psScheme.verifyZKtokenModified(token,avk,message,MockFactory.mockMsMessage(),commitments);
            fail("Should throw IllegalArgumentException, message type");
        }catch (IllegalArgumentException e){
        }
        try{
            psScheme.verifyZKtokenModified(token,avk,message,wrongAttrNamesMsg,commitments);
            fail("Should throw IllegalArgumentException, message wrong attributes");
        }catch (IllegalArgumentException e){
        }
        try{
            psScheme.verifyZKtokenModified(tokenWrong1,avk,message,mRevealAttr,commitments);
            fail("Should throw IllegalArgumentException, token invalid attr");
        }catch (IllegalArgumentException e){
        }
        try{
            psScheme.verifyZKtokenModified(token,avk,message,mRevealAttr,wrongCommitments1);
            fail("Should throw IllegalArgumentException, commitments invalid attr");
        }catch (IllegalArgumentException e){
        }
        try{
            psScheme.verifyZKtokenModified(token,avk,message,mRevealAttr,wrongCommitments2);
            fail("Should throw IllegalArgumentException, commitments invalid attr intersect");
        }catch (IllegalArgumentException e){
        }
    }
}
