package eu.olympus.util.pairingBLS461;

import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.util.CommonCrypto;
import eu.olympus.util.Util;
import eu.olympus.util.pairingInterfaces.*;
import org.apache.commons.codec.Charsets;
import org.miracl.core.BLS12461.*;
import org.miracl.core.HASH512;
import org.miracl.core.HMAC;
import org.miracl.core.RAND;

public class PairingBuilderBLS461 implements PairingBuilder {

    private RAND rng;

    public PairingBuilderBLS461(){
        rng = new RAND();
    }
    
    @Override
    public void seedRandom(byte[] seed) {
     	rng.clean();
        rng.seed(seed.length, seed);
    }
    
    @Override
    public Pairing getPairing() {
        return new PairingBLS461();
    }

    @Override
    public Group2ElementBLS461 getGroup2Generator() {
        return new Group2ElementBLS461(ECP2.generator());
    }

    @Override
    public Group1ElementBLS461 getGroup1Generator() {
        return new Group1ElementBLS461(ECP.generator());
    }

    @Override
    public Group3Element getGroup3Generator() {
        return getPairing().pair(getGroup2Generator(),getGroup1Generator());
    }

    @Override
    public ZpElementBLS461 getRandomZpElement() {
        return new ZpElementBLS461(BIG.randomnum(PairingBLS461.p, rng));
    }

    @Override
    public ZpElement getZpElementFromAttribute(Attribute attributeValue, AttributeDefinition attributeDefinition) {
        BIG res= Util.BigIntegerToBIG(attributeDefinition.toBigIntegerRepresentation(attributeValue));
        return new ZpElementBLS461(res);
    }

    @Override
    public ZpElement getZpElementFromEpoch(long epoch) {
        BIG b=new BIG();
        b.incl(epoch);
        return new ZpElementBLS461(b);
    }

    @Override
    public Hash0 getHash0() {
        return new Hash0BLS461();
    }

    @Override
    public Hash1 getHash1() {
        return new Hash1BLS461();
    }

    @Override
    public Hash2 getHash2() { return new Hash2BLS461(); }

    @Override
    public ZpElement getZpElementZero() {
        BIG x=new BIG();
        x.zero();
        return new ZpElementBLS461(x);
    }

    @Override
    public ZpElement hashZpElementFromBytes(byte[] bytes) {
        return new ZpElementBLS461(hashModOrder(bytes));
    }

    @Override
    public Group2Element hashGroup2ElementFromBytes(byte[] bytes) {
        return new Group2ElementBLS461(hashToECP2(bytes));
    }

    @Override
    public Group1Element hashGroup1ElementFromBytes(byte[] bytes) {
        return new Group1ElementBLS461(hashToECP(bytes));
    }

    @Override
    public ZpElement getZpElementOne() {
        return new ZpElementBLS461(new BIG(1));
    }

    @Override
    public Hash2Modified getHash2Mod() {
        return new Hash2ModifiedBLS461();
    }


    private static BIG hashModOrder(byte[] data) {
        HASH512 hash = new HASH512();
        for (byte b : data) {
            hash.process(b);
        }
        byte[] hasheddata = hash.hash();
        BIG ret = BIG.fromBytes(hasheddata);
        ret.mod(PairingBLS461.p);
        return ret;
    }

    /**
     *  Hashes bytes to an amcl.ECP2
     *
     * @param input The data to be hashed
     * @return A ECP2 element
     */
    private ECP2 hashToECP2(byte[] input) {
        FP realA = hashToFP(input, "real-a");
        FP imaginaryA = hashToFP(input, "imaginary-a");
        FP2 fpA = new FP2(realA, imaginaryA);
        FP realB = hashToFP(input, "real-b");
        FP imaginaryB = hashToFP(input, "imaginary-b");
        FP2 fpB = new FP2(realB, imaginaryB);
        ECP2 PA = ECP2.map2point(fpA);
        ECP2 PB = ECP2.map2point(fpB);
        PA.add(PB);
        PA.cfp();
        PA.affine();
        return PA;
    }

    private FP hashToFP(byte[] input, String salt) {
        // Use PBKDF2 to prevent potential issues with extension attacks given SHA2 is used with 2 iterations, hashing to BLS.BFS bytes
        byte[] hash = HMAC.PBKDF2(HMAC.MC_SHA2, 32, input, salt.getBytes(Charsets.UTF_8), 2, BLS.BFS+CommonCrypto.STATISTICAL_SEC_BYTES);
        BIG res = BIG.fromBytes(hash);
        // Note that technically the digest should be used as input to a universal hash function hashing exactly to the field size
        res.mod(new BIG(ROM.Modulus));
        return new FP(res);
    }

    public ECP hashToECP(byte[] input) {
        return BLS.bls_hash_to_point(input);
    }



}
