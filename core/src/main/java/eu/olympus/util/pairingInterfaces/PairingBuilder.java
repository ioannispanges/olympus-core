package eu.olympus.util.pairingInterfaces;

import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;

public interface PairingBuilder {

    /**
     * @return Pairing object that contains pairing methods.
     */
    Pairing getPairing();

    /**
     * Seeds the random generator used in the builder.
     * @param seed
     */
    void seedRandom(byte[] seed);
    
    /**
     * @return Generator of the first group of the pairing.
     */
    Group2Element getGroup2Generator();

    /**
     * @return Generator of the second group of the pairing.
     */
    Group1Element getGroup1Generator();

    /**
     * @return Generator of the third group of the pairing.
     */
    Group3Element getGroup3Generator();

    /**
     * @return Random element from Zp.
     */
    ZpElement getRandomZpElement();

    /**
     * @param attributeValue Attribute that has to be transformed into a Zp element.
     * @param attributeDefinition Definition of the attribute for which attributeValue is a value (extra info like min/max...).
     * @return The Zp element corresponding to the attribute el.
     */
    ZpElement getZpElementFromAttribute(Attribute attributeValue, AttributeDefinition attributeDefinition);

    /**
     * @param epoch Epoch that has to be transformed into a Zp element.
     * @return The Zp element corresponding to the epoch .
     */
    ZpElement getZpElementFromEpoch(long epoch);

    /**
     * @return Hash0 implementation.
     */
    Hash0 getHash0();

    /**
     * @return Hash1 implementation.
     */
    Hash1 getHash1();

    /**
     * @return Hash2 implementation.
     */
    Hash2 getHash2();

    /**
     * @return Zero as a ZpElement.
     */
    ZpElement getZpElementZero();

    /**
     * Used for hashing/challenge computation
     * @return A ZpElement from a byte array
     */
    ZpElement hashZpElementFromBytes(byte[] bytes);

    /**
     * Used for hashing/challenge computation
     * @return A Group2Element from a byte array
     */
    Group2Element hashGroup2ElementFromBytes(byte[] bytes);

    /**
     * Used for hashing/challenge computation
     * @return A Group1Element from a byte array
     */
    Group1Element hashGroup1ElementFromBytes(byte[] bytes);

    /**
     * @return One as a ZpElement.
     */
    ZpElement getZpElementOne();

    Hash2Modified getHash2Mod();
}
