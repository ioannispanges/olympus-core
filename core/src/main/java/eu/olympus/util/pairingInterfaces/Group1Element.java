package eu.olympus.util.pairingInterfaces;

import eu.olympus.protos.serializer.PabcSerializer;

/**
 * Interface for the elements of the first group of the pairing.
 */
public interface Group1Element {

    /**
     * Multiplicative operation of the group (both elements are not modified)
     * @param el2 Element to be multiplied.
     * @return this*el2.
     */
    Group1Element mul(Group1Element el2);

    /**
     * Exponentiation operation of the group (both elements are not modified)
     * @param exp Exponent.
     * @return this^exp.
     */
    Group1Element exp(ZpElement exp);

    /**
     * Inverse exponentiation (both elements are not modified)
     * @param exp Exponent.
     * @return this^(-exp).
     */
    Group1Element invExp(ZpElement exp);

    /**
     * Check if the element is a unit.
     * @return this==1G
     */
    boolean isUnity();

    /**
     * For serialization using protobuf
     * @return Protobuf version of the element
     */
    PabcSerializer.Group1Element toProto();

    /**
     * Multiexponentiation (calling element is only used for type resolution). It may be slower than doing it "by hand"
     * if the number of elements is small (e.g., for BLS461 breaking point is around 25)
     * @param elements Group1elements that will be bases
     * @param exponents ZpElements that will be exponents
     * @return elements[0]^exponents[0]···elements[n]^exponents[n]
     */
    Group1Element multiExp(Group1Element[] elements, ZpElement[] exponents);

    /**
     * Mostly for hashing/challenge computation purposes
     * @return Bytes from
     */
    byte[] toBytes();
}
