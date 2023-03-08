package eu.olympus.util.pairingInterfaces;

import eu.olympus.protos.serializer.PabcSerializer;

/**
 * Interface for the elements of the second group of the pairing.
 */
public interface Group2Element {

    /**
     * Multiplicative operation of the group (both elements are not modified)
     * @param el2 Element to be multiplied.
     * @return this*el2.
     */
    Group2Element mul(Group2Element el2);

    /**
     * Exponentiation operation of the group (both elements are not modified)
     * @param exp Exponent.
     * @return this^exp.
     */
    Group2Element exp(ZpElement exp);

    /**
     * Inverse exponentiation (both elements are not modified)
     * @param exp Exponent.
     * @return this^(-exp).
     */
    Group2Element invExp(ZpElement exp);

    /**
     * Check if the element is a unit.
     * @return this==1G
     */
    boolean isUnity();

    /**
     * For serialization using protobuf
     * @return Protobuf version of the element
     */
    PabcSerializer.Group2Element toProto();

    /**
     * Mostly for hashing/challenge computation purposes
     * @return Bytes from
     */
    byte[] toBytes();

}
