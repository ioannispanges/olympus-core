package eu.olympus.util.rangeProof.model;

import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.ZpElement;

import java.util.Arrays;

public class GroupVector {

    private final int MULTIEXP_BREAKPOINT=25;
    protected Group1Element[] v;

    public GroupVector(Group1Element ... v) {
        this.v=new Group1Element[v.length];
        for (int i = 0; i < v.length; i++)
            this.v[i] = v[i];
    }

    /**
     * Creates a new GroupVector that is the concatenation of the argument vectors
     * @param vectors
     * @return
     */
    public static GroupVector concat(GroupVector ... vectors) {
        int amount = 0;
        int offset = 0;
        for (GroupVector arr : vectors) {
            amount += arr.v.length;
        }
        Group1Element[] dest = new Group1Element[amount];
        for (GroupVector arr :vectors) {
            System.arraycopy(arr.v, 0, dest, offset, arr.v.length);
            offset += arr.v.length;
        }
        return new GroupVector(dest);
    }


    /**
     * Vector composed from elements v_start to v_finish, inclusive (remember math indexing is used,
     * so v=(v_1,v_2,...,v_n)
     * @param start First index included
     * @param finish Last index included
     * @return Subvector
     */
    public GroupVector subVector(int start, int finish){
        return new GroupVector(Arrays.copyOfRange(v,start-1,finish));
    }

    /**
     * Get vector component v=(v_1,v_2,...,v_n)
     * @param index
     * @return v_i
     */
    public Group1Element getComponent(int index){
        return v[index-1];
    }

    /**
     *
     * @return Vector size
     */
    public int size(){
        return v.length;
    }

    /**
     * Power each component by the correspondent exponent and multiply the results
     * @param exponents Vector of exponents
     * @return g_1^(exp_1)···g_n^(exp_n)
     */
    public Group1Element expMult(ZpVector exponents) {
        if(size()!=exponents.size())
            throw new IllegalArgumentException("Not matching sizes");
        if(size()<MULTIEXP_BREAKPOINT){
            Group1Element result=v[0].exp(exponents.v[0]);
            for(int i=1;i<v.length;i++)
                result=result.mul(v[i].exp(exponents.v[i]));
            return result;
        }else{
            return this.v[0].multiExp(this.v,exponents.v);
        }

    }

    /**
     * Power each component by the correspondent exponent
     * @param exponents Vector of exponents
     * @return (g_1^(exp_1),...,g_n^(exp_n))
     */
    public GroupVector exp(ZpVector exponents) {
        if(size()!=exponents.size())
            throw new IllegalArgumentException("Not matching sizes");
        Group1Element[] result=new Group1Element[v.length];
        for(int i=0;i<v.length;i++)
            result[i]=v[i].exp(exponents.v[i]);
        return new GroupVector(result);
    }

    /**
     * Power  all components to the same exponent
     * @param exponent Exponent
     * @return (g_1^(exp),...,g_n^(exp))
     */
    public GroupVector expScalar(ZpElement exponent) {
        ZpElement[] array=new ZpElement[v.length];
        Arrays.fill(array,exponent);
        return exp(new ZpVector(array));
    }

    /**
     * Hadamard (component-wise) product
     * @param operand2
     * @return this o operand2
     */
    public GroupVector hadamardProduct(GroupVector operand2){
        if(v.length!=operand2.v.length)
            throw new IllegalArgumentException("Lengths do not match");
        Group1Element[] result=new Group1Element[v.length];
        for(int i=0;i<v.length;i++)
            result[i]=v[i].mul(operand2.v[i]);
        return new GroupVector(result);
    }

    /**
     * Return the multiplication of the components of the vector
     * @return v_1·v_2···v_n
     */
    public Group1Element mulComponents() {
        Group1Element result=v[0];
        for(int i=1;i<v.length;i++){
            result=result.mul(v[i]);
        }
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        GroupVector objVector=(GroupVector)obj;
        if(size()!=objVector.size())
            return false;
        for(int i=0;i<v.length;i++){
            if(!v[i].equals(objVector.v[i]))
                return false;
        }
        return true;
    }


}
