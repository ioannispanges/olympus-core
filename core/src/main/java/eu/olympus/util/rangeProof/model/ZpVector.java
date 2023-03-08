package eu.olympus.util.rangeProof.model;

import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;

import java.util.Arrays;

/**
 * Vector of Zp elements, indexed like math vectors (starting from 1)
 */
public class ZpVector {

    protected ZpElement[] v;

    public ZpVector(ZpElement ... v) {
        this.v=new ZpElement[v.length];
        for (int i = 0; i < v.length; i++)
            this.v[i] = v[i];
    }

    /**
     * New ZpVector with n components equal to el.
     * @param el
     * @param n
     */
    public ZpVector(ZpElement el,int n){
        this.v=new ZpElement[n];
        Arrays.fill(this.v,el);
    }

    /**
     * Creates a new ZpVector that is the concatenation of the argument vectors
     * @param vectors
     * @return
     */
    public static ZpVector concat(ZpVector... vectors){
        int amount = 0;
        int offset = 0;
        for (ZpVector arr : vectors) {
            amount += arr.v.length;
        }
        ZpElement[] dest = new ZpElement[amount];
        for (ZpVector arr :vectors) {
            System.arraycopy(arr.v, 0, dest, offset, arr.v.length);
            offset += arr.v.length;
        }
        return new ZpVector(dest);
    }

    /**
     * Generate a vector of length n with random components using builder
     * @param n
     * @param builder
     * @return
     */
    public static ZpVector randomVector(int n, PairingBuilder builder) {
        ZpElement[] v=new ZpElement[n];
        for(int i=0;i<n;i++)
            v[i]=builder.getRandomZpElement();
        return new ZpVector(v);
    }

    /**
     * Return ZpVector equal to (y^0,y^1,y^(n-1))
     * @param y
     * @param n
     * @return
     */
    public static ZpVector expandExpN(ZpElement y, int n,PairingBuilder builder) {
        ZpElement[] v=new ZpElement[n];
        ZpElement yAux=builder.getZpElementOne();
        v[0]=yAux;
        for(int i=1;i<n;i++){
            yAux=yAux.mul(y);
            v[i]=yAux;
        }
        return new ZpVector(v);
    }

    /**
     * Vector composed from elements v_start to v_finish, inclusive (remember math indexing is used,
     * so v=(v_1,v_2,...,v_n)
     * @param start First index included
     * @param finish Last index included
     * @return Subvector (v_start,...,v_finish)
     */
    public ZpVector subvector(int start, int finish){
        return new ZpVector(Arrays.copyOfRange(v,start-1,finish));
    }

    /**
     * Inner (dot) product
     * @param operand2
     * @return this dot operand2
     */
    public ZpElement innerProduct(ZpVector operand2){
        if(v.length!=operand2.v.length)
            throw new IllegalArgumentException("Lengths do not match");
        ZpElement result=v[0].mul(operand2.v[0]);
        for(int i=1;i<v.length;i++){
            result=result.add(v[i].mul(operand2.v[i]));
        }
        return result;
    }

    /**
     * Hadamard (component-wise) product
     * @param operand2
     * @return this o operand2
     */
    public ZpVector hadamardProduct(ZpVector operand2){
        if(v.length!=operand2.v.length)
            throw new IllegalArgumentException("Lengths do not match");
        ZpElement[] result=new ZpElement[v.length];
        for(int i=0;i<v.length;i++)
            result[i]=v[i].mul(operand2.v[i]);
        return new ZpVector(result);
    }

    /**
     * Get vector component v=(v_1,v_2,...,v_n)
     * @param index
     * @return v_i
     */
    public ZpElement getComponent(int index){
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
     * Multiplies each vector component by the element x
     * @param x
     * @return (x·v_1,...,x·v_n)
     */
    public ZpVector mulScalar(ZpElement x) {
        ZpElement[] result=new ZpElement[v.length];
        for(int i=0;i<v.length;i++)
            result[i]=v[i].mul(x);
        return new ZpVector(result);
    }

    /**
     * Adds two vectors
     * @param operand2
     * @return this+operand2
     */
    public ZpVector add(ZpVector operand2) {
        if(v.length!=operand2.v.length)
            throw new IllegalArgumentException("Lengths do not match");
        ZpElement[] result=new ZpElement[v.length];
        for(int i=0;i<v.length;i++)
            result[i]=v[i].add(operand2.v[i]);
        return new ZpVector(result);
    }

    /**
     * Subtract two vectors
     * @param operand2
     * @return this-operand2
     */
    public ZpVector sub(ZpVector operand2) {
        if(v.length!=operand2.v.length)
            throw new IllegalArgumentException("Lengths do not match");
        ZpElement[] result=new ZpElement[v.length];
        for(int i=0;i<v.length;i++)
            result[i]=v[i].sub(operand2.v[i]);
        return new ZpVector(result);
    }

    /**
     * Get a vector with the LittleEndian bit representation of the element z using n bits
     * @param z
     * @param n
     * @return
     */
    public static ZpVector bitRepresentation(ZpElement z, int n){
        ZpElement[] bits=new ZpElement[n];
        for(int i=0;i<n;i++){
            bits[i]=z.getBit(i);
        }
        return new ZpVector(bits);
    }

    /**
     * Return the sum of the components of the vector
     * @return v_1+v_2+...+v_n
     */
    public ZpElement sumComponents() {
        ZpElement result=v[0];
        for(int i=1;i<v.length;i++){
            result=result.add(v[i]);
        }
        return result;
    }

    @Override
    public String toString() {
        String res="[";
        for(ZpElement el:v)
            res+="\n"+el.toString();
        res+=" ]";
        return res;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        ZpVector objVector=(ZpVector)obj;
        if(size()!=objVector.size())
            return false;
        for(int i=0;i<v.length;i++){
            if(!v[i].equals(objVector.v[i]))
                return false;
        }
        return true;
    }


    public ZpVector copy() {
        return new ZpVector(this.v);
    }

}
