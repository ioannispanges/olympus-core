package eu.olympus.util.rangeProof.model;

import eu.olympus.util.pairingInterfaces.ZpElement;

public class ZpVectorPolynomial {

    private ZpVector[] coefficients;

    public ZpVectorPolynomial(ZpVector ... coefficients) {
        this.coefficients=new ZpVector[coefficients.length];
        for (int i = 0; i < coefficients.length; i++)
            this.coefficients[i] = coefficients[i];
    }


    /**
     * Return p(x) for polynomial p and value x.
     * @param x
     * @return
     */
    public ZpVector eval(ZpElement x){
        ZpVector result=coefficients[0].copy();
        for(int i=1;i<coefficients.length;i++)
            result=result.add(coefficients[1].mulScalar(x.pow(i)));
        return result;
    }

}
