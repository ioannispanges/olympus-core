//import org.miracl.core.BLS12461.BIG;
//import org.miracl.core.BLS12461.DBIG;
//import org.miracl.core.BLS12461.FP2;
//import org.miracl.core.BLS12461.ROM;
//
//public class FP12 {
//
//    // Define the constant used for optimization
//    private static final long OPTIMIZATION_CONSTANT = 524287L;
//
//    // Define the two FP2 objects stored in FP12
//    private FP2 a, b;
//
//    // Constructor
//    public FP12(FP2 a, FP2 b) {
//        this.a = a;
//        this.b = b;
//    }
//
//    public void mul(FP12 y) {
//        if ((long)(this.a.getA() + this.a.b.XES + this.b.a.XES + this.b.getB()) * (long)(y.a.a.XES + y.a.b.XES + y.b.a.XES + y.b.b.XES) > OPTIMIZATION_CONSTANT) {
//            if (this.a.getA().XES <= 1) {
//            } else {
//                this.a.a.reduce();
//            }
//            if (this.a.b.XES > 1) {
//                this.a.b.reduce();
//            }
//            if (this.b.a.XES > 1) {
//                this.b.a.reduce();
//            }
//            if (this.b.b.XES > 1) {
//                this.b.b.reduce();
//            }
//        }
//
//        DBIG pR = new DBIG(0);
//        BIG C = new BIG(this.a.a.x);
//        BIG D = new BIG(y.a.a.x);
//        pR.ucopy(new BIG(ROM.Modulus));
//        DBIG A = BIG.mul(this.a.a.x, y.a.a.x);
//        DBIG B = BIG.mul(this.b.b.x, y.b.b.x);
//        C.add(this.a.b.x);
//        C.norm();
//        D.add(y.a.b.x);
//        D.norm();
//        DBIG E = BIG.mul(C, D);
//        DBIG F = new DBIG(A);
//        F.add(B);
//        B.rsub(pR);
//        A.add(B);
//        A.norm();
//        E.sub(F);
//        E.norm();
//        this.a.a.x.copy(FP12.mod(A));
//        this.a.a.XES = 3;
//        this.b.b.x.copy(FP12.mod(E));
//        this.b.b.XES = 2;
//    }
//}
