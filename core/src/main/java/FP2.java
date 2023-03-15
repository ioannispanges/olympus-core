////
//// Source code recreated from a .class file by Quiltflower
////
//
//
//package org.miracl.core.BLS12461;
//
//import org.miracl.core.RAND;
//
//public final class FP2 {
//    private final FP a;
//    private final FP b;
//
//    public void reduce() {
//        this.a.reduce();
//        this.b.reduce();
//    }
//
//    public void norm() {
//        this.a.norm();
//        this.b.norm();
//    }
//
//    public boolean iszilch() {
//        return this.a.iszilch() && this.b.iszilch();
//    }
//
//    public int islarger() {
//        if (this.iszilch()) {
//            return 0;
//        } else {
//            int cmp = this.b.islarger();
//            return cmp != 0 ? cmp : this.a.islarger();
//        }
//    }
//
//    public void toBytes(byte[] bf) {
//        byte[] t = new byte[58];
//        this.b.toBytes(t);
//
//        for(int i = 0; i < 58; ++i) {
//            bf[i] = t[i];
//        }
//
//        this.a.toBytes(t);
//
//        for(int i = 0; i < 58; ++i) {
//            bf[i + 58] = t[i];
//        }
//    }
//
//    public static FP2 fromBytes(byte[] bf) {
//        byte[] t = new byte[58];
//
//        for(int i = 0; i < 58; ++i) {
//            t[i] = bf[i];
//        }
//
//        FP tb = FP.fromBytes(t);
//
//        for(int i = 0; i < 58; ++i) {
//            t[i] = bf[i + 58];
//        }
//
//        FP ta = FP.fromBytes(t);
//        return new FP2(ta, tb);
//    }
//
//    public void cmove(FP2 g, int d) {
//        this.a.cmove(g.a, d);
//        this.b.cmove(g.b, d);
//    }
//
//    public boolean isunity() {
//        FP one = new FP(1);
//        return this.a.equals(one) && this.b.iszilch();
//    }
//
//    public boolean equals(FP2 x) {
//        return this.a.equals(x.a) && this.b.equals(x.b);
//    }
//
//    public FP2() {
//        this.a = new FP();
//        this.b = new FP();
//    }
//
//    public FP2(int c) {
//        this.a = new FP(c);
//        this.b = new FP();
//    }
//
//    public FP2(int c, int d) {
//        this.a = new FP(c);
//        this.b = new FP(d);
//    }
//
//    public FP2(FP2 x) {
//        this.a = new FP(x.a);
//        this.b = new FP(x.b);
//    }
//
//    public FP2(FP c, FP d) {
//        this.a = new FP(c);
//        this.b = new FP(d);
//    }
//
//    public FP2(BIG c, BIG d) {
//        this.a = new FP(c);
//        this.b = new FP(d);
//    }
//
//    public FP2(FP c) {
//        this.a = new FP(c);
//        this.b = new FP();
//    }
//
//    public FP2(BIG c) {
//        this.a = new FP(c);
//        this.b = new FP();
//    }
//
//    public FP2(RAND rng) {
//        this.a = new FP(rng);
//        this.b = new FP(rng);
//    }
//
//    public BIG getA() {
//        return this.a.redc();
//    }
//
//    public BIG getB() {
//        return this.b.redc();
//    }
//
//    public FP geta() {
//        return this.a;
//    }
//
//    public FP getb() {
//        return this.b;
//    }
//
//    public void copy(FP2 x) {
//        this.a.copy(x.a);
//        this.b.copy(x.b);
//    }
//
//    public void zero() {
//        this.a.zero();
//        this.b.zero();
//    }
//
//    public void one() {
//        this.a.one();
//        this.b.zero();
//    }
//
//    public int sign() {
//        int p1 = this.a.sign();
//        int p2 = this.b.sign();
//        int u = this.a.iszilch() ? 1 : 0;
//        return p1 ^ (p1 ^ p2) & u;
//    }
//
//    public void neg() {
//        FP m = new FP(this.a);
//        FP t = new FP();
//        m.add(this.b);
//        m.neg();
//        t.copy(m);
//        t.add(this.b);
//        this.b.copy(m);
//        this.b.add(this.a);
//        this.a.copy(t);
//    }
//
//    public void conj() {
//        this.b.neg();
//        this.b.norm();
//    }
//
//    public void add(FP2 x) {
//        this.a.add(x.a);
//        this.b.add(x.b);
//    }
//
//    public void sub(FP2 x) {
//        FP2 m = new FP2(x);
//        m.neg();
//        this.add(m);
//    }
//
//    public void rsub(FP2 x) {
//        this.neg();
//        this.add(x);
//    }
//
//    public void pmul(FP s) {
//        this.a.mul(s);
//        this.b.mul(s);
//    }
//
//    public void imul(int c) {
//        this.a.imul(c);
//        this.b.imul(c);
//    }
//
//    public void sqr() {
//        FP w1 = new FP(this.a);
//        FP w3 = new FP(this.a);
//        FP mb = new FP(this.b);
//        w1.add(this.b);
//        mb.neg();
//        w3.add(this.a);
//        w3.norm();
//        this.b.mul(w3);
//        this.a.add(mb);
//        w1.norm();
//        this.a.norm();
//        this.a.mul(w1);
//    }
//
//    public void mul(FP2 y) {
//        int xe = this.a.XES + this.b.XES;
//        int ye = y.a.XES + y.b.XES;
//        if ((long)xe * (long)ye > 524287L) {
//            if (this.a.XES > 1) {
//                this.a.reduce();
//            }
//
//            if (this.b.XES > 1) {
//                this.b.reduce();
//            }
//        }
//
//        DBIG pR = new DBIG(0);
//        BIG C = new BIG(this.a.x);
//        BIG D = new BIG(y.a.x);
//        pR.ucopy(new BIG(ROM.Modulus));
//        DBIG A = BIG.mul(this.a.x, y.a.x);
//        DBIG B = BIG.mul(this.b.x, y.b.x);
//        C.add(this.b.x);
//        D.add(y.b.x);
//        DBIG E = BIG.mul(C, D);
//        DBIG F = new DBIG(A);
//        F.add(B);
//        B.rsub(pR);
//        A.add(B);
//        A.norm();
//        E.sub(F);
//        this.a.x.copy(FP.mod(A));
//        this.a.XES = 3;
//        this.b.x.copy(FP.mod(E));
//        this.b.XES = 2;
//    }
//
//
//
//
//
//    public int qr(FP h) {
//        FP2 c = new FP2(this);
//        c.conj();
//        c.mul(this);
//        return c.geta().qr(h);
//    }
//
//    public void sqrt(FP h) {
//        if (!this.iszilch()) {
//            FP w1 = new FP(this.b);
//            FP w2 = new FP(this.a);
//            FP w3 = new FP(this.a);
//            FP w4 = new FP();
//            FP hint = new FP();
//            w1.sqr();
//            w2.sqr();
//            w1.add(w2);
//            w1.norm();
//            w1 = w1.sqrt(h);
//            w2.copy(this.a);
//            w2.add(w1);
//            w2.norm();
//            w2.div2();
//            w1.copy(this.b);
//            w1.div2();
//            int qr = w2.qr(hint);
//            w3.copy(hint);
//            w3.neg();
//            w3.norm();
//            w4.copy(w2);
//            w4.neg();
//            w4.norm();
//            w2.cmove(w4, 1 - qr);
//            hint.cmove(w3, 1 - qr);
//            this.a.copy(w2.sqrt(hint));
//            w3.copy(w2);
//            w3.inverse(hint);
//            w3.mul(this.a);
//            this.b.copy(w3);
//            this.b.mul(w1);
//            w4.copy(this.a);
//            this.a.cmove(this.b, 1 - qr);
//            this.b.cmove(w4, 1 - qr);
//            int sgn = this.sign();
//            FP2 nr = new FP2(this);
//            nr.neg();
//            nr.norm();
//            this.cmove(nr, sgn);
//        }
//    }
//
//    public String toString() {
//        return "[" + this.a.toString() + "," + this.b.toString() + "]";
//    }
//
//    public String toRawString() {
//        return "[" + this.a.toRawString() + "," + this.b.toRawString() + "]";
//    }
//
//    public void inverse(FP h) {
//        this.norm();
//        FP w1 = new FP(this.a);
//        FP w2 = new FP(this.b);
//        w1.sqr();
//        w2.sqr();
//        w1.add(w2);
//        w1.inverse(h);
//        this.a.mul(w1);
//        w1.neg();
//        w1.norm();
//        this.b.mul(w1);
//    }
//
//    public void div2() {
//        this.a.div2();
//        this.b.div2();
//    }
//
//    public void times_i() {
//        FP z = new FP(this.a);
//        this.a.copy(this.b);
//        this.a.neg();
//        this.b.copy(z);
//    }
//
//    public void mul_ip() {
//        FP2 t = new FP2(this);
//        int i = 0;
//        this.times_i();
//
//        while(i > 0) {
//            t.add(t);
//            t.norm();
//            --i;
//        }
//
//        this.add(t);
//    }
//
//    public void div_ip() {
//        FP2 z = new FP2(1, 1);
//        z.inverse(null);
//        this.norm();
//        this.mul(z);
//    }
//}
