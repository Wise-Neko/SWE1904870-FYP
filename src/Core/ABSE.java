package Core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.io.Base64;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class ABSE {

    public static void setup(String []u,PublicKey pubK, MasterPrivateKey msk) {

        int n = u.length; //Get the attributes set length

        PairingFactory.getInstance().setUsePBCWhenPossible(true);

        pubK.p = PairingFactory.getPairing("src/Core/a.properties"); //Created bilinear groups

        Pairing pairing = pubK.p; //Get the pairing from the PublicKey class

        pubK.g1 = pairing.getG1().newRandomElement();
        pubK.g2 = pairing.getG2().newRandomElement(); //If not initialized, G2 will be null
        pubK.g2.set(pubK.g1); //Let G2 = G1
        pubK.g_a = pairing.getG1().newRandomElement();
        pubK.g_b = pairing.getG1().newRandomElement();
        pubK.g_c = pairing.getG1().newRandomElement();

        Element a,b,c;
        a = pairing.getZr().newElement();  //Zp is included in the library as Zr
        b = pairing.getZr().newElement();
        c = pairing.getZr().newElement();
        msk.a = a.setToRandom(); //Randomly select within the element
        msk.b = b.setToRandom();
        msk.c = c.setToRandom();

        msk.r = new Element[2*n];
        msk.x = new Element[2*n];
        for(int i=0;i<2*u.length;i++){
            msk.r[i]=pairing.getZr().newRandomElement();
            msk.x[i]=pairing.getG1().newRandomElement();
        }

        pubK.u = new Element[2*n];
        pubK.y = new Element[2*n];
        for(int i=0;i<2*u.length;i++){
            pubK.u[i] = pairing.getG1().newElement();
            pubK.y[i] = pairing.getGT().newElement();
        }

        Element r_neg = pairing.getZr().newElement();
        for(int i=0;i<2*u.length;i++){
            pubK.y[i] = pairing.pairing(pubK.g1, msk.x[i]); //Pairing between G1 and x
            r_neg = msk.r[i].duplicate(); // Let both variable be the same
            r_neg.negate(); // Let r = -r
            pubK.u[i] = pubK.g1.duplicate();
            pubK.u[i] = pubK.u[i].powZn(r_neg);
        }

        pubK.g_a = pubK.g1.duplicate(); //Get G
        pubK.g_a = pubK.g_a.powZn(msk.a); //Power the G to a
        pubK.g_b = pubK.g1.duplicate(); //Same as above
        pubK.g_b = pubK.g_b.powZn(msk.b);
        pubK.g_c = pubK.g1.duplicate();
        pubK.g_c = pubK.g_c.powZn(msk.c);
    }

    public static CipherText enc(String []u,PublicKey pub, String []policy, Index index){

        CipherText cph = new CipherText();
        Pairing pairing = pub.p; //Get the pairing from the PublicKey class

        Element t1 = pairing.getZr().newRandomElement();
        Element t2 = pairing.getZr().newRandomElement();

        cph.u_gate = pairing.getG1().newElement(); //Initialize a new element
        cph.u_gate = pub.g1.duplicate();
        cph.u_gate.powZn(t2);

        for(int i = 0; i < u.length; i++){  //For each attribute in the access policy
            if(attributeWithinPolicy(policy, u[i])){
                cph.u_gate.mul(pub.u[i]); //The attribute is within the policy (positive u)
            }
            else{
                cph.u_gate.mul(pub.u[i + u.length]); //The attribute is not within the policy (negative u)
            }
        }

        cph.w0 = pairing.getG1().newElement();
        cph.w0 = pub.g_c.duplicate();
        cph.w0.powZn(t1);

        Element m = pairing.getZr().newElement(); // Get the plaintext message and map it to Z

        Element add = t1.duplicate();
        add.add(t2);
        Element w01 = pub.g_a.duplicate();
        w01.powZn(add);
        Element w02 = pub.g_b.duplicate();
        w02.powZn(t1);

        cph.w = pairing.getG1().newElement();

        //Index indTemp;
        byte []indexTmp = index.keyword.getBytes();
        m = m.setFromHash(indexTmp, 0, indexTmp.length); //Hashing algorithm in the JPBC library


        cph.w = w01.duplicate();
        cph.w.mul(w02.powZn(m));

        return cph;
    }

    public static boolean attributeWithinPolicy(String []attrs,String u){
        boolean gate = false;

        for(int i = 0; i < attrs.length; i++){
            if(u.equals(attrs[i])){
                gate = true;    //If user attributes is in access policy
                break;
            }
        }
        return gate;
    }

    public static PrivateKey keygen(String []u,PublicKey pub, MasterPrivateKey msk, String[] attrs){
        int len = u.length;
        PrivateKey prv = new PrivateKey();
        Pairing pairing= pub.p;
        prv.sig = new Element[len];
        prv.y = new Element[len];


        prv.v = pairing.getG2().newElement();
        prv.sig_user = pairing.getG2().newElement();
        prv.y_user = pairing.getGT().newElement();
        for(int i=0;i<len;i++){
            prv.sig[i] = pairing.getG2().newElement();
            prv.y[i] = pairing.getGT().newElement();
        }

        prv.v = pub.g2.duplicate();
        prv.v.powZn(msk.a);
        prv.v.powZn(msk.c);

        for(int i=0;i<len;i++)
            prv.sig[i] = prv.v.duplicate();

        for(int i=0;i<len;i++){
            if(isContain(attrs,u[i])){
                prv.sig[i].powZn(msk.r[i]);
                prv.sig[i].mul(msk.x[i]);
                prv.y[i] = pub.y[i].duplicate();
            }
            else{
                prv.sig[i].powZn(msk.r[i+len]);
                prv.sig[i].mul(msk.x[i+len]);
                prv.y[i] = pub.y[i+len].duplicate();
            }
        }
        prv.sig_user = prv.sig[0].duplicate();
        prv.y_user = prv.y[0].duplicate();
        for(int i=1;i<len;i++){
            prv.sig_user.mul(prv.sig[i]);
            prv.y_user.mul(prv.y[i]);
        }
        return prv;

    }

    public static boolean isContain(String []attrs,String u){
        boolean ret = false;
        for(int i=0;i<attrs.length;i++){
            if(u.equals(attrs[i])){
                ret = true;
                break;
            }
        }
        return ret;
    }

    public static Token tokenGen(PrivateKey prv, PublicKey pub, String word){
        Pairing pairing = pub.p;
        Token token = new Token();

        token.tok1 = pairing.getG2().newElement();
        token.tok3 = pairing.getG2().newElement();
        token.tok4 = pairing.getG2().newElement();
        token.tok5 = pairing.getGT().newElement();

        Element wm = pairing.getZr().newElement();
        byte []w = word.getBytes();
        wm = wm.setFromHash(w, 0, w.length);

        Element s = pairing.getZr().newElement();
        s.setToRandom();

        token.tok1 = pub.g_b.duplicate();
        token.tok1.powZn(wm);
        token.tok1.mul(pub.g_a);
        token.tok1.powZn(s);
        token.tok2 = pairing.getG2().newElement();
        token.tok2 = pub.g_c.duplicate();
        token.tok2.powZn(s);
        token.tok3 = prv.v.duplicate();
        token.tok3.powZn(s);
        token.tok4 = prv.sig_user.duplicate();
        token.tok4.powZn(s);
        token.tok5 = prv.y_user.duplicate();
        token.tok5.powZn(s);

        return token;

    }


    public static boolean search(PublicKey pub, Token token, String[] cph) throws IOException {
        boolean ret = false;
        Pairing pairing = pub.p;
        Element E = pairing.getGT().newElement();
        Field<?> G1 = pairing.getG1();
        Element u_gate = G1.newElementFromBytes(Base64.decode(cph[2]));
        Element w = G1.newElementFromBytes(Base64.decode(cph[1]));
        Element w0 = G1.newElementFromBytes(Base64.decode(cph[0]));

        E=pairing.pairing(u_gate, token.tok3);
        E=E.mul(pairing.pairing(pub.g1, token.tok4));
        E=E.div(token.tok5);

        Element left = pairing.getGT().newElement();
        Element right = pairing.getGT().newElement();

        left = pairing.pairing(w0, token.tok1);
        left = left.mul(E);
        right = pairing.pairing(w, token.tok2);

        if(left.equals(right)){
            ret = true;
            System.out.println("Success");
        }
        return ret;
    }
}
