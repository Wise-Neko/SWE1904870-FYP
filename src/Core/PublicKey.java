package Core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class PublicKey {

    public Pairing p;               // Pairing of the bilinear group
    public Element g1;
    public Element g2;
    public Element g_a;				// G_1 random element
    public Element g_b;				// G_1 random element
    public Element g_c;				// G_1 random element
    public Element []u ;
    public Element []y ;
}
