package Core;

import it.unisa.dia.gas.jpbc.Element;

public class PrivateKey {

    public Element v;  /* G_2 */
    public Element sig_user; /* G_2 */
    public Element y_user; /* G_T */
    public Element sig[];
    public Element y[];
}
