import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.math.BigInteger;
import java.io.Serializable;

/**AGGIUNGERE PROVIDER (AFFIDABILI) A JAVA.SECURITY
Dinamicamente, è possibile aggiungere i provider importando queste due librerie.
Staticamente, è stato possibile aggiungere una linea di testo al file java.security
presente in jre/lib/security/ e in jdk1.7.0_60/lib/security
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

*/

 /*Il protocollo Needham-Schroeder garantisce autenticazione tramite lo scambio delle Nonce delle entità A e B
  1. A ----> B : {A , Na}k_b  //Nel primo scambio di messaggi, A invia a B la sua identità e la sua Nonce, codificandolo con la chiave pubblica di B
  2. B ----> A : {Na,Nb}k_a //Nel secondo scambio di messaggi, B torna indietro ad A la Nonce di A e la sua Nonce per autenticarsi, codificandolo con la chiave pubblica di A
  3. A ----> B : {Nb}k_b //Nel terzo scambio di messaggi, A restituisce a B la Nonce di B che gli è appena stata inviata codificandolo con la chiave pubblica di B
  */

class Coppia<E,F> implements Serializable //Questo permette all'oggetto di poter essere scritto come Stream Input/Output
{
  private E fst;
  private F snd;
  public Coppia(E fst)
  {
    this.fst=fst;
    snd=null;
  }
  public Coppia(E fst, F snd)
  {
    this.fst=fst;
    this.snd=snd;
  }
  public E getFst(){return fst;}
  public F getSnd(){return snd;}
}


public class NeedhamSchroeder
{
  //Primo/secondo punto del protocollo, codificare il messaggio {A,N_a}/{N_a,N_b} con la chiave pubblica di B/A
  public static Coppia codifica(BigInteger el1, BigInteger el2, CryptedMessage cm, Key kb) throws IllegalBlockSizeException, BadPaddingException,NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException,UnsupportedEncodingException 
  {      
    String v1c=cm.encrypt(el1.toString(),kb);
    String v2c=cm.encrypt(el2.toString(),kb);
    Coppia c=new Coppia(v1c,v2c);
    return c;
  }
  
  //Decodifica del primo/secondo messaggio con la chiave privata di B/A
  
  public static Coppia decodifica(Coppia C,CryptedMessage kb) throws IllegalBlockSizeException, BadPaddingException,NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException,UnsupportedEncodingException, IOException
  {
    
    String v1c=kb.decrypt( ((String)C.getFst()) ,kb); 
    String v2c=kb.decrypt( ((String)C.getSnd()) ,kb); 
    Coppia cc=new Coppia(v1c,v2c);
    return cc;
  }
  
  //Terzo punto del protocollo, codificare il messaggio {N_b} con la chiave pubblica di B
  public static String codifica_3(BigInteger N_b, CryptedMessage cm,Key kb) throws IllegalBlockSizeException, BadPaddingException,NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException,UnsupportedEncodingException
  {
    String vc=cm.encrypt(N_b.toString(),kb);
    return vc;
  }
  
  //Decodifica del terzo messaggio con la chiave privata di A
  public static String decodifica_3(String N_b,CryptedMessage kb) throws IllegalBlockSizeException, BadPaddingException,NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException,UnsupportedEncodingException, IOException
  {
    String dec=kb.decrypt(N_b, kb);
    return dec;
  }
}