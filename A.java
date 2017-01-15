import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.util.Random;
import java.math.BigInteger;
import java.security.*;

public class A
{
  private static String identita;
  private static CryptedMessage chiaviA;
  public A(String nome) throws SocketException,UnknownHostException,IOException, NoSuchAlgorithmException
  {
    identita=nome;
    chiaviA=new CryptedMessage();
  }
  public static BigInteger IdNum()
  {
    int val=0;
    for(int i=0;i<identita.length();i++)
      val+=(int)identita.charAt(i);
    String tmp=(""+val);
    BigInteger bi=new BigInteger(tmp);
    return bi;
  }
  public String getName()
  {
    return identita;
  }
  public static BigInteger GeneraNonce()
  {
    Random randomGenerator = new Random();
    return new BigInteger(64, randomGenerator);
  }
   public static Key getPublicKey()
  {
    return chiaviA.getPublicKey();
  }
 
  public static void main(String [] args)
  {
    try{
      
      /**PRESENTAZIONE DELL'INTERLOCUTORE A*/
      
      //A professore=new A("Giampaolo Bella");
      String ID="";
      if(args.length>0)
        ID=args[0];
      else
        ID="Giampaolo Bella";
      A professore=new A(ID);
      final BigInteger na=professore.GeneraNonce();
      BigInteger id_a=professore.IdNum();
      
      CryptedMessage chiaviA=new CryptedMessage();
      Key ApubKey=chiaviA.getPublicKey();
      
      /**CONNESSIONE CON IL SERVER SOCKET SULLA PORTA 12345*/
      
      System.out.println("Tentativo di connessione sulla porta 12345...");
      
      Socket clientA=new Socket("localhost",12345);
      clientA.setSoTimeout(30000);
      System.out.println("Connessione stabilita con entita' esterna (B)!\n");
      
      /**SCAMBIO DELLE CHIAVI: 
      1) INVIO DELLA CHIAVE PUBBLICA DI A*/
      
      System.out.println("Comunico la mia chiave pubblica: "+ApubKey+"\n");
      
      ObjectOutputStream oos=new ObjectOutputStream(clientA.getOutputStream());
      oos.writeObject((Object)ApubKey);
      
      /**SCAMBIO DELLE CHIAVI: 
      2) RICEZIONE DELLA CHIAVE PUBBLICA DI B*/
      
      ObjectInputStream ois=new ObjectInputStream(clientA.getInputStream());
      Key k_b=(Key)ois.readObject();
      
      System.out.println("Ho ottenuto la chiave pubblica dell'entita' B: "+k_b+"\n");
      
      /**Needham-Schroeder (latoA)
      1) A ----> B : {A,Na}k_b
      Viene effettuata la codifica della coppia di elementi ID di A e Nonce A con la chiave pubblica di B.
      Gli algoritmi di codifica/decodifica sono contenuti nell'oggetto CryptedMessage "chiaviA", questo noto solo ad A.
      Essi necessitano di un parametro Key per la codifica/decodifica del messaggio.
      Una volta codificato il messaggio ( o Coppia di elementi ) , si procede all'invio.
      */
      System.out.println("Impacchetto il messaggio...");
      
      Coppia IDa_Na=NeedhamSchroeder.codifica(id_a,na,chiaviA,k_b); //effettua una chiamata di .encrypt() separatamente su "id_a" e poi su "na".
      oos.writeObject((Object)IDa_Na); //mandiamo la coppia di elementi cifrati a B. ... EDIT: Non essendo serializzabile, non posso inviare l'oggetto Coppia
      
      System.out.println("Primo messaggio spedito!");
    
      /**Needham-Schroeder (latoA)
      2) B ----> A : {Na,Nb}k_a
      Viene effettuata la decodifica della coppia di elementi Nonce A e Nonce B con la chiave privata di A.
      */
      
      
      Coppia Na_Nb=(Coppia)ois.readObject(); // memorizzo il messaggio ricevuto con i suoi contenuti
      
      System.out.println("Secondo messaggio ricevuto, elaborazione in corso...");
      
      Coppia decNa_Nb=NeedhamSchroeder.decodifica(Na_Nb,chiaviA); //decodifico, analogamente a come è stato svolto da B, gli elementi contenuti nel messaggio ricevuto
      
      BigInteger bigtempNa=new BigInteger((String)decNa_Nb.getFst());
      if(na.equals(bigtempNa))
        System.out.println("Ok, questa e' la mia Nonce che ti ho inviato all'inizio.");
      else
      {
        System.out.println("Non e' la Nonce che ti ho inviato io, la comunicazione e' compromessa.");
        ois.close();
        oos.close();
        clientA.close();
      }
      
      /**Needham-Schroeder (latoA)
      3) A ----> B : {Nb}k_b
      Viene effettuata la codifica del messaggio contenente la Nonce B con la chiave pubblica di B.
      Terminate le operazioni di codifica, si spedisce il messaggio criptato a B.
      */
      
      System.out.println("Impacchetto il terzo messaggio...");
      
      BigInteger bigtempNb=new BigInteger((String)decNa_Nb.getSnd()); //alloco una variabile temporanea pari al valore Nonce B ricevuto nel secondo passaggio
      String encBigtempNb=NeedhamSchroeder.codifica_3(bigtempNb, chiaviA, k_b);
      Coppia finale=new Coppia(encBigtempNb);
      oos.writeObject((Object)finale);
      
      System.out.println("Terzo messaggio spedito, restituisco cio' che ho ricevuto!");
      
      ois.close();
      oos.close();
 
      
      clientA.close();
    }
    catch(Exception e)
    {
      e.printStackTrace();
    }
  }
}