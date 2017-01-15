import javax.crypto.*;
import java.io.*;
import java.util.Random;
import java.math.BigInteger;
import java.security.*;
import java.net.*;


public class B
{
  private static String identita;
  private static CryptedMessage chiaviB;
  public B(String nome) throws SocketException, IOException, NoSuchAlgorithmException
  {
    identita=nome;
    chiaviB=new CryptedMessage();
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
    return chiaviB.getPublicKey();
  }
  
  public static void main(String[] args)
  {
    try
    {
      /**PRESENTAZIONE DELL'INTERLOCUTORE B*/
      String ID="";
      if(args.length>0)
        ID=args[0];
      else
        ID="Giuseppe Emmanuello";
      B studente=new B(ID);
      final BigInteger nb=studente.GeneraNonce();
      BigInteger id_b=studente.IdNum();
      
      CryptedMessage chiaviB=new CryptedMessage();
      Key BpubKey=chiaviB.getPublicKey();
      
      /**APERTURA CONNESSIONI SULLA PORTA 12345*/
      
      ServerSocket ServerB=new ServerSocket(12345);
      ServerB.setSoTimeout(30000);
     
      System.out.println("In attesa di comunicazioni sulla porta 12345..."); //(E' ovvio che in un programma di sicurezza non si comunicano tutti i passaggi)
      
      Socket clientB=ServerB.accept();
      clientB.setSoTimeout(30000);
      
      System.out.println("Connessione stabilita con entita' esterna.(A)\n");
      
      /**SCAMBIO DELLE CHIAVI: 
      1) RICEZIONE DELLA CHIAVE PUBBLICA DI A*/
      
      ObjectInputStream ois=new ObjectInputStream(clientB.getInputStream());
      Key k_a=(Key)ois.readObject();
      
      System.out.println("Ho ricevuto la chiave pubblica dell'entita' A: "+k_a+"\n");
      
      /**SCAMBIO DELLE CHIAVI: 
      2) INVIO DELLA CHIAVE PUBBLICA DI B*/
      
      System.out.println("Comunico la mia chiave pubblica: "+BpubKey+"\n");
      
      ObjectOutputStream oos=new ObjectOutputStream(clientB.getOutputStream());
      oos.writeObject((Object)BpubKey);
      
      /**Needham-Schroeder (latoB)
      1) A ----> B : {A,Na}k_b
      Viene effettuata la decodifica della coppia di elementi ID di A e Nonce A con la chiave privata di B.
      Gli algoritmi di codifica/decodifica sono contenuti nell'oggetto CryptedMessage "chiaviB", questo noto solo ad B.
      Essi necessitano di un parametro Key per la codifica/decodifica del messaggio.
      Una volta decodificato il messaggio ed elaborato i dati, si procede al secondo passo del protocollo.
      */
      
      Coppia IDa_Na=(Coppia)ois.readObject(); //prendiamo la coppia dallo stream in input.
      
      System.out.println("Primo messaggio ricevuto!");
      
      Coppia decIDa_Na=NeedhamSchroeder.decodifica(IDa_Na,chiaviB); //effettua una chiamata .decrypt() che decifra gli elementi contenuti nel messaggio ricevuto
      
      
      /**Needham-Schroeder (latoB)
      2) B ----> A : {Na,Nb}k_a
      Viene effettuata la codifica della coppia di elementi Nonce A e Nonce B con la chiave pubblica di A.
      Appena terminate le operazioni di codifica, il messaggio, contenente Nonce A e Nonce B viene spedito ad A.
      */
      
      System.out.println("Impacchetto il secondo messaggio...");
      
      BigInteger bigtempNa=new BigInteger((String)decIDa_Na.getSnd()); //creo una variabile BigInteger temporanea, pari alla Nonce A ricevuta
      Coppia Na_Nb=NeedhamSchroeder.codifica(bigtempNa,nb,chiaviB,k_a); //codifico l'elemento ricevuto prima e la Nonce B preparandoli come messaggio
      
      oos.writeObject((Object)Na_Nb);
      
      System.out.println("Secondo messaggio spedito!");
      
      /**Needham-Schroeder (latoB)
      3) A ----> B : {Nb}k_b
      Viene effettuata la decodifica del messaggio contenente Nonce B con la chiave privata di B.
      Se la Nonce B ricevuta corrisponde alla Nonce B del suo proprietario B, allora il protocollo ha avuto successo.
      */
  
      
      Coppia finale=(Coppia)ois.readObject();
      
      System.out.println("Terzo messaggio ricevuto: procedo al controllo della Nonce ricevuta/inviata.");
      
      String encBigtempNb=(String)finale.getFst();
      String bigtempNb=NeedhamSchroeder.decodifica_3(encBigtempNb,chiaviB);
      
      BigInteger corrispondenza=new BigInteger(bigtempNb);
      
      if(nb.equals(corrispondenza))
        System.out.println("Si, e' lei: ho riconosciuto la mia Nonce!");
      else
      {
        System.out.println("Non e' la Nonce che ti ho inviato. Non credo tu sia A");
        clientB.close();
        ServerB.close();
        ois.close();
        oos.close();
      }
      
      ois.close();
      oos.close();

      clientB.close();
      ServerB.close();
    }
    catch(Exception e)
    {
      e.printStackTrace();
    }
  }
}