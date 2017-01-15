import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
 
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

/**BASE64Decoder / BASE64Encoder
Le librerie per la codifica/decodifica del messaggio in byte basata sullo schema in base64, 
utilizzato negli standard RFC 4648 e 2045, sono librerie pubbliche offerte dalla Sun che non sono
state incluse nelle API(fino a JDK8). Offrono una codifica/decodifica molto veloce da byte a Stringhe.*/

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class CryptedMessage
{
  private KeyPair chiavi;
  public CryptedMessage() throws NoSuchAlgorithmException {
	KeyPairGenerator generator;
	generator = KeyPairGenerator.getInstance("RSA");
	generator.initialize(2048); //grandezza della chiave RSA
	chiavi = generator.generateKeyPair();
    }

  public Key getPublicKey()
    {
      return chiavi.getPublic();
    }
  protected Key getPrivateKey()
    {
      return chiavi.getPrivate();
    }
  public String encrypt(String message, Key PK) throws IllegalBlockSizeException,
	    BadPaddingException, NoSuchAlgorithmException,
	    NoSuchPaddingException, InvalidKeyException,
	    UnsupportedEncodingException{
	// Come prima cosa, si sceglie un algoritmo di cifratura, instanziandolo in un oggetto Cipher.
	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	cipher.init(Cipher.ENCRYPT_MODE, PK);
  
	// Si prendono i byte vergini che verranno elaborati,  
	// Si sceglie come formato standard dei caratteri, necessario per la codifica
	byte[] stringBytes = message.getBytes("UTF8");        
        
	// Si codifica utilizzando l'algoritmo scelto in precedenza
	byte[] raw = cipher.doFinal(stringBytes);
 
	// Per evitare problemi con blocchi di dimensione errata, viene effettuata una conversione in base64
	BASE64Encoder encoder = new BASE64Encoder();
	String base64 = encoder.encode(raw);
  
	return base64;
    }
    
    public String decrypt(String encrypted, CryptedMessage chiavi) throws InvalidKeyException,
	    NoSuchAlgorithmException, NoSuchPaddingException,
	    IllegalBlockSizeException, BadPaddingException, IOException {
 
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, chiavi.getPrivateKey());
    
		//Per prima cosa si decodifica il messaggio partendo da quello in base64
		BASE64Decoder decoder = new BASE64Decoder();
		byte[] raw = decoder.decodeBuffer(encrypted);
 
		//Poi si decodifica il messaggio
    
		byte[] stringBytes = cipher.doFinal(raw);
    
		//Infine trasformiamo i byte decodificati in stringhe
		String clear = new String(stringBytes, "UTF8");
		return clear;
    }
}