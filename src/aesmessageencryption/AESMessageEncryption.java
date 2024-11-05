/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package aesmessageencryption;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 *
 * @author utku
 */
public class AESMessageEncryption {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
      try {
            // Anahtar oluşturma
            SecretKey secretKey = AESUtil.generateSecretKey();

            // Şifrelenecek mesaj
            String message = "FENERBAHCE!";
            System.out.println("Plain Text: " + message);
            // Mesajı şifreleme
            String encryptedMessage = AESUtil.encrypt(message, secretKey);
            System.out.println("Şifrelenmiş Mesaj: " + encryptedMessage);

            // Şifrelenmiş mesajı çözme
            String decryptedMessage = AESUtil.decrypt(encryptedMessage, secretKey);
            System.out.println("Çözülmüş Mesaj: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
