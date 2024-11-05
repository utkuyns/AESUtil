/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
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

public class AESUtil {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int AES_KEY_SIZE = 128; // 128, 192 veya 256 bit olabilir

    // Anahtar üretimi
    public static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    // IV üretimi (her mesaj için ayrı bir IV olmalı)
    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16]; // 16 byte = 128 bit
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Mesajı şifreleme
    public static String encrypt(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        IvParameterSpec ivParameterSpec = generateIv();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        
        // Şifreli mesajı ve IV'yi Base64 formatında birleştir
        String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
        String iv = Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
        
        return iv + ":" + encryptedMessage;
    }

    // Şifreli mesajı çözme
    public static String decrypt(String encryptedData, SecretKey secretKey) throws Exception {
        String[] parts = encryptedData.split(":");
        String iv = parts[0];
        String encryptedMessage = parts[1];
        
        IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        
        return new String(decryptedBytes);
    }
}
