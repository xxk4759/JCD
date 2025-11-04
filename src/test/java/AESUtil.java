import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;

public class AESUtil {
    private static final byte[] STATIC_IV = new byte[16]; // 行 4
    private static byte[] cachedNonce; // 行 5
    private static final String AL = "DES";

    public static void main(String[] args) throws Exception {
        // AES/CBC
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 行 9
        SecretKey secretKey = keyGen.generateKey(); // 行 10
        SecretKey secretKeyCopy = secretKey; // 密钥复制，行 11
        String mode = "AES/CBC/PKCS5Padding"; // 行 12
        Cipher cipher = Cipher.getInstance(mode); // 行 13
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(STATIC_IV)); // 行 14
        String plainText = "Hello, A";
        byte[] encrypted = cipher.doFinal(plainText.getBytes()); // 行 16
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyCopy, new IvParameterSpec(STATIC_IV)); // 行 17

        // AES/CBC (重新赋值密钥)
        keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 行 20
        secretKey = keyGen.generateKey(); // 行 21
        IvParameterSpec iv2 = new IvParameterSpec(STATIC_IV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv2); // 行 22
        secretKey = keyGen.generateKey(); // 重新赋值，行 23
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv2); // 行 24

        // DES/CBC/NoPadding
        keyGen = KeyGenerator.getInstance(AL);
        keyGen.init(56); // 行 27
        secretKey = keyGen.generateKey(); // 行 28
        cipher = Cipher.getInstance("DES/CBC/NoPadding"); // 行 29
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[8])); // 行 30
        encrypted = cipher.doFinal("12345678".getBytes()); // 行 31

        // Blowfish/CFB
        byte[] key = new byte[8]; // 64位，行 32
        new SecureRandom().nextBytes(key); // 行 33
        SecretKeySpec keySpec = new SecretKeySpec(key, "Blowfish"); // 行 34
        cipher = Cipher.getInstance("Blowfish/CFB/NoPadding"); // 行 35
        byte[] iv = new byte[8]; // 行 36
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv)); // 行 37
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv)); // 行 38



        // AES/CFB (修复密钥长度)
        byte[] aesKey = new byte[16]; // 128位，行 48
        new SecureRandom().nextBytes(aesKey); // 行 49
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES"); // 行 50
        cipher = Cipher.getInstance("AES/CFB/NoPadding"); // 行 51
        byte[] dynamicIv = new byte[16]; // 行 52
        new SecureRandom().nextBytes(dynamicIv); // 行 53
        cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, new IvParameterSpec(dynamicIv)); // 行 54
        cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, new IvParameterSpec(dynamicIv)); // 行 55

        // AES/OFB
        keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 行 56
        secretKey = keyGen.generateKey(); // 行 57
        cipher = Cipher.getInstance("AES/OFB/NoPadding"); // 行 58
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(STATIC_IV)); // 行 59
        encrypted = cipher.doFinal(plainText.getBytes()); // 行 60


        // RSA
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(1024); // 行 80
        KeyPair rsaPair = rsaGen.generateKeyPair(); // 行 81
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // 行 82
        cipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic()); // 行 83
    }
}