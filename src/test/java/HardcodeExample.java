import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class HardcodeExample {
    public static void main(String[] args) {
        HardcodeExample hardcodeExample = new HardcodeExample();
        try {

            hardcodeExample.testHardcoded();
        } catch (Exception e) {
            System.err.println("运行测试时发生异常: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void testHardcodedConstant() {
        byte[] key1 = "hardcodedkey".getBytes();
        SecretKeySpec spec1 = new SecretKeySpec(key1, "AES");
    }

    public void testHardcodedArray() {
        byte[] key2 = new byte[]{1, 2, 3, 4};
        SecretKeySpec spec2 = new SecretKeySpec(key2, "AES");
    }

    public void testStringToBytes() {
        String str = "hardcoded";
        byte[] key3 = str.getBytes();
        SecretKeySpec spec3 = new SecretKeySpec(key3, "AES");
    }
    public void testHardcoded() throws Exception {

        byte[] key = "hardcodedkeysdfg".getBytes();
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        byte[] iv = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] plaintext = "secretmessage".getBytes();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        cipher.doFinal(plaintext);
    }

}

