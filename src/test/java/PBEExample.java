import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBEExample {
    public static void main(String[] args) {
        PBEExample example = new PBEExample();
        example.testLowIterations();
        example.testSafeIterations();
        example.testLowStringIterations();
    }

    public void testLowIterations() {
        char[] password = "mypassword".toCharArray();
        byte[] salt = new byte[]{1, 2, 3, 4};
        int iterations = 500;
        int keyLength = 256; // 添加密钥长度
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            System.out.println("Key generated with low iterations: " + key.length * 8 + " bits");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void testLowStringIterations() {
        char[] password = "mypassword".toCharArray();
        byte[] salt = new byte[]{1, 2, 3, 4};
        int keyLength = 256;
        String strIterations = "800"; // 低迭代次数 (String)
        int iterations = Integer.parseInt(strIterations);
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations,keyLength);
        try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void testSafeIterations() {
        char[] password = "mypassword".toCharArray();
        byte[] salt = new byte[]{1, 2, 3, 4};
        int iterations = 10000;
        int keyLength = 256; // 添加密钥长度
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            System.out.println("Key generated with safe iterations: " + key.length * 8 + " bits");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}