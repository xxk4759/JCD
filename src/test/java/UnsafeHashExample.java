import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class UnsafeHashExample {
    public static void main(String[] args) {
        // 示例字符串
        String input = "Hello, Soot!";

        // 使用MD5哈希函数（不安全）
        try {
            MessageDigest md5Digest = MessageDigest.getInstance("MD5");
            byte[] md5Hash = md5Digest.digest(input.getBytes());
            System.out.println("MD5 Hash: " + bytesToHex(md5Hash));
        } catch (NoSuchAlgorithmException e) {
            System.out.println("MD5 algorithm not found.");
        }

        // 使用SHA-1哈希函数（不安全）
        try {
            MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
            byte[] sha1Hash = sha1Digest.digest(input.getBytes());
            System.out.println("SHA-1 Hash: " + bytesToHex(sha1Hash));
        } catch (NoSuchAlgorithmException e) {
            System.out.println("SHA-1 algorithm not found.");
        }

        // 使用SHA-256哈希函数（安全）
        try {
            MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
            byte[] sha256Hash = sha256Digest.digest(input.getBytes());
            System.out.println("SHA-256 Hash: " + bytesToHex(sha256Hash));
        } catch (NoSuchAlgorithmException e) {
            System.out.println("SHA-256 algorithm not found.");
        }
    }

    // 辅助方法：将字节数组转换为十六进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}