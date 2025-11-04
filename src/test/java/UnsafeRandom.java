import java.util.Random;

public class UnsafeRandom {
    public static void main(String[] args) {
        // 使用 java.util.Random
        Random random = new Random();
        int randomInt = random.nextInt();
        System.out.println("Random integer: " + randomInt);

        // 使用 Math.random()
        double randomDouble = Math.random();
        System.out.println("Random double: " + randomDouble);
    }
}