import org.miracl.core.BLS12461.FP2;

public class Main_Time3 {
    public static void main(String[] args) {
        // Create a new instance of the FP2 class
        FP2 fp2 = new FP2();

        // Measure the time it takes to execute the mul method
        long startTime = System.nanoTime();
        fp2.mul(fp2);
        long endTime = System.nanoTime();
        double elapsedTime = (endTime - startTime)/1_000_000_000.0;

        // Print the elapsed time
        System.out.println("Elapsed time: " + elapsedTime + " in seconds");
    }
}
