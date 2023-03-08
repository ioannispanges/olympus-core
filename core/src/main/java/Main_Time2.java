import org.miracl.core.BLS12461.FP2;

public class Main_Time2 {
    private FP2 fp2Object;

    public Main_Time2() {
        // Initialize an instance of FP2
        this.fp2Object = new FP2();
    }

    public void run() {
        FP2 y = new FP2(); // Initialize another instance of FP2 for the parameter of mul method
        long startTime = System.nanoTime();

        // Call the mul method of FP2
        this.fp2Object.mul(y);

        long endTime = System.nanoTime();
        double elapsedTime = (endTime - startTime)/1_000_000_000.0; // convert nanoseconds to seconds;
        System.out.println("Elapsed time: " + elapsedTime + "in seconds");
    }

    public static void main(String[] args) {
        Main_Time2 main = new Main_Time2(); // Create an instance of Main
        main.run(); // Call the run method to measure the elapsed time
    }
}
