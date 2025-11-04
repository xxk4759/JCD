import soot.*;
import soot.options.Options;
import soot.util.Chain;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;

public class Entry {

        protected static PrintWriter writer;

        public static void main(String[] args) {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Please input the JAR file or class folder path：");
            String classpath = scanner.nextLine();

            File file = new File(classpath);

            String fileName = new File(classpath).getName().replace(".jar", "");
            String timestamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss").format(new Date());
            String reportFile = fileName + "_report_" + timestamp + ".txt";

            G.reset();
            Options.v().set_process_dir(new ArrayList<>(Collections.singletonList(classpath)));

            // 设置类路径，包含输入 JAR 和系统类路径
            String systemClassPath = System.getProperty("java.class.path");
            String sootClassPath = classpath;
            if (systemClassPath != null) {
                sootClassPath += File.pathSeparator + systemClassPath;
            }
            Options.v().set_soot_classpath(sootClassPath);
            Options.v().set_allow_phantom_refs(true);
            Options.v().set_prepend_classpath(true);
            Options.v().set_keep_line_number(true);
            Options.v().set_whole_program(true);
            Options.v().set_output_format(Options.output_format_none);
           Options.v().set_exclude(Arrays.asList("java.awt.", "javax.swing.", "sun.", "com.sun."));
            Options.v().set_exclude(Arrays.asList(
                    "java.awt.", "java.awt.image.",
                    "javax.swing.",
                    "sun.", "com.sun.", "com.sun.imageio.",
                    "org.apache.", "org.w3c.", "org.xml.",
                    "java.util.", "java.io.", "java.net." // 加强排除
            ));
            Options.v().set_no_bodies_for_excluded(true);

            // 添加基本类
            Scene.v().addBasicClass("java.lang.Throwable", SootClass.BODIES);
            // 确保 Entry 类加载

                Scene.v().addBasicClass("Entry", SootClass.BODIES); // 提升到 BODIES
                Scene.v().forceResolve("Entry", SootClass.BODIES); // 强制解析
                Scene.v().loadNecessaryClasses();


            try {
                SootClass entryClass = Scene.v().getSootClass("Entry");
                // 精确查找 main 方法
                SootMethod entryMethod = entryClass.getMethod("void main(java.lang.String[])");
                if (entryMethod == null) {
                    System.err.println("Cannot find main method in Entry");
                    throw new RuntimeException("Main method not found in Entry");
                }
                List<SootMethod> entryPoints = new ArrayList<>();
                entryPoints.add(entryMethod);
                Scene.v().setEntryPoints(entryPoints);
            } catch (Exception e) {
                System.err.println("Failed to set entry point: " + e.getMessage());
                throw e;
            }

        try {
            // 加载类并预加载方法体
            Scene.v().loadNecessaryClasses();
            Chain<SootClass> appClasses = Scene.v().getApplicationClasses();
            List<SootClass> safeClasses = new CopyOnWriteArrayList<>(appClasses);
            System.out.println("Loaded classes: " + safeClasses.size());
            SootAnalysisWorker.initialize(safeClasses);

            writer = new PrintWriter(new BufferedWriter(new FileWriter(reportFile)));
            writer.println("=== Analysis Report for " + fileName + " - " + timestamp + " ===");

            // 创建检测器任务队列
            int threadCount = 5;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            List<Future<List<String>>> futures = new ArrayList<>();
            BlockingQueue<SootMethod> cipherQueue = new LinkedBlockingQueue<>();
            BlockingQueue<SootMethod> hardcodeQueue = new LinkedBlockingQueue<>();
            BlockingQueue<SootMethod> pbeQueue = new LinkedBlockingQueue<>();
            BlockingQueue<SootMethod> httpQueue = new LinkedBlockingQueue<>();
            BlockingQueue<SootMethod> sslQueue = new LinkedBlockingQueue<>();

            // 填充任务队列
            for (SootClass sootClass : safeClasses) {
                for (SootMethod method : sootClass.getMethods()) {
                    if (method.isConcrete() && SootAnalysisWorker.getMethodBody(method) != null) {
                        cipherQueue.offer(method);
                        hardcodeQueue.offer(method);
                        pbeQueue.offer(method);
                        httpQueue.offer(method);
                        sslQueue.offer(method);
                    }
                }
            }
            System.out.println("Queued " + cipherQueue.size() + " methods for each detector");

            // 提交检测器任务
            futures.add(executor.submit(() -> CipherFinder.detect(cipherQueue)));
            futures.add(executor.submit(() -> HardCodeDetector.detect(hardcodeQueue)));
            futures.add(executor.submit(() -> PBEDetector.detect(pbeQueue)));
            futures.add(executor.submit(() -> HttpDetector.detect(httpQueue)));
            futures.add(executor.submit(() -> SSLDetector.detect(sslQueue)));

            // 收集结果
            for (Future<List<String>> future : futures) {
                try {
                    List<String> vulnerabilities = future.get(5, TimeUnit.MINUTES);
                    for (String report : vulnerabilities) {
                        writer.println(report);
                    }
                } catch (TimeoutException e) {
                    System.err.println("Detector task timed out: " + e.getMessage());
                } catch (InterruptedException | ExecutionException e) {
                    System.err.println("Detector task error: " + e.getMessage());
                }
            }

            writer.println("=== End of All Report ===");
            writer.flush();

            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.MINUTES)) {
                    System.err.println("Executor did not terminate, forcing shutdown");
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                System.err.println("Executor termination interrupted: " + e.getMessage());
            }

            // 清理缓存
            SootAnalysisWorker.clearCache();

        } catch (IOException e) {
            System.err.println("Failed to write report file: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Failed to analyze: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (writer != null) {
                writer.close();
            }
        }
            System.exit(0);
        }
}