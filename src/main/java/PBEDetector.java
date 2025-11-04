import soot.*;
import soot.jimple.*;
import java.io.*;
import java.util.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.concurrent.*;
import soot.toolkits.graph.*;

public class PBEDetector {
    private static final int MIN_ITERATION_COUNT = 1000;
    private static final Set<String> TARGET_CLASSES = new HashSet<>(Arrays.asList(
            "javax.crypto.spec.PBEKeySpec"
    ));

    public static List<String> detect(BlockingQueue<SootMethod> methodQueue) {
        System.out.println("PBEDetector Detecting...");
        List<String> vulnerabilities = Collections.synchronizedList(new ArrayList<>());
        vulnerabilities.add("=== PBEDetector Vulnerability Report ===");

        ExecutorService executor = Executors.newFixedThreadPool(5);
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        while (!methodQueue.isEmpty()) {
            SootMethod method = methodQueue.poll();
            if (method != null) {
                CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                    try {
                        analyzeMethod(method, vulnerabilities);
                    } catch (InterruptedException e) {
                        System.err.println("Task interrupted: " + method.getSignature() + ": " + e.getMessage());
                        Thread.currentThread().interrupt(); // 恢复中断状态
                    } catch (Exception e) {
                        System.err.println("Error: " + method.getSignature() + ": " + e.getMessage());
                    }
                }, executor).orTimeout(5, TimeUnit.SECONDS).exceptionally(e -> {
                    // 实时打印超时
                    if (e.getCause() instanceof TimeoutException) {
                        System.err.println("Timeout: " + method.getSignature() + " after 5 seconds");
                    }
                    return null;
                });
                futures.add(future);
            }
        }

        // 等待任务完成或超时
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).whenComplete((result, throwable) -> {
            futures.forEach(f -> f.cancel(true)); // 取消未完成任务
            executor.shutdownNow(); // 强制终止线程池
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    System.err.println("Executor forced shutdown");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).join();

        vulnerabilities.add("=== End of Report ===");
        return vulnerabilities;
    }

    private static void analyzeMethod(SootMethod method, List<String> vulnerabilities) throws InterruptedException {

        Body body = SootAnalysisWorker.getMethodBody(method);
        if (body == null) return;

        if (containsTargetAPI(method)) {
            checkPBE(body, method, vulnerabilities);
        }
    }

    private static boolean containsTargetAPI(SootMethod method) {
        try {
            Body body = method.retrieveActiveBody();
            for (Unit unit : body.getUnits()) {
                InvokeExpr invokeExpr = null;
                if (unit instanceof InvokeStmt) {
                    invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
                } else if (unit instanceof AssignStmt) {
                    Value rightOp = ((AssignStmt) unit).getRightOp();
                    if (rightOp instanceof InvokeExpr) {
                        invokeExpr = (InvokeExpr) rightOp;
                    }
                }
                if (invokeExpr != null && TARGET_CLASSES.contains(invokeExpr.getMethod().getDeclaringClass().getName())) {
                    return true;
                }
            }
        } catch (Exception e) {
            // 忽略无法获取方法体的异常
        }
        return false;
    }

    private static void checkPBE(Body body, SootMethod method, List<String> vulnerabilities) {

        HardCodeDetector.HardcodeFlowAnalysis analysis = new HardCodeDetector.HardcodeFlowAnalysis(new BriefUnitGraph(body));

        for (Unit unit : body.getUnits()) {
            if (unit instanceof InvokeStmt) {
                InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
                SootMethod invokedMethod = invokeExpr.getMethod();

                if (invokedMethod.getDeclaringClass().getName().equals("javax.crypto.spec.PBEKeySpec") &&
                        invokedMethod.getName().equals("<init>") && invokeExpr.getArgCount() >= 3) {

                    // 检查迭代次数
                    Value iterArg = invokeExpr.getArg(2);
                    Map<Object, HardCodeDetector.Condition> possibleIters = analysis.getPossibleValuesWithConditions(iterArg);
                    for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleIters.entrySet()) {
                        if (!entry.getValue().isReachable()) continue;
                        if (entry.getKey() instanceof Integer && (Integer) entry.getKey() < MIN_ITERATION_COUNT) {
                            HardCodeDetector.HardcodedInfo info = analysis.getHardcodedInfo(body, iterArg, entry.getKey());
                            String location = unit.getJavaSourceStartLineNumber() != -1
                                    ? "line " + unit.getJavaSourceStartLineNumber()
                                    : "unknown location";
                            HardCodeDetector.reportVulnerability(method, unit,
                                    "PBE iteration count too low: " + entry.getKey() + ", recommend " + MIN_ITERATION_COUNT + "+",
                                    location, vulnerabilities);
                        }
                    }
                }
            }
        }

    }

}