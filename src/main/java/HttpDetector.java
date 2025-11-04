import soot.*;
import soot.jimple.*;
import soot.tagkit.LineNumberTag;
import soot.tagkit.Tag;
import soot.toolkits.graph.*;
import java.util.concurrent.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.io.*;
import java.util.*;

public class HttpDetector {
    private static final Set<String> HTTP_PORTS = new HashSet<>(Arrays.asList("80", "8080"));
    private static final Set<Integer> HTTP_PORT_NUMBERS = new HashSet<>(Arrays.asList(80, 8080));
    private static final Set<String> TARGET_CLASSES = new HashSet<>(Arrays.asList(
            "java.net.URL", "org.apache.http.client.methods.HttpGet",
            "okhttp3.Request$Builder", "java.net.Socket", "java.net.ServerSocket"
    ));

    public static List<String> detect(BlockingQueue<SootMethod> methodQueue) {
        System.out.println("HttpDetector Detecting...");
        List<String> vulnerabilities = Collections.synchronizedList(new ArrayList<>());
        vulnerabilities.add("=== HttpDetector Vulnerability Report ===");

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
                        Thread.currentThread().interrupt();
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
            detectURLUsage(body, method, vulnerabilities);
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

    private static void detectURLUsage(Body body, SootMethod method, List<String> vulnerabilities) {
        UnitGraph graph = new BriefUnitGraph(body);
        HardCodeDetector.HardcodeFlowAnalysis analysis = new HardCodeDetector.HardcodeFlowAnalysis(graph);

        for (Unit unit : body.getUnits()) {
            if (unit instanceof InvokeStmt) {
                InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
                SootMethod invokedMethod = invokeExpr.getMethod();
                String methodSig = invokedMethod.getSignature();
                String location = HardCodeDetector.getSourceLine(body,unit);

                // 检测 HTTP URL（扩展支持 OkHttp 和 HttpURLConnection）
                if (methodSig.contains("java.net.URL: void <init>") ||
                        methodSig.contains("org.apache.http.client.methods.HttpGet: void <init>") ||
                        methodSig.contains("okhttp3.Request$Builder: void <init>(java.lang.String)") ||
                        methodSig.contains("java.net.URL: java.net.URLConnection openConnection()")) {
                    checkHttpArgs(body, invokeExpr, analysis, method, unit, "HTTP URL", vulnerabilities, location);
                }
                // 检测 HTTP 默认端口
                else if (methodSig.contains("java.net.Socket: void <init>") ||
                        methodSig.contains("java.net.ServerSocket: void <init>")) {
                    checkHttpPorts(body, invokeExpr, analysis, method, unit, vulnerabilities, location);
                }
            }
        }
    }

    private static void checkHttpArgs(Body body, InvokeExpr invokeExpr, HardCodeDetector.HardcodeFlowAnalysis analysis,
                                      SootMethod method, Unit unit, String type, List<String> vulnerabilities, String location) {
        for (int i = 0; i < invokeExpr.getArgCount(); i++) {
            Value arg = invokeExpr.getArg(i);
            Map<Object, HardCodeDetector.Condition> possibleValues = analysis.getPossibleValuesWithConditions(arg);
            for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleValues.entrySet()) {
                if (!entry.getValue().isReachable()) continue;
                String argValue = entry.getKey() != null ? entry.getKey().toString() : "unknown";
                if (argValue.contains("http:") && !argValue.contains("https:")) { // 区分 HTTPS
                    HardCodeDetector.reportVulnerability(method, unit,
                            "Detected insecure " + type + ": " + argValue, location, vulnerabilities);
                }
            }
        }
    }

    private static void checkHttpPorts(Body body, InvokeExpr invokeExpr, HardCodeDetector.HardcodeFlowAnalysis analysis,
                                       SootMethod method, Unit unit, List<String> vulnerabilities, String location) {
        for (int i = 0; i < invokeExpr.getArgCount(); i++) {
            Value arg = invokeExpr.getArg(i);
            Map<Object, HardCodeDetector.Condition> possibleValues = analysis.getPossibleValuesWithConditions(arg);
            for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleValues.entrySet()) {
                if (!entry.getValue().isReachable()) continue;
                Object argValue = entry.getKey();
                if (argValue != null) {
                    String strValue = argValue.toString().trim().replaceAll("[\"']", "");
                    // 检查字符串端口
                    if (HTTP_PORTS.contains(strValue)) {
                        HardCodeDetector.reportVulnerability(method, unit,
                                "Detected insecure HTTP default port in " + method.getSignature() + ": " + strValue,
                                location, vulnerabilities);
                    }
                    // 检查整数端口
                    else if (argValue instanceof Integer && HTTP_PORT_NUMBERS.contains((Integer) argValue)) {
                        HardCodeDetector.reportVulnerability(method, unit,
                                "Detected insecure HTTP default port in " + method.getSignature() + ": " + argValue,
                                location, vulnerabilities);
                    }
                }
            }
        }
    }


}