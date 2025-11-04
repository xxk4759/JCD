import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.*;
import soot.toolkits.scalar.*;
import soot.tagkit.LineNumberTag;
import soot.tagkit.Tag;
import java.util.concurrent.*;

import java.io.*;
import java.util.*;

public class HardCodeDetector {
    private static final Set<String> TARGET_CLASSES = new HashSet<>(Arrays.asList(
            "javax.crypto.spec.SecretKeySpec",
            "javax.crypto.spec.IvParameterSpec",
            "javax.crypto.Cipher",
            "javax.crypto.spec.PBEKeySpec",
            "java.util.Random",
            "java.security.SecureRandom"
    ));
    private static final Map<String, Object> staticFieldValues = new HashMap<>();

    public static List<String> detect(BlockingQueue<SootMethod> methodQueue) {
        System.out.println("HardCodeDetector Detecting...");
        List<String> vulnerabilities = Collections.synchronizedList(new ArrayList<>());
        vulnerabilities.add("=== HardCodeDetector Vulnerability Report ===");

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
            checkForHardcodedValues(body, method, vulnerabilities, 0);
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

    private static void checkForHardcodedValues(Body body, SootMethod method, List<String> vulnerabilities, int depth) {
        if (depth > 3) return;
        UnitGraph graph = new BriefUnitGraph(body);
        HardcodeFlowAnalysis analysis = new HardcodeFlowAnalysis(graph);

        for (Unit unit : body.getUnits()) {
            if (unit instanceof InvokeStmt) {
                InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
                SootMethod invokedMethod = invokeExpr.getMethod();
                String className = invokedMethod.getDeclaringClass().getName();
                String methodName = invokedMethod.getName();

                if (className.equals("javax.crypto.spec.SecretKeySpec") && methodName.equals("<init>")) {
                    checkHardcodedArg(body, method, unit, invokeExpr.getArg(0), "key", analysis, vulnerabilities);
                } else if (className.equals("javax.crypto.spec.IvParameterSpec") && methodName.equals("<init>")) {
                    checkHardcodedArg(body, method, unit, invokeExpr.getArg(0), "IV", analysis, vulnerabilities);
                } else if (className.equals("javax.crypto.Cipher") && methodName.equals("doFinal")) {
                    checkHardcodedArg(body, method, unit, invokeExpr.getArg(0), "plaintext", analysis, vulnerabilities);
                } else if (className.equals("javax.crypto.spec.GCMParameterSpec") && methodName.equals("<init>")) {
                    checkHardcodedArg(body, method, unit, invokeExpr.getArg(1), "nonce", analysis, vulnerabilities);
                }
                else if (className.equals("javax.crypto.spec.PBEKeySpec") && methodName.equals("<init>")) {
                    checkHardcodedArg(body, method, unit, invokeExpr.getArg(0), "password", analysis, vulnerabilities);
                    checkHardcodedArg(body, method, unit, invokeExpr.getArg(1), "Salt", analysis, vulnerabilities);
                }
                else if ((className.equals("java.util.Random") || className.equals("java.security.SecureRandom"))
                        && methodName.equals("setSeed")) {
                    checkHardcodedArg(body, method, unit, invokeExpr.getArg(0), "random seed", analysis, vulnerabilities);
                }
            }
        }
        // 追溯调用
        CallGraph callGraph = SootAnalysisWorker.getCallGraph();
        Iterator<Edge> edges = callGraph.edgesOutOf(method);
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod target = edge.tgt();
            Body targetBody = SootAnalysisWorker.getMethodBody(target);
            if (targetBody != null) {
                checkForHardcodedValues(targetBody, target, vulnerabilities, depth + 1);
            }
        }
    }

    private static void checkHardcodedArg(Body body, SootMethod method, Unit unit, Value arg, String type,
                                          HardCodeDetector.HardcodeFlowAnalysis analysis, List<String> vulnerabilities) {
        Map<Object, HardCodeDetector.Condition> values = analysis.getPossibleValuesWithConditions(arg);
        if(analysis.isDynamicallyModified(body,arg)) return;
        for (Map.Entry<Object, HardCodeDetector.Condition> entry : values.entrySet()) {
            if (entry.getValue().isReachable()) {
                Object key = entry.getKey();
                if (key == null) {
                    continue;
                }
                String valueStr = key instanceof byte[]
                        ? Arrays.toString((byte[]) key)
                        : key.toString();
                String location = unit.getJavaSourceStartLineNumber() != -1
                        ? "line " + unit.getJavaSourceStartLineNumber()
                        : method.getSignature();
                String message = "Detected hardcoded " + type + ": " + valueStr;
                HardCodeDetector.reportVulnerability(method, unit, message, location, vulnerabilities);
            }
        }
    }

    public static class Condition {
        private final boolean isConstant;
        private final Set<Unit> conditions;

        public Condition(boolean isConstant, Set<Unit> conditions) {
            this.isConstant = isConstant;
            this.conditions = conditions;
        }

        public boolean isReachable() {
            if (isConstant) return true;
            for (Unit cond : conditions) {
                if (cond instanceof IfStmt) {
                    Value condition = ((IfStmt) cond).getCondition();
                    if (condition instanceof IntConstant && ((IntConstant) condition).value == 0) {
                        return false;
                    }
                }
            }
            return true;
        }
    }

    public static class HardcodeFlowAnalysis extends ForwardFlowAnalysis<Unit, Map<Local, Map<Object, Condition>>> {
        private final Map<Local, Map<Object, Condition>> valueMap = new HashMap<>();
        private final UnitGraph graph;
        private final Set<Local> modifiedLocals = new HashSet<>();//动态变量

        public HardcodeFlowAnalysis(UnitGraph graph) {
            super(graph);
            this.graph = graph;
            extractStaticFields(graph.getBody().getMethod().getDeclaringClass());
            doAnalysis();
            finishAnalysis();
        }

        private void extractStaticFields(SootClass sootClass) {
            if (sootClass.declaresMethodByName("<clinit>")) {
                SootMethod clinit = sootClass.getMethodByName("<clinit>");
                if (clinit.isConcrete()) {
                    try {
                        Body clinitBody = clinit.retrieveActiveBody();
                        for (Unit u : clinitBody.getUnits()) {
                            if (u instanceof AssignStmt) {
                                AssignStmt assignStmt = (AssignStmt) u;
                                if (assignStmt.getLeftOp() instanceof StaticFieldRef) {
                                    StaticFieldRef staticField = (StaticFieldRef) assignStmt.getLeftOp();
                                    SootField field = staticField.getField();
                                    Value rightOp = assignStmt.getRightOp();
                                    if (field.getType().toString().equals("[B")) {
                                        if (rightOp instanceof NewArrayExpr) {
                                            NewArrayExpr arrayExpr = (NewArrayExpr) rightOp;
                                            int size = getArraySize(arrayExpr);
                                            if (size >= 0) {
                                                byte[] value = new byte[size];
                                                staticFieldValues.put(field.getSignature(), value);

                                            }
                                        } else if (rightOp instanceof Local) {

                                        }
                                    } else if (rightOp instanceof StringConstant) {
                                        String value = ((StringConstant) rightOp).value;
                                        staticFieldValues.put(field.getSignature(), value);
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        System.out.println("[DEBUG] Failed to retrieve <clinit> body: " + e.getMessage());
                    }
                }
            }
        }

        private int getArraySize(NewArrayExpr arrayExpr) {
            Value sizeValue = arrayExpr.getSize();
            if (sizeValue instanceof IntConstant) {
                return ((IntConstant) sizeValue).value;
            }
            return -1;
        }

        @Override
        protected void flowThrough(Map<Local, Map<Object, Condition>> in, Unit unit, Map<Local, Map<Object, Condition>> out) {
            out.clear();
            for (Map.Entry<Local, Map<Object, Condition>> entry : in.entrySet()) {
                out.put(entry.getKey(), new HashMap<>(entry.getValue()));
            }

            if (unit instanceof AssignStmt) {
                AssignStmt assignStmt = (AssignStmt) unit;
                Value left = assignStmt.getLeftOp();
                Value right = assignStmt.getRightOp();
                if (left instanceof Local) {
                    Map<Object, Condition> values = out.computeIfAbsent((Local) left, k -> new HashMap<>());
                    values.clear();
                    if (right instanceof Constant) {
                        values.put(right.toString(), new Condition(true, Collections.emptySet()));
                    } else if (right instanceof NewArrayExpr) {
                        NewArrayExpr arrayExpr = (NewArrayExpr) right;
                        String arrayValue = "new " + arrayExpr.getBaseType() + "[" + arrayExpr.getSize() + "]";
                        values.put(arrayValue, new Condition(true, Collections.emptySet()));
                    } else if (right instanceof InvokeExpr) {
                        InvokeExpr invokeExpr = (InvokeExpr) right;
                        String methodSig = invokeExpr.getMethod().getSignature();
                        SootMethod invokedMethod = invokeExpr.getMethod();
                        String declaringClass = invokedMethod.getDeclaringClass().getName();

                        // 处理 getBytes
                        if (methodSig.contains("getBytes") && invokeExpr instanceof InstanceInvokeExpr) {
                            InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) invokeExpr;
                            Value base = instanceInvoke.getBase();
                            Map<Object, Condition> baseValues = in.get(base);
                            if (baseValues != null && !baseValues.isEmpty()) {
                                for (Map.Entry<Object, Condition> entry : baseValues.entrySet()) {
                                    String transformed = "\"" + entry.getKey() + "\".getBytes()";
                                    values.put(transformed, entry.getValue());
                                }
                            } else {
                                values.put("\"null\".getBytes()", new Condition(true, Collections.emptySet()));
                            }
                        }
                        // 处理 toArray
                        else if (methodSig.contains("toArray") && declaringClass.equals("java.util.List") &&
                                invokeExpr instanceof InstanceInvokeExpr) {
                            InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) invokeExpr;
                            Value base = instanceInvoke.getBase();
                            Map<Object, Condition> baseValues = in.get(base);
                            if (baseValues != null && !baseValues.isEmpty()) {
                                for (Map.Entry<Object, Condition> entry : baseValues.entrySet()) {
                                    Object key = entry.getKey();
                                    String transformed;
                                    if (key instanceof Collection) {
                                        transformed = Arrays.toString(((Collection<?>) key).toArray()) + ".toArray()";
                                    } else {
                                        transformed = "[" + key + "].toArray()";
                                    }
                                    values.put(transformed, entry.getValue());
                                }
                            } else {
                                values.put("\"null\".toArray()", new Condition(true, Collections.emptySet()));
                            }
                        }
                        // 处理 toCharArray
                        else if (methodSig.contains("toCharArray") && declaringClass.equals("java.lang.String") &&
                                invokeExpr instanceof InstanceInvokeExpr) {
                            InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) invokeExpr;
                            Value base = instanceInvoke.getBase();
                            Map<Object, Condition> baseValues = in.get(base);
                            if (baseValues != null && !baseValues.isEmpty()) {
                                for (Map.Entry<Object, Condition> entry : baseValues.entrySet()) {
                                    String transformed = "\"" + entry.getKey() + "\".toCharArray()";
                                    values.put(transformed, entry.getValue());
                                }
                            } else {
                                values.put("\"null\".toCharArray()", new Condition(true, Collections.emptySet()));
                            }
                        }

                    } else if (right instanceof Local) {
                        Map<Object, Condition> rightValues = in.get(right);
                        if (rightValues != null) {
                            values.putAll(rightValues);
                        }
                    }else if (right instanceof StaticFieldRef) {
                        StaticFieldRef staticField = (StaticFieldRef) right;
                        SootField field = staticField.getField();
                        Object fieldValue = staticFieldValues.get(field.getSignature());
                        if (fieldValue != null) {
                            values.put(fieldValue, new Condition(true, Collections.emptySet()));
                        } else {
                            values.put(field.getSignature(), new Condition(true, Collections.emptySet()));
                        }
                    }
                } else if (left instanceof StaticFieldRef) {
                    StaticFieldRef staticField = (StaticFieldRef) left;
                    SootField field = staticField.getField();
                    if (right instanceof Local) {
                        Map<Object, Condition> rightValues = in.get(right);
                        if (rightValues != null && !rightValues.isEmpty()) {
                            Object value = rightValues.keySet().iterator().next();
                            staticFieldValues.put(field.getSignature(), value);
                        }
                    }else if (right instanceof NewArrayExpr) {
                        NewArrayExpr arrayExpr = (NewArrayExpr) right;
                        int size = getArraySize(arrayExpr);
                        if (size >= 0) {
                            byte[] value = new byte[size];
                            staticFieldValues.put(field.getSignature(), value);
                        }
                    } else if (right instanceof Constant) {
                        staticFieldValues.put(field.getSignature(), right.toString());
                    }
                }
            }

            if (unit instanceof InvokeStmt) {
                InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
                SootMethod method = invokeExpr.getMethod();
                if (method.getName().equals("nextBytes") &&
                        invokeExpr.getArgCount() > 0 && invokeExpr.getArg(0) instanceof Local) {
                    modifiedLocals.add((Local) invokeExpr.getArg(0));
                }
            }

            if (unit instanceof IfStmt) {
                IfStmt ifStmt = (IfStmt) unit;
                List<Unit> successors = graph.getSuccsOf(unit);
                for (Unit succ : successors) {
                    Map<Local, Map<Object, Condition>> succFlow = getFlowBefore(succ);
                    for (Local local : succFlow.keySet()) {
                        Map<Object, Condition> values = succFlow.get(local);
                        for (Map.Entry<Object, Condition> entry : values.entrySet()) {
                            Set<Unit> conditions = new HashSet<>(entry.getValue().conditions);
                            conditions.add(unit);
                            entry.setValue(new Condition(false, conditions));
                        }
                    }
                }
            }
        }

        @Override
        protected Map<Local, Map<Object, Condition>> newInitialFlow() {
            return new HashMap<>();
        }

        @Override
        protected void merge(Map<Local, Map<Object, Condition>> in1, Map<Local, Map<Object, Condition>> in2,
                             Map<Local, Map<Object, Condition>> out) {
            out.clear();
            Set<Local> allLocals = new HashSet<>(in1.keySet());
            allLocals.addAll(in2.keySet());
            for (Local local : allLocals) {
                Map<Object, Condition> values1 = in1.getOrDefault(local, Collections.emptyMap());
                Map<Object, Condition> values2 = in2.getOrDefault(local, Collections.emptyMap());
                Map<Object, Condition> merged = new HashMap<>(values1);
                for (Map.Entry<Object, Condition> entry : values2.entrySet()) {
                    Object value = entry.getKey();
                    Condition cond2 = entry.getValue();
                    Condition cond1 = merged.get(value);
                    if (cond1 == null) {
                        merged.put(value, cond2);
                    } else {
                        Set<Unit> conditions = new HashSet<>(cond1.conditions);
                        conditions.addAll(cond2.conditions);
                        merged.put(value, new Condition(cond1.isConstant && cond2.isConstant, conditions));
                    }
                }
                if (!merged.isEmpty()) {
                    out.put(local, merged);
                }
            }
        }

        @Override
        protected void copy(Map<Local, Map<Object, Condition>> source, Map<Local, Map<Object, Condition>> dest) {
            dest.clear();
            for (Map.Entry<Local, Map<Object, Condition>> entry : source.entrySet()) {
                dest.put(entry.getKey(), new HashMap<>(entry.getValue()));
            }
        }

        public Map<Object, Condition> getPossibleValuesWithConditions(Value value) {
            Map<Object, Condition> result = new HashMap<>();
            if (value instanceof Constant) {
                if (value instanceof IntConstant) {
                    result.put(Integer.valueOf(((IntConstant) value).value), new Condition(true, Collections.emptySet()));
                } else if (value instanceof StringConstant) {
                    result.put(((StringConstant) value).value, new Condition(true, Collections.emptySet()));
                } else if (value instanceof LongConstant) {
                    result.put(Long.valueOf(((LongConstant) value).value), new Condition(true, Collections.emptySet()));
                } else if (value instanceof FloatConstant) {
                    result.put(Float.valueOf(((FloatConstant) value).value), new Condition(true, Collections.emptySet()));
                } else if (value instanceof DoubleConstant) {
                    result.put(Double.valueOf(((DoubleConstant) value).value), new Condition(true, Collections.emptySet()));
                } else if (value instanceof ClassConstant) {
                    result.put(((ClassConstant) value).getValue(), new Condition(true, Collections.emptySet()));
                } else if (value instanceof NullConstant) {
                    result.put(null, new Condition(true, Collections.emptySet()));
                } else {
                    result.put(value.toString(), new Condition(true, Collections.emptySet()));
                }
            } else if (value instanceof Local) {
                Map<Object, Condition> values = valueMap.get(value);
                if (values != null) {
                    result.putAll(values);
                }
            } else if (value instanceof NewArrayExpr) {
                NewArrayExpr arrayExpr = (NewArrayExpr) value;
                String arrayValue = "new " + arrayExpr.getBaseType() + "[" + arrayExpr.getSize() + "]";
                result.put(arrayValue, new Condition(true, Collections.emptySet()));
            } else if (value instanceof StaticFieldRef) {
                StaticFieldRef staticField = (StaticFieldRef) value;
                SootField field = staticField.getField();
                Object fieldValue = staticFieldValues.get(field.getSignature());
                if (fieldValue != null) {
                    result.put(fieldValue, new Condition(true, Collections.emptySet()));
                } else {
                    result.put(field.getSignature(), new Condition(true, Collections.emptySet()));
                }
            }
            return result.isEmpty() ? Collections.singletonMap(null, new Condition(true, Collections.emptySet())) : result;
        }

        public HardcodedInfo getHardcodedInfo(Body body, Value value, Object detectedValue) {
            if (value instanceof Constant || value instanceof NewArrayExpr) {
                return new HardcodedInfo(detectedValue.toString(), "unknown line"); // 模拟实际行号丢失
            } else if (value instanceof Local) {
                for (Unit unit : body.getUnits()) {
                    if (unit instanceof AssignStmt) {
                        AssignStmt stmt = (AssignStmt) unit;
                        if (stmt.getLeftOp().equals(value)) {
                            Value rightOp = stmt.getRightOp();
                            if (rightOp instanceof Constant || rightOp instanceof NewArrayExpr) {
                                return new HardcodedInfo(detectedValue.toString(), getSourceLine(body, stmt));
                            } else if (rightOp instanceof InvokeExpr) {
                                InvokeExpr invokeExpr = (InvokeExpr) rightOp;
                                String sig = invokeExpr.getMethod().getSignature();
                                if (sig.contains("getBytes") && invokeExpr instanceof InstanceInvokeExpr) {
                                    return new HardcodedInfo(detectedValue.toString(), getSourceLine(body, unit));
                                }
                            }
                        }
                    }
                }
            }
            return null;
        }

        public boolean isDynamicallyModified(Body body, Value value) {
            if (value instanceof Local) {
                return modifiedLocals.contains((Local) value);
            }
            return false;
        }

        private void finishAnalysis() {
            if (!graph.getTails().isEmpty()) {
                Map<Local, Map<Object, Condition>> finalState = getFlowAfter(graph.getTails().get(0));
                valueMap.clear();
                for (Map.Entry<Local, Map<Object, Condition>> entry : finalState.entrySet()) {
                    valueMap.put(entry.getKey(), new HashMap<>(entry.getValue()));
                }
            }
        }
    }

    private static Unit findDefiningUnit(Body body, Value value) {
        for (Unit unit : body.getUnits()) {
            if (unit instanceof AssignStmt) {
                AssignStmt stmt = (AssignStmt) unit;
                if (stmt.getLeftOp().equals(value)) {
                    return stmt;
                }
            }
        }
        return null;
    }

    protected static String getSourceLine(Body body, Unit unit) {
        if (unit == null) return "unknown line";
        Tag lineTag = unit.getTag("LineNumberTag");
        if (lineTag != null) {
            int lineNumber = ((LineNumberTag) lineTag).getLineNumber();
            return "line " + (lineNumber); // 模拟行号偏移（如 +10）
        }
        return "unknown line";
    }

    public static class HardcodedInfo {
        public String value;
        public String location;

        HardcodedInfo(String value, String location) {
            this.value = value;
            this.location = location;
        }
    }

    public static void reportVulnerability(SootMethod method, Unit unit, String message, String location, List<String> vulnerabilities) {
        String report = String.format("[Vulnerability] %s in %s at %s", message, method.getSignature(), location);
        vulnerabilities.add(report);
    }
}