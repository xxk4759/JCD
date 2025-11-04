# 🛡️ JCD — Java Crypto Detector
*A Soot-based static analysis tool for detecting cryptographic vulnerabilities in Java applications*

---

## 🔍 Overview

**JCD (Java Crypto Detector)** is a **static analysis tool built upon the [Soot](https://github.com/soot-oss/soot) framework**, designed to automatically detect **cryptographic security vulnerabilities** in Java bytecode.  
It analyzes `.class` files or JAR packages **without executing the program**, tracing data flow and control flow to locate issues such as **hardcoded keys, weak encryption algorithms, insecure protocols, PBE misconfigurations, and SSL/TLS misuse**.

JCD is suitable for **security auditing**, **software assurance**, and **automated vulnerability scanning** in development pipelines.

---

## ⚙️ Key Features

| Module | Description |
|---------|-------------|
| **Entry** | Main entry point. Initializes the Soot environment, reads target input, distributes analysis tasks, and generates reports. |
| **Soot Analysis Worker** | Loads bytecode methods and constructs context-sensitive call graphs. |
| **Detectors** | Includes five independent detectors: `HardCodeDetector`, `SSLDetector`, `PBEDetector`, `CipherFinder`, and `HttpDetector`. |
| **Parallel Executor** | Implements concurrent method-level analysis using multi-threaded task queues. |
| **Report Generator** | Produces human-readable vulnerability reports with method signatures, line numbers, and descriptions. |

---

## 🧠 Technical Highlights

- **Powered by Soot Framework**  
  Utilizes Soot’s intermediate representations (Jimple), call graph construction (Spark algorithm), and inter-procedural data flow analysis.

- **Context-sensitive Analysis**  
  Tracks variable definitions and data flows across multiple methods and classes.

- **Highly Parallelized**  
  Implements method-level task partitioning and parallel execution using Java’s `ExecutorService` and `CompletableFuture`.

- **Full Bytecode Compatibility**  
  Supports Java 8–17 class versions (52.0–61.0) through dynamic module path configuration and optional ASM backend integration.

---

## 🧩 Supported Vulnerability Categories

| Category | Examples |
|-----------|-----------|
| **Hardcoded Secrets** | Hardcoded keys, IVs, passwords, nonces, seeds |
| **Weak Algorithms / Configurations** | DES, MD5, SHA-1, ECB mode, weak key lengths |
| **Weak PBE Configuration** | Low iteration counts (< 1000) |
| **Insecure Communication** | Use of HTTP instead of HTTPS |
| **SSL/TLS Issues** | Empty trust managers, accepting all hostnames, weak protocols (TLSv1.1, SSLv3) |

---

## 🚀 Usage

### 🔧 Environment Setup

JCD is **built upon the Soot framework**, so you must ensure that Soot and its dependencies are correctly configured.  
Refer to the official [Soot GitHub page](https://github.com/soot-oss/soot) for installation and environment setup instructions.

> 💡 **Recommended:** Build and run JCD within an IDE such as **IntelliJ IDEA** or **Eclipse**, using **Maven** to automatically configure the Soot environment and dependencies.  
> This ensures that the classpath and Soot configuration are correctly initialized before running the analysis.

### ▶️ Running JCD

1. **Run the Entry class**

You can input:
- a single `.class` file  
- a directory containing compiled class files  
- or a `.jar` package

```bash
java Entry
```

2. **View the report**

A report file named `report_<timestamp>.txt` will be generated in the working directory, containing all detected vulnerabilities.

---

## 🧩 Example Output

```
[Vulnerability] Weak hash function: MD5 in <UnsafeHashExample: void main()> at line 11
[Vulnerability] Hardcoded IV: <AESUtil: byte[] STATIC_IV> in <AESUtil: void main()> at line 19
[Vulnerability] Insecure HTTP URL: http://example.com in <TestVulnerabilities: void testHttpUsage()> at line 107
[Vulnerability] SSLContext initialized with null TrustManager in <TestVulnerabilities: void testSSLSettings()> at line 119
```

---

## 📊 Performance Evaluation

| Project | LOC | Analysis Time |
|----------|-----|---------------|
| Java-WebSocket | 15,905 | 21.29 s |
| Apache Shiro | 44,949 | 29.61 s |
| Spring Security-Core | 34,014 | 36.33 s |

Average analysis time for large-scale projects: **< 40 seconds**  
Detection accuracy: **> 90%** (verified on self-constructed vulnerability test cases)

---

## 🧾 License

This project is released under the **MIT License**.

---

## 📎 Additional Information

- The repository includes several **sample Java files** containing intentional vulnerabilities for testing and demonstration.  
- JCD is developed as part of a **research and patent project**:  
  *“A Soot-based Java Cryptographic Static Analysis Tool and Method”* (Patent CN pending, 2025).
