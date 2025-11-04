import javax.net.ssl.*;
import java.security.cert.X509Certificate;

public class TestSSL {
    static TrustManager[] tms = new TrustManager[]{new MyTrustManager()};
    static class MyTrustManager implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }

    static class MyVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) { return true; }
    }

    public static void main(String[] args) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.1");
        ctx.init(null, new TrustManager[]{new MyTrustManager()}, null);
        TrustManager[] tms1 = new TrustManager[]{new MyTrustManager(), new MyTrustManager()};
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        ctx.init(null, tms, null);
    }
}