import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.Socket;
import java.net.ServerSocket;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class HttpProtocolExample {
    public static void main(String[] args) {
        try {
            // 使用 java.net.HttpURLConnection
            URL url = new URL("http://baidu.com");
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            System.out.println("HttpURLConnection: " + httpURLConnection.getResponseCode());

            // 使用 java.net.URL
            URLConnection urlConnection = url.openConnection();
            System.out.println("URLConnection: " + urlConnection.getContentType());

            // 使用 java.net.Socket
            Socket socket = new Socket("baidu.com", 80);
            System.out.println("Socket: " + socket.getInetAddress());

            // 使用 java.net.ServerSocket
            ServerSocket serverSocket = new ServerSocket(8080);
            System.out.println("ServerSocket: " + serverSocket.getInetAddress());

            // 使用 org.apache.http
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet("http://baidu.com");
            httpClient.execute(httpGet).close();
            System.out.println("Apache HTTP Client: Request executed");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}