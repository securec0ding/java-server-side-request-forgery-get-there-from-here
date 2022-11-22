package com.hunter2.testcases.simplessrf.InternalOnlyApi;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * This controller allows access to one of two tokens.
 * - a Public token returning a publicly accessible string and
 * - a secret token, containing a value that should not be leaked outside the application scope
 */
@Controller
@RequestMapping("/token")
public class TokenAccessController {
    // For the scope of this example the secretToken is hardcoded/retrieved from Environment
    private String secretToken = System.getenv("PATH");
    private String publicToken = "Hi!";

    @Value("${server.port}")
    private String serverPort;


    /**
     * Available from: http://x.x.x.x:yyyy/token/public
     *
     * @return The publicly accessible token
     */
    @GetMapping("/public")
    @ResponseBody
    public String getPublicToken() {
        return publicToken;
    }


    /**
     * Available from: http://foobar.lab.dev.ht/token/secret (when accessed through SecurityLab)
     * This method allows access to the *secret* value only to connections arriving from the same host
     * by checking that the originating the request's ip is 127.0.0.1.
     * <p>
     * This is a sample created only for the purpose of this demo. In order to provide access control functionalities
     * it is advisable to evaluate the architecture carefully and identify the best approach.
     * This controller method applies a basic validation (just for the purpose of this sample) allowing access based
     * on the IP of the received request.
     * To facilitate the exercise and debugging, the method prints the IP address of the clients accessing the method
     * <p>
     * <p>
     * A good lab exercise could be to:
     * 1) Try to access
     * --->  https://foobar.lab.dev.ht/token/public
     * and note that it is accessible without any limitation
     *
     * 2) Try to access
     * --->  https://foobar.lab.dev.ht/token/secret
     * and notice that we get an error message because our source IP doesn't satisfy the allow-list
     * (it is good to note down the error message returned in this page since it will be useful later)
     *
     * 3) Try a first attack attempt at the SSRF by trying accessing www.google.com
     * --->  https://foobar.lab.dev.ht/example/get?subdomain=www.google.com?
     * and notice that we can retrieve the google homepage
     *
     * 4) Try a different attack attempt at the SSRF by trying accessing /token/public
     * --->  https://foobar.lab.dev.ht/example/get?subdomain=foobar.lab.dev.ht/token/public?
     * note that even though we know that /token/public is publicly accessible, it cannot be accessed through SSRF
     * (The reason is that since the HTTP connection happens on the server, when we pass the public hostname,
     * it tries to access it globally and it cannot access the lab since we request to click "access the lab".)
     *
     * 5) We can try to use the local hostname only (foobar.lab and NOT foobar.lab.dev.ht) :
     * --->  https://foobar.lab.dev.ht/example/get?subdomain=foobar.lab/token/public?
     * this can get to the server correctly, but it cannot access the webserver. How is that possible?
     * The reason is that once we access the server from inside Docker, the port where the server is listening
     * is the port that is assigned in *application.properties* when the application is started.
     * Here is where the error message form the step 2) comes handy. We can use the port number that is reported in the
     * error message. Let's assume the error message is:
     * [Server cf8ff9f95ff7/10.0.1.216:48882] - UNAUTHORIZED CONNECTION FROM [10.0.1.3] the port number is 48882
     * [Server abcdefghijkl/x.x.x.x:NNNNN] - UNAUTHORIZED CONNECTION FROM [y.y.y.y] the port number is NNNNN
     * we can now improve our attack url:
     * --->  https://foobar.lab.dev.ht/example/get?subdomain=abcdefghijkl:NNNNN/token/public?
     *
     * 6) Great, we can now try to get our flag by accessing the secret endpoint url:
     * --->  https://foobar.lab.dev.ht/example/get?subdomain=abcdefghijkl:NNNNN/token/secret
     * surprisingly this url won't work. It still reports access restricted message. The clue about the why is
     * in the error message itself. The server sees the originating IP to be the local ip of the server and not
     * the expected 127.0.0.1. The reason for this is the routing on the server. In order to solve this it is enough
     * to replace abcdefghijkl with 127.0.0.1
     * When accessing a localhost ip, such as 127.0.0.1, the usual routing protocol will try to reach it
     * without going on the network and accessing it directly. This means that our API method sees the request
     * originating from 127.0.0.1, thus allowing us to get access to secret. Both these URLs should work:
     * --->  https://foobar.lab.dev.ht/example/get?subdomain=127.0.0.1:NNNNN/token/secret
     * --->  https://foobar.lab.dev.ht/example/get?subdomain=localhost:NNNNN/token/secret
     *
     * @param request The request that is accessing the API method
     * @return the *secret* value
     */
    @GetMapping("/secret")
    @ResponseBody
    public ResponseEntity<String> getSecretToken(HttpServletRequest request) {
        System.out.println("Attempt at accessing secret from: [" + request.getRemoteAddr() + "]");

        if ("127.0.0.1".equals(request.getRemoteAddr())) {
            System.out.println("Successful access to secret from: [" + request.getRemoteAddr() + "]");
            return ResponseEntity.status(HttpStatus.OK).body(secretToken);
        }

        return ResponseEntity.status(HttpStatus.OK).body(unauthorizedErrorMessage(request));

    }

    /**
     * Function to log the unauthorized access. Returns the server name, server ip, server port and the origin ip
     * of the request
     *
     * @param request request to retrieve information from
     * @return the unauthorized-access error message
     */
    private String unauthorizedErrorMessage(HttpServletRequest request) {
        // Generate Error Log as report for the unauthorized access
        String serverHostName = "undefined";
        String serverAddress = "x.x.x.x";

        try {
            System.out.println("getLocalHost:" + InetAddress.getLocalHost());
            System.out.println("getLoopbackAddress:" + InetAddress.getLoopbackAddress());
            serverHostName = InetAddress.getLocalHost().getHostName();
            serverAddress = InetAddress.getLocalHost().getHostAddress();

        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        System.out.println("Rejected connection from: " + request.getRemoteAddr());
        return String.format("[Server %s/%s:%s] - UNAUTHORIZED CONNECTION FROM [%s]",
                serverHostName, serverAddress, serverPort, request.getRemoteAddr());
    }

}