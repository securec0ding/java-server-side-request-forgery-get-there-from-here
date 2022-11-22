package com.hunter2.testcases.simplessrf;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Arrays;

@Controller
@RequestMapping("/example_partial_remediation")
public class PublicAreaPartialRemediation {

    /**
     * Expected usage : http://127.0.0.1:8093/example_partial_remediation/get?subdomain=www
     * <p>
     * This API method assumes that the user would be passing the subdomain to retrieve data from (www).
     * Unfortunately by allowing unvalidated input, a malicious user can provide a crafted string that
     * hijack the connection to a completely different URL, while disabling the developer-provided strings from the URL.
     * By adding an ? at the end of the user provided string, whatever string is concatenated in the application
     * will be passed to the URL connection as an url parameter and not as part of the destination URL
     * <p>
     * <p>
     * <p>
     * This sample contains an *Incomplete fix*.
     * The code is testing that the final domain starts with an "approved" subdomain from the list defined by the line
     * ArrayList<String> validSubdomains = new ArrayList<>(Arrays.asList("www", "foo", "bar"));
     *
     * Note how the previous valid exploit:
     * http://x.x.x.x:yyyy/example/get?subdomain=127.0.0.1:8093/token/secret?
     * doesn't work anymore with the current remediation implemented here.
     * Nevertheless, this allow-list check can be bypassed easily by creating a crafted domain
     * that starts with an approved string.
     * <p>
     * Ex 1. The following URL will retrieve Google homepage.
     * In this case the destination URL (www.google.com) starts already with a value in our allow-list (www)
     * http://server.public.ip:8093/example/get?subdomain=www.google.com?
     * <p>
     * <p>
     * Ex 2 . The following URL satisfies the allow-list by passing a dummy username (foo) with the same value
     * of a token in the allow-list (foo) as part of the destination URL: foo@127.0.0.1:8093/token/secret?
     * http://server.public.ip:8093/example/get?subdomain=foo@127.0.0.1:8093/token/secret?
     * <p>
     * The previous attack relies on the possibility to pass username and password directly in the url as
     * http://username:password@your.server.ip
     * In our case they are not required, and they are both discarded. We need them just to satisfy the allow-list's check.
     * Read: https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#access_using_credentials_in_the_url
     * <p>
     * Note: Adapt the destination IP to the one that works on your system. It may not be 127.0.0.1,  but
     * it can be the public ip of your server or the internal ip of your docker instance
     *
     * @param subdomain the subdomain to access from http://[subdomain].example.com
     * @return HTML content to be rendered
     */
    @GetMapping("/get")
    @ResponseBody
    public ResponseEntity<String> retrieveExampleCom(@RequestParam String subdomain) {

        StringBuilder accumulatedText = new StringBuilder();
        // Creating the complete domain path to connect to
        String vulnerableDomain = subdomain + ".example.com/";


        ArrayList<String> validSubdomains = new ArrayList<>(Arrays.asList("www", "foo", "bar"));
        boolean isValidSubdomain = false;

        for (int idx = 0; idx < validSubdomains.size() && !isValidSubdomain; idx++) {
            if (vulnerableDomain.startsWith(validSubdomains.get(idx)))
                isValidSubdomain = true;
        }

        if (!isValidSubdomain)
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("INVALID SUBDOMAIN");


        try {
            // The full domain string is created by concatenating the protocol to the full path
            URL domainUrl = new URL("http://" + vulnerableDomain);
            URLConnection urlConnection1 = domainUrl.openConnection();
            try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(urlConnection1.getInputStream()))) {
                String readLine;
                while ((readLine = bufferedReader.readLine()) != null) {
                    accumulatedText.append(readLine);
                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
            accumulatedText.append("Malformed URL");
        } catch (IOException e) {
            e.printStackTrace();

            accumulatedText.append("IOException - ").append(e.getClass());
        }

        return ResponseEntity.status(HttpStatus.OK).body(accumulatedText.toString());

    }
}