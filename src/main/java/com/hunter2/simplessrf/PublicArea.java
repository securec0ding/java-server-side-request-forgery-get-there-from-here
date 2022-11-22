package com.hunter2.testcases.simplessrf;

import org.springframework.stereotype.Controller;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
@RequestMapping("/example")
public class PublicArea {

    /**
     * Expected usage : http://x.x.x.x:yyyy/example/get?subdomain=www
     * <p>
     * Sample Vulnerable URL: http://x.x.x.x:yyyy/example/get?subdomain=127.0.0.1:8093/token/secret?
     * <p>
     * This API method assumes that the user would be passing the subdomain to retrieve data from (www).
     * Unfortunately by allowing unvalidated input, a malicious user can provide a crafted string that
     * hijack the connection to a completely different URL, while disabling the developer-provided strings from the URL.
     * By adding an ? at the end of the user provided string, whatever string is concatenated in the application
     * will be passed to the URL connection as an url parameter and not as part of the destination URL
     * <p>
     * <p>
     *
     * @param subdomain the subdomain to access from http://[subdomain].example.com
     * @return HTML content to be rendered
     */
    @GetMapping("/get")
    @ResponseBody
    public ResponseEntity retrieveExampleCom(@RequestParam String subdomain) {

        StringBuilder accumulatedText = new StringBuilder();
        // Creating the complete domain path to connect to
        String vulnerableDomain = subdomain + ".example.com/";
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

    private boolean IsValidSubdomain(String subdomain)
    {
        ArrayList<String> validSubdomains = new ArrayList<>(Arrays.asList("www", "foo", "bar"));
        boolean isValidSubdomain = false;

        for (int idx = 0; idx < validSubdomains.size() && !isValidSubdomain; idx++) {
            if (subdomain.equals(validSubdomains.get(idx)))
                isValidSubdomain = true;
        }

        return isValidSubdomain;
    }
}