package burp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender implements IBurpExtender, IScannerCheck, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;

    //CRLF variables
    private static final String CRLFHeader = "Burp-Verification-Header: ";
    private static final Pattern CRLFPattern = Pattern.compile("\\n\\s*" + CRLFHeader);
    private static final List<String> CRLFSplitters = new ArrayList<String>();
    private static String CRLFDescription = "";


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)  {
        this.callbacks = callbacks;

        this.helpers = callbacks.getHelpers();
        this.output = callbacks.getStdout();


        callbacks.setExtensionName("Burp CRLF plugin");
        callbacks.registerScannerCheck(BurpExtender.this);
        callbacks.registerHttpListener(BurpExtender.this);
        println("Burp CRLF plugin");

        initCRLFSplitters();
        
        CRLFDescription = "HTTP response splitting occurs when:<br/><ul>" +
                "<li>Data enters a web application through an untrusted source, most frequently an HTTP request.</li>\n" +
                "<li>The data is included in an HTTP response header sent to a web user without being validated for malicious characters.</li></ul>\n" +
                "HTTP response splitting is a means to an end, not an end in itself. At its root, the attack is straightforward: \n" +
                "an attacker passes malicious data to a vulnerable application, and the application includes the data in an HTTP response header.<br/><br/>\n" +
                "To mount a successful exploit, the application must allow input that contains CR (carriage return, also given by %0d or \\r) \n" +
                "and LF (line feed, also given by %0a or \\n)characters into the header AND the underlying platform must be vulnerable to the injection\n" +
                "of such characters. These characters not only give attackers control of the remaining headers and body of the response the application intends"+
                "to send, but also allow them to create additional responses entirely under their control.<br/><br/>\n" +
                "The example below uses a Java example, but this issue has been fixed in virtually all modern Java EE application servers." +
                "If you are concerned about this risk, you should test on the platform of concern to see if the underlying platform allows for CR or LF characters"+
                "to be injected into headers. We suspect that, in general, this vulnerability has been fixed in most modern application servers, regardless of what language the code has been written in.";

    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        baseRequestResponse.getHttpService().getHost();
        List<IScanIssue> results = new ArrayList<IScanIssue>();
        checkResult res = doCRLF(baseRequestResponse, insertionPoint);
        if (res!=null)
        {
            IHttpRequestResponse attack = res.getAttack();
            results.add(new CustomScanIssue(attack.getHttpService(),
                    this.helpers.analyzeRequest(attack).getUrl(),
                    new IHttpRequestResponse[]{attack},
                    "HTTP Response Splitting",
                    "Vulnerability detected by <b>BurpCRLFPlugin</b> <br/><br/>" + res.getAttackDetails(),
                    CRLFDescription, res.getPriority(), "Firm"));
        }

       
        return results;
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse){
        return null;
    }


    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        return 0;
    }


    public checkResult doCRLF(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint){

        String uuid = UUID.randomUUID().toString().replaceAll("-", "");

        IHttpService httpService = baseRequestResponse.getHttpService();
        IHttpRequestResponse checkUUID = this.callbacks.makeHttpRequest(httpService,
                insertionPoint.buildRequest(this.helpers.stringToBytes(uuid)));

        String respHeaders = String.join("\n", this.helpers.analyzeResponse(checkUUID.getResponse()).getHeaders());


        if (respHeaders.contains(uuid)) {
            for (String payload: CRLFSplitters) {
                String finalPayload = new StringBuffer().append(uuid.substring(0,5))
                        .append(payload)
                        .append(CRLFHeader)
                        .append(uuid.substring(6))
                        .toString();

                IHttpRequestResponse attack = this.callbacks.makeHttpRequest(httpService,
                        insertionPoint.buildRequest(this.helpers.stringToBytes(finalPayload)));

                String respAttackHeaders = String.join("\n",this.helpers.analyzeResponse(attack.getResponse()).getHeaders());

                Matcher m = CRLFPattern.matcher(respAttackHeaders);

                if (m.find() ){
                    String body = this.helpers.bytesToString(attack.getResponse());

                    List requestMarkers = new ArrayList(1);
                    requestMarkers.add(insertionPoint.getPayloadOffsets(this.helpers.stringToBytes(finalPayload)));
                    List responseMarkers = new ArrayList(1);
                    //println(Integer.toString(body.indexOf(CRLFHeader)));
                    //println(Integer.toString(body.indexOf(CRLFHeader)+CRLFHeader.length()));
                    responseMarkers.add(new int[]{body.indexOf(CRLFHeader), body.indexOf(CRLFHeader)+CRLFHeader.length() });


                    String attackDetails = "Vulnerability detected at <b>" + insertionPoint.getInsertionPointName() + "</b>, " +
                            "payload was set to <b>" + this.helpers.urlEncode(finalPayload) + "</b><br/>" +
                            "Found response: " + m.group();
                    return new checkResult(true,
                            finalPayload,
                            this.callbacks.applyMarkers(attack,requestMarkers,responseMarkers),
                            "High",
                            attackDetails);
                }
            }
        }
        return null;
    }


    public void initCRLFSplitters()
    {
        byte[] CDRIVES = new byte[] {(byte)0xE5, (byte)0x98, (byte)0x8A, (byte)0xE5, (byte)0x98, (byte)0x8D, };
        CRLFSplitters.add(this.helpers.bytesToString(CDRIVES));
        CRLFSplitters.add("\r\n");
        CRLFSplitters.add("\r ");
        CRLFSplitters.add("\r\t");
        CRLFSplitters.add("\r\n ");
        CRLFSplitters.add("\r\n\t");
        CRLFSplitters.add("\r\n\t");

        CRLFSplitters.add("%0d");
        CRLFSplitters.add("%0a");
        CRLFSplitters.add("%0d%0a");
        CRLFSplitters.add("%0d%0a%09");
        CRLFSplitters.add("%0d+");
        CRLFSplitters.add("%0d%20");
        CRLFSplitters.add("%0d%0a+");
        CRLFSplitters.add("%E5%98%8A%E5%98%8D");
        CRLFSplitters.add("%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D");
    }


    private void println(String toPrint) {
        try {
            this.output.write(toPrint.getBytes());
            this.output.write("\n".getBytes());
            this.output.flush();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		// TODO Auto-generated method stub
		
	}
}
