package burp;

import java.net.URL;

class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;
    private String background;

    public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name,
                           String detail, String background, String severity, String confidence)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.confidence = confidence;
        this.background = background;
    }

    public URL getUrl()
    {
        return this.url;
    }

    public String getIssueName()
    {
        return this.name;
    }

    public int getIssueType()
    {
        return 0;
    }

    public String getSeverity()
    {
        return this.severity;
    }

    public String getConfidence()
    {
        return this.confidence;
    }

    public String getIssueBackground()
    {
        return this.background;
    }

    public String getRemediationBackground()
    {
        return null;
    }

    public String getIssueDetail()
    {
        return this.detail;
    }

    public String getRemediationDetail()
    {
        return null;
    }

    public IHttpRequestResponse[] getHttpMessages()
    {
        return this.httpMessages;
    }

    public IHttpService getHttpService()
    {
        return this.httpService;
    }
}