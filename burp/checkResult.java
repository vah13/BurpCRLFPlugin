package burp;

public class checkResult {

    private boolean status;
    private String payload;
    private IHttpRequestResponse attack;
    private String priority;
    private String attackDetails;

    public boolean status() {
        return status;
    }

    public String getPayload() {
        return payload;
    }

    public IHttpRequestResponse getAttack() {
        return attack;
    }

    public String getPriority() {
        return priority;
    }

    public String getAttackDetails() { return attackDetails;}



    public checkResult(boolean status, String payload, IHttpRequestResponse attack, String priority, String attackDetails) {
        this.status = status;
        this.payload = payload;
        this.attack = attack;
        this.priority = priority;
        this.attackDetails = attackDetails;
    }

}
