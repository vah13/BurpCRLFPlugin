package burp;

import java.util.regex.Pattern;

class MatchRule
{
    private Pattern pattern;
    private Integer matchGroup;
    private String type;

    public MatchRule(Pattern pattern, Integer matchGroup, String type)
    {
        this.pattern = pattern;
        this.matchGroup = matchGroup;
        this.type = type;
    }

    public Pattern getPattern() {
        return this.pattern;
    }

    public Integer getMatchGroup() {
        return this.matchGroup;
    }

    public String getType() {
        return this.type;
    }
}