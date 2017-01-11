package burp;

class ScannerMatch
        implements Comparable<ScannerMatch>
{
    private Integer start;
    private int end;
    private String match;
    private String type;

    public ScannerMatch(int start, int end, String match, String type)
    {
        this.start = Integer.valueOf(start);
        this.end = end;
        this.match = match;
        this.type = type;
    }

    public int getStart() {
        return this.start.intValue();
    }

    public int getEnd() {
        return this.end;
    }

    public String getMatch() {
        return this.match;
    }

    public String getType() {
        return this.type;
    }

    public int compareTo(ScannerMatch m)
    {
        return this.start.compareTo(Integer.valueOf(m.getStart()));
    }
}