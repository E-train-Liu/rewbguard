package dk.brics.automaton;

public class RPattern implements Cloneable {
    public String pattern;
    public String flags;
    public String[] sources;

    public RPattern(String pattern, String flags, String[] sources) {
        this.pattern = pattern;
        this.flags = flags;
        this.sources = sources;
    }
    public RPattern(String pattern, String flags) {
        this(pattern, flags, null);
    }
    public RPattern(String pattern) {
        this(pattern, null, null);
    }
    public RPattern() {}

    @Override
    public RPattern clone() {
        try {
            return (RPattern) super.clone();
        } catch (CloneNotSupportedException error) {
            throw new InternalError("clone error even after implementing Cloneable", error);
        }
    }

    @Override
    public String toString() {
        return '/' + this.pattern + '/' + (this.flags != null ? this.flags : "");
    }
}
