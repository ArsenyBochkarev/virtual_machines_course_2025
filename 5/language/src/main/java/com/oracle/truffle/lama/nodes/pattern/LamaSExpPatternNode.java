package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.runtime.LamaSExp;

public class LamaSExpPatternNode extends LamaPatternNode {
    private final String expectedTag;
    @Children
    private final LamaPatternNode[] args;

    public LamaSExpPatternNode(String expectedTag, LamaPatternNode[] args) {
        this.expectedTag = expectedTag;
        this.args = args;
    }

    @Override
    public boolean executeMatch(VirtualFrame frame, Object value) {
        if (!(value instanceof LamaSExp sexpr)) return false;

        if (!expectedTag.equals(sexpr.constructor()))
            return false;
        if (args.length != sexpr.arguments().length)
            return false;

        for (int i = 0; i < args.length; i++) {
            if (!args[i].executeMatch(frame, sexpr.arguments()[i]))
                return false;
        }
        return true;
    }
}