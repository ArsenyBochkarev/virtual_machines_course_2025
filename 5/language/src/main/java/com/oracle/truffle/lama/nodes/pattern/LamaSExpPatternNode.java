package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.ExplodeLoop;
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
    @ExplodeLoop
    public boolean executeMatch(VirtualFrame frame, Object value) {
        if (!(value instanceof LamaSExp sexpr)) return false;

        if (!check(sexpr))
            return false;

        for (int i = 0; i < args.length; i++) {
            if (!args[i].executeMatch(frame, sexpr.arguments()[i]))
                return false;
        }
        return true;
    }

    @CompilerDirectives.TruffleBoundary
    public boolean check(LamaSExp sexpr) {
        if (!expectedTag.equals(sexpr.constructor()))
            return false;
        return args.length == sexpr.arguments().length;
    }
}