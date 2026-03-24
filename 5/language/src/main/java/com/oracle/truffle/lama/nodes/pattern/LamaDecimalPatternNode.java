package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaTypeException;
import com.oracle.truffle.lama.runtime.LamaSExp;

public class LamaDecimalPatternNode extends LamaPatternNode {
    private final Long constant;

    public LamaDecimalPatternNode(Long constant) {
        this.constant = constant;
    }

    @Override
    public boolean executeMatch(VirtualFrame frame, Object value) {
        if (!(value instanceof Long v))
            throw new LamaTypeException("Pattern expects Long from value", value);
        return check(v);
    }

    @CompilerDirectives.TruffleBoundary
    public boolean check(Long value) {
        return constant.equals(value);
    }
}
