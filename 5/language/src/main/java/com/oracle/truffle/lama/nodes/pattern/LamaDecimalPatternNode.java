package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaTypeException;

public class LamaDecimalPatternNode extends LamaPatternNode {
    private final Long constant;

    public LamaDecimalPatternNode(Long constant) {
        this.constant = constant;
    }

    @Override
    public boolean executeMatch(VirtualFrame frame, Object value) {
        if (!(value instanceof Long))
            throw new LamaTypeException("Pattern expects Long from value", value);
        return constant.equals(value);
    }
}
