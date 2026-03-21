package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaTypeException;
import com.oracle.truffle.lama.runtime.LamaString;

public class LamaStringPatternNode extends LamaPatternNode {
    private final LamaString content;

    public LamaStringPatternNode(String str) {
        this.content = new LamaString(str);
    }

    @Override
    public boolean executeMatch(VirtualFrame frame, Object value) {
        if (!(value instanceof LamaString))
            throw new LamaTypeException("Pattern expects String from value", value);
        return content.toString().equals(value.toString());
    }
}
