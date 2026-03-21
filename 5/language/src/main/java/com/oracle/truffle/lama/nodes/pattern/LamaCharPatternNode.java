package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaTypeException;

public class LamaCharPatternNode extends LamaPatternNode {
    private final char content;

    public LamaCharPatternNode(char c) {
        this.content = c;
    }

    @Override
    public boolean executeMatch(VirtualFrame frame, Object value) {
        if (!(value instanceof Character))
            throw new LamaTypeException("Pattern expects Char from value", value);
        return content == (char)value;
    }
}
