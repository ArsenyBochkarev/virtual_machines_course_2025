package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaTypeException;

public class LamaBoolPatternNode extends LamaPatternNode {
    private final Boolean content;

    public LamaBoolPatternNode(Boolean b) {
        this.content = b;
    }

    @Override
    public boolean executeMatch(VirtualFrame frame, Object value) {
        if (value instanceof Boolean b)
            return content.equals(b);
        if (value instanceof Long l)
            return (content.equals(Boolean.FALSE) && l.equals(0L)) || (content.equals(Boolean.TRUE) && l.equals(1L));
        throw new LamaTypeException("Pattern expects Bool or Long from value", value);
    }
}
