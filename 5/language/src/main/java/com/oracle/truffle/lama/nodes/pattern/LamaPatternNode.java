package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public abstract class LamaPatternNode extends LamaExpressionNode {
    public abstract boolean executeMatch(VirtualFrame frame, Object value);

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        throw new UnsupportedOperationException("Patterns cannot be evaluated as normal expressions");
    }
}