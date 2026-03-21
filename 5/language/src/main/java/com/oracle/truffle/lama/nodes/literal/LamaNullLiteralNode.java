package com.oracle.truffle.lama.nodes.literal;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public final class LamaNullLiteralNode extends LamaExpressionNode {
    @Override
    public Object executeGeneric(VirtualFrame frame) {
        return 0L;
    }
}