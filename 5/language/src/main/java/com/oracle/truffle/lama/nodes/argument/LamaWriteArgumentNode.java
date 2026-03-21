package com.oracle.truffle.lama.nodes.argument;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public final class LamaWriteArgumentNode extends LamaExpressionNode {
    private final int index;
    @Child
    private LamaExpressionNode valueNode;

    public LamaWriteArgumentNode(int index, LamaExpressionNode valueNode) {
        this.index = index;
        this.valueNode = valueNode;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object value = valueNode.executeGeneric(frame);
        Object[] args = frame.getArguments();
        args[index] = value;
        return value;
    }
}