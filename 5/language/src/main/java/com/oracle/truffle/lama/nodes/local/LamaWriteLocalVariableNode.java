package com.oracle.truffle.lama.nodes.local;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public final class LamaWriteLocalVariableNode extends LamaExpressionNode {
    private final int slot;
    @Child
    private LamaExpressionNode valueNode;

    public LamaWriteLocalVariableNode(int slot, LamaExpressionNode valueNode) {
        this.slot = slot;
        this.valueNode = valueNode;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object value = valueNode.executeGeneric(frame);
        frame.setObject(slot, value);
        return value;
    }
}