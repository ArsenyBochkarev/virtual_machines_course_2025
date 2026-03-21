package com.oracle.truffle.lama.nodes.global;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;
import com.oracle.truffle.lama.runtime.LamaContext;

public final class LamaWriteGlobalVariableNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode valueNode;
    private final String name;

    public LamaWriteGlobalVariableNode(String name, LamaExpressionNode valueNode) {
        this.name = name;
        this.valueNode = valueNode;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object value = valueNode.executeGeneric(frame);
        LamaContext.get(this).setGlobal(name, value);
        return value;
    }
}