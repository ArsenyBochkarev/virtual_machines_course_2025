package com.oracle.truffle.lama.nodes.literal;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;
import com.oracle.truffle.lama.runtime.LamaArray;

public final class LamaArrayLiteralNode extends LamaExpressionNode {
    @Children
    private final LamaExpressionNode[] elementNodes;

    public LamaArrayLiteralNode(LamaExpressionNode[] elementNodes) {
        this.elementNodes = elementNodes;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object[] elements = new Object[elementNodes.length];
        for (int i = 0; i < elementNodes.length; i++) {
            elements[i] = elementNodes[i].executeGeneric(frame);
        }
        return new LamaArray(elements);
    }
}