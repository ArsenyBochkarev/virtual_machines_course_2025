package com.oracle.truffle.lama.nodes.controlflow;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.ExplodeLoop;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public final class LamaSequenceNode extends LamaExpressionNode {
    @Children
    private final LamaExpressionNode[] expressions;

    public LamaSequenceNode(LamaExpressionNode[] expressions) {
        this.expressions = expressions;
    }

    @Override
    @ExplodeLoop
    public Object executeGeneric(VirtualFrame frame) {
        Object result = null;
        for (LamaExpressionNode expr : expressions) {
            result = expr.executeGeneric(frame);
        }
        return result;
    }

    public LamaExpressionNode[] getExpressions() {
        return expressions;
    }
}