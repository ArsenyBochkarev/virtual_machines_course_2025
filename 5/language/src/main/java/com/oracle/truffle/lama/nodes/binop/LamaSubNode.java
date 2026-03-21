package com.oracle.truffle.lama.nodes.binop;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public final class LamaSubNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode left;
    @Child
    private LamaExpressionNode right;

    public LamaSubNode(LamaExpressionNode left, LamaExpressionNode right) {
        this.left = left;
        this.right = right;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object leftVal = left.executeGeneric(frame);
        Object rightVal = right.executeGeneric(frame);
        if (leftVal instanceof Long && rightVal instanceof Long) {
            return (long) leftVal - (long) rightVal;
        }
        throw new LamaException("Type error in subtraction", this);
    }
}