package com.oracle.truffle.lama.nodes.binop;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public final class LamaDivNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode left;
    @Child
    private LamaExpressionNode right;

    public LamaDivNode(LamaExpressionNode left, LamaExpressionNode right) {
        this.left = left;
        this.right = right;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object leftVal = left.executeGeneric(frame);
        Object rightVal = right.executeGeneric(frame);
        if (leftVal instanceof Long && rightVal instanceof Long) {
            long r = (long) rightVal;
            if (r == 0) {
                throw new LamaException("Division by zero", this);
            }
            return (long) leftVal / r;
        }
        throw new LamaException("Type error in division", this);
    }
}