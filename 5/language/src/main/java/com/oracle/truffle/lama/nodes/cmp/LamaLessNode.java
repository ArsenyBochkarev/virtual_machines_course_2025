package com.oracle.truffle.lama.nodes.cmp;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public final class LamaLessNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode left;
    @Child
    private LamaExpressionNode right;

    public LamaLessNode(LamaExpressionNode left, LamaExpressionNode right) {
        this.left = left;
        this.right = right;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object leftVal = left.executeGeneric(frame);
        Object rightVal = right.executeGeneric(frame);
        if (leftVal instanceof Long && rightVal instanceof Long) {
            return (long) leftVal < (long) rightVal ? 1L : 0L;
        }
        throw new LamaException("Type error in comparison", this);
    }

    @CompilerDirectives.TruffleBoundary
    public Object calculateRes(Long leftVal, Long rightVal) {
        return leftVal < rightVal ? 1L : 0L;
    }
}