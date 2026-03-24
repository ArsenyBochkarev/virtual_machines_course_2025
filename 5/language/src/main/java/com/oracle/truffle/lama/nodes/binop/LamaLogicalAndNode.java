package com.oracle.truffle.lama.nodes.binop;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.Node;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public class LamaLogicalAndNode extends LamaExpressionNode {
    @Node.Child
    private LamaExpressionNode left;
    @Node.Child
    private LamaExpressionNode right;

    public LamaLogicalAndNode(LamaExpressionNode left, LamaExpressionNode right) {
        this.left = left;
        this.right = right;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object leftVal = left.executeGeneric(frame);
        Object rightVal = right.executeGeneric(frame);
        if (isTrue(leftVal) && isTrue(rightVal))
            return 1L;
        return 0L;
    }

    @CompilerDirectives.TruffleBoundary
    private static boolean isTrue(Object value) {
        if (value instanceof Long) {
            return (Long) value != 0;
        }
        throw new LamaException("Condition must be an integer", null);
    }
}
