package com.oracle.truffle.lama.nodes.binop;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

import java.util.Objects;

public final class LamaAddNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode left;
    @Child
    private LamaExpressionNode right;

    public LamaAddNode(LamaExpressionNode left, LamaExpressionNode right) {
        this.left = left;
        this.right = right;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object leftVal = left.executeGeneric(frame);
        Object rightVal = right.executeGeneric(frame);
        if (leftVal instanceof Long lv && rightVal instanceof Long rv) {
            return calculateRes(lv, rv);
        }
        throw new LamaException("Type error in addition", this);
    }

    @CompilerDirectives.TruffleBoundary
    public Long calculateRes(Long leftVal, Long rightVal) {
        return leftVal + rightVal;
    }
}