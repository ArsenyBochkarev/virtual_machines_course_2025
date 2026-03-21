package com.oracle.truffle.lama.nodes.unop;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public final class LamaUnaryMinusNode extends LamaExpressionNode {
    @Child private LamaExpressionNode operand;

    public LamaUnaryMinusNode(LamaExpressionNode operand) {
        this.operand = operand;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object value = operand.executeGeneric(frame);
        if (value instanceof Long) {
            return -(long) value;
        }
        throw new LamaException("Type error in unary minus", this);
    }
}