package com.oracle.truffle.lama.nodes.local;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.UnexpectedResultException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public final class LamaReadLocalVariableNode extends LamaExpressionNode {
    private final int slot;

    public LamaReadLocalVariableNode(int slot) {
        this.slot = slot;
    }

    public int getSlot() {
        return slot;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        return frame.getValue(slot);
    }

    @Override
    public long executeLong(VirtualFrame frame) throws UnexpectedResultException {
        Object value = frame.getValue(slot);
        if (value instanceof Long) {
            return (Long) value;
        }
        throw new UnexpectedResultException(value);
    }
}