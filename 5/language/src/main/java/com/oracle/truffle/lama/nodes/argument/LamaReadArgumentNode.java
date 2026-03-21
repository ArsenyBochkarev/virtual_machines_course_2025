package com.oracle.truffle.lama.nodes.argument;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public final class LamaReadArgumentNode extends LamaExpressionNode {
    private final int index;

    public LamaReadArgumentNode(int index) {
        this.index = index;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object[] args = frame.getArguments();
        if (args == null || index < 0 || index >= args.length) {
            throw new LamaException("Argument index out of bounds: " + index, this);
        }
        return args[index];
    }

    @Override
    public long executeLong(VirtualFrame frame) {
        Object value = executeGeneric(frame);
        if (value instanceof Long) {
            return (Long) value;
        }
        throw new LamaException("Argument is not long", this);
    }

    public int getIndex() {
        return index;
    }
}