package com.oracle.truffle.lama.nodes.expression;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.Node;
import com.oracle.truffle.api.nodes.UnexpectedResultException;
import com.oracle.truffle.lama.exception.LamaTypeException;
import com.oracle.truffle.lama.runtime.LamaContext;

public abstract class LamaExpressionNode extends Node {
    public abstract Object executeGeneric(VirtualFrame frame);

    public long executeLong(VirtualFrame frame) throws UnexpectedResultException {
        Object v = executeGeneric(frame);
        if (v instanceof Long sv)
            return sv;
        throw new LamaTypeException("Long expected", v);
    }
}
