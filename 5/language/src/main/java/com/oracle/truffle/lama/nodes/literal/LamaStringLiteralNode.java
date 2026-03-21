package com.oracle.truffle.lama.nodes.literal;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;
import com.oracle.truffle.lama.runtime.LamaString;

public final class LamaStringLiteralNode extends LamaExpressionNode {
    private final LamaString value;

    public LamaStringLiteralNode(String value) {
        this.value = new LamaString(value);
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        return value;
    }
}