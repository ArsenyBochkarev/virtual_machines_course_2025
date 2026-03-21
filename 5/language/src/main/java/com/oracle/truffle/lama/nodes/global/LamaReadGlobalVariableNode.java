package com.oracle.truffle.lama.nodes.global;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;
import com.oracle.truffle.lama.runtime.LamaContext;

public final class LamaReadGlobalVariableNode extends LamaExpressionNode {
    private final String name;

    public LamaReadGlobalVariableNode(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        return LamaContext.get(this).getGlobal(name);
    }
}