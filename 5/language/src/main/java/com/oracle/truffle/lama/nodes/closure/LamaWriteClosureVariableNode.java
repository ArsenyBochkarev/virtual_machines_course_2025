package com.oracle.truffle.lama.nodes.closure;

import com.oracle.truffle.api.frame.MaterializedFrame;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.ExplodeLoop;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public class LamaWriteClosureVariableNode extends LamaExpressionNode {
    private final int depth;
    private final int slot;
    @Child
    private LamaExpressionNode valueNode;

    public LamaWriteClosureVariableNode(int d, int slot, LamaExpressionNode valueNode) {
        this.depth = d;
        this.slot = slot;
        this.valueNode = valueNode;
    }

    @Override
    @ExplodeLoop
    public Object executeGeneric(VirtualFrame frame) {
        Object value = valueNode.executeGeneric(frame);
        MaterializedFrame current = (MaterializedFrame) frame.getArguments()[0];
        for (int i = 1; i < depth; i++) {
            current = (MaterializedFrame) current.getArguments()[0];
        }
        current.setObject(slot, value);
        return value;
    }
}