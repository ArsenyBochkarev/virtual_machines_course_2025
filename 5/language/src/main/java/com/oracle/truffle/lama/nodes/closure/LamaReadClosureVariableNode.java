package com.oracle.truffle.lama.nodes.closure;

import com.oracle.truffle.api.frame.MaterializedFrame;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.ExplodeLoop;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public class LamaReadClosureVariableNode extends LamaExpressionNode {
    private final int depth;
    private final int slot;

    public LamaReadClosureVariableNode(int d, int slot) {
        this.depth = d;
        this.slot = slot;
    }

    public int getDepth() {
        return depth;
    }
    public int getSlot() {
        return slot;
    }

    @Override
    @ExplodeLoop
    public Object executeGeneric(VirtualFrame frame) {
        // 0-indexed argument is a parent frame
        MaterializedFrame current = (MaterializedFrame) frame.getArguments()[0];
        for (int i = 1; i < depth; i++) {
            current = (MaterializedFrame) current.getArguments()[0];
        }
        return current.getValue(slot);
    }
}