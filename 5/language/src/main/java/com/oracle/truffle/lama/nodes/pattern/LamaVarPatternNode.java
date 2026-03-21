package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.frame.VirtualFrame;

public class LamaVarPatternNode extends LamaPatternNode {
    private final int slot;
    public LamaVarPatternNode(int slot) { this.slot = slot; }

    @Override
    public boolean executeMatch(VirtualFrame frame, Object value) {
        frame.setObject(slot, value);
        return true;
    }
}
