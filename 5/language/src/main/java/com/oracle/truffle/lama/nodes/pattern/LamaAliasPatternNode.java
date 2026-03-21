package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.frame.VirtualFrame;

public class LamaAliasPatternNode extends LamaPatternNode {
    private final int slot;
    @Child
    private LamaPatternNode innerPattern;

    public LamaAliasPatternNode(int slot, LamaPatternNode innerPattern) {
        this.slot = slot;
        this.innerPattern = innerPattern;
    }

    @Override
    public boolean executeMatch(VirtualFrame frame, Object value) {
        if (innerPattern.executeMatch(frame, value)) {
            frame.setObject(slot, value);
            return true;
        }
        return false;
    }
}