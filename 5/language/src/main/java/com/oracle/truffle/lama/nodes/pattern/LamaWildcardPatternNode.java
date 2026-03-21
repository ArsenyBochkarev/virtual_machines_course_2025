package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.frame.VirtualFrame;

public class LamaWildcardPatternNode extends LamaPatternNode {
    @Override
    public boolean executeMatch(VirtualFrame frame, Object value) {
        return true;
    }
}
