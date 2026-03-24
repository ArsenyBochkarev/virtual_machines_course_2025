package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.ExplodeLoop;
import com.oracle.truffle.lama.exception.LamaTypeException;
import com.oracle.truffle.lama.runtime.LamaArray;

public final class LamaArrayPatternNode extends LamaPatternNode {
    @Children
    private final LamaPatternNode[] elementPatterns;

    public LamaArrayPatternNode(LamaPatternNode[] elementPatterns) {
        this.elementPatterns = elementPatterns;
    }

    @Override
    @ExplodeLoop
    public boolean executeMatch(VirtualFrame frame, Object value) {
        if (!(value instanceof LamaArray arr)) {
            throw new LamaTypeException("Pattern expects Array from value", value);
        }
        if (!check(arr))
            return false;
        for (int i = 0; i < elementPatterns.length; i++) {
            if (!elementPatterns[i].executeMatch(frame, arr.get(i))) {
                return false;
            }
        }
        return true;
    }

    @CompilerDirectives.TruffleBoundary
    public boolean check(LamaArray arr) {
        return arr.length() == elementPatterns.length;
    }
}