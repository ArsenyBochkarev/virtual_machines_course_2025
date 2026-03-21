package com.oracle.truffle.lama.nodes.pattern;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.runtime.LamaArray;
import com.oracle.truffle.lama.runtime.LamaSExp;
import com.oracle.truffle.lama.runtime.LamaFunctionObject;
import com.oracle.truffle.lama.runtime.LamaString;

public class LamaSharpPatternNode extends LamaPatternNode {
    public enum PatType {
        VAL, FUN, STR, ARRAY, SEXP, BOX
    }
    private final PatType expectedT;

    public LamaSharpPatternNode(PatType expectedShape) {
        this.expectedT = expectedShape;
    }

    @Override
    public boolean executeMatch(VirtualFrame frame, Object value) {
        if (value == null)
            return false;

        return switch (expectedT) {
            case VAL -> (value instanceof Long || value instanceof Integer);
            case STR -> (value instanceof LamaString);
            case FUN -> (value instanceof LamaFunctionObject);
            case ARRAY -> (value instanceof LamaArray);
            case SEXP -> (value instanceof LamaSExp);
            case BOX -> !(value instanceof Long || value instanceof Integer);
        };
    }
}
