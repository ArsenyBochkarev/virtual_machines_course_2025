package com.oracle.truffle.lama.nodes.array;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.exception.LamaTypeException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;
import com.oracle.truffle.lama.runtime.LamaArray;
import com.oracle.truffle.lama.runtime.LamaSExp;
import com.oracle.truffle.lama.runtime.LamaString;

public final class LamaReadArrayNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode arrayNode;
    @Child
    private LamaExpressionNode indexNode;

    public LamaReadArrayNode(LamaExpressionNode arrayNode, LamaExpressionNode indexNode) {
        this.arrayNode = arrayNode;
        this.indexNode = indexNode;
    }

    public LamaExpressionNode getArrayNode() {
        return arrayNode;
    }

    public LamaExpressionNode getIndexNode() {
        return indexNode;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object array = arrayNode.executeGeneric(frame);
        Object indexObj = indexNode.executeGeneric(frame);
        if (!(indexObj instanceof Long)) {
            throw new LamaException("Index must be an integer", this);
        }
        long index = (Long) indexObj;
        if (array instanceof LamaString str) {
            if (index < 0 || index >= str.length()) {
                throw new LamaException("String index out of bounds: " + index, this);
            }
            return str.get((int) index);
        } else if (array instanceof LamaArray arr) {
            if (index < 0 || index >= arr.length()) {
                throw new LamaException("Array index out of bounds: " + index, this);
            }
            return arr.get((int) index);
        } else if (array instanceof LamaSExp sexp) {
            if (index < 0 || index >= sexp.arguments().length) {
                throw new LamaException("S-Expression index out of bounds: " + index, this);
            }
            return sexp.get((int)index);
        }
        throw new LamaTypeException("Indexing not supported for this type", array);
    }
}