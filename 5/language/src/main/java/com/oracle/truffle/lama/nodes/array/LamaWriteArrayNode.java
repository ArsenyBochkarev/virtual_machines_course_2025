package com.oracle.truffle.lama.nodes.array;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.exception.LamaTypeException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;
import com.oracle.truffle.lama.runtime.LamaArray;
import com.oracle.truffle.lama.runtime.LamaString;

public final class LamaWriteArrayNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode arrayNode;
    @Child
    private LamaExpressionNode indexNode;
    @Child
    private LamaExpressionNode valueNode;

    public LamaWriteArrayNode(LamaExpressionNode arrayNode, LamaExpressionNode indexNode, LamaExpressionNode valueNode) {
        this.arrayNode = arrayNode;
        this.indexNode = indexNode;
        this.valueNode = valueNode;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object array = arrayNode.executeGeneric(frame);
        Object indexObj = indexNode.executeGeneric(frame);
        Object valueObj = valueNode.executeGeneric(frame);
        if (!(indexObj instanceof Long)) {
            throw new LamaTypeException("Index must be an integer", indexObj);
        }
        long index = (Long) indexObj;
        if (!(valueObj instanceof Long)) {
            throw new LamaTypeException("Value must be an integer (character code)", valueObj);
        }
        long value = (Long) valueObj;
        if (array instanceof LamaString str) {
            if (index < 0 || index >= str.length()) {
                throw new LamaException("String index out of bounds: " + index, this);
            }
            str.set((int) index, value);
            return value;
        }
        if (array instanceof LamaArray arr) {
            if (index < 0 || index >= arr.length()) {
                throw new LamaException("Array index out of bounds: " + index, this);
            }
            arr.set((int) index, value);
            return value;
        }
        throw new LamaTypeException("Indexed assignment not supported for this type", array);
    }
}