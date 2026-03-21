package com.oracle.truffle.lama.nodes.controlflow;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.UnexpectedResultException;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public class LamaWhileNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode condition;
    @Child
    private LamaExpressionNode body;

    public LamaWhileNode(LamaExpressionNode condition, LamaExpressionNode body) {
        this.condition = condition;
        this.body = body;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        while (checkCond(frame)) {
            body.executeGeneric(frame);
        }

        return 0L;
    }

    private boolean checkCond(VirtualFrame frame) {
        try {
            long value = condition.executeLong(frame);
            return value != 0;
        } catch (UnexpectedResultException e) {
            throw new LamaException("Unexpected error in while loop checkCond", null);
        }
    }
}