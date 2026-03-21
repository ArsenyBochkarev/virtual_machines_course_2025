package com.oracle.truffle.lama.nodes.controlflow;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.UnexpectedResultException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public class LamaDoWhileNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode condition;
    @Child
    private LamaExpressionNode body;

    public LamaDoWhileNode(LamaExpressionNode condition, LamaExpressionNode body) {
        this.condition = condition;
        this.body = body;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        do {
            body.executeGeneric(frame);
        } while (checkCond(frame));

        return 0;
    }

    private boolean checkCond(VirtualFrame frame) {
        try {
            long value = condition.executeLong(frame);
            return value != 0;
        } catch (UnexpectedResultException e) {
            return false;
        }
    }
}