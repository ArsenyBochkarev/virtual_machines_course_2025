package com.oracle.truffle.lama.nodes.controlflow;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.UnexpectedResultException;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public class LamaForLoopNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode init;
    @Child
    private LamaExpressionNode condition;
    @Child
    private LamaExpressionNode step;
    @Child
    private LamaExpressionNode body;

    public LamaForLoopNode(LamaExpressionNode i, LamaExpressionNode cond, LamaExpressionNode s, LamaExpressionNode b) {
        this.body = b;
        this.init = i;
        this.condition = cond;
        this.step = s;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        init.executeGeneric(frame);
        while(checkCond(frame)) {
            body.executeGeneric(frame);
            step.executeGeneric(frame);
        }
        return 0L;
    }

    private boolean checkCond(VirtualFrame frame) {
        try {
            long value = condition.executeLong(frame);
            return value != 0;
        } catch (UnexpectedResultException e) {
            throw new LamaException("Unexpected error in for loop checkCond", null);
        }
    }
}
