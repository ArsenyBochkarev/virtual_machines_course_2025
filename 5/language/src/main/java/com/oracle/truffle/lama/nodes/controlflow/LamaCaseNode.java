package com.oracle.truffle.lama.nodes.controlflow;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

public class LamaCaseNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode scrutinee;
    @Children
    private final LamaCaseBranchNode[] branches;

    public LamaCaseNode(LamaExpressionNode scrutinee, LamaCaseBranchNode[] branches) {
        this.scrutinee = scrutinee;
        this.branches = branches;
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object value = scrutinee.executeGeneric(frame);

        for (LamaCaseBranchNode branch : branches) {
            if (branch.executeMatch(frame, value)) {
                return branch.executeBody(frame);
            }
        }
        return 0L;
    }
}