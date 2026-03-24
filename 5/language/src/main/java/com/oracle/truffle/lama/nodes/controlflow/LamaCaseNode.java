package com.oracle.truffle.lama.nodes.controlflow;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.ExplodeLoop;
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
    @ExplodeLoop(kind = ExplodeLoop.LoopExplosionKind.FULL_UNROLL_UNTIL_RETURN)
    public Object executeGeneric(VirtualFrame frame) {
        Object value = scrutinee.executeGeneric(frame);

        for (int i = 0; i < branches.length; i++) {
            LamaCaseBranchNode branch = branches[i];
            if (branch.executeMatch(frame, value)) {
                return branch.executeBody(frame);
            }
        }
        return 0L;
    }
}