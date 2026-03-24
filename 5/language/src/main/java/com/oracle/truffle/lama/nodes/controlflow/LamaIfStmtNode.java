package com.oracle.truffle.lama.nodes.controlflow;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.ExplodeLoop;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.exception.LamaTypeException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;

import java.util.List;

public final class LamaIfStmtNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode conditionNode;
    @Child
    private LamaExpressionNode thenNode;
    @Children
    private final LamaExpressionNode[] elifConditions;
    @Children
    private final LamaExpressionNode[] elifBodies;
    @Child
    private LamaExpressionNode elseNode;

    public LamaIfStmtNode(LamaExpressionNode conditionNode, LamaExpressionNode thenNode,
                      List<LamaExpressionNode> elifConditions,
                      List<LamaExpressionNode> elifBodies,
                      LamaExpressionNode elseNode) {
        this.conditionNode = conditionNode;
        this.thenNode = thenNode;
        this.elifConditions = elifConditions.toArray(new LamaExpressionNode[0]);
        this.elifBodies = elifBodies.toArray(new LamaExpressionNode[0]);
        this.elseNode = elseNode;
    }

    @Override
    @ExplodeLoop
    public Object executeGeneric(VirtualFrame frame) {
        if (isTrue(conditionNode.executeGeneric(frame))) {
            return thenNode.executeGeneric(frame);
        }
        for (int i = 0; i < elifConditions.length; i++) {
            if (isTrue(elifConditions[i].executeGeneric(frame))) {
                return elifBodies[i].executeGeneric(frame);
            }
        }
        if (elseNode != null) {
            return elseNode.executeGeneric(frame);
        }
        return null; // No branch was accessed
    }

    @CompilerDirectives.TruffleBoundary
    private static boolean isTrue(Object value) {
        if (value instanceof Long) {
            return (Long) value != 0;
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        throw new LamaTypeException("Condition must be a Long or Boolean", value);
    }

    public LamaExpressionNode getThenNode() {
        return thenNode;
    }

    public LamaExpressionNode getElseNode() {
        return elseNode;
    }

    public LamaExpressionNode getCond() {
        return conditionNode;
    }

    public LamaExpressionNode[] getElifConds() {
        return elifConditions;
    }

    public LamaExpressionNode[] getElifBodies() {
        return elifBodies;
    }
}
