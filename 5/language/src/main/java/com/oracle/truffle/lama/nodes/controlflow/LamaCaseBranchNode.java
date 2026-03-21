package com.oracle.truffle.lama.nodes.controlflow;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.Node;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;
import com.oracle.truffle.lama.nodes.pattern.LamaPatternNode;

public class LamaCaseBranchNode extends Node {
    @Child
    private LamaPatternNode pattern;
    @Child
    private LamaExpressionNode body;

    public LamaCaseBranchNode(LamaPatternNode pattern, LamaExpressionNode body) {
        this.pattern = pattern;
        this.body = body;
    }

    public boolean executeMatch(VirtualFrame frame, Object value) {
        return pattern.executeMatch(frame, value);
    }

    public Object executeBody(VirtualFrame frame) {
        return body.executeGeneric(frame);
    }
}