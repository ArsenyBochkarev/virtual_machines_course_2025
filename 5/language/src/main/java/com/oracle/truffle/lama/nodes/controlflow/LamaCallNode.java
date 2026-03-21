package com.oracle.truffle.lama.nodes.controlflow;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.exception.LamaTypeException;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;
import com.oracle.truffle.lama.runtime.LamaFunctionObject;
import java.util.List;

public final class LamaCallNode extends LamaExpressionNode {
    @Child
    private LamaExpressionNode functionNode;
    @Children
    private final LamaExpressionNode[] argumentNodes;

    public LamaCallNode(LamaExpressionNode functionNode, List<LamaExpressionNode> args) {
        this.functionNode = functionNode;
        this.argumentNodes = args.toArray(new LamaExpressionNode[0]);
    }

    @Override
    public Object executeGeneric(VirtualFrame frame) {
        Object function = functionNode.executeGeneric(frame);
        if (!(function instanceof LamaFunctionObject funcObj)) {
            throw new LamaTypeException("Object not a function", function);
        }

        // We put funcObj scope as 0-indexed argument
        Object[] arguments = new Object[argumentNodes.length + 1];
        arguments[0] = funcObj.capturedScope;

        for (int i = 0; i < argumentNodes.length; i++) {
            arguments[i + 1] = argumentNodes[i].executeGeneric(frame);
        }
        return funcObj.callTarget.call(arguments);
    }
}