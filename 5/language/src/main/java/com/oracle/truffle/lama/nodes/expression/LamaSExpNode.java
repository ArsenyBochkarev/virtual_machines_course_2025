package com.oracle.truffle.lama.nodes.expression;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.ExplodeLoop;
import com.oracle.truffle.lama.runtime.LamaSExp;

public class LamaSExpNode extends LamaExpressionNode {
    private final String constructor;
    @Children
    private final LamaExpressionNode[] args;

    public LamaSExpNode(String constructor, LamaExpressionNode[] args) {
        this.constructor = constructor;
        this.args = args;
    }

    @Override
    @ExplodeLoop
    public Object executeGeneric(VirtualFrame frame) {
        Object[] evaluatedArgs = new Object[args.length];
        for (int i = 0; i < args.length; i++) {
            evaluatedArgs[i] = args[i].executeGeneric(frame);
        }
        return new LamaSExp(constructor, evaluatedArgs);
    }
}
