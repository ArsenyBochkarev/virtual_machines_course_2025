package com.oracle.truffle.lama.nodes.builtins;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.RootNode;
import com.oracle.truffle.lama.LamaLanguage;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.runtime.LamaContext;

public final class LamaWriteBuiltinRootNode extends RootNode {
    public LamaWriteBuiltinRootNode(LamaLanguage language) {
        super(language);
    }

    @Override
    public Object execute(VirtualFrame frame) {
        Object[] args = frame.getArguments();
        if (args.length != 2) {
            throw new LamaException("write expects exactly two arguments: scope and argument itself", this);
        }
        Object arg = args[1];
        LamaContext.get(this).getOutput().println(arg.toString());
        return 0;
    }
}