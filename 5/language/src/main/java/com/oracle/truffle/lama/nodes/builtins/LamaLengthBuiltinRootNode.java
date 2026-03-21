package com.oracle.truffle.lama.nodes.builtins;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.RootNode;
import com.oracle.truffle.lama.LamaLanguage;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.exception.LamaTypeException;
import com.oracle.truffle.lama.runtime.LamaArray;
import com.oracle.truffle.lama.runtime.LamaSExp;
import com.oracle.truffle.lama.runtime.LamaString;

public class LamaLengthBuiltinRootNode extends RootNode {
    public LamaLengthBuiltinRootNode(LamaLanguage language) {
        super(language);
    }

    @Override
    public Object execute(VirtualFrame frame) {
        Object[] args = frame.getArguments();
        if (args.length != 2) {
            throw new LamaException("length expects exactly two arguments: scope and argument itself", this);
        }
        Object arg = args[1];
        if (arg instanceof LamaString str) {
            return (long) str.length();
        } else if (arg instanceof LamaArray arr) {
            return (long) arr.length();
        } else if (arg instanceof LamaSExp sexp) {
            return (long) sexp.arguments().length;
        }
        throw new LamaTypeException("length argument must be a string, array or s-exp", arg);
    }
}
