package com.oracle.truffle.lama.nodes.builtins;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.RootNode;
import com.oracle.truffle.lama.LamaLanguage;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.nodes.LamaRootNode;
import com.oracle.truffle.lama.runtime.LamaArray;
import com.oracle.truffle.lama.runtime.LamaSExp;
import com.oracle.truffle.lama.runtime.LamaString;

public final class LamaStringBuiltinRootNode extends RootNode {
    public LamaStringBuiltinRootNode(LamaLanguage language) {
        super(language);
    }

    @Override
    public Object execute(VirtualFrame frame) {
        Object[] args = frame.getArguments();
        if (args.length != 2) {
            throw new LamaException("string expects exactly two arguments: scope and argument itself", this);
        }
        Object arg = args[1];
        if (arg instanceof Long larg) {
            return new LamaString(Long.toString(larg));
        } else if (arg instanceof LamaString str) {
            return new LamaString("\"" + str.toString() + "\"");
        } else if (arg instanceof LamaArray array) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < array.length(); i++) {
                if (i > 0)
                    sb.append(", ");
                sb.append(array.get(i).toString());
            }
            sb.append("]");
            return new LamaString(sb.toString());
        } else if (arg instanceof LamaSExp sexp) {
            return new LamaString(sexp.toString());
        } else {
            return new LamaString(arg.toString());
        }
    }
}
