package com.oracle.truffle.lama.runtime;

import com.oracle.truffle.api.CallTarget;
import com.oracle.truffle.api.frame.MaterializedFrame;
import com.oracle.truffle.api.interop.InteropLibrary;
import com.oracle.truffle.api.interop.TruffleObject;
import com.oracle.truffle.api.library.ExportLibrary;
import com.oracle.truffle.api.library.ExportMessage;
import com.oracle.truffle.lama.exception.LamaException;

@ExportLibrary(InteropLibrary.class)
public final class LamaFunctionObject implements TruffleObject {
    public final CallTarget callTarget;
    private final int arity;
    public final MaterializedFrame capturedScope;

    public LamaFunctionObject(CallTarget callTarget, int arity, MaterializedFrame sc) {
        this.callTarget = callTarget;
        this.arity = arity;
        this.capturedScope = sc;
    }

    @ExportMessage
    boolean isExecutable() {
        return true;
    }

    @ExportMessage
    Object execute(Object[] arguments) {
        if (arguments.length != arity) {
            throw new LamaException("Function expects " + arity + " arguments, but got " + arguments.length, null);
        }
        return callTarget.call(arguments);
    }
}