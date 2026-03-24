package com.oracle.truffle.lama.runtime;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.interop.InteropLibrary;
import com.oracle.truffle.api.interop.TruffleObject;
import com.oracle.truffle.api.library.ExportLibrary;

import java.util.Arrays;
import java.util.stream.Collectors;

@ExportLibrary(InteropLibrary.class)
public record LamaSExp(String constructor, Object[] arguments) implements TruffleObject {
    @CompilerDirectives.TruffleBoundary
    public Object get(int index) {
        return arguments[index];
    }
    public void set(int index, Object value) {
        arguments[index] = value;
    }

    @Override
    @CompilerDirectives.TruffleBoundary
    public String toString() {
        if (arguments.length == 0) {
            return constructor;
        } else {
            String argsStr = Arrays.stream(arguments)
                    .map(Object::toString)
                    .collect(Collectors.joining(", "));
            return constructor + " (" + argsStr + ")";
        }
    }
}