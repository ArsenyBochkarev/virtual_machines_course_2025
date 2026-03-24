package com.oracle.truffle.lama.exception;

import com.oracle.truffle.api.CompilerDirectives;
import org.antlr.v4.runtime.ParserRuleContext;

public class LamaTypeException extends LamaException {
    @CompilerDirectives.TruffleBoundary
    public LamaTypeException(String message) {
        super(message);
    }

    @CompilerDirectives.TruffleBoundary
    public LamaTypeException(String message, Object obj) {
        super(formatMessage(message, obj));
    }

    private static String formatMessage(String message, Object obj) {
        return message + ", type: " + obj.getClass().getName();
    }
}