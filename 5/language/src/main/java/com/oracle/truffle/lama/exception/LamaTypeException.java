package com.oracle.truffle.lama.exception;

import org.antlr.v4.runtime.ParserRuleContext;

public class LamaTypeException extends LamaException {
    public LamaTypeException(String message) {
        super(message);
    }

    public LamaTypeException(String message, Object obj) {
        super(formatMessage(message, obj));
    }

    private static String formatMessage(String message, Object obj) {
        return message + ", type: " + obj.getClass().getName();
    }
}