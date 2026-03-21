package com.oracle.truffle.lama.exception;

import org.antlr.v4.runtime.ParserRuleContext;

public class LamaParsingException extends LamaException {
    public LamaParsingException(String message) {
        super(message);
    }

    public LamaParsingException(String message, ParserRuleContext ctx) {
        super(formatMessage(message, ctx));
    }

    private static String formatMessage(String message, ParserRuleContext ctx) {
        if (ctx == null)
            return message;
        int line = ctx.getStart().getLine();
        int col = ctx.getStart().getCharPositionInLine();
        return message + " at line " + line + ":" + col;
    }
}