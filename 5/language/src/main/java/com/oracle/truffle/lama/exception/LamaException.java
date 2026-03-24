package com.oracle.truffle.lama.exception;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.exception.AbstractTruffleException;
import com.oracle.truffle.api.nodes.Node;

import java.io.Serial;

public class LamaException extends AbstractTruffleException {

    @Serial
    private static final long serialVersionUID = 1L;

    @CompilerDirectives.TruffleBoundary
    public LamaException(String message, Node location) {
        super(message, location);
    }

    @CompilerDirectives.TruffleBoundary
    public LamaException(String message, Throwable cause, Node location) {
        super(message, cause, UNLIMITED_STACK_TRACE, location);
    }

    @CompilerDirectives.TruffleBoundary
    public LamaException(String message) {
        super(message);
    }
}