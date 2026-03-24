package com.oracle.truffle.lama.runtime;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.interop.InteropLibrary;
import com.oracle.truffle.api.interop.TruffleObject;
import com.oracle.truffle.api.library.ExportLibrary;

@ExportLibrary(InteropLibrary.class)
public final class LamaArray implements TruffleObject {
    private final Object[] elements;

    public LamaArray(int size) {
        this.elements = new Object[size];
    }

    public LamaArray(Object[] elements) {
        this.elements = elements;
    }

    @CompilerDirectives.TruffleBoundary
    public int length() {
        return elements.length;
    }

    @CompilerDirectives.TruffleBoundary
    public Object get(int index) {
        return elements[index];
    }
    public void set(int index, Object value) {
        elements[index] = value;
    }
    public Object[] getElements() {
        return elements;
    }
}