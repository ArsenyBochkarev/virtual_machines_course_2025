package com.oracle.truffle.lama.runtime;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.interop.InteropLibrary;
import com.oracle.truffle.api.interop.TruffleObject;
import com.oracle.truffle.api.library.ExportLibrary;

@ExportLibrary(InteropLibrary.class)
public final class LamaString implements TruffleObject {
    private String str;

    public LamaString(String value) {
        this.str = value;
    }

    @CompilerDirectives.TruffleBoundary
    public int length() {
        return str.length();
    }

    @CompilerDirectives.TruffleBoundary
    public long get(int index) {
        return str.charAt(index);
    }
    public void set(int index, long value) {
        StringBuilder sb = new StringBuilder(str);
        sb.setCharAt(index, (char)value);
        str = sb.toString();
    }

    public String toString() {
        return this.str;
    }
}