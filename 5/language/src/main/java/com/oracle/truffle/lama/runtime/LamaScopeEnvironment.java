package com.oracle.truffle.lama.runtime;

import java.util.HashMap;
import java.util.Map;

// List for scopes
public class LamaScopeEnvironment {
    public final LamaScopeEnvironment parent;
    public final boolean isFunctionBoundary;
    public final Map<String, Integer> locals = new HashMap<>();

    public LamaScopeEnvironment(LamaScopeEnvironment parent, boolean isFunctionBoundary) {
        this.parent = parent;
        this.isFunctionBoundary = isFunctionBoundary;
    }

    // Pair of current scope's depth and slot
    public int[] resolve(String name) {
        LamaScopeEnvironment curr = this;
        int depth = 0;
        while (curr != null) {
            // Search in local slots
            if (curr.locals.containsKey(name)) {
                return new int[]{depth, curr.locals.get(name)};
            }
            if (curr.isFunctionBoundary) {
                depth++;
            }
            curr = curr.parent;
        }
        return null;
    }
}