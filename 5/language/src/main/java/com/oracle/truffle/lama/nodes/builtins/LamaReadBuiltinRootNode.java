package com.oracle.truffle.lama.nodes.builtins;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.RootNode;
import com.oracle.truffle.lama.LamaLanguage;
import com.oracle.truffle.lama.exception.LamaException;
import com.oracle.truffle.lama.runtime.LamaContext;

import java.io.BufferedReader;
import java.io.IOException;

public class LamaReadBuiltinRootNode extends RootNode {
    private final BufferedReader reader;

    public LamaReadBuiltinRootNode(LamaLanguage language) {
        super(language);
        this.reader = LamaContext.get(this).getInput();
    }

    @Override
    public Object execute(VirtualFrame frame) {
        String line = null;
        try {
            LamaContext.get(this).getOutput().print("> ");
            line = reader.readLine();
        } catch (IOException e) {
            throw new LamaException("Error reading from input: " + e.getMessage(), this);
        }
        if (line == null) {
            return 0L;
        }
        return Long.parseLong(line.trim());
    }
}