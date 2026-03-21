package com.oracle.truffle.lama;

import com.oracle.truffle.api.CallTarget;
import com.oracle.truffle.api.TruffleLanguage;
import com.oracle.truffle.api.frame.FrameDescriptor;
import com.oracle.truffle.lama.nodes.LamaRootNode;
import com.oracle.truffle.lama.parser.LamaCustomParser;
import com.oracle.truffle.lama.runtime.LamaContext;
import org.antlr.v4.runtime.CharStreams;

@TruffleLanguage.Registration(id = "lama", name = "Lama")
public final class LamaLanguage extends TruffleLanguage<LamaContext> {
    @Override
    protected CallTarget parse(ParsingRequest request) throws Exception {
        FrameDescriptor.Builder builder = FrameDescriptor.newBuilder();
        LamaCustomParser visitor = new LamaCustomParser(this, builder);
        LamaRootNode rootNode = visitor.parse(this, CharStreams.fromReader(request.getSource().getReader()));
        return rootNode.getCallTarget();
    }

    @Override
    protected LamaContext createContext(Env env) {
        return new LamaContext(env);
    }
}
