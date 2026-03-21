package com.oracle.truffle.lama.parser;

import com.oracle.truffle.api.CallTarget;
import com.oracle.truffle.api.frame.FrameDescriptor;
import com.oracle.truffle.api.frame.FrameSlotKind;
import com.oracle.truffle.lama.LamaLanguage;
import com.oracle.truffle.lama.nodes.argument.LamaReadArgumentNode;
import com.oracle.truffle.lama.nodes.argument.LamaWriteArgumentNode;
import com.oracle.truffle.lama.nodes.array.LamaReadArrayNode;
import com.oracle.truffle.lama.nodes.array.LamaWriteArrayNode;
import com.oracle.truffle.lama.nodes.builtins.LamaLengthBuiltinRootNode;
import com.oracle.truffle.lama.nodes.builtins.LamaReadBuiltinRootNode;
import com.oracle.truffle.lama.nodes.builtins.LamaStringBuiltinRootNode;
import com.oracle.truffle.lama.nodes.builtins.LamaWriteBuiltinRootNode;
import com.oracle.truffle.lama.exception.LamaParsingException;
import com.oracle.truffle.lama.nodes.binop.*;
import com.oracle.truffle.lama.nodes.closure.LamaReadClosureVariableNode;
import com.oracle.truffle.lama.nodes.closure.LamaWriteClosureVariableNode;
import com.oracle.truffle.lama.nodes.cmp.*;
import com.oracle.truffle.lama.nodes.controlflow.*;
import com.oracle.truffle.lama.nodes.expression.LamaExpressionNode;
import com.oracle.truffle.lama.nodes.expression.LamaSExpNode;
import com.oracle.truffle.lama.nodes.global.LamaReadGlobalVariableNode;
import com.oracle.truffle.lama.nodes.global.LamaWriteGlobalVariableNode;
import com.oracle.truffle.lama.nodes.literal.*;
import com.oracle.truffle.lama.nodes.pattern.*;
import com.oracle.truffle.lama.nodes.local.LamaReadLocalVariableNode;
import com.oracle.truffle.lama.nodes.local.LamaWriteLocalVariableNode;
import com.oracle.truffle.lama.nodes.unop.LamaUnaryMinusNode;
import com.oracle.truffle.lama.runtime.LamaScopeEnvironment;
import org.antlr.v4.runtime.CharStream;
import com.oracle.truffle.lama.nodes.*;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;

import java.util.*;

public class LamaCustomParser extends LamaBaseVisitor<LamaExpressionNode>  {
    private final FrameDescriptor.Builder builder;
    private final LamaLanguage language;
    private LamaScopeEnvironment environment;
    private final Set<String> globalNames;

    public LamaCustomParser(LamaLanguage language, FrameDescriptor.Builder builder) {
        this.language = language;
        this.builder = builder;
        this.environment = new LamaScopeEnvironment(null, false);
        this.globalNames = new HashSet<>();
    }
    public LamaCustomParser(LamaLanguage language, FrameDescriptor.Builder builder, LamaScopeEnvironment parentEnv, Set<String> globalNames) {
        this.language = language;
        this.builder = builder;
        this.environment = new LamaScopeEnvironment(parentEnv, true); // New function is a new function boundary
        this.globalNames = globalNames;
    }

    private LamaExpressionNode createBuiltinFunction(String name) {
        CallTarget target;
        int arity = switch (name) {
            case "write" -> {
                target = new LamaWriteBuiltinRootNode(language).getCallTarget();
                yield 1;
            }
            case "read" -> {
                target = new LamaReadBuiltinRootNode(language).getCallTarget();
                yield 0;
            }
            case "length" -> {
                target = new LamaLengthBuiltinRootNode(language).getCallTarget();
                yield 1;
            }
            case "string" -> {
                target = new LamaStringBuiltinRootNode(language).getCallTarget();
                yield 1;
            }
            default -> throw new LamaParsingException("Unknown builtin: " + name);
        };
        return new LamaFunctionLiteralNode(target, arity);
    }

    LamaParser parser;
    public LamaRootNode parse(LamaLanguage language, CharStream inputStream) {
        var lexer = new LamaLexer(inputStream);
        lexer.removeErrorListeners();

        String[] builtins = {"write", "read", "length", "string"};
        globalNames.addAll(Arrays.asList(builtins));

        parser = new LamaParser(new CommonTokenStream(lexer));
        parser.removeErrorListeners();
        parser.addErrorListener(new BaseErrorListener() {
            @Override
            public void syntaxError(Recognizer<?, ?> recognizer, Object offendingSymbol, int line, int charPositionInLine, String msg, RecognitionException e) {
                System.err.println("Syntax error at line " + line + ":" + charPositionInLine + " " + msg);
            }
        });
        LamaParser.ProgramContext context = parser.program();

        List<LamaExpressionNode> initNodes = new ArrayList<>();
        for (String name : builtins) {
            LamaExpressionNode builtinValue = createBuiltinFunction(name);
            initNodes.add(new LamaWriteGlobalVariableNode(name, builtinValue));
        }
        // Builtin inits should go before entryNode
        List<LamaExpressionNode> allNodes = new ArrayList<>(initNodes);

        LamaExpressionNode entryNode = parseTopScope(context.topScope(), language, builder);
        allNodes.add(entryNode);
        LamaExpressionNode finalNode = allNodes.size() == 1 ? allNodes.get(0) : new LamaSequenceNode(allNodes.toArray(new LamaExpressionNode[0]));
        return new LamaRootNode(language, builder.build(), finalNode);
    }

    private void declareVariable(String name) {
        if (environment.locals.containsKey(name)) {
            throw new LamaParsingException("Duplicate variable: " + name);
        }
        int slot = builder.addSlot(FrameSlotKind.Object, name, null);
        environment.locals.put(name, slot);
    }

    private LamaExpressionNode parseFunDefinition(LamaParser.FunDefinitionContext ctx) {
        List<LamaParser.PatternContext> patternCtxs = new ArrayList<>();
        if (ctx.patternList() != null)
            patternCtxs.addAll(ctx.patternList().pattern());
        int arity = patternCtxs.size();

        FrameDescriptor.Builder bodyBuilder = FrameDescriptor.newBuilder();
        LamaCustomParser bodyParser = new LamaCustomParser(this.language, bodyBuilder, this.environment, this.globalNames);

        List<LamaPatternNode> patternNodes = new ArrayList<>();
        for (LamaParser.PatternContext pCtx : patternCtxs) {
            patternNodes.add((LamaPatternNode) bodyParser.visit(pCtx));
        }

        LamaParser.ScopeExpressionContext bodyExprCtx = ctx.scopeExpression();
        LamaExpressionNode currentBody = bodyParser.visit(bodyExprCtx);

        // Desugaring patterns from function arguments
        for (int i = arity - 1; i >= 0; i--) {
            // 0-indexed element is scope
            LamaExpressionNode scrutinee = new LamaReadArgumentNode(i + 1);
            LamaCaseBranchNode branch = new LamaCaseBranchNode(patternNodes.get(i), currentBody);
            currentBody = new LamaCaseNode(scrutinee, new LamaCaseBranchNode[]{branch});
        }

        LamaRootNode functionRootNode = new LamaRootNode(language, bodyBuilder.build(), currentBody);
        return new LamaFunctionLiteralNode(functionRootNode.getCallTarget(), arity);
    }

    public LamaExpressionNode parseTopScope(LamaParser.TopScopeContext context, LamaLanguage language, FrameDescriptor.Builder builder) {
        LamaParser.ExpressionContext SEC = context.expression();
        List<LamaParser.DefinitionContext> defs = context.definition();

        for (LamaParser.DefinitionContext defCtx : defs) {
            if (defCtx.varDefinition() != null) {
                LamaParser.VarDefinitionContext varDefCtx = defCtx.varDefinition();
                for (LamaParser.VarInitContext varInitCtx : varDefCtx.varInit()) {
                    String name = varInitCtx.LIDENT().getText();
                    if (name.equals("_")) {
                        throw new LamaParsingException("_ is reserved and cannot be the name of a variable", varInitCtx);
                    }
                    globalNames.add(name); // All vars added at this level are global
                }
            } else if (defCtx.funDefinition() != null) {
                LamaParser.FunDefinitionContext funDefCtx = defCtx.funDefinition();
                String name = funDefCtx.LIDENT().getText();
                globalNames.add(name); // All vars added at this level are global
            } else {
                throw new LamaParsingException("Unsupported definition type", defCtx);
            }
        }

        // Collect variables' initializers
        List<LamaExpressionNode> initNodes = new ArrayList<>();
        for (LamaParser.DefinitionContext defCtx : defs) {
            if (defCtx.varDefinition() != null) {
                LamaParser.VarDefinitionContext varDefCtx = defCtx.varDefinition();
                for (LamaParser.VarInitContext varInitCtx : varDefCtx.varInit()) {
                    String name = varInitCtx.LIDENT().getText();
                    LamaParser.AssignExpressionContext initExprCtx = varInitCtx.assignExpression();
                    LamaExpressionNode valueNode = (initExprCtx != null) ? visit(initExprCtx) : new LamaNullLiteralNode();
                    initNodes.add(new LamaWriteGlobalVariableNode(name, valueNode));
                }
            } else if (defCtx.funDefinition() != null) {
                LamaParser.FunDefinitionContext funDefCtx = defCtx.funDefinition();
                String name = funDefCtx.LIDENT().getText();
                LamaExpressionNode funNode = parseFunDefinition(funDefCtx);
                initNodes.add(new LamaWriteGlobalVariableNode(name, funNode));
            }
        }

        LamaExpressionNode mainNode = SEC.accept(this);
        if (defs.isEmpty()) {
            return mainNode;
        }

        // Initialize all variables
        List<LamaExpressionNode> allNodes = new ArrayList<>(initNodes);
        if (mainNode != null) {
            allNodes.add(mainNode);
        }

        if (allNodes.size() == 1) {
            return allNodes.get(0);
        } else {
            return new LamaSequenceNode(allNodes.toArray(new LamaExpressionNode[0]));
        }
    }

    @Override
    public LamaExpressionNode visitScopeExpression(LamaParser.ScopeExpressionContext ctx) {
        var outerEnv = this.environment;

        try {
            this.environment = new LamaScopeEnvironment(outerEnv, false); // Block is not function boundary

            List<LamaParser.DefinitionContext> defs = ctx.definition();
            List<LamaExpressionNode> initNodes = new ArrayList<>();

            for (LamaParser.DefinitionContext defCtx : defs) {
                if (defCtx.varDefinition() != null) {
                    for (LamaParser.VarInitContext varInitCtx : defCtx.varDefinition().varInit()) {
                        String name = varInitCtx.LIDENT().getText();
                        if (name.equals("_")) {
                            throw new LamaParsingException("_ is reserved and cannot be the name of a variable", varInitCtx);
                        }
                        declareVariable(name);
                    }
                } else if (defCtx.funDefinition() != null) {
                    String name = defCtx.funDefinition().LIDENT().getText();
                    declareVariable(name);
                }
            }

            // init newly collected variables
            for (LamaParser.DefinitionContext defCtx : defs) {
                if (defCtx.varDefinition() != null) {
                    for (LamaParser.VarInitContext varInitCtx : defCtx.varDefinition().varInit()) {
                        String name = varInitCtx.LIDENT().getText();
                        int slot = environment.locals.get(name);

                        LamaParser.AssignExpressionContext initExprCtx = varInitCtx.assignExpression();
                        LamaExpressionNode valueNode = (initExprCtx != null) ? visit(initExprCtx) : new LamaNullLiteralNode();

                        initNodes.add(new LamaWriteLocalVariableNode(slot, valueNode));
                    }
                } else if (defCtx.funDefinition() != null) {
                    LamaParser.FunDefinitionContext funDefCtx = defCtx.funDefinition();
                    String name = funDefCtx.LIDENT().getText();
                    int slot = environment.locals.get(name);
                    LamaExpressionNode funNode = parseFunDefinition(funDefCtx);
                    initNodes.add(new LamaWriteLocalVariableNode(slot, funNode));
                }
            }

            LamaExpressionNode bodyNode = null;
            if (ctx.expression() != null) {
                bodyNode = visit(ctx.expression());
            }

            if (initNodes.isEmpty()) {
                return bodyNode != null ? bodyNode : new LamaNullLiteralNode();
            }

            if (bodyNode != null) {
                initNodes.add(bodyNode);
            }

            if (initNodes.size() == 1) {
                return initNodes.get(0);
            } else {
                return new LamaSequenceNode(initNodes.toArray(new LamaExpressionNode[0]));
            }
        } finally {
            this.environment = outerEnv;
        }
    }

    @Override
    public LamaExpressionNode visitExpression(LamaParser.ExpressionContext ctx) {
        return visit(ctx.sequenceExpression());
    }

    @Override
    public LamaExpressionNode visitSequenceExpression(LamaParser.SequenceExpressionContext ctx) {
        List<LamaParser.AssignExpressionContext> assignCtxs = ctx.assignExpression();
        if (assignCtxs.size() == 1) {
            return visit(assignCtxs.get(0));
        }
        List<LamaExpressionNode> exprs = new ArrayList<>();
        for (var assignCtx : assignCtxs) {
            exprs.add(visit(assignCtx));
        }
        return new LamaSequenceNode(exprs.toArray(new LamaExpressionNode[0]));
    }

    @Override
    public LamaExpressionNode visitAssignExpression(LamaParser.AssignExpressionContext ctx) {
        if (ctx.ASSIGN() == null) {
            return visit(ctx.consExpression());
        }
        LamaExpressionNode left = visit(ctx.consExpression());
        LamaExpressionNode right = visit(ctx.assignExpression());

        return transformToAssignment(left, right, ctx);
    }

    @Override
    public LamaExpressionNode visitConsExpression(LamaParser.ConsExpressionContext ctx) {
        if (ctx.COLON() == null) {
            return visit(ctx.logicalOrExpression());
        }
        LamaExpressionNode head = visit(ctx.logicalOrExpression());
        LamaExpressionNode tail = visit(ctx.consExpression());

        // h : t -> Cons(h, t)
        return new LamaSExpNode("Cons", new LamaExpressionNode[]{head, tail});
    }

    private LamaExpressionNode transformToAssignment(LamaExpressionNode left, LamaExpressionNode right, LamaParser.AssignExpressionContext ctx) {
        if (left instanceof LamaReadLocalVariableNode llv) {
            return new LamaWriteLocalVariableNode(llv.getSlot(), right);
        } else if (left instanceof LamaReadClosureVariableNode cl) {
            return new LamaWriteClosureVariableNode(cl.getDepth(), cl.getSlot(), right);
        } else if (left instanceof LamaReadGlobalVariableNode lgv) {
            return new LamaWriteGlobalVariableNode(lgv.getName(), right);
        } else if (left instanceof LamaReadArrayNode arr) {
            return new LamaWriteArrayNode(arr.getArrayNode(), arr.getIndexNode(), right);
        } else if (left instanceof LamaReadArgumentNode arg) {
            return new LamaWriteArgumentNode(arg.getIndex(), right);
        } else if (left instanceof LamaSequenceNode seq) {
            // `(a; b) := c` transformed into `a; (b := c)`
            LamaExpressionNode[] exprs = seq.getExpressions();
            LamaExpressionNode[] newExprs = Arrays.copyOf(exprs, exprs.length);

            if (newExprs.length > 0) {
                newExprs[newExprs.length - 1] = transformToAssignment(newExprs[newExprs.length - 1], right, ctx);
            }
            return new LamaSequenceNode(newExprs);
        } else if (left instanceof LamaIfStmtNode ifNode) {
            // `if c then x else y fi := 10` transformed into `if c then x:=10 else y:=10 fi`
            LamaExpressionNode newThen = transformToAssignment(ifNode.getThenNode(), right, ctx);
            LamaExpressionNode newElse = transformToAssignment(ifNode.getElseNode(), right, ctx);

            return new LamaIfStmtNode(ifNode.getCond(), newThen, List.of(ifNode.getElifConds()), List.of(ifNode.getElifBodies()), newElse);
        }

        throw new LamaParsingException("Left side of assignment must be a reference. Found: " + left.getClass().getSimpleName(), ctx);
    }

    @Override
    public LamaExpressionNode visitLogicalOrExpression(LamaParser.LogicalOrExpressionContext ctx) {
        List<LamaParser.LogicalAndExpressionContext> andCtxs = ctx.logicalAndExpression();
        if (andCtxs.size() == 1) {
            return visit(andCtxs.get(0));
        }
        LamaExpressionNode result = visit(andCtxs.get(0));
        for (int i = 1; i < andCtxs.size(); i++) {
            result = new LamaLogicalOrNode(result, visit(andCtxs.get(i)));
        }
        return result;
    }

    @Override
    public LamaExpressionNode visitLogicalAndExpression(LamaParser.LogicalAndExpressionContext ctx) {
        List<LamaParser.EqualityExpressionContext> eqCtxs = ctx.equalityExpression();
        if (eqCtxs.size() == 1) {
            return visit(eqCtxs.get(0));
        }
        LamaExpressionNode result = visit(eqCtxs.get(0));
        for (int i = 1; i < eqCtxs.size(); i++) {
            result = new LamaLogicalAndNode(result, visit(eqCtxs.get(i)));
        }
        return result;
    }

    @Override
    public LamaExpressionNode visitAdditiveExpression(LamaParser.AdditiveExpressionContext ctx) {
        List<LamaParser.MultiplicativeExpressionContext> mulCtxs = ctx.multiplicativeExpression();
        if (mulCtxs.size() == 1) {
            return visit(mulCtxs.get(0));
        }
        LamaExpressionNode result = visit(mulCtxs.get(0));
        for (int i = 1; i < mulCtxs.size(); i++) {
            if (ctx.PLUS(i - 1) != null) {
                result = new LamaAddNode(result, visit(mulCtxs.get(i)));
            } else if (ctx.MINUS(i - 1) != null) {
                result = new LamaSubNode(result, visit(mulCtxs.get(i)));
            } else {
                throw new LamaParsingException("Expected + or -", ctx);
            }
        }
        return result;
    }

    @Override
    public LamaExpressionNode visitMultiplicativeExpression(LamaParser.MultiplicativeExpressionContext ctx) {
        List<LamaParser.PrefixExpressionContext> prefCtxs = ctx.prefixExpression();
        if (prefCtxs.size() == 1) {
            return visit(prefCtxs.get(0));
        }
        LamaExpressionNode result = visit(prefCtxs.get(0));
        for (int i = 1; i < prefCtxs.size(); i++) {
            if (ctx.MUL(i - 1) != null) {
                result = new LamaMulNode(result, visit(prefCtxs.get(i)));
            } else if (ctx.DIV(i - 1) != null) {
                result = new LamaDivNode(result, visit(prefCtxs.get(i)));
            } else if (ctx.MOD(i - 1) != null) {
                result = new LamaModNode(result, visit(prefCtxs.get(i)));
            } else {
                throw new LamaParsingException("Expected *, / or %", ctx);
            }
        }
        return result;
    }

    @Override
    public LamaExpressionNode visitPrefixExpression(LamaParser.PrefixExpressionContext ctx) {
        LamaExpressionNode result = visit(ctx.postfixExpression());
        if (ctx.MINUS() != null) {
            result = new LamaUnaryMinusNode(result);
        }
        return result;
    }

    @Override
    public LamaExpressionNode visitLitPrimary(LamaParser.LitPrimaryContext ctx) {
        return visit(ctx.literal());
    }

    @Override
    public LamaExpressionNode visitIdPrimary(LamaParser.IdPrimaryContext ctx) {
        return visit(ctx.identifier());
    }

    @Override
    public LamaExpressionNode visitParenPrimary(LamaParser.ParenPrimaryContext ctx) {
        return visit(ctx.scopeExpression());
    }

    @Override
    public LamaExpressionNode visitLoopPrimary(LamaParser.LoopPrimaryContext ctx) {
        var loopExprctx = ctx.loopExpression();
        if (loopExprctx.whileLoop() != null) {
            return visit(loopExprctx.whileLoop());
        } else if (loopExprctx.doWhileLoop() != null) {
            return visit(loopExprctx.doWhileLoop());
        } else if (loopExprctx.forLoop() != null) {
            return visit(loopExprctx.forLoop());
        }
        throw new LamaParsingException("Unknown loop type", ctx);
    }

    @Override
    public LamaExpressionNode visitBasePrimary(LamaParser.BasePrimaryContext ctx) {
        return visit(ctx.primary());
    }

    @Override
    public LamaExpressionNode visitCallSuffix(LamaParser.CallSuffixContext ctx) {
        LamaExpressionNode callee = visit(ctx.postfixExpression());
        List<LamaExpressionNode> args = new ArrayList<>();
        if (ctx.argumentList() != null) {
            for (LamaParser.ExpressionContext exprCtx : ctx.argumentList().expression()) {
                args.add(visit(exprCtx));
            }
        }
        return new LamaCallNode(callee, args);
    }

    @Override
    public LamaExpressionNode visitLiteral(LamaParser.LiteralContext ctx) {
        if (ctx.DECIMAL() != null) {
            long value = Long.parseLong(ctx.DECIMAL().getText());
            return new LamaIntLiteralNode(value);
        } else if (ctx.TRUE() != null) {
            return new LamaIntLiteralNode(1);
        } else if (ctx.FALSE() != null) {
            return new LamaIntLiteralNode(0);
        } else if (ctx.STRING() != null) {
            String text = ctx.STRING().getText();
            String content = text.substring(1, text.length() - 1).replace("\"\"", "\"");
            return new LamaStringLiteralNode(content);
        } else if (ctx.CHAR() != null) {
            String text = ctx.CHAR().getText();
            char ch = getCh(ctx, text);
            return new LamaCharLiteralNode(ch);
        }
        throw new LamaParsingException("Unsupported literal: " + ctx.getText(), ctx);
    }

    private static char getCh(LamaParser.LiteralContext ctx, String text) {
        String content = text.substring(1, text.length() - 1);
        char ch;
        if (content.startsWith("\\")) {
            ch = switch (content) {
                case "\\n" -> '\n';
                case "\\t" -> '\t';
                case "\\\\" -> '\\';
                case "\\'" -> '\'';
                default -> throw new LamaParsingException("Unsupported escape sequence: " + content, ctx);
            };
        } else {
            if (content.length() != 1) {
                throw new LamaParsingException("Invalid character literal: " + text, ctx);
            }
            ch = content.charAt(0);
        }
        return ch;
    }

    private static char getCh(LamaParser.CharPatternContext ctx, String text) {
        String content = text.substring(1, text.length() - 1);
        char ch;
        if (content.startsWith("\\")) {
            ch = switch (content) {
                case "\\n" -> '\n';
                case "\\t" -> '\t';
                case "\\\\" -> '\\';
                case "\\'" -> '\'';
                default -> throw new LamaParsingException("Unsupported escape sequence: " + content, ctx);
            };
        } else {
            if (content.length() != 1) {
                throw new LamaParsingException("Invalid character literal: " + text, ctx);
            }
            ch = content.charAt(0);
        }
        return ch;
    }

    @Override
    public LamaExpressionNode visitIdentifier(LamaParser.IdentifierContext ctx) {
        String name = (ctx.LIDENT() != null) ? ctx.LIDENT().getText() : ctx.UIDENT().getText();
        int[] resolved = environment.resolve(name);
        if (resolved != null) {
            int depth = resolved[0];
            int slot = resolved[1];
            if (depth == 0) {
                return new LamaReadLocalVariableNode(slot);
            } else {
                return new LamaReadClosureVariableNode(depth, slot);
            }
        }

        // Search in global variables
        if (globalNames.contains(name)) {
            return new LamaReadGlobalVariableNode(name);
        }

        throw new LamaParsingException("Undefined variable: " + name, ctx);
    }

    @Override
    public LamaExpressionNode visitEqualityExpression(LamaParser.EqualityExpressionContext ctx) {
        List<LamaParser.RelationalExpressionContext> relCtxs = ctx.relationalExpression();
        if (relCtxs.size() == 1) {
            return visit(relCtxs.get(0));
        }
        LamaExpressionNode result = visit(relCtxs.get(0));
        for (int i = 1; i < relCtxs.size(); i++) {
            if (ctx.EQ(i-1) != null) {
                result = new LamaEqualNode(result, visit(relCtxs.get(i)));
            } else if (ctx.NE(i-1) != null) {
                result = new LamaNotEqualNode(result, visit(relCtxs.get(i)));
            } else {
                throw new LamaParsingException("Expected == or !=", ctx);
            }
        }
        return result;
    }

    @Override
    public LamaExpressionNode visitRelationalExpression(LamaParser.RelationalExpressionContext ctx) {
        List<LamaParser.AdditiveExpressionContext> addCtxs = ctx.additiveExpression();
        if (addCtxs.size() == 1) {
            return visit(addCtxs.get(0));
        }
        LamaExpressionNode result = visit(addCtxs.get(0));
        for (int i = 1; i < addCtxs.size(); i++) {
            if (ctx.LT(i-1) != null) {
                result = new LamaLessNode(result, visit(addCtxs.get(i)));
            } else if (ctx.LE(i-1) != null) {
                result = new LamaLessEqualNode(result, visit(addCtxs.get(i)));
            } else if (ctx.GT(i-1) != null) {
                result = new LamaGreaterNode(result, visit(addCtxs.get(i)));
            } else if (ctx.GE(i-1) != null) {
                result = new LamaGreaterEqualNode(result, visit(addCtxs.get(i)));
            } else {
                throw new LamaParsingException("Expected relational operator", ctx);
            }
        }
        return result;
    }

    @Override
    public LamaExpressionNode visitWhileLoop(LamaParser.WhileLoopContext ctx) {
        LamaExpressionNode condition = visit(ctx.sequenceExpression());
        LamaExpressionNode body = visit(ctx.scopeExpression());
        return new LamaWhileNode(condition, body);
    }

    @Override
    public LamaExpressionNode visitDoWhileLoop(LamaParser.DoWhileLoopContext ctx) {
        // Same thing as for parsing regular scoped expressions, isolating do ... while scope
        var outerEnv = this.environment;
        try {
            LamaParser.ScopeExpressionContext scopeCtx = ctx.scopeExpression();
            List<LamaParser.DefinitionContext> defs = scopeCtx.definition();
            List<LamaExpressionNode> initNodes = new ArrayList<>();

            for (LamaParser.DefinitionContext defCtx : defs) {
                if (defCtx.varDefinition() != null) {
                    for (LamaParser.VarInitContext varInitCtx : defCtx.varDefinition().varInit()) {
                        String name = varInitCtx.LIDENT().getText();
                        int slot = builder.addSlot(FrameSlotKind.Object, name, null);
                        environment.locals.put(name, slot);
                    }
                } else if (defCtx.funDefinition() != null) {
                    String name = defCtx.funDefinition().LIDENT().getText();
                    int slot = builder.addSlot(FrameSlotKind.Object, name, null);
                    environment.locals.put(name, slot);
                }
            }

            for (LamaParser.DefinitionContext defCtx : defs) {
                if (defCtx.varDefinition() != null) {
                    for (LamaParser.VarInitContext varInitCtx : defCtx.varDefinition().varInit()) {
                        String name = varInitCtx.LIDENT().getText();
                        int slot = environment.locals.get(name);
                        LamaParser.AssignExpressionContext initExprCtx = varInitCtx.assignExpression();
                        LamaExpressionNode valueNode = (initExprCtx != null) ? visit(initExprCtx) : new LamaNullLiteralNode();
                        initNodes.add(new LamaWriteLocalVariableNode(slot, valueNode));
                    }
                } else if (defCtx.funDefinition() != null) {
                    LamaParser.FunDefinitionContext funDefCtx = defCtx.funDefinition();
                    String name = funDefCtx.LIDENT().getText();
                    int slot = environment.locals.get(name);
                    LamaExpressionNode funNode = parseFunDefinition(funDefCtx);
                    initNodes.add(new LamaWriteLocalVariableNode(slot, funNode));
                }
            }

            LamaExpressionNode bodyExpr = null;
            if (scopeCtx.expression() != null) {
                bodyExpr = visit(scopeCtx.expression());
            }

            if (bodyExpr != null) {
                initNodes.add(bodyExpr);
            }

            LamaExpressionNode fullBody;
            if (initNodes.isEmpty()) {
                fullBody = new LamaNullLiteralNode();
            } else if (initNodes.size() == 1) {
                fullBody = initNodes.get(0);
            } else {
                fullBody = new LamaSequenceNode(initNodes.toArray(new LamaExpressionNode[0]));
            }
            LamaExpressionNode condition = visit(ctx.sequenceExpression());
            return new LamaDoWhileNode(condition, fullBody);

        } finally {
            this.environment = outerEnv;
        }
    }

    @Override
    public LamaExpressionNode visitSkipPrimary(LamaParser.SkipPrimaryContext ctx) {
        return new LamaNullLiteralNode();
    }

    @Override
    public LamaExpressionNode visitForLoop(LamaParser.ForLoopContext ctx) {
        // Same thing as for parsing regular scoped expressions, isolating do ... while scope
        LamaExpressionNode initNode = new LamaNullLiteralNode();

        // We need declared variables to be observable inside all the loop
        // So copying logic from visitScopeExpression here
        if (ctx.forInit() != null && ctx.forInit().scopeExpression() != null) {
            LamaParser.ScopeExpressionContext initScopeCtx = ctx.forInit().scopeExpression();
            List<LamaParser.DefinitionContext> defs = initScopeCtx.definition();
            List<LamaExpressionNode> initNodes = new ArrayList<>();

            for (LamaParser.DefinitionContext defCtx : defs) {
                if (defCtx.varDefinition() != null) {
                    for (LamaParser.VarInitContext varInitCtx : defCtx.varDefinition().varInit()) {
                        String name = varInitCtx.LIDENT().getText();
                        int slot = builder.addSlot(FrameSlotKind.Object, name, null);
                        environment.locals.put(name, slot);
                    }
                } else if (defCtx.funDefinition() != null) {
                    String name = defCtx.funDefinition().LIDENT().getText();
                    int slot = builder.addSlot(FrameSlotKind.Object, name, null);
                    environment.locals.put(name, slot);
                }
            }

            for (LamaParser.DefinitionContext defCtx : defs) {
                if (defCtx.varDefinition() != null) {
                    for (LamaParser.VarInitContext varInitCtx : defCtx.varDefinition().varInit()) {
                        String name = varInitCtx.LIDENT().getText();
                        int slot = environment.locals.get(name);
                        LamaParser.AssignExpressionContext assignCtx = varInitCtx.assignExpression();
                        LamaExpressionNode valueNode = (assignCtx != null) ? visit(assignCtx) : new LamaNullLiteralNode();
                        initNodes.add(new LamaWriteLocalVariableNode(slot, valueNode));
                    }
                } else if (defCtx.funDefinition() != null) {
                    LamaParser.FunDefinitionContext funDefCtx = defCtx.funDefinition();
                    String name = funDefCtx.LIDENT().getText();
                    int slot = environment.locals.get(name);
                    LamaExpressionNode funNode = parseFunDefinition(funDefCtx);
                    initNodes.add(new LamaWriteLocalVariableNode(slot, funNode));
                }
            }

            // initialization expression
            if (initScopeCtx.expression() != null) {
                initNodes.add(visit(initScopeCtx.expression()));
            }

            if (initNodes.isEmpty()) {
                initNode = new LamaNullLiteralNode();
            } else if (initNodes.size() == 1) {
                initNode = initNodes.get(0);
            } else {
                initNode = new LamaSequenceNode(initNodes.toArray(new LamaExpressionNode[0]));
            }
        }

        LamaExpressionNode condition = ctx.expression() != null
                ? visit(ctx.expression())
                : new LamaIntLiteralNode(1);
        LamaExpressionNode step = (ctx.forStep() != null && ctx.forStep().assignExpression() != null)
                ? visit(ctx.forStep().assignExpression())
                : new LamaNullLiteralNode();

        LamaExpressionNode body = visit(ctx.scopeExpression());
        return new LamaForLoopNode(initNode, condition, step, body);
    }

    @Override
    public LamaExpressionNode visitIfExpression(LamaParser.IfExpressionContext ctx) {
        List<LamaParser.ExpressionContext> exprs = ctx.expression();
        List<LamaParser.ScopeExpressionContext> bodies = ctx.scopeExpression();
        int numElif = ctx.ELIF().size();

        // First cond must exist
        LamaExpressionNode cond = visit(exprs.get(0));
        LamaExpressionNode thenPart = visit(bodies.get(0));

        List<LamaExpressionNode> elifConds = new ArrayList<>();
        List<LamaExpressionNode> elifBodies = new ArrayList<>();
        for (int i = 0; i < numElif; i++) {
            // Collect 'elif's, if any
            elifConds.add(visit(exprs.get(1 + i)));
            elifBodies.add(visit(bodies.get(1 + i)));
        }

        LamaExpressionNode elsePart = null;
        if (ctx.ELSE() != null) {
            elsePart = visit(bodies.get(bodies.size() - 1));
        }

        return new LamaIfStmtNode(cond, thenPart, elifConds, elifBodies, elsePart);
    }

    @Override
    public LamaExpressionNode visitDotSuffix(LamaParser.DotSuffixContext ctx) {
        // This will be transformed into LamaCallNode
        LamaExpressionNode receiver = visit(ctx.postfixExpression());
        String fieldName = ctx.LIDENT().getText();

        LamaExpressionNode funcNode;
        if (globalNames.contains(fieldName)) {
            funcNode = new LamaReadGlobalVariableNode(fieldName);
        } else if (environment.locals.containsKey(fieldName)) {
            funcNode = new LamaReadLocalVariableNode(environment.locals.get(fieldName));
        } else {
            throw new LamaParsingException("Undefined function for dot notation: " + fieldName, ctx);
        }

        List<LamaExpressionNode> args = new ArrayList<>();
        args.add(receiver);
        return new LamaCallNode(funcNode, args);
    }

    @Override
    public LamaExpressionNode visitIndexSuffix(LamaParser.IndexSuffixContext ctx) {
        LamaExpressionNode receiver = visit(ctx.postfixExpression());
        LamaExpressionNode index = visit(ctx.expression());
        return new LamaReadArrayNode(receiver, index);
    }

    @Override
    public LamaExpressionNode visitArrayPrimary(LamaParser.ArrayPrimaryContext ctx) {
        return visit(ctx.arrayLiteral());
    }

    @Override
    public LamaExpressionNode visitArrayLiteral(LamaParser.ArrayLiteralContext ctx) {
        List<LamaParser.ExpressionContext> exprs = ctx.expression();
        if (exprs.isEmpty()) {
            return new LamaArrayLiteralNode(new LamaExpressionNode[0]);
        }
        List<LamaExpressionNode> elements = new ArrayList<>();
        for (var e : exprs) {
            elements.add(visit(e));
        }
        return new LamaArrayLiteralNode(elements.toArray(new LamaExpressionNode[0]));
    }

    @Override
    public LamaExpressionNode visitSexpPrimary(LamaParser.SexpPrimaryContext ctx) {
        return visit(ctx.sexp());
    }

    @Override
    public LamaExpressionNode visitSexp(LamaParser.SexpContext ctx) {
        String name = ctx.UIDENT().getText();
        List<LamaExpressionNode> args = new ArrayList<>();
        if (ctx.expression() != null) {
            for (var exprCtx : ctx.expression()) {
                args.add(visit(exprCtx));
            }
        }
        return new LamaSExpNode(name, args.toArray(new LamaExpressionNode[0]));
    }

    @Override
    public LamaExpressionNode visitVarPattern(LamaParser.VarPatternContext ctx) {
        String name = ctx.LIDENT().getText();
        // No `declareVariable` here because we'll need slot value for var pattern constructor
        int slot = builder.addSlot(FrameSlotKind.Object, name, null);
        environment.locals.put(name, slot);
        return new LamaVarPatternNode(slot);
    }

    @Override
    public LamaExpressionNode visitSexpPatternWithArgs(LamaParser.SexpPatternWithArgsContext ctx) {
        String name = ctx.UIDENT().getText();
        List<LamaPatternNode> args = new ArrayList<>();
        if (ctx.patternList() != null) {
            for (var pCtx : ctx.patternList().pattern()) {
                args.add((LamaPatternNode) visit(pCtx));
            }
        }
        return new LamaSExpPatternNode(name, args.toArray(new LamaPatternNode[0]));
    }

    @Override
    public LamaExpressionNode visitSexpPatternNoArgs(LamaParser.SexpPatternNoArgsContext ctx) {
        return new LamaSExpPatternNode(ctx.UIDENT().getText(), new LamaPatternNode[0]);
    }

    @Override
    public LamaExpressionNode visitArrayPattern(LamaParser.ArrayPatternContext ctx) {
        List<LamaParser.PatternContext> patterns = ctx.patternList() != null ? ctx.patternList().pattern() : Collections.emptyList();
        List<LamaPatternNode> elementNodes = new ArrayList<>();
        for (var p : patterns) {
            LamaExpressionNode node = visit(p);
            if (!(node instanceof LamaPatternNode)) {
                throw new LamaParsingException("Expected pattern inside array pattern", p);
            }
            elementNodes.add((LamaPatternNode) node);
        }
        return new LamaArrayPatternNode(elementNodes.toArray(new LamaPatternNode[0]));
    }

    @Override
    public LamaExpressionNode visitListPattern(LamaParser.ListPatternContext ctx) {
        LamaPatternNode result = new LamaSExpPatternNode("Nil", new LamaPatternNode[0]);
        if (ctx.patternList() != null) {
            List<LamaParser.PatternContext> patterns = ctx.patternList().pattern();
            for (int i = patterns.size() - 1; i >= 0; i--) {
                LamaPatternNode head = (LamaPatternNode) visit(patterns.get(i));
                result = new LamaSExpPatternNode("Cons", new LamaPatternNode[]{head, result});
            }
        }
        return result;
    }

    @Override
    public LamaExpressionNode visitConsPattern(LamaParser.ConsPatternContext ctx) {
        LamaPatternNode head = (LamaPatternNode) visit(ctx.pattern(0));
        LamaPatternNode tail = (LamaPatternNode) visit(ctx.pattern(1));
        return new LamaSExpPatternNode("Cons", new LamaPatternNode[]{head, tail});
    }

    @Override
    public LamaExpressionNode visitWildcardPattern(LamaParser.WildcardPatternContext ctx) {
        return new LamaWildcardPatternNode();
    }

    @Override
    public LamaExpressionNode visitDecimalPattern(LamaParser.DecimalPatternContext ctx) {
        long value = Long.parseLong(ctx.DECIMAL().getText());
        return new LamaDecimalPatternNode(value);
    }

    @Override
    public LamaExpressionNode visitStringPattern(LamaParser.StringPatternContext ctx) {
        String text = ctx.STRING().getText();
        String content = text.substring(1, text.length() - 1).replace("\"\"", "\"");
        return new LamaStringPatternNode(content);
    }

    @Override
    public LamaExpressionNode visitCharPattern(LamaParser.CharPatternContext ctx) {
        String text = ctx.CHAR().getText();
        char ch = getCh(ctx, text);
        return new LamaCharPatternNode(ch);
    }

    @Override
    public LamaExpressionNode visitTruePattern(LamaParser.TruePatternContext ctx) {
        return new LamaBoolPatternNode(true);
    }

    @Override
    public LamaExpressionNode visitFalsePattern(LamaParser.FalsePatternContext ctx) {
        return new LamaBoolPatternNode(false);
    }

    @Override
    public LamaExpressionNode visitParenPattern(LamaParser.ParenPatternContext ctx) {
        return visit(ctx.pattern());
    }

    @Override
    public LamaExpressionNode visitCaseExpression(LamaParser.CaseExpressionContext ctx) {
        LamaExpressionNode scrutinee = visit(ctx.expression());
        List<LamaCaseBranchNode> branches = new ArrayList<>();

        for (var branchCtx : ctx.caseBranch()) {
            for (int i = 0; i < branchCtx.pattern().size(); i++) {
                var patternCtx = branchCtx.pattern(i);
                var exprCtx = branchCtx.expression(i);

                // We need to isolate branch's scope
                var outerEnv = this.environment;
                try {
                    LamaPatternNode patternNode = (LamaPatternNode) visit(patternCtx); // This will add vars to ctx
                    LamaExpressionNode bodyNode = visit(exprCtx);

                    branches.add(new LamaCaseBranchNode(patternNode, bodyNode));
                } finally {
                    this.environment = outerEnv;
                }
            }
        }
        return new LamaCaseNode(scrutinee, branches.toArray(new LamaCaseBranchNode[0]));
    }

    @Override
    public LamaExpressionNode visitLetExpression(LamaParser.LetExpressionContext ctx) {
        // `let pattern = expr IN body` is a sugar for `case expr of pattern -> body esac`
        LamaExpressionNode valueExpr = visit(ctx.expression(0));

        // We need to isolate branch's scope
        var outerEnv = this.environment;
        try {
            LamaPatternNode patternNode = (LamaPatternNode) visit(ctx.pattern()); // This will add vars to ctx
            LamaExpressionNode bodyNode = visit(ctx.expression(1));

            LamaCaseBranchNode branch = new LamaCaseBranchNode(patternNode, bodyNode);
            return new LamaCaseNode(valueExpr, new LamaCaseBranchNode[]{branch});
        } finally {
            this.environment = outerEnv;
        }
    }

    @Override
    public LamaExpressionNode visitListPrimary(LamaParser.ListPrimaryContext ctx) {
        return visit(ctx.listLiteral());
    }

    @Override
    public LamaExpressionNode visitListLiteral(LamaParser.ListLiteralContext ctx) {
        // {} -> Nil
        LamaExpressionNode result = new LamaSExpNode("Nil", new LamaExpressionNode[0]);

        if (ctx.expression() != null && !ctx.expression().isEmpty()) {
            List<LamaParser.ExpressionContext> exprs = ctx.expression();
            // `{a, b, c}` transformed into `Cons(a, Cons(b, Cons(c, Nil)))`
            for (int i = exprs.size() - 1; i >= 0; i--) {
                LamaExpressionNode head = visit(exprs.get(i));
                result = new LamaSExpNode("Cons", new LamaExpressionNode[]{head, result});
            }
        }
        return result;
    }

    @Override
    public LamaExpressionNode visitAliasPattern(LamaParser.AliasPatternContext ctx) {
        String name = ctx.LIDENT().getText();
        // No `declareVariable` here because we'll need slot for alias pattern constructor
        int slot = builder.addSlot(FrameSlotKind.Object, name, null);
        environment.locals.put(name, slot);

        LamaPatternNode inner = (LamaPatternNode) visit(ctx.pattern());
        return new LamaAliasPatternNode(slot, inner);
    }

    @Override
    public LamaExpressionNode visitSharpValPattern(LamaParser.SharpValPatternContext ctx) {
        return new LamaSharpPatternNode(LamaSharpPatternNode.PatType.VAL);
    }

    @Override
    public LamaExpressionNode visitSharpFunPattern(LamaParser.SharpFunPatternContext ctx) {
        return new LamaSharpPatternNode(LamaSharpPatternNode.PatType.FUN);
    }

    @Override
    public LamaExpressionNode visitSharpStrPattern(LamaParser.SharpStrPatternContext ctx) {
        return new LamaSharpPatternNode(LamaSharpPatternNode.PatType.STR);
    }

    @Override
    public LamaExpressionNode visitSharpArrayPattern(LamaParser.SharpArrayPatternContext ctx) {
        return new LamaSharpPatternNode(LamaSharpPatternNode.PatType.ARRAY);
    }

    @Override
    public LamaExpressionNode visitSharpSexpPattern(LamaParser.SharpSexpPatternContext ctx) {
        return new LamaSharpPatternNode(LamaSharpPatternNode.PatType.SEXP);
    }

    @Override
    public LamaExpressionNode visitSharpBoxPattern(LamaParser.SharpBoxPatternContext ctx) {
        return new LamaSharpPatternNode(LamaSharpPatternNode.PatType.BOX);
    }
}
