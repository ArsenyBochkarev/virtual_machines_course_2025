// Generated from language/src/main/java/com/oracle/truffle/lama/parser/Lama.g4 by ANTLR 4.13.2
package com.oracle.truffle.lama.parser;
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.*;
import org.antlr.v4.runtime.tree.*;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast", "CheckReturnValue", "this-escape"})
public class LamaParser extends Parser {
	static { RuntimeMetaData.checkVersion("4.13.2", RuntimeMetaData.VERSION); }

	protected static final DFA[] _decisionToDFA;
	protected static final PredictionContextCache _sharedContextCache =
		new PredictionContextCache();
	public static final int
		T__0=1, T__1=2, T__2=3, IMPORT=4, VAR=5, FUN=6, IF=7, THEN=8, ELSE=9, 
		FI=10, ELIF=11, CASE=12, OF=13, ESAC=14, LET=15, IN=16, WHILE=17, DO=18, 
		OD=19, FOR=20, SKIP_RULE=21, TRUE=22, FALSE=23, PUBLIC=24, ASSIGN=25, 
		OR=26, AND=27, EQ=28, NE=29, LT=30, LE=31, GT=32, GE=33, PLUS=34, MINUS=35, 
		MUL=36, DIV=37, MOD=38, CONS=39, DOT=40, LPAREN=41, RPAREN=42, LBRACK=43, 
		RBRACK=44, LBRACE=45, RBRACE=46, COMMA=47, SEMICOLON=48, COLON=49, ARROW=50, 
		UNDERSCORE=51, SHARP_VAL=52, SHARP_FUN=53, SHARP_STR=54, SHARP_ARRAY=55, 
		SHARP_SEXP=56, SHARP_BOX=57, UIDENT=58, LIDENT=59, DECIMAL=60, STRING=61, 
		CHAR=62, WS=63, LINE_COMMENT=64, BLOCK_COMMENT=65;
	public static final int
		RULE_program = 0, RULE_topScope = 1, RULE_importStatement = 2, RULE_scopeExpression = 3, 
		RULE_definition = 4, RULE_varDefinition = 5, RULE_varInit = 6, RULE_funDefinition = 7, 
		RULE_patternList = 8, RULE_pattern = 9, RULE_expression = 10, RULE_sequenceExpression = 11, 
		RULE_assignExpression = 12, RULE_consExpression = 13, RULE_logicalOrExpression = 14, 
		RULE_logicalAndExpression = 15, RULE_equalityExpression = 16, RULE_relationalExpression = 17, 
		RULE_additiveExpression = 18, RULE_multiplicativeExpression = 19, RULE_prefixExpression = 20, 
		RULE_postfixExpression = 21, RULE_primary = 22, RULE_literal = 23, RULE_identifier = 24, 
		RULE_arrayLiteral = 25, RULE_listLiteral = 26, RULE_sexp = 27, RULE_ifExpression = 28, 
		RULE_letExpression = 29, RULE_caseExpression = 30, RULE_caseBranch = 31, 
		RULE_loopExpression = 32, RULE_whileLoop = 33, RULE_doWhileLoop = 34, 
		RULE_forLoop = 35, RULE_forInit = 36, RULE_forStep = 37, RULE_lambdaExpression = 38, 
		RULE_argumentList = 39;
	private static String[] makeRuleNames() {
		return new String[] {
			"program", "topScope", "importStatement", "scopeExpression", "definition", 
			"varDefinition", "varInit", "funDefinition", "patternList", "pattern", 
			"expression", "sequenceExpression", "assignExpression", "consExpression", 
			"logicalOrExpression", "logicalAndExpression", "equalityExpression", 
			"relationalExpression", "additiveExpression", "multiplicativeExpression", 
			"prefixExpression", "postfixExpression", "primary", "literal", "identifier", 
			"arrayLiteral", "listLiteral", "sexp", "ifExpression", "letExpression", 
			"caseExpression", "caseBranch", "loopExpression", "whileLoop", "doWhileLoop", 
			"forLoop", "forInit", "forStep", "lambdaExpression", "argumentList"
		};
	}
	public static final String[] ruleNames = makeRuleNames();

	private static String[] makeLiteralNames() {
		return new String[] {
			null, "'='", "'@'", "'|'", "'import'", "'var'", "'fun'", "'if'", "'then'", 
			"'else'", "'fi'", "'elif'", "'case'", "'of'", "'esac'", "'let'", "'in'", 
			"'while'", "'do'", "'od'", "'for'", "'skip'", "'true'", "'false'", "'public'", 
			"':='", "'!!'", "'&&'", "'=='", "'!='", "'<'", "'<='", "'>'", "'>='", 
			"'+'", "'-'", "'*'", "'/'", "'%'", "'::'", "'.'", "'('", "')'", "'['", 
			"']'", "'{'", "'}'", "','", "';'", "':'", "'->'", "'_'", "'#val'", "'#fun'", 
			"'#str'", "'#array'", "'#sexp'", "'#box'"
		};
	}
	private static final String[] _LITERAL_NAMES = makeLiteralNames();
	private static String[] makeSymbolicNames() {
		return new String[] {
			null, null, null, null, "IMPORT", "VAR", "FUN", "IF", "THEN", "ELSE", 
			"FI", "ELIF", "CASE", "OF", "ESAC", "LET", "IN", "WHILE", "DO", "OD", 
			"FOR", "SKIP_RULE", "TRUE", "FALSE", "PUBLIC", "ASSIGN", "OR", "AND", 
			"EQ", "NE", "LT", "LE", "GT", "GE", "PLUS", "MINUS", "MUL", "DIV", "MOD", 
			"CONS", "DOT", "LPAREN", "RPAREN", "LBRACK", "RBRACK", "LBRACE", "RBRACE", 
			"COMMA", "SEMICOLON", "COLON", "ARROW", "UNDERSCORE", "SHARP_VAL", "SHARP_FUN", 
			"SHARP_STR", "SHARP_ARRAY", "SHARP_SEXP", "SHARP_BOX", "UIDENT", "LIDENT", 
			"DECIMAL", "STRING", "CHAR", "WS", "LINE_COMMENT", "BLOCK_COMMENT"
		};
	}
	private static final String[] _SYMBOLIC_NAMES = makeSymbolicNames();
	public static final Vocabulary VOCABULARY = new VocabularyImpl(_LITERAL_NAMES, _SYMBOLIC_NAMES);

	/**
	 * @deprecated Use {@link #VOCABULARY} instead.
	 */
	@Deprecated
	public static final String[] tokenNames;
	static {
		tokenNames = new String[_SYMBOLIC_NAMES.length];
		for (int i = 0; i < tokenNames.length; i++) {
			tokenNames[i] = VOCABULARY.getLiteralName(i);
			if (tokenNames[i] == null) {
				tokenNames[i] = VOCABULARY.getSymbolicName(i);
			}

			if (tokenNames[i] == null) {
				tokenNames[i] = "<INVALID>";
			}
		}
	}

	@Override
	@Deprecated
	public String[] getTokenNames() {
		return tokenNames;
	}

	@Override

	public Vocabulary getVocabulary() {
		return VOCABULARY;
	}

	@Override
	public String getGrammarFileName() { return "Lama.g4"; }

	@Override
	public String[] getRuleNames() { return ruleNames; }

	@Override
	public String getSerializedATN() { return _serializedATN; }

	@Override
	public ATN getATN() { return _ATN; }

	public LamaParser(TokenStream input) {
		super(input);
		_interp = new ParserATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ProgramContext extends ParserRuleContext {
		public TopScopeContext topScope() {
			return getRuleContext(TopScopeContext.class,0);
		}
		public TerminalNode EOF() { return getToken(LamaParser.EOF, 0); }
		public List<ImportStatementContext> importStatement() {
			return getRuleContexts(ImportStatementContext.class);
		}
		public ImportStatementContext importStatement(int i) {
			return getRuleContext(ImportStatementContext.class,i);
		}
		public ProgramContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_program; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitProgram(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ProgramContext program() throws RecognitionException {
		ProgramContext _localctx = new ProgramContext(_ctx, getState());
		enterRule(_localctx, 0, RULE_program);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(83);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==IMPORT) {
				{
				{
				setState(80);
				importStatement();
				}
				}
				setState(85);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(86);
			topScope();
			setState(87);
			match(EOF);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class TopScopeContext extends ParserRuleContext {
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public List<DefinitionContext> definition() {
			return getRuleContexts(DefinitionContext.class);
		}
		public DefinitionContext definition(int i) {
			return getRuleContext(DefinitionContext.class,i);
		}
		public TopScopeContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_topScope; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitTopScope(this);
			else return visitor.visitChildren(this);
		}
	}

	public final TopScopeContext topScope() throws RecognitionException {
		TopScopeContext _localctx = new TopScopeContext(_ctx, getState());
		enterRule(_localctx, 2, RULE_topScope);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(92);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,1,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(89);
					definition();
					}
					} 
				}
				setState(94);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,1,_ctx);
			}
			setState(95);
			expression();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ImportStatementContext extends ParserRuleContext {
		public TerminalNode IMPORT() { return getToken(LamaParser.IMPORT, 0); }
		public List<TerminalNode> LIDENT() { return getTokens(LamaParser.LIDENT); }
		public TerminalNode LIDENT(int i) {
			return getToken(LamaParser.LIDENT, i);
		}
		public List<TerminalNode> COMMA() { return getTokens(LamaParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(LamaParser.COMMA, i);
		}
		public TerminalNode SEMICOLON() { return getToken(LamaParser.SEMICOLON, 0); }
		public ImportStatementContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_importStatement; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitImportStatement(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ImportStatementContext importStatement() throws RecognitionException {
		ImportStatementContext _localctx = new ImportStatementContext(_ctx, getState());
		enterRule(_localctx, 4, RULE_importStatement);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(97);
			match(IMPORT);
			setState(98);
			match(LIDENT);
			setState(103);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==COMMA) {
				{
				{
				setState(99);
				match(COMMA);
				setState(100);
				match(LIDENT);
				}
				}
				setState(105);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(107);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==SEMICOLON) {
				{
				setState(106);
				match(SEMICOLON);
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ScopeExpressionContext extends ParserRuleContext {
		public List<DefinitionContext> definition() {
			return getRuleContexts(DefinitionContext.class);
		}
		public DefinitionContext definition(int i) {
			return getRuleContext(DefinitionContext.class,i);
		}
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public ScopeExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_scopeExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitScopeExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ScopeExpressionContext scopeExpression() throws RecognitionException {
		ScopeExpressionContext _localctx = new ScopeExpressionContext(_ctx, getState());
		enterRule(_localctx, 6, RULE_scopeExpression);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(112);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,4,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(109);
					definition();
					}
					} 
				}
				setState(114);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,4,_ctx);
			}
			setState(116);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,5,_ctx) ) {
			case 1:
				{
				setState(115);
				expression();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class DefinitionContext extends ParserRuleContext {
		public VarDefinitionContext varDefinition() {
			return getRuleContext(VarDefinitionContext.class,0);
		}
		public FunDefinitionContext funDefinition() {
			return getRuleContext(FunDefinitionContext.class,0);
		}
		public DefinitionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_definition; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitDefinition(this);
			else return visitor.visitChildren(this);
		}
	}

	public final DefinitionContext definition() throws RecognitionException {
		DefinitionContext _localctx = new DefinitionContext(_ctx, getState());
		enterRule(_localctx, 8, RULE_definition);
		try {
			setState(120);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case VAR:
				enterOuterAlt(_localctx, 1);
				{
				setState(118);
				varDefinition();
				}
				break;
			case FUN:
				enterOuterAlt(_localctx, 2);
				{
				setState(119);
				funDefinition();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class VarDefinitionContext extends ParserRuleContext {
		public TerminalNode VAR() { return getToken(LamaParser.VAR, 0); }
		public List<VarInitContext> varInit() {
			return getRuleContexts(VarInitContext.class);
		}
		public VarInitContext varInit(int i) {
			return getRuleContext(VarInitContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(LamaParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(LamaParser.COMMA, i);
		}
		public TerminalNode SEMICOLON() { return getToken(LamaParser.SEMICOLON, 0); }
		public VarDefinitionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_varDefinition; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitVarDefinition(this);
			else return visitor.visitChildren(this);
		}
	}

	public final VarDefinitionContext varDefinition() throws RecognitionException {
		VarDefinitionContext _localctx = new VarDefinitionContext(_ctx, getState());
		enterRule(_localctx, 10, RULE_varDefinition);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(122);
			match(VAR);
			setState(123);
			varInit();
			setState(128);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,7,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(124);
					match(COMMA);
					setState(125);
					varInit();
					}
					} 
				}
				setState(130);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,7,_ctx);
			}
			setState(132);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==SEMICOLON) {
				{
				setState(131);
				match(SEMICOLON);
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class VarInitContext extends ParserRuleContext {
		public TerminalNode LIDENT() { return getToken(LamaParser.LIDENT, 0); }
		public AssignExpressionContext assignExpression() {
			return getRuleContext(AssignExpressionContext.class,0);
		}
		public VarInitContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_varInit; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitVarInit(this);
			else return visitor.visitChildren(this);
		}
	}

	public final VarInitContext varInit() throws RecognitionException {
		VarInitContext _localctx = new VarInitContext(_ctx, getState());
		enterRule(_localctx, 12, RULE_varInit);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(134);
			match(LIDENT);
			setState(137);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__0) {
				{
				setState(135);
				match(T__0);
				setState(136);
				assignExpression();
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class FunDefinitionContext extends ParserRuleContext {
		public TerminalNode FUN() { return getToken(LamaParser.FUN, 0); }
		public TerminalNode LIDENT() { return getToken(LamaParser.LIDENT, 0); }
		public TerminalNode LPAREN() { return getToken(LamaParser.LPAREN, 0); }
		public TerminalNode RPAREN() { return getToken(LamaParser.RPAREN, 0); }
		public TerminalNode LBRACE() { return getToken(LamaParser.LBRACE, 0); }
		public ScopeExpressionContext scopeExpression() {
			return getRuleContext(ScopeExpressionContext.class,0);
		}
		public TerminalNode RBRACE() { return getToken(LamaParser.RBRACE, 0); }
		public PatternListContext patternList() {
			return getRuleContext(PatternListContext.class,0);
		}
		public TerminalNode SEMICOLON() { return getToken(LamaParser.SEMICOLON, 0); }
		public FunDefinitionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_funDefinition; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitFunDefinition(this);
			else return visitor.visitChildren(this);
		}
	}

	public final FunDefinitionContext funDefinition() throws RecognitionException {
		FunDefinitionContext _localctx = new FunDefinitionContext(_ctx, getState());
		enterRule(_localctx, 14, RULE_funDefinition);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(139);
			match(FUN);
			setState(140);
			match(LIDENT);
			setState(141);
			match(LPAREN);
			setState(143);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 9221166416542040064L) != 0)) {
				{
				setState(142);
				patternList();
				}
			}

			setState(145);
			match(RPAREN);
			setState(146);
			match(LBRACE);
			setState(147);
			scopeExpression();
			setState(148);
			match(RBRACE);
			setState(150);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==SEMICOLON) {
				{
				setState(149);
				match(SEMICOLON);
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class PatternListContext extends ParserRuleContext {
		public List<PatternContext> pattern() {
			return getRuleContexts(PatternContext.class);
		}
		public PatternContext pattern(int i) {
			return getRuleContext(PatternContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(LamaParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(LamaParser.COMMA, i);
		}
		public PatternListContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_patternList; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitPatternList(this);
			else return visitor.visitChildren(this);
		}
	}

	public final PatternListContext patternList() throws RecognitionException {
		PatternListContext _localctx = new PatternListContext(_ctx, getState());
		enterRule(_localctx, 16, RULE_patternList);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(152);
			pattern(0);
			setState(157);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==COMMA) {
				{
				{
				setState(153);
				match(COMMA);
				setState(154);
				pattern(0);
				}
				}
				setState(159);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class PatternContext extends ParserRuleContext {
		public PatternContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_pattern; }
	 
		public PatternContext() { }
		public void copyFrom(PatternContext ctx) {
			super.copyFrom(ctx);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ListPatternContext extends PatternContext {
		public TerminalNode LBRACE() { return getToken(LamaParser.LBRACE, 0); }
		public TerminalNode RBRACE() { return getToken(LamaParser.RBRACE, 0); }
		public PatternListContext patternList() {
			return getRuleContext(PatternListContext.class,0);
		}
		public ListPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitListPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ParenPatternContext extends PatternContext {
		public TerminalNode LPAREN() { return getToken(LamaParser.LPAREN, 0); }
		public PatternContext pattern() {
			return getRuleContext(PatternContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(LamaParser.RPAREN, 0); }
		public ParenPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitParenPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class TruePatternContext extends PatternContext {
		public TerminalNode TRUE() { return getToken(LamaParser.TRUE, 0); }
		public TruePatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitTruePattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class DecimalPatternContext extends PatternContext {
		public TerminalNode DECIMAL() { return getToken(LamaParser.DECIMAL, 0); }
		public DecimalPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitDecimalPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SharpStrPatternContext extends PatternContext {
		public TerminalNode SHARP_STR() { return getToken(LamaParser.SHARP_STR, 0); }
		public SharpStrPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSharpStrPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SexpPatternNoArgsContext extends PatternContext {
		public TerminalNode UIDENT() { return getToken(LamaParser.UIDENT, 0); }
		public SexpPatternNoArgsContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSexpPatternNoArgs(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class WildcardPatternContext extends PatternContext {
		public TerminalNode UNDERSCORE() { return getToken(LamaParser.UNDERSCORE, 0); }
		public WildcardPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitWildcardPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class AliasPatternContext extends PatternContext {
		public TerminalNode LIDENT() { return getToken(LamaParser.LIDENT, 0); }
		public PatternContext pattern() {
			return getRuleContext(PatternContext.class,0);
		}
		public AliasPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitAliasPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SharpSexpPatternContext extends PatternContext {
		public TerminalNode SHARP_SEXP() { return getToken(LamaParser.SHARP_SEXP, 0); }
		public SharpSexpPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSharpSexpPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SharpFunPatternContext extends PatternContext {
		public TerminalNode SHARP_FUN() { return getToken(LamaParser.SHARP_FUN, 0); }
		public SharpFunPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSharpFunPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class VarPatternContext extends PatternContext {
		public TerminalNode LIDENT() { return getToken(LamaParser.LIDENT, 0); }
		public VarPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitVarPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class CharPatternContext extends PatternContext {
		public TerminalNode CHAR() { return getToken(LamaParser.CHAR, 0); }
		public CharPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitCharPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ConsPatternContext extends PatternContext {
		public List<PatternContext> pattern() {
			return getRuleContexts(PatternContext.class);
		}
		public PatternContext pattern(int i) {
			return getRuleContext(PatternContext.class,i);
		}
		public TerminalNode COLON() { return getToken(LamaParser.COLON, 0); }
		public ConsPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitConsPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class StringPatternContext extends PatternContext {
		public TerminalNode STRING() { return getToken(LamaParser.STRING, 0); }
		public StringPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitStringPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SharpBoxPatternContext extends PatternContext {
		public TerminalNode SHARP_BOX() { return getToken(LamaParser.SHARP_BOX, 0); }
		public SharpBoxPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSharpBoxPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class FalsePatternContext extends PatternContext {
		public TerminalNode FALSE() { return getToken(LamaParser.FALSE, 0); }
		public FalsePatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitFalsePattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SharpValPatternContext extends PatternContext {
		public TerminalNode SHARP_VAL() { return getToken(LamaParser.SHARP_VAL, 0); }
		public SharpValPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSharpValPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SharpArrayPatternContext extends PatternContext {
		public TerminalNode SHARP_ARRAY() { return getToken(LamaParser.SHARP_ARRAY, 0); }
		public SharpArrayPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSharpArrayPattern(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SexpPatternWithArgsContext extends PatternContext {
		public TerminalNode UIDENT() { return getToken(LamaParser.UIDENT, 0); }
		public TerminalNode LPAREN() { return getToken(LamaParser.LPAREN, 0); }
		public TerminalNode RPAREN() { return getToken(LamaParser.RPAREN, 0); }
		public PatternListContext patternList() {
			return getRuleContext(PatternListContext.class,0);
		}
		public SexpPatternWithArgsContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSexpPatternWithArgs(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ArrayPatternContext extends PatternContext {
		public TerminalNode LBRACK() { return getToken(LamaParser.LBRACK, 0); }
		public TerminalNode RBRACK() { return getToken(LamaParser.RBRACK, 0); }
		public PatternListContext patternList() {
			return getRuleContext(PatternListContext.class,0);
		}
		public ArrayPatternContext(PatternContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitArrayPattern(this);
			else return visitor.visitChildren(this);
		}
	}

	public final PatternContext pattern() throws RecognitionException {
		return pattern(0);
	}

	private PatternContext pattern(int _p) throws RecognitionException {
		ParserRuleContext _parentctx = _ctx;
		int _parentState = getState();
		PatternContext _localctx = new PatternContext(_ctx, _parentState);
		PatternContext _prevctx = _localctx;
		int _startState = 18;
		enterRecursionRule(_localctx, 18, RULE_pattern, _p);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(198);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,16,_ctx) ) {
			case 1:
				{
				_localctx = new AliasPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;

				setState(161);
				match(LIDENT);
				setState(162);
				match(T__1);
				setState(163);
				pattern(20);
				}
				break;
			case 2:
				{
				_localctx = new SharpValPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(164);
				match(SHARP_VAL);
				}
				break;
			case 3:
				{
				_localctx = new SharpFunPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(165);
				match(SHARP_FUN);
				}
				break;
			case 4:
				{
				_localctx = new SharpStrPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(166);
				match(SHARP_STR);
				}
				break;
			case 5:
				{
				_localctx = new SharpArrayPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(167);
				match(SHARP_ARRAY);
				}
				break;
			case 6:
				{
				_localctx = new SharpSexpPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(168);
				match(SHARP_SEXP);
				}
				break;
			case 7:
				{
				_localctx = new SharpBoxPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(169);
				match(SHARP_BOX);
				}
				break;
			case 8:
				{
				_localctx = new VarPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(170);
				match(LIDENT);
				}
				break;
			case 9:
				{
				_localctx = new SexpPatternWithArgsContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(171);
				match(UIDENT);
				setState(172);
				match(LPAREN);
				setState(174);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 9221166416542040064L) != 0)) {
					{
					setState(173);
					patternList();
					}
				}

				setState(176);
				match(RPAREN);
				}
				break;
			case 10:
				{
				_localctx = new SexpPatternNoArgsContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(177);
				match(UIDENT);
				}
				break;
			case 11:
				{
				_localctx = new ArrayPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(178);
				match(LBRACK);
				setState(180);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 9221166416542040064L) != 0)) {
					{
					setState(179);
					patternList();
					}
				}

				setState(182);
				match(RBRACK);
				}
				break;
			case 12:
				{
				_localctx = new ListPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(183);
				match(LBRACE);
				setState(185);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 9221166416542040064L) != 0)) {
					{
					setState(184);
					patternList();
					}
				}

				setState(187);
				match(RBRACE);
				}
				break;
			case 13:
				{
				_localctx = new WildcardPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(188);
				match(UNDERSCORE);
				}
				break;
			case 14:
				{
				_localctx = new DecimalPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(189);
				match(DECIMAL);
				}
				break;
			case 15:
				{
				_localctx = new StringPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(190);
				match(STRING);
				}
				break;
			case 16:
				{
				_localctx = new CharPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(191);
				match(CHAR);
				}
				break;
			case 17:
				{
				_localctx = new TruePatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(192);
				match(TRUE);
				}
				break;
			case 18:
				{
				_localctx = new FalsePatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(193);
				match(FALSE);
				}
				break;
			case 19:
				{
				_localctx = new ParenPatternContext(_localctx);
				_ctx = _localctx;
				_prevctx = _localctx;
				setState(194);
				match(LPAREN);
				setState(195);
				pattern(0);
				setState(196);
				match(RPAREN);
				}
				break;
			}
			_ctx.stop = _input.LT(-1);
			setState(205);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,17,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					if ( _parseListeners!=null ) triggerExitRuleEvent();
					_prevctx = _localctx;
					{
					{
					_localctx = new ConsPatternContext(new PatternContext(_parentctx, _parentState));
					pushNewRecursionContext(_localctx, _startState, RULE_pattern);
					setState(200);
					if (!(precpred(_ctx, 1))) throw new FailedPredicateException(this, "precpred(_ctx, 1)");
					setState(201);
					match(COLON);
					setState(202);
					pattern(1);
					}
					} 
				}
				setState(207);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,17,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			unrollRecursionContexts(_parentctx);
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ExpressionContext extends ParserRuleContext {
		public SequenceExpressionContext sequenceExpression() {
			return getRuleContext(SequenceExpressionContext.class,0);
		}
		public ExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_expression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ExpressionContext expression() throws RecognitionException {
		ExpressionContext _localctx = new ExpressionContext(_ctx, getState());
		enterRule(_localctx, 20, RULE_expression);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(208);
			sequenceExpression();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class SequenceExpressionContext extends ParserRuleContext {
		public List<AssignExpressionContext> assignExpression() {
			return getRuleContexts(AssignExpressionContext.class);
		}
		public AssignExpressionContext assignExpression(int i) {
			return getRuleContext(AssignExpressionContext.class,i);
		}
		public List<TerminalNode> SEMICOLON() { return getTokens(LamaParser.SEMICOLON); }
		public TerminalNode SEMICOLON(int i) {
			return getToken(LamaParser.SEMICOLON, i);
		}
		public SequenceExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_sequenceExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSequenceExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SequenceExpressionContext sequenceExpression() throws RecognitionException {
		SequenceExpressionContext _localctx = new SequenceExpressionContext(_ctx, getState());
		enterRule(_localctx, 22, RULE_sequenceExpression);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(210);
			assignExpression();
			setState(215);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,18,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(211);
					match(SEMICOLON);
					setState(212);
					assignExpression();
					}
					} 
				}
				setState(217);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,18,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class AssignExpressionContext extends ParserRuleContext {
		public ConsExpressionContext consExpression() {
			return getRuleContext(ConsExpressionContext.class,0);
		}
		public TerminalNode ASSIGN() { return getToken(LamaParser.ASSIGN, 0); }
		public AssignExpressionContext assignExpression() {
			return getRuleContext(AssignExpressionContext.class,0);
		}
		public AssignExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_assignExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitAssignExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final AssignExpressionContext assignExpression() throws RecognitionException {
		AssignExpressionContext _localctx = new AssignExpressionContext(_ctx, getState());
		enterRule(_localctx, 24, RULE_assignExpression);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(218);
			consExpression();
			setState(221);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,19,_ctx) ) {
			case 1:
				{
				setState(219);
				match(ASSIGN);
				setState(220);
				assignExpression();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ConsExpressionContext extends ParserRuleContext {
		public LogicalOrExpressionContext logicalOrExpression() {
			return getRuleContext(LogicalOrExpressionContext.class,0);
		}
		public TerminalNode COLON() { return getToken(LamaParser.COLON, 0); }
		public ConsExpressionContext consExpression() {
			return getRuleContext(ConsExpressionContext.class,0);
		}
		public ConsExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_consExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitConsExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ConsExpressionContext consExpression() throws RecognitionException {
		ConsExpressionContext _localctx = new ConsExpressionContext(_ctx, getState());
		enterRule(_localctx, 26, RULE_consExpression);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(223);
			logicalOrExpression();
			setState(226);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,20,_ctx) ) {
			case 1:
				{
				setState(224);
				match(COLON);
				setState(225);
				consExpression();
				}
				break;
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class LogicalOrExpressionContext extends ParserRuleContext {
		public List<LogicalAndExpressionContext> logicalAndExpression() {
			return getRuleContexts(LogicalAndExpressionContext.class);
		}
		public LogicalAndExpressionContext logicalAndExpression(int i) {
			return getRuleContext(LogicalAndExpressionContext.class,i);
		}
		public List<TerminalNode> OR() { return getTokens(LamaParser.OR); }
		public TerminalNode OR(int i) {
			return getToken(LamaParser.OR, i);
		}
		public LogicalOrExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_logicalOrExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitLogicalOrExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LogicalOrExpressionContext logicalOrExpression() throws RecognitionException {
		LogicalOrExpressionContext _localctx = new LogicalOrExpressionContext(_ctx, getState());
		enterRule(_localctx, 28, RULE_logicalOrExpression);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(228);
			logicalAndExpression();
			setState(233);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,21,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(229);
					match(OR);
					setState(230);
					logicalAndExpression();
					}
					} 
				}
				setState(235);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,21,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class LogicalAndExpressionContext extends ParserRuleContext {
		public List<EqualityExpressionContext> equalityExpression() {
			return getRuleContexts(EqualityExpressionContext.class);
		}
		public EqualityExpressionContext equalityExpression(int i) {
			return getRuleContext(EqualityExpressionContext.class,i);
		}
		public List<TerminalNode> AND() { return getTokens(LamaParser.AND); }
		public TerminalNode AND(int i) {
			return getToken(LamaParser.AND, i);
		}
		public LogicalAndExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_logicalAndExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitLogicalAndExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LogicalAndExpressionContext logicalAndExpression() throws RecognitionException {
		LogicalAndExpressionContext _localctx = new LogicalAndExpressionContext(_ctx, getState());
		enterRule(_localctx, 30, RULE_logicalAndExpression);
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(236);
			equalityExpression();
			setState(241);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,22,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(237);
					match(AND);
					setState(238);
					equalityExpression();
					}
					} 
				}
				setState(243);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,22,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class EqualityExpressionContext extends ParserRuleContext {
		public List<RelationalExpressionContext> relationalExpression() {
			return getRuleContexts(RelationalExpressionContext.class);
		}
		public RelationalExpressionContext relationalExpression(int i) {
			return getRuleContext(RelationalExpressionContext.class,i);
		}
		public List<TerminalNode> EQ() { return getTokens(LamaParser.EQ); }
		public TerminalNode EQ(int i) {
			return getToken(LamaParser.EQ, i);
		}
		public List<TerminalNode> NE() { return getTokens(LamaParser.NE); }
		public TerminalNode NE(int i) {
			return getToken(LamaParser.NE, i);
		}
		public EqualityExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_equalityExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitEqualityExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final EqualityExpressionContext equalityExpression() throws RecognitionException {
		EqualityExpressionContext _localctx = new EqualityExpressionContext(_ctx, getState());
		enterRule(_localctx, 32, RULE_equalityExpression);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(244);
			relationalExpression();
			setState(249);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,23,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(245);
					_la = _input.LA(1);
					if ( !(_la==EQ || _la==NE) ) {
					_errHandler.recoverInline(this);
					}
					else {
						if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
						_errHandler.reportMatch(this);
						consume();
					}
					setState(246);
					relationalExpression();
					}
					} 
				}
				setState(251);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,23,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class RelationalExpressionContext extends ParserRuleContext {
		public List<AdditiveExpressionContext> additiveExpression() {
			return getRuleContexts(AdditiveExpressionContext.class);
		}
		public AdditiveExpressionContext additiveExpression(int i) {
			return getRuleContext(AdditiveExpressionContext.class,i);
		}
		public List<TerminalNode> LT() { return getTokens(LamaParser.LT); }
		public TerminalNode LT(int i) {
			return getToken(LamaParser.LT, i);
		}
		public List<TerminalNode> LE() { return getTokens(LamaParser.LE); }
		public TerminalNode LE(int i) {
			return getToken(LamaParser.LE, i);
		}
		public List<TerminalNode> GT() { return getTokens(LamaParser.GT); }
		public TerminalNode GT(int i) {
			return getToken(LamaParser.GT, i);
		}
		public List<TerminalNode> GE() { return getTokens(LamaParser.GE); }
		public TerminalNode GE(int i) {
			return getToken(LamaParser.GE, i);
		}
		public RelationalExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_relationalExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitRelationalExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final RelationalExpressionContext relationalExpression() throws RecognitionException {
		RelationalExpressionContext _localctx = new RelationalExpressionContext(_ctx, getState());
		enterRule(_localctx, 34, RULE_relationalExpression);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(252);
			additiveExpression();
			setState(257);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,24,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(253);
					_la = _input.LA(1);
					if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & 16106127360L) != 0)) ) {
					_errHandler.recoverInline(this);
					}
					else {
						if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
						_errHandler.reportMatch(this);
						consume();
					}
					setState(254);
					additiveExpression();
					}
					} 
				}
				setState(259);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,24,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class AdditiveExpressionContext extends ParserRuleContext {
		public List<MultiplicativeExpressionContext> multiplicativeExpression() {
			return getRuleContexts(MultiplicativeExpressionContext.class);
		}
		public MultiplicativeExpressionContext multiplicativeExpression(int i) {
			return getRuleContext(MultiplicativeExpressionContext.class,i);
		}
		public List<TerminalNode> PLUS() { return getTokens(LamaParser.PLUS); }
		public TerminalNode PLUS(int i) {
			return getToken(LamaParser.PLUS, i);
		}
		public List<TerminalNode> MINUS() { return getTokens(LamaParser.MINUS); }
		public TerminalNode MINUS(int i) {
			return getToken(LamaParser.MINUS, i);
		}
		public AdditiveExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_additiveExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitAdditiveExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final AdditiveExpressionContext additiveExpression() throws RecognitionException {
		AdditiveExpressionContext _localctx = new AdditiveExpressionContext(_ctx, getState());
		enterRule(_localctx, 36, RULE_additiveExpression);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(260);
			multiplicativeExpression();
			setState(265);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,25,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(261);
					_la = _input.LA(1);
					if ( !(_la==PLUS || _la==MINUS) ) {
					_errHandler.recoverInline(this);
					}
					else {
						if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
						_errHandler.reportMatch(this);
						consume();
					}
					setState(262);
					multiplicativeExpression();
					}
					} 
				}
				setState(267);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,25,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class MultiplicativeExpressionContext extends ParserRuleContext {
		public List<PrefixExpressionContext> prefixExpression() {
			return getRuleContexts(PrefixExpressionContext.class);
		}
		public PrefixExpressionContext prefixExpression(int i) {
			return getRuleContext(PrefixExpressionContext.class,i);
		}
		public List<TerminalNode> MUL() { return getTokens(LamaParser.MUL); }
		public TerminalNode MUL(int i) {
			return getToken(LamaParser.MUL, i);
		}
		public List<TerminalNode> DIV() { return getTokens(LamaParser.DIV); }
		public TerminalNode DIV(int i) {
			return getToken(LamaParser.DIV, i);
		}
		public List<TerminalNode> MOD() { return getTokens(LamaParser.MOD); }
		public TerminalNode MOD(int i) {
			return getToken(LamaParser.MOD, i);
		}
		public MultiplicativeExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_multiplicativeExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitMultiplicativeExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final MultiplicativeExpressionContext multiplicativeExpression() throws RecognitionException {
		MultiplicativeExpressionContext _localctx = new MultiplicativeExpressionContext(_ctx, getState());
		enterRule(_localctx, 38, RULE_multiplicativeExpression);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			setState(268);
			prefixExpression();
			setState(273);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,26,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					{
					{
					setState(269);
					_la = _input.LA(1);
					if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & 481036337152L) != 0)) ) {
					_errHandler.recoverInline(this);
					}
					else {
						if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
						_errHandler.reportMatch(this);
						consume();
					}
					setState(270);
					prefixExpression();
					}
					} 
				}
				setState(275);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,26,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class PrefixExpressionContext extends ParserRuleContext {
		public PostfixExpressionContext postfixExpression() {
			return getRuleContext(PostfixExpressionContext.class,0);
		}
		public TerminalNode MINUS() { return getToken(LamaParser.MINUS, 0); }
		public PrefixExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_prefixExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitPrefixExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final PrefixExpressionContext prefixExpression() throws RecognitionException {
		PrefixExpressionContext _localctx = new PrefixExpressionContext(_ctx, getState());
		enterRule(_localctx, 40, RULE_prefixExpression);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(277);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==MINUS) {
				{
				setState(276);
				match(MINUS);
				}
			}

			setState(279);
			postfixExpression(0);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class PostfixExpressionContext extends ParserRuleContext {
		public PostfixExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_postfixExpression; }
	 
		public PostfixExpressionContext() { }
		public void copyFrom(PostfixExpressionContext ctx) {
			super.copyFrom(ctx);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class CallSuffixContext extends PostfixExpressionContext {
		public PostfixExpressionContext postfixExpression() {
			return getRuleContext(PostfixExpressionContext.class,0);
		}
		public TerminalNode LPAREN() { return getToken(LamaParser.LPAREN, 0); }
		public TerminalNode RPAREN() { return getToken(LamaParser.RPAREN, 0); }
		public ArgumentListContext argumentList() {
			return getRuleContext(ArgumentListContext.class,0);
		}
		public CallSuffixContext(PostfixExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitCallSuffix(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class DotSuffixContext extends PostfixExpressionContext {
		public PostfixExpressionContext postfixExpression() {
			return getRuleContext(PostfixExpressionContext.class,0);
		}
		public TerminalNode DOT() { return getToken(LamaParser.DOT, 0); }
		public TerminalNode LIDENT() { return getToken(LamaParser.LIDENT, 0); }
		public DotSuffixContext(PostfixExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitDotSuffix(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class BasePrimaryContext extends PostfixExpressionContext {
		public PrimaryContext primary() {
			return getRuleContext(PrimaryContext.class,0);
		}
		public BasePrimaryContext(PostfixExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitBasePrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class IndexSuffixContext extends PostfixExpressionContext {
		public PostfixExpressionContext postfixExpression() {
			return getRuleContext(PostfixExpressionContext.class,0);
		}
		public TerminalNode LBRACK() { return getToken(LamaParser.LBRACK, 0); }
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public TerminalNode RBRACK() { return getToken(LamaParser.RBRACK, 0); }
		public IndexSuffixContext(PostfixExpressionContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitIndexSuffix(this);
			else return visitor.visitChildren(this);
		}
	}

	public final PostfixExpressionContext postfixExpression() throws RecognitionException {
		return postfixExpression(0);
	}

	private PostfixExpressionContext postfixExpression(int _p) throws RecognitionException {
		ParserRuleContext _parentctx = _ctx;
		int _parentState = getState();
		PostfixExpressionContext _localctx = new PostfixExpressionContext(_ctx, _parentState);
		PostfixExpressionContext _prevctx = _localctx;
		int _startState = 42;
		enterRecursionRule(_localctx, 42, RULE_postfixExpression, _p);
		int _la;
		try {
			int _alt;
			enterOuterAlt(_localctx, 1);
			{
			{
			_localctx = new BasePrimaryContext(_localctx);
			_ctx = _localctx;
			_prevctx = _localctx;

			setState(282);
			primary();
			}
			_ctx.stop = _input.LT(-1);
			setState(300);
			_errHandler.sync(this);
			_alt = getInterpreter().adaptivePredict(_input,30,_ctx);
			while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
				if ( _alt==1 ) {
					if ( _parseListeners!=null ) triggerExitRuleEvent();
					_prevctx = _localctx;
					{
					setState(298);
					_errHandler.sync(this);
					switch ( getInterpreter().adaptivePredict(_input,29,_ctx) ) {
					case 1:
						{
						_localctx = new CallSuffixContext(new PostfixExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_postfixExpression);
						setState(284);
						if (!(precpred(_ctx, 4))) throw new FailedPredicateException(this, "precpred(_ctx, 4)");
						setState(285);
						match(LPAREN);
						setState(287);
						_errHandler.sync(this);
						_la = _input.LA(1);
						if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 8935187874567327936L) != 0)) {
							{
							setState(286);
							argumentList();
							}
						}

						setState(289);
						match(RPAREN);
						}
						break;
					case 2:
						{
						_localctx = new IndexSuffixContext(new PostfixExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_postfixExpression);
						setState(290);
						if (!(precpred(_ctx, 3))) throw new FailedPredicateException(this, "precpred(_ctx, 3)");
						setState(291);
						match(LBRACK);
						setState(292);
						expression();
						setState(293);
						match(RBRACK);
						}
						break;
					case 3:
						{
						_localctx = new DotSuffixContext(new PostfixExpressionContext(_parentctx, _parentState));
						pushNewRecursionContext(_localctx, _startState, RULE_postfixExpression);
						setState(295);
						if (!(precpred(_ctx, 2))) throw new FailedPredicateException(this, "precpred(_ctx, 2)");
						setState(296);
						match(DOT);
						setState(297);
						match(LIDENT);
						}
						break;
					}
					} 
				}
				setState(302);
				_errHandler.sync(this);
				_alt = getInterpreter().adaptivePredict(_input,30,_ctx);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			unrollRecursionContexts(_parentctx);
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class PrimaryContext extends ParserRuleContext {
		public PrimaryContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_primary; }
	 
		public PrimaryContext() { }
		public void copyFrom(PrimaryContext ctx) {
			super.copyFrom(ctx);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class LitPrimaryContext extends PrimaryContext {
		public LiteralContext literal() {
			return getRuleContext(LiteralContext.class,0);
		}
		public LitPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitLitPrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ListPrimaryContext extends PrimaryContext {
		public ListLiteralContext listLiteral() {
			return getRuleContext(ListLiteralContext.class,0);
		}
		public ListPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitListPrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ParenPrimaryContext extends PrimaryContext {
		public TerminalNode LPAREN() { return getToken(LamaParser.LPAREN, 0); }
		public ScopeExpressionContext scopeExpression() {
			return getRuleContext(ScopeExpressionContext.class,0);
		}
		public TerminalNode RPAREN() { return getToken(LamaParser.RPAREN, 0); }
		public ParenPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitParenPrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class ArrayPrimaryContext extends PrimaryContext {
		public ArrayLiteralContext arrayLiteral() {
			return getRuleContext(ArrayLiteralContext.class,0);
		}
		public ArrayPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitArrayPrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class LoopPrimaryContext extends PrimaryContext {
		public LoopExpressionContext loopExpression() {
			return getRuleContext(LoopExpressionContext.class,0);
		}
		public LoopPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitLoopPrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class IfPrimaryContext extends PrimaryContext {
		public IfExpressionContext ifExpression() {
			return getRuleContext(IfExpressionContext.class,0);
		}
		public IfPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitIfPrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SkipPrimaryContext extends PrimaryContext {
		public TerminalNode SKIP_RULE() { return getToken(LamaParser.SKIP_RULE, 0); }
		public SkipPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSkipPrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class SexpPrimaryContext extends PrimaryContext {
		public SexpContext sexp() {
			return getRuleContext(SexpContext.class,0);
		}
		public SexpPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSexpPrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class IdPrimaryContext extends PrimaryContext {
		public IdentifierContext identifier() {
			return getRuleContext(IdentifierContext.class,0);
		}
		public IdPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitIdPrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class CasePrimaryContext extends PrimaryContext {
		public CaseExpressionContext caseExpression() {
			return getRuleContext(CaseExpressionContext.class,0);
		}
		public CasePrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitCasePrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class LambdaPrimaryContext extends PrimaryContext {
		public LambdaExpressionContext lambdaExpression() {
			return getRuleContext(LambdaExpressionContext.class,0);
		}
		public LambdaPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitLambdaPrimary(this);
			else return visitor.visitChildren(this);
		}
	}
	@SuppressWarnings("CheckReturnValue")
	public static class LetPrimaryContext extends PrimaryContext {
		public LetExpressionContext letExpression() {
			return getRuleContext(LetExpressionContext.class,0);
		}
		public LetPrimaryContext(PrimaryContext ctx) { copyFrom(ctx); }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitLetPrimary(this);
			else return visitor.visitChildren(this);
		}
	}

	public final PrimaryContext primary() throws RecognitionException {
		PrimaryContext _localctx = new PrimaryContext(_ctx, getState());
		enterRule(_localctx, 44, RULE_primary);
		try {
			setState(318);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,31,_ctx) ) {
			case 1:
				_localctx = new LitPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 1);
				{
				setState(303);
				literal();
				}
				break;
			case 2:
				_localctx = new SexpPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 2);
				{
				setState(304);
				sexp();
				}
				break;
			case 3:
				_localctx = new IdPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 3);
				{
				setState(305);
				identifier();
				}
				break;
			case 4:
				_localctx = new ParenPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 4);
				{
				setState(306);
				match(LPAREN);
				setState(307);
				scopeExpression();
				setState(308);
				match(RPAREN);
				}
				break;
			case 5:
				_localctx = new ArrayPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 5);
				{
				setState(310);
				arrayLiteral();
				}
				break;
			case 6:
				_localctx = new ListPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 6);
				{
				setState(311);
				listLiteral();
				}
				break;
			case 7:
				_localctx = new IfPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 7);
				{
				setState(312);
				ifExpression();
				}
				break;
			case 8:
				_localctx = new LetPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 8);
				{
				setState(313);
				letExpression();
				}
				break;
			case 9:
				_localctx = new CasePrimaryContext(_localctx);
				enterOuterAlt(_localctx, 9);
				{
				setState(314);
				caseExpression();
				}
				break;
			case 10:
				_localctx = new LoopPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 10);
				{
				setState(315);
				loopExpression();
				}
				break;
			case 11:
				_localctx = new SkipPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 11);
				{
				setState(316);
				match(SKIP_RULE);
				}
				break;
			case 12:
				_localctx = new LambdaPrimaryContext(_localctx);
				enterOuterAlt(_localctx, 12);
				{
				setState(317);
				lambdaExpression();
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class LiteralContext extends ParserRuleContext {
		public TerminalNode DECIMAL() { return getToken(LamaParser.DECIMAL, 0); }
		public TerminalNode STRING() { return getToken(LamaParser.STRING, 0); }
		public TerminalNode CHAR() { return getToken(LamaParser.CHAR, 0); }
		public TerminalNode TRUE() { return getToken(LamaParser.TRUE, 0); }
		public TerminalNode FALSE() { return getToken(LamaParser.FALSE, 0); }
		public LiteralContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_literal; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitLiteral(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LiteralContext literal() throws RecognitionException {
		LiteralContext _localctx = new LiteralContext(_ctx, getState());
		enterRule(_localctx, 46, RULE_literal);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(320);
			_la = _input.LA(1);
			if ( !((((_la) & ~0x3f) == 0 && ((1L << _la) & 8070450532260511744L) != 0)) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class IdentifierContext extends ParserRuleContext {
		public TerminalNode LIDENT() { return getToken(LamaParser.LIDENT, 0); }
		public TerminalNode UIDENT() { return getToken(LamaParser.UIDENT, 0); }
		public IdentifierContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_identifier; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitIdentifier(this);
			else return visitor.visitChildren(this);
		}
	}

	public final IdentifierContext identifier() throws RecognitionException {
		IdentifierContext _localctx = new IdentifierContext(_ctx, getState());
		enterRule(_localctx, 48, RULE_identifier);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(322);
			_la = _input.LA(1);
			if ( !(_la==UIDENT || _la==LIDENT) ) {
			_errHandler.recoverInline(this);
			}
			else {
				if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
				_errHandler.reportMatch(this);
				consume();
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ArrayLiteralContext extends ParserRuleContext {
		public TerminalNode LBRACK() { return getToken(LamaParser.LBRACK, 0); }
		public TerminalNode RBRACK() { return getToken(LamaParser.RBRACK, 0); }
		public List<ExpressionContext> expression() {
			return getRuleContexts(ExpressionContext.class);
		}
		public ExpressionContext expression(int i) {
			return getRuleContext(ExpressionContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(LamaParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(LamaParser.COMMA, i);
		}
		public ArrayLiteralContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_arrayLiteral; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitArrayLiteral(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ArrayLiteralContext arrayLiteral() throws RecognitionException {
		ArrayLiteralContext _localctx = new ArrayLiteralContext(_ctx, getState());
		enterRule(_localctx, 50, RULE_arrayLiteral);
		int _la;
		try {
			setState(337);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,33,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(324);
				match(LBRACK);
				setState(325);
				match(RBRACK);
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(326);
				match(LBRACK);
				setState(327);
				expression();
				setState(332);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==COMMA) {
					{
					{
					setState(328);
					match(COMMA);
					setState(329);
					expression();
					}
					}
					setState(334);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(335);
				match(RBRACK);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ListLiteralContext extends ParserRuleContext {
		public TerminalNode LBRACE() { return getToken(LamaParser.LBRACE, 0); }
		public TerminalNode RBRACE() { return getToken(LamaParser.RBRACE, 0); }
		public List<ExpressionContext> expression() {
			return getRuleContexts(ExpressionContext.class);
		}
		public ExpressionContext expression(int i) {
			return getRuleContext(ExpressionContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(LamaParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(LamaParser.COMMA, i);
		}
		public ListLiteralContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_listLiteral; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitListLiteral(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ListLiteralContext listLiteral() throws RecognitionException {
		ListLiteralContext _localctx = new ListLiteralContext(_ctx, getState());
		enterRule(_localctx, 52, RULE_listLiteral);
		int _la;
		try {
			setState(352);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,35,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(339);
				match(LBRACE);
				setState(340);
				match(RBRACE);
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(341);
				match(LBRACE);
				setState(342);
				expression();
				setState(347);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==COMMA) {
					{
					{
					setState(343);
					match(COMMA);
					setState(344);
					expression();
					}
					}
					setState(349);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(350);
				match(RBRACE);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class SexpContext extends ParserRuleContext {
		public TerminalNode UIDENT() { return getToken(LamaParser.UIDENT, 0); }
		public TerminalNode LPAREN() { return getToken(LamaParser.LPAREN, 0); }
		public TerminalNode RPAREN() { return getToken(LamaParser.RPAREN, 0); }
		public List<ExpressionContext> expression() {
			return getRuleContexts(ExpressionContext.class);
		}
		public ExpressionContext expression(int i) {
			return getRuleContext(ExpressionContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(LamaParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(LamaParser.COMMA, i);
		}
		public SexpContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_sexp; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitSexp(this);
			else return visitor.visitChildren(this);
		}
	}

	public final SexpContext sexp() throws RecognitionException {
		SexpContext _localctx = new SexpContext(_ctx, getState());
		enterRule(_localctx, 54, RULE_sexp);
		int _la;
		try {
			setState(368);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,38,_ctx) ) {
			case 1:
				enterOuterAlt(_localctx, 1);
				{
				setState(354);
				match(UIDENT);
				setState(355);
				match(LPAREN);
				setState(357);
				_errHandler.sync(this);
				_la = _input.LA(1);
				if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 8935187874567327936L) != 0)) {
					{
					setState(356);
					expression();
					}
				}

				setState(363);
				_errHandler.sync(this);
				_la = _input.LA(1);
				while (_la==COMMA) {
					{
					{
					setState(359);
					match(COMMA);
					setState(360);
					expression();
					}
					}
					setState(365);
					_errHandler.sync(this);
					_la = _input.LA(1);
				}
				setState(366);
				match(RPAREN);
				}
				break;
			case 2:
				enterOuterAlt(_localctx, 2);
				{
				setState(367);
				match(UIDENT);
				}
				break;
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class IfExpressionContext extends ParserRuleContext {
		public TerminalNode IF() { return getToken(LamaParser.IF, 0); }
		public List<ExpressionContext> expression() {
			return getRuleContexts(ExpressionContext.class);
		}
		public ExpressionContext expression(int i) {
			return getRuleContext(ExpressionContext.class,i);
		}
		public List<TerminalNode> THEN() { return getTokens(LamaParser.THEN); }
		public TerminalNode THEN(int i) {
			return getToken(LamaParser.THEN, i);
		}
		public List<ScopeExpressionContext> scopeExpression() {
			return getRuleContexts(ScopeExpressionContext.class);
		}
		public ScopeExpressionContext scopeExpression(int i) {
			return getRuleContext(ScopeExpressionContext.class,i);
		}
		public TerminalNode FI() { return getToken(LamaParser.FI, 0); }
		public List<TerminalNode> ELIF() { return getTokens(LamaParser.ELIF); }
		public TerminalNode ELIF(int i) {
			return getToken(LamaParser.ELIF, i);
		}
		public TerminalNode ELSE() { return getToken(LamaParser.ELSE, 0); }
		public IfExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_ifExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitIfExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final IfExpressionContext ifExpression() throws RecognitionException {
		IfExpressionContext _localctx = new IfExpressionContext(_ctx, getState());
		enterRule(_localctx, 56, RULE_ifExpression);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(370);
			match(IF);
			setState(371);
			expression();
			setState(372);
			match(THEN);
			setState(373);
			scopeExpression();
			setState(381);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==ELIF) {
				{
				{
				setState(374);
				match(ELIF);
				setState(375);
				expression();
				setState(376);
				match(THEN);
				setState(377);
				scopeExpression();
				}
				}
				setState(383);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			setState(386);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==ELSE) {
				{
				setState(384);
				match(ELSE);
				setState(385);
				scopeExpression();
				}
			}

			setState(388);
			match(FI);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class LetExpressionContext extends ParserRuleContext {
		public TerminalNode LET() { return getToken(LamaParser.LET, 0); }
		public PatternContext pattern() {
			return getRuleContext(PatternContext.class,0);
		}
		public List<ExpressionContext> expression() {
			return getRuleContexts(ExpressionContext.class);
		}
		public ExpressionContext expression(int i) {
			return getRuleContext(ExpressionContext.class,i);
		}
		public TerminalNode IN() { return getToken(LamaParser.IN, 0); }
		public LetExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_letExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitLetExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LetExpressionContext letExpression() throws RecognitionException {
		LetExpressionContext _localctx = new LetExpressionContext(_ctx, getState());
		enterRule(_localctx, 58, RULE_letExpression);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(390);
			match(LET);
			setState(391);
			pattern(0);
			setState(392);
			match(T__0);
			setState(393);
			expression();
			setState(394);
			match(IN);
			setState(395);
			expression();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class CaseExpressionContext extends ParserRuleContext {
		public TerminalNode CASE() { return getToken(LamaParser.CASE, 0); }
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public TerminalNode OF() { return getToken(LamaParser.OF, 0); }
		public TerminalNode ESAC() { return getToken(LamaParser.ESAC, 0); }
		public List<CaseBranchContext> caseBranch() {
			return getRuleContexts(CaseBranchContext.class);
		}
		public CaseBranchContext caseBranch(int i) {
			return getRuleContext(CaseBranchContext.class,i);
		}
		public CaseExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_caseExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitCaseExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final CaseExpressionContext caseExpression() throws RecognitionException {
		CaseExpressionContext _localctx = new CaseExpressionContext(_ctx, getState());
		enterRule(_localctx, 60, RULE_caseExpression);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(397);
			match(CASE);
			setState(398);
			expression();
			setState(399);
			match(OF);
			setState(401); 
			_errHandler.sync(this);
			_la = _input.LA(1);
			do {
				{
				{
				setState(400);
				caseBranch();
				}
				}
				setState(403); 
				_errHandler.sync(this);
				_la = _input.LA(1);
			} while ( (((_la) & ~0x3f) == 0 && ((1L << _la) & 9221166416542040064L) != 0) );
			setState(405);
			match(ESAC);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class CaseBranchContext extends ParserRuleContext {
		public List<PatternContext> pattern() {
			return getRuleContexts(PatternContext.class);
		}
		public PatternContext pattern(int i) {
			return getRuleContext(PatternContext.class,i);
		}
		public List<TerminalNode> ARROW() { return getTokens(LamaParser.ARROW); }
		public TerminalNode ARROW(int i) {
			return getToken(LamaParser.ARROW, i);
		}
		public List<ExpressionContext> expression() {
			return getRuleContexts(ExpressionContext.class);
		}
		public ExpressionContext expression(int i) {
			return getRuleContext(ExpressionContext.class,i);
		}
		public CaseBranchContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_caseBranch; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitCaseBranch(this);
			else return visitor.visitChildren(this);
		}
	}

	public final CaseBranchContext caseBranch() throws RecognitionException {
		CaseBranchContext _localctx = new CaseBranchContext(_ctx, getState());
		enterRule(_localctx, 62, RULE_caseBranch);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(407);
			pattern(0);
			setState(408);
			match(ARROW);
			setState(409);
			expression();
			setState(417);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==T__2) {
				{
				{
				setState(410);
				match(T__2);
				setState(411);
				pattern(0);
				setState(412);
				match(ARROW);
				setState(413);
				expression();
				}
				}
				setState(419);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class LoopExpressionContext extends ParserRuleContext {
		public WhileLoopContext whileLoop() {
			return getRuleContext(WhileLoopContext.class,0);
		}
		public DoWhileLoopContext doWhileLoop() {
			return getRuleContext(DoWhileLoopContext.class,0);
		}
		public ForLoopContext forLoop() {
			return getRuleContext(ForLoopContext.class,0);
		}
		public LoopExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_loopExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitLoopExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LoopExpressionContext loopExpression() throws RecognitionException {
		LoopExpressionContext _localctx = new LoopExpressionContext(_ctx, getState());
		enterRule(_localctx, 64, RULE_loopExpression);
		try {
			setState(423);
			_errHandler.sync(this);
			switch (_input.LA(1)) {
			case WHILE:
				enterOuterAlt(_localctx, 1);
				{
				setState(420);
				whileLoop();
				}
				break;
			case DO:
				enterOuterAlt(_localctx, 2);
				{
				setState(421);
				doWhileLoop();
				}
				break;
			case FOR:
				enterOuterAlt(_localctx, 3);
				{
				setState(422);
				forLoop();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class WhileLoopContext extends ParserRuleContext {
		public TerminalNode WHILE() { return getToken(LamaParser.WHILE, 0); }
		public SequenceExpressionContext sequenceExpression() {
			return getRuleContext(SequenceExpressionContext.class,0);
		}
		public TerminalNode DO() { return getToken(LamaParser.DO, 0); }
		public ScopeExpressionContext scopeExpression() {
			return getRuleContext(ScopeExpressionContext.class,0);
		}
		public TerminalNode OD() { return getToken(LamaParser.OD, 0); }
		public WhileLoopContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_whileLoop; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitWhileLoop(this);
			else return visitor.visitChildren(this);
		}
	}

	public final WhileLoopContext whileLoop() throws RecognitionException {
		WhileLoopContext _localctx = new WhileLoopContext(_ctx, getState());
		enterRule(_localctx, 66, RULE_whileLoop);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(425);
			match(WHILE);
			setState(426);
			sequenceExpression();
			setState(427);
			match(DO);
			setState(428);
			scopeExpression();
			setState(429);
			match(OD);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class DoWhileLoopContext extends ParserRuleContext {
		public TerminalNode DO() { return getToken(LamaParser.DO, 0); }
		public ScopeExpressionContext scopeExpression() {
			return getRuleContext(ScopeExpressionContext.class,0);
		}
		public TerminalNode WHILE() { return getToken(LamaParser.WHILE, 0); }
		public SequenceExpressionContext sequenceExpression() {
			return getRuleContext(SequenceExpressionContext.class,0);
		}
		public TerminalNode OD() { return getToken(LamaParser.OD, 0); }
		public DoWhileLoopContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_doWhileLoop; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitDoWhileLoop(this);
			else return visitor.visitChildren(this);
		}
	}

	public final DoWhileLoopContext doWhileLoop() throws RecognitionException {
		DoWhileLoopContext _localctx = new DoWhileLoopContext(_ctx, getState());
		enterRule(_localctx, 68, RULE_doWhileLoop);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(431);
			match(DO);
			setState(432);
			scopeExpression();
			setState(433);
			match(WHILE);
			setState(434);
			sequenceExpression();
			setState(435);
			match(OD);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ForLoopContext extends ParserRuleContext {
		public TerminalNode FOR() { return getToken(LamaParser.FOR, 0); }
		public List<TerminalNode> COMMA() { return getTokens(LamaParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(LamaParser.COMMA, i);
		}
		public TerminalNode DO() { return getToken(LamaParser.DO, 0); }
		public ScopeExpressionContext scopeExpression() {
			return getRuleContext(ScopeExpressionContext.class,0);
		}
		public TerminalNode OD() { return getToken(LamaParser.OD, 0); }
		public ForInitContext forInit() {
			return getRuleContext(ForInitContext.class,0);
		}
		public ExpressionContext expression() {
			return getRuleContext(ExpressionContext.class,0);
		}
		public ForStepContext forStep() {
			return getRuleContext(ForStepContext.class,0);
		}
		public ForLoopContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_forLoop; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitForLoop(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ForLoopContext forLoop() throws RecognitionException {
		ForLoopContext _localctx = new ForLoopContext(_ctx, getState());
		enterRule(_localctx, 70, RULE_forLoop);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(437);
			match(FOR);
			setState(439);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,44,_ctx) ) {
			case 1:
				{
				setState(438);
				forInit();
				}
				break;
			}
			setState(441);
			match(COMMA);
			setState(443);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 8935187874567327936L) != 0)) {
				{
				setState(442);
				expression();
				}
			}

			setState(445);
			match(COMMA);
			setState(447);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,46,_ctx) ) {
			case 1:
				{
				setState(446);
				forStep();
				}
				break;
			}
			setState(449);
			match(DO);
			setState(450);
			scopeExpression();
			setState(451);
			match(OD);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ForInitContext extends ParserRuleContext {
		public ScopeExpressionContext scopeExpression() {
			return getRuleContext(ScopeExpressionContext.class,0);
		}
		public ForInitContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_forInit; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitForInit(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ForInitContext forInit() throws RecognitionException {
		ForInitContext _localctx = new ForInitContext(_ctx, getState());
		enterRule(_localctx, 72, RULE_forInit);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(453);
			scopeExpression();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ForStepContext extends ParserRuleContext {
		public AssignExpressionContext assignExpression() {
			return getRuleContext(AssignExpressionContext.class,0);
		}
		public ForStepContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_forStep; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitForStep(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ForStepContext forStep() throws RecognitionException {
		ForStepContext _localctx = new ForStepContext(_ctx, getState());
		enterRule(_localctx, 74, RULE_forStep);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(455);
			assignExpression();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class LambdaExpressionContext extends ParserRuleContext {
		public TerminalNode FUN() { return getToken(LamaParser.FUN, 0); }
		public TerminalNode LPAREN() { return getToken(LamaParser.LPAREN, 0); }
		public TerminalNode RPAREN() { return getToken(LamaParser.RPAREN, 0); }
		public TerminalNode LBRACE() { return getToken(LamaParser.LBRACE, 0); }
		public ScopeExpressionContext scopeExpression() {
			return getRuleContext(ScopeExpressionContext.class,0);
		}
		public TerminalNode RBRACE() { return getToken(LamaParser.RBRACE, 0); }
		public PatternListContext patternList() {
			return getRuleContext(PatternListContext.class,0);
		}
		public LambdaExpressionContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_lambdaExpression; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitLambdaExpression(this);
			else return visitor.visitChildren(this);
		}
	}

	public final LambdaExpressionContext lambdaExpression() throws RecognitionException {
		LambdaExpressionContext _localctx = new LambdaExpressionContext(_ctx, getState());
		enterRule(_localctx, 76, RULE_lambdaExpression);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(457);
			match(FUN);
			setState(458);
			match(LPAREN);
			setState(460);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if ((((_la) & ~0x3f) == 0 && ((1L << _la) & 9221166416542040064L) != 0)) {
				{
				setState(459);
				patternList();
				}
			}

			setState(462);
			match(RPAREN);
			setState(463);
			match(LBRACE);
			setState(464);
			scopeExpression();
			setState(465);
			match(RBRACE);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	@SuppressWarnings("CheckReturnValue")
	public static class ArgumentListContext extends ParserRuleContext {
		public List<ExpressionContext> expression() {
			return getRuleContexts(ExpressionContext.class);
		}
		public ExpressionContext expression(int i) {
			return getRuleContext(ExpressionContext.class,i);
		}
		public List<TerminalNode> COMMA() { return getTokens(LamaParser.COMMA); }
		public TerminalNode COMMA(int i) {
			return getToken(LamaParser.COMMA, i);
		}
		public ArgumentListContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_argumentList; }
		@Override
		public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
			if ( visitor instanceof LamaVisitor ) return ((LamaVisitor<? extends T>)visitor).visitArgumentList(this);
			else return visitor.visitChildren(this);
		}
	}

	public final ArgumentListContext argumentList() throws RecognitionException {
		ArgumentListContext _localctx = new ArgumentListContext(_ctx, getState());
		enterRule(_localctx, 78, RULE_argumentList);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(467);
			expression();
			setState(472);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==COMMA) {
				{
				{
				setState(468);
				match(COMMA);
				setState(469);
				expression();
				}
				}
				setState(474);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public boolean sempred(RuleContext _localctx, int ruleIndex, int predIndex) {
		switch (ruleIndex) {
		case 9:
			return pattern_sempred((PatternContext)_localctx, predIndex);
		case 21:
			return postfixExpression_sempred((PostfixExpressionContext)_localctx, predIndex);
		}
		return true;
	}
	private boolean pattern_sempred(PatternContext _localctx, int predIndex) {
		switch (predIndex) {
		case 0:
			return precpred(_ctx, 1);
		}
		return true;
	}
	private boolean postfixExpression_sempred(PostfixExpressionContext _localctx, int predIndex) {
		switch (predIndex) {
		case 1:
			return precpred(_ctx, 4);
		case 2:
			return precpred(_ctx, 3);
		case 3:
			return precpred(_ctx, 2);
		}
		return true;
	}

	public static final String _serializedATN =
		"\u0004\u0001A\u01dc\u0002\u0000\u0007\u0000\u0002\u0001\u0007\u0001\u0002"+
		"\u0002\u0007\u0002\u0002\u0003\u0007\u0003\u0002\u0004\u0007\u0004\u0002"+
		"\u0005\u0007\u0005\u0002\u0006\u0007\u0006\u0002\u0007\u0007\u0007\u0002"+
		"\b\u0007\b\u0002\t\u0007\t\u0002\n\u0007\n\u0002\u000b\u0007\u000b\u0002"+
		"\f\u0007\f\u0002\r\u0007\r\u0002\u000e\u0007\u000e\u0002\u000f\u0007\u000f"+
		"\u0002\u0010\u0007\u0010\u0002\u0011\u0007\u0011\u0002\u0012\u0007\u0012"+
		"\u0002\u0013\u0007\u0013\u0002\u0014\u0007\u0014\u0002\u0015\u0007\u0015"+
		"\u0002\u0016\u0007\u0016\u0002\u0017\u0007\u0017\u0002\u0018\u0007\u0018"+
		"\u0002\u0019\u0007\u0019\u0002\u001a\u0007\u001a\u0002\u001b\u0007\u001b"+
		"\u0002\u001c\u0007\u001c\u0002\u001d\u0007\u001d\u0002\u001e\u0007\u001e"+
		"\u0002\u001f\u0007\u001f\u0002 \u0007 \u0002!\u0007!\u0002\"\u0007\"\u0002"+
		"#\u0007#\u0002$\u0007$\u0002%\u0007%\u0002&\u0007&\u0002\'\u0007\'\u0001"+
		"\u0000\u0005\u0000R\b\u0000\n\u0000\f\u0000U\t\u0000\u0001\u0000\u0001"+
		"\u0000\u0001\u0000\u0001\u0001\u0005\u0001[\b\u0001\n\u0001\f\u0001^\t"+
		"\u0001\u0001\u0001\u0001\u0001\u0001\u0002\u0001\u0002\u0001\u0002\u0001"+
		"\u0002\u0005\u0002f\b\u0002\n\u0002\f\u0002i\t\u0002\u0001\u0002\u0003"+
		"\u0002l\b\u0002\u0001\u0003\u0005\u0003o\b\u0003\n\u0003\f\u0003r\t\u0003"+
		"\u0001\u0003\u0003\u0003u\b\u0003\u0001\u0004\u0001\u0004\u0003\u0004"+
		"y\b\u0004\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0005\u0005"+
		"\u007f\b\u0005\n\u0005\f\u0005\u0082\t\u0005\u0001\u0005\u0003\u0005\u0085"+
		"\b\u0005\u0001\u0006\u0001\u0006\u0001\u0006\u0003\u0006\u008a\b\u0006"+
		"\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0003\u0007\u0090\b\u0007"+
		"\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0003\u0007"+
		"\u0097\b\u0007\u0001\b\u0001\b\u0001\b\u0005\b\u009c\b\b\n\b\f\b\u009f"+
		"\t\b\u0001\t\u0001\t\u0001\t\u0001\t\u0001\t\u0001\t\u0001\t\u0001\t\u0001"+
		"\t\u0001\t\u0001\t\u0001\t\u0001\t\u0001\t\u0003\t\u00af\b\t\u0001\t\u0001"+
		"\t\u0001\t\u0001\t\u0003\t\u00b5\b\t\u0001\t\u0001\t\u0001\t\u0003\t\u00ba"+
		"\b\t\u0001\t\u0001\t\u0001\t\u0001\t\u0001\t\u0001\t\u0001\t\u0001\t\u0001"+
		"\t\u0001\t\u0001\t\u0003\t\u00c7\b\t\u0001\t\u0001\t\u0001\t\u0005\t\u00cc"+
		"\b\t\n\t\f\t\u00cf\t\t\u0001\n\u0001\n\u0001\u000b\u0001\u000b\u0001\u000b"+
		"\u0005\u000b\u00d6\b\u000b\n\u000b\f\u000b\u00d9\t\u000b\u0001\f\u0001"+
		"\f\u0001\f\u0003\f\u00de\b\f\u0001\r\u0001\r\u0001\r\u0003\r\u00e3\b\r"+
		"\u0001\u000e\u0001\u000e\u0001\u000e\u0005\u000e\u00e8\b\u000e\n\u000e"+
		"\f\u000e\u00eb\t\u000e\u0001\u000f\u0001\u000f\u0001\u000f\u0005\u000f"+
		"\u00f0\b\u000f\n\u000f\f\u000f\u00f3\t\u000f\u0001\u0010\u0001\u0010\u0001"+
		"\u0010\u0005\u0010\u00f8\b\u0010\n\u0010\f\u0010\u00fb\t\u0010\u0001\u0011"+
		"\u0001\u0011\u0001\u0011\u0005\u0011\u0100\b\u0011\n\u0011\f\u0011\u0103"+
		"\t\u0011\u0001\u0012\u0001\u0012\u0001\u0012\u0005\u0012\u0108\b\u0012"+
		"\n\u0012\f\u0012\u010b\t\u0012\u0001\u0013\u0001\u0013\u0001\u0013\u0005"+
		"\u0013\u0110\b\u0013\n\u0013\f\u0013\u0113\t\u0013\u0001\u0014\u0003\u0014"+
		"\u0116\b\u0014\u0001\u0014\u0001\u0014\u0001\u0015\u0001\u0015\u0001\u0015"+
		"\u0001\u0015\u0001\u0015\u0001\u0015\u0003\u0015\u0120\b\u0015\u0001\u0015"+
		"\u0001\u0015\u0001\u0015\u0001\u0015\u0001\u0015\u0001\u0015\u0001\u0015"+
		"\u0001\u0015\u0001\u0015\u0005\u0015\u012b\b\u0015\n\u0015\f\u0015\u012e"+
		"\t\u0015\u0001\u0016\u0001\u0016\u0001\u0016\u0001\u0016\u0001\u0016\u0001"+
		"\u0016\u0001\u0016\u0001\u0016\u0001\u0016\u0001\u0016\u0001\u0016\u0001"+
		"\u0016\u0001\u0016\u0001\u0016\u0001\u0016\u0003\u0016\u013f\b\u0016\u0001"+
		"\u0017\u0001\u0017\u0001\u0018\u0001\u0018\u0001\u0019\u0001\u0019\u0001"+
		"\u0019\u0001\u0019\u0001\u0019\u0001\u0019\u0005\u0019\u014b\b\u0019\n"+
		"\u0019\f\u0019\u014e\t\u0019\u0001\u0019\u0001\u0019\u0003\u0019\u0152"+
		"\b\u0019\u0001\u001a\u0001\u001a\u0001\u001a\u0001\u001a\u0001\u001a\u0001"+
		"\u001a\u0005\u001a\u015a\b\u001a\n\u001a\f\u001a\u015d\t\u001a\u0001\u001a"+
		"\u0001\u001a\u0003\u001a\u0161\b\u001a\u0001\u001b\u0001\u001b\u0001\u001b"+
		"\u0003\u001b\u0166\b\u001b\u0001\u001b\u0001\u001b\u0005\u001b\u016a\b"+
		"\u001b\n\u001b\f\u001b\u016d\t\u001b\u0001\u001b\u0001\u001b\u0003\u001b"+
		"\u0171\b\u001b\u0001\u001c\u0001\u001c\u0001\u001c\u0001\u001c\u0001\u001c"+
		"\u0001\u001c\u0001\u001c\u0001\u001c\u0001\u001c\u0005\u001c\u017c\b\u001c"+
		"\n\u001c\f\u001c\u017f\t\u001c\u0001\u001c\u0001\u001c\u0003\u001c\u0183"+
		"\b\u001c\u0001\u001c\u0001\u001c\u0001\u001d\u0001\u001d\u0001\u001d\u0001"+
		"\u001d\u0001\u001d\u0001\u001d\u0001\u001d\u0001\u001e\u0001\u001e\u0001"+
		"\u001e\u0001\u001e\u0004\u001e\u0192\b\u001e\u000b\u001e\f\u001e\u0193"+
		"\u0001\u001e\u0001\u001e\u0001\u001f\u0001\u001f\u0001\u001f\u0001\u001f"+
		"\u0001\u001f\u0001\u001f\u0001\u001f\u0001\u001f\u0005\u001f\u01a0\b\u001f"+
		"\n\u001f\f\u001f\u01a3\t\u001f\u0001 \u0001 \u0001 \u0003 \u01a8\b \u0001"+
		"!\u0001!\u0001!\u0001!\u0001!\u0001!\u0001\"\u0001\"\u0001\"\u0001\"\u0001"+
		"\"\u0001\"\u0001#\u0001#\u0003#\u01b8\b#\u0001#\u0001#\u0003#\u01bc\b"+
		"#\u0001#\u0001#\u0003#\u01c0\b#\u0001#\u0001#\u0001#\u0001#\u0001$\u0001"+
		"$\u0001%\u0001%\u0001&\u0001&\u0001&\u0003&\u01cd\b&\u0001&\u0001&\u0001"+
		"&\u0001&\u0001&\u0001\'\u0001\'\u0001\'\u0005\'\u01d7\b\'\n\'\f\'\u01da"+
		"\t\'\u0001\'\u0000\u0002\u0012*(\u0000\u0002\u0004\u0006\b\n\f\u000e\u0010"+
		"\u0012\u0014\u0016\u0018\u001a\u001c\u001e \"$&(*,.02468:<>@BDFHJLN\u0000"+
		"\u0006\u0001\u0000\u001c\u001d\u0001\u0000\u001e!\u0001\u0000\"#\u0001"+
		"\u0000$&\u0002\u0000\u0016\u0017<>\u0001\u0000:;\u0201\u0000S\u0001\u0000"+
		"\u0000\u0000\u0002\\\u0001\u0000\u0000\u0000\u0004a\u0001\u0000\u0000"+
		"\u0000\u0006p\u0001\u0000\u0000\u0000\bx\u0001\u0000\u0000\u0000\nz\u0001"+
		"\u0000\u0000\u0000\f\u0086\u0001\u0000\u0000\u0000\u000e\u008b\u0001\u0000"+
		"\u0000\u0000\u0010\u0098\u0001\u0000\u0000\u0000\u0012\u00c6\u0001\u0000"+
		"\u0000\u0000\u0014\u00d0\u0001\u0000\u0000\u0000\u0016\u00d2\u0001\u0000"+
		"\u0000\u0000\u0018\u00da\u0001\u0000\u0000\u0000\u001a\u00df\u0001\u0000"+
		"\u0000\u0000\u001c\u00e4\u0001\u0000\u0000\u0000\u001e\u00ec\u0001\u0000"+
		"\u0000\u0000 \u00f4\u0001\u0000\u0000\u0000\"\u00fc\u0001\u0000\u0000"+
		"\u0000$\u0104\u0001\u0000\u0000\u0000&\u010c\u0001\u0000\u0000\u0000("+
		"\u0115\u0001\u0000\u0000\u0000*\u0119\u0001\u0000\u0000\u0000,\u013e\u0001"+
		"\u0000\u0000\u0000.\u0140\u0001\u0000\u0000\u00000\u0142\u0001\u0000\u0000"+
		"\u00002\u0151\u0001\u0000\u0000\u00004\u0160\u0001\u0000\u0000\u00006"+
		"\u0170\u0001\u0000\u0000\u00008\u0172\u0001\u0000\u0000\u0000:\u0186\u0001"+
		"\u0000\u0000\u0000<\u018d\u0001\u0000\u0000\u0000>\u0197\u0001\u0000\u0000"+
		"\u0000@\u01a7\u0001\u0000\u0000\u0000B\u01a9\u0001\u0000\u0000\u0000D"+
		"\u01af\u0001\u0000\u0000\u0000F\u01b5\u0001\u0000\u0000\u0000H\u01c5\u0001"+
		"\u0000\u0000\u0000J\u01c7\u0001\u0000\u0000\u0000L\u01c9\u0001\u0000\u0000"+
		"\u0000N\u01d3\u0001\u0000\u0000\u0000PR\u0003\u0004\u0002\u0000QP\u0001"+
		"\u0000\u0000\u0000RU\u0001\u0000\u0000\u0000SQ\u0001\u0000\u0000\u0000"+
		"ST\u0001\u0000\u0000\u0000TV\u0001\u0000\u0000\u0000US\u0001\u0000\u0000"+
		"\u0000VW\u0003\u0002\u0001\u0000WX\u0005\u0000\u0000\u0001X\u0001\u0001"+
		"\u0000\u0000\u0000Y[\u0003\b\u0004\u0000ZY\u0001\u0000\u0000\u0000[^\u0001"+
		"\u0000\u0000\u0000\\Z\u0001\u0000\u0000\u0000\\]\u0001\u0000\u0000\u0000"+
		"]_\u0001\u0000\u0000\u0000^\\\u0001\u0000\u0000\u0000_`\u0003\u0014\n"+
		"\u0000`\u0003\u0001\u0000\u0000\u0000ab\u0005\u0004\u0000\u0000bg\u0005"+
		";\u0000\u0000cd\u0005/\u0000\u0000df\u0005;\u0000\u0000ec\u0001\u0000"+
		"\u0000\u0000fi\u0001\u0000\u0000\u0000ge\u0001\u0000\u0000\u0000gh\u0001"+
		"\u0000\u0000\u0000hk\u0001\u0000\u0000\u0000ig\u0001\u0000\u0000\u0000"+
		"jl\u00050\u0000\u0000kj\u0001\u0000\u0000\u0000kl\u0001\u0000\u0000\u0000"+
		"l\u0005\u0001\u0000\u0000\u0000mo\u0003\b\u0004\u0000nm\u0001\u0000\u0000"+
		"\u0000or\u0001\u0000\u0000\u0000pn\u0001\u0000\u0000\u0000pq\u0001\u0000"+
		"\u0000\u0000qt\u0001\u0000\u0000\u0000rp\u0001\u0000\u0000\u0000su\u0003"+
		"\u0014\n\u0000ts\u0001\u0000\u0000\u0000tu\u0001\u0000\u0000\u0000u\u0007"+
		"\u0001\u0000\u0000\u0000vy\u0003\n\u0005\u0000wy\u0003\u000e\u0007\u0000"+
		"xv\u0001\u0000\u0000\u0000xw\u0001\u0000\u0000\u0000y\t\u0001\u0000\u0000"+
		"\u0000z{\u0005\u0005\u0000\u0000{\u0080\u0003\f\u0006\u0000|}\u0005/\u0000"+
		"\u0000}\u007f\u0003\f\u0006\u0000~|\u0001\u0000\u0000\u0000\u007f\u0082"+
		"\u0001\u0000\u0000\u0000\u0080~\u0001\u0000\u0000\u0000\u0080\u0081\u0001"+
		"\u0000\u0000\u0000\u0081\u0084\u0001\u0000\u0000\u0000\u0082\u0080\u0001"+
		"\u0000\u0000\u0000\u0083\u0085\u00050\u0000\u0000\u0084\u0083\u0001\u0000"+
		"\u0000\u0000\u0084\u0085\u0001\u0000\u0000\u0000\u0085\u000b\u0001\u0000"+
		"\u0000\u0000\u0086\u0089\u0005;\u0000\u0000\u0087\u0088\u0005\u0001\u0000"+
		"\u0000\u0088\u008a\u0003\u0018\f\u0000\u0089\u0087\u0001\u0000\u0000\u0000"+
		"\u0089\u008a\u0001\u0000\u0000\u0000\u008a\r\u0001\u0000\u0000\u0000\u008b"+
		"\u008c\u0005\u0006\u0000\u0000\u008c\u008d\u0005;\u0000\u0000\u008d\u008f"+
		"\u0005)\u0000\u0000\u008e\u0090\u0003\u0010\b\u0000\u008f\u008e\u0001"+
		"\u0000\u0000\u0000\u008f\u0090\u0001\u0000\u0000\u0000\u0090\u0091\u0001"+
		"\u0000\u0000\u0000\u0091\u0092\u0005*\u0000\u0000\u0092\u0093\u0005-\u0000"+
		"\u0000\u0093\u0094\u0003\u0006\u0003\u0000\u0094\u0096\u0005.\u0000\u0000"+
		"\u0095\u0097\u00050\u0000\u0000\u0096\u0095\u0001\u0000\u0000\u0000\u0096"+
		"\u0097\u0001\u0000\u0000\u0000\u0097\u000f\u0001\u0000\u0000\u0000\u0098"+
		"\u009d\u0003\u0012\t\u0000\u0099\u009a\u0005/\u0000\u0000\u009a\u009c"+
		"\u0003\u0012\t\u0000\u009b\u0099\u0001\u0000\u0000\u0000\u009c\u009f\u0001"+
		"\u0000\u0000\u0000\u009d\u009b\u0001\u0000\u0000\u0000\u009d\u009e\u0001"+
		"\u0000\u0000\u0000\u009e\u0011\u0001\u0000\u0000\u0000\u009f\u009d\u0001"+
		"\u0000\u0000\u0000\u00a0\u00a1\u0006\t\uffff\uffff\u0000\u00a1\u00a2\u0005"+
		";\u0000\u0000\u00a2\u00a3\u0005\u0002\u0000\u0000\u00a3\u00c7\u0003\u0012"+
		"\t\u0014\u00a4\u00c7\u00054\u0000\u0000\u00a5\u00c7\u00055\u0000\u0000"+
		"\u00a6\u00c7\u00056\u0000\u0000\u00a7\u00c7\u00057\u0000\u0000\u00a8\u00c7"+
		"\u00058\u0000\u0000\u00a9\u00c7\u00059\u0000\u0000\u00aa\u00c7\u0005;"+
		"\u0000\u0000\u00ab\u00ac\u0005:\u0000\u0000\u00ac\u00ae\u0005)\u0000\u0000"+
		"\u00ad\u00af\u0003\u0010\b\u0000\u00ae\u00ad\u0001\u0000\u0000\u0000\u00ae"+
		"\u00af\u0001\u0000\u0000\u0000\u00af\u00b0\u0001\u0000\u0000\u0000\u00b0"+
		"\u00c7\u0005*\u0000\u0000\u00b1\u00c7\u0005:\u0000\u0000\u00b2\u00b4\u0005"+
		"+\u0000\u0000\u00b3\u00b5\u0003\u0010\b\u0000\u00b4\u00b3\u0001\u0000"+
		"\u0000\u0000\u00b4\u00b5\u0001\u0000\u0000\u0000\u00b5\u00b6\u0001\u0000"+
		"\u0000\u0000\u00b6\u00c7\u0005,\u0000\u0000\u00b7\u00b9\u0005-\u0000\u0000"+
		"\u00b8\u00ba\u0003\u0010\b\u0000\u00b9\u00b8\u0001\u0000\u0000\u0000\u00b9"+
		"\u00ba\u0001\u0000\u0000\u0000\u00ba\u00bb\u0001\u0000\u0000\u0000\u00bb"+
		"\u00c7\u0005.\u0000\u0000\u00bc\u00c7\u00053\u0000\u0000\u00bd\u00c7\u0005"+
		"<\u0000\u0000\u00be\u00c7\u0005=\u0000\u0000\u00bf\u00c7\u0005>\u0000"+
		"\u0000\u00c0\u00c7\u0005\u0016\u0000\u0000\u00c1\u00c7\u0005\u0017\u0000"+
		"\u0000\u00c2\u00c3\u0005)\u0000\u0000\u00c3\u00c4\u0003\u0012\t\u0000"+
		"\u00c4\u00c5\u0005*\u0000\u0000\u00c5\u00c7\u0001\u0000\u0000\u0000\u00c6"+
		"\u00a0\u0001\u0000\u0000\u0000\u00c6\u00a4\u0001\u0000\u0000\u0000\u00c6"+
		"\u00a5\u0001\u0000\u0000\u0000\u00c6\u00a6\u0001\u0000\u0000\u0000\u00c6"+
		"\u00a7\u0001\u0000\u0000\u0000\u00c6\u00a8\u0001\u0000\u0000\u0000\u00c6"+
		"\u00a9\u0001\u0000\u0000\u0000\u00c6\u00aa\u0001\u0000\u0000\u0000\u00c6"+
		"\u00ab\u0001\u0000\u0000\u0000\u00c6\u00b1\u0001\u0000\u0000\u0000\u00c6"+
		"\u00b2\u0001\u0000\u0000\u0000\u00c6\u00b7\u0001\u0000\u0000\u0000\u00c6"+
		"\u00bc\u0001\u0000\u0000\u0000\u00c6\u00bd\u0001\u0000\u0000\u0000\u00c6"+
		"\u00be\u0001\u0000\u0000\u0000\u00c6\u00bf\u0001\u0000\u0000\u0000\u00c6"+
		"\u00c0\u0001\u0000\u0000\u0000\u00c6\u00c1\u0001\u0000\u0000\u0000\u00c6"+
		"\u00c2\u0001\u0000\u0000\u0000\u00c7\u00cd\u0001\u0000\u0000\u0000\u00c8"+
		"\u00c9\n\u0001\u0000\u0000\u00c9\u00ca\u00051\u0000\u0000\u00ca\u00cc"+
		"\u0003\u0012\t\u0001\u00cb\u00c8\u0001\u0000\u0000\u0000\u00cc\u00cf\u0001"+
		"\u0000\u0000\u0000\u00cd\u00cb\u0001\u0000\u0000\u0000\u00cd\u00ce\u0001"+
		"\u0000\u0000\u0000\u00ce\u0013\u0001\u0000\u0000\u0000\u00cf\u00cd\u0001"+
		"\u0000\u0000\u0000\u00d0\u00d1\u0003\u0016\u000b\u0000\u00d1\u0015\u0001"+
		"\u0000\u0000\u0000\u00d2\u00d7\u0003\u0018\f\u0000\u00d3\u00d4\u00050"+
		"\u0000\u0000\u00d4\u00d6\u0003\u0018\f\u0000\u00d5\u00d3\u0001\u0000\u0000"+
		"\u0000\u00d6\u00d9\u0001\u0000\u0000\u0000\u00d7\u00d5\u0001\u0000\u0000"+
		"\u0000\u00d7\u00d8\u0001\u0000\u0000\u0000\u00d8\u0017\u0001\u0000\u0000"+
		"\u0000\u00d9\u00d7\u0001\u0000\u0000\u0000\u00da\u00dd\u0003\u001a\r\u0000"+
		"\u00db\u00dc\u0005\u0019\u0000\u0000\u00dc\u00de\u0003\u0018\f\u0000\u00dd"+
		"\u00db\u0001\u0000\u0000\u0000\u00dd\u00de\u0001\u0000\u0000\u0000\u00de"+
		"\u0019\u0001\u0000\u0000\u0000\u00df\u00e2\u0003\u001c\u000e\u0000\u00e0"+
		"\u00e1\u00051\u0000\u0000\u00e1\u00e3\u0003\u001a\r\u0000\u00e2\u00e0"+
		"\u0001\u0000\u0000\u0000\u00e2\u00e3\u0001\u0000\u0000\u0000\u00e3\u001b"+
		"\u0001\u0000\u0000\u0000\u00e4\u00e9\u0003\u001e\u000f\u0000\u00e5\u00e6"+
		"\u0005\u001a\u0000\u0000\u00e6\u00e8\u0003\u001e\u000f\u0000\u00e7\u00e5"+
		"\u0001\u0000\u0000\u0000\u00e8\u00eb\u0001\u0000\u0000\u0000\u00e9\u00e7"+
		"\u0001\u0000\u0000\u0000\u00e9\u00ea\u0001\u0000\u0000\u0000\u00ea\u001d"+
		"\u0001\u0000\u0000\u0000\u00eb\u00e9\u0001\u0000\u0000\u0000\u00ec\u00f1"+
		"\u0003 \u0010\u0000\u00ed\u00ee\u0005\u001b\u0000\u0000\u00ee\u00f0\u0003"+
		" \u0010\u0000\u00ef\u00ed\u0001\u0000\u0000\u0000\u00f0\u00f3\u0001\u0000"+
		"\u0000\u0000\u00f1\u00ef\u0001\u0000\u0000\u0000\u00f1\u00f2\u0001\u0000"+
		"\u0000\u0000\u00f2\u001f\u0001\u0000\u0000\u0000\u00f3\u00f1\u0001\u0000"+
		"\u0000\u0000\u00f4\u00f9\u0003\"\u0011\u0000\u00f5\u00f6\u0007\u0000\u0000"+
		"\u0000\u00f6\u00f8\u0003\"\u0011\u0000\u00f7\u00f5\u0001\u0000\u0000\u0000"+
		"\u00f8\u00fb\u0001\u0000\u0000\u0000\u00f9\u00f7\u0001\u0000\u0000\u0000"+
		"\u00f9\u00fa\u0001\u0000\u0000\u0000\u00fa!\u0001\u0000\u0000\u0000\u00fb"+
		"\u00f9\u0001\u0000\u0000\u0000\u00fc\u0101\u0003$\u0012\u0000\u00fd\u00fe"+
		"\u0007\u0001\u0000\u0000\u00fe\u0100\u0003$\u0012\u0000\u00ff\u00fd\u0001"+
		"\u0000\u0000\u0000\u0100\u0103\u0001\u0000\u0000\u0000\u0101\u00ff\u0001"+
		"\u0000\u0000\u0000\u0101\u0102\u0001\u0000\u0000\u0000\u0102#\u0001\u0000"+
		"\u0000\u0000\u0103\u0101\u0001\u0000\u0000\u0000\u0104\u0109\u0003&\u0013"+
		"\u0000\u0105\u0106\u0007\u0002\u0000\u0000\u0106\u0108\u0003&\u0013\u0000"+
		"\u0107\u0105\u0001\u0000\u0000\u0000\u0108\u010b\u0001\u0000\u0000\u0000"+
		"\u0109\u0107\u0001\u0000\u0000\u0000\u0109\u010a\u0001\u0000\u0000\u0000"+
		"\u010a%\u0001\u0000\u0000\u0000\u010b\u0109\u0001\u0000\u0000\u0000\u010c"+
		"\u0111\u0003(\u0014\u0000\u010d\u010e\u0007\u0003\u0000\u0000\u010e\u0110"+
		"\u0003(\u0014\u0000\u010f\u010d\u0001\u0000\u0000\u0000\u0110\u0113\u0001"+
		"\u0000\u0000\u0000\u0111\u010f\u0001\u0000\u0000\u0000\u0111\u0112\u0001"+
		"\u0000\u0000\u0000\u0112\'\u0001\u0000\u0000\u0000\u0113\u0111\u0001\u0000"+
		"\u0000\u0000\u0114\u0116\u0005#\u0000\u0000\u0115\u0114\u0001\u0000\u0000"+
		"\u0000\u0115\u0116\u0001\u0000\u0000\u0000\u0116\u0117\u0001\u0000\u0000"+
		"\u0000\u0117\u0118\u0003*\u0015\u0000\u0118)\u0001\u0000\u0000\u0000\u0119"+
		"\u011a\u0006\u0015\uffff\uffff\u0000\u011a\u011b\u0003,\u0016\u0000\u011b"+
		"\u012c\u0001\u0000\u0000\u0000\u011c\u011d\n\u0004\u0000\u0000\u011d\u011f"+
		"\u0005)\u0000\u0000\u011e\u0120\u0003N\'\u0000\u011f\u011e\u0001\u0000"+
		"\u0000\u0000\u011f\u0120\u0001\u0000\u0000\u0000\u0120\u0121\u0001\u0000"+
		"\u0000\u0000\u0121\u012b\u0005*\u0000\u0000\u0122\u0123\n\u0003\u0000"+
		"\u0000\u0123\u0124\u0005+\u0000\u0000\u0124\u0125\u0003\u0014\n\u0000"+
		"\u0125\u0126\u0005,\u0000\u0000\u0126\u012b\u0001\u0000\u0000\u0000\u0127"+
		"\u0128\n\u0002\u0000\u0000\u0128\u0129\u0005(\u0000\u0000\u0129\u012b"+
		"\u0005;\u0000\u0000\u012a\u011c\u0001\u0000\u0000\u0000\u012a\u0122\u0001"+
		"\u0000\u0000\u0000\u012a\u0127\u0001\u0000\u0000\u0000\u012b\u012e\u0001"+
		"\u0000\u0000\u0000\u012c\u012a\u0001\u0000\u0000\u0000\u012c\u012d\u0001"+
		"\u0000\u0000\u0000\u012d+\u0001\u0000\u0000\u0000\u012e\u012c\u0001\u0000"+
		"\u0000\u0000\u012f\u013f\u0003.\u0017\u0000\u0130\u013f\u00036\u001b\u0000"+
		"\u0131\u013f\u00030\u0018\u0000\u0132\u0133\u0005)\u0000\u0000\u0133\u0134"+
		"\u0003\u0006\u0003\u0000\u0134\u0135\u0005*\u0000\u0000\u0135\u013f\u0001"+
		"\u0000\u0000\u0000\u0136\u013f\u00032\u0019\u0000\u0137\u013f\u00034\u001a"+
		"\u0000\u0138\u013f\u00038\u001c\u0000\u0139\u013f\u0003:\u001d\u0000\u013a"+
		"\u013f\u0003<\u001e\u0000\u013b\u013f\u0003@ \u0000\u013c\u013f\u0005"+
		"\u0015\u0000\u0000\u013d\u013f\u0003L&\u0000\u013e\u012f\u0001\u0000\u0000"+
		"\u0000\u013e\u0130\u0001\u0000\u0000\u0000\u013e\u0131\u0001\u0000\u0000"+
		"\u0000\u013e\u0132\u0001\u0000\u0000\u0000\u013e\u0136\u0001\u0000\u0000"+
		"\u0000\u013e\u0137\u0001\u0000\u0000\u0000\u013e\u0138\u0001\u0000\u0000"+
		"\u0000\u013e\u0139\u0001\u0000\u0000\u0000\u013e\u013a\u0001\u0000\u0000"+
		"\u0000\u013e\u013b\u0001\u0000\u0000\u0000\u013e\u013c\u0001\u0000\u0000"+
		"\u0000\u013e\u013d\u0001\u0000\u0000\u0000\u013f-\u0001\u0000\u0000\u0000"+
		"\u0140\u0141\u0007\u0004\u0000\u0000\u0141/\u0001\u0000\u0000\u0000\u0142"+
		"\u0143\u0007\u0005\u0000\u0000\u01431\u0001\u0000\u0000\u0000\u0144\u0145"+
		"\u0005+\u0000\u0000\u0145\u0152\u0005,\u0000\u0000\u0146\u0147\u0005+"+
		"\u0000\u0000\u0147\u014c\u0003\u0014\n\u0000\u0148\u0149\u0005/\u0000"+
		"\u0000\u0149\u014b\u0003\u0014\n\u0000\u014a\u0148\u0001\u0000\u0000\u0000"+
		"\u014b\u014e\u0001\u0000\u0000\u0000\u014c\u014a\u0001\u0000\u0000\u0000"+
		"\u014c\u014d\u0001\u0000\u0000\u0000\u014d\u014f\u0001\u0000\u0000\u0000"+
		"\u014e\u014c\u0001\u0000\u0000\u0000\u014f\u0150\u0005,\u0000\u0000\u0150"+
		"\u0152\u0001\u0000\u0000\u0000\u0151\u0144\u0001\u0000\u0000\u0000\u0151"+
		"\u0146\u0001\u0000\u0000\u0000\u01523\u0001\u0000\u0000\u0000\u0153\u0154"+
		"\u0005-\u0000\u0000\u0154\u0161\u0005.\u0000\u0000\u0155\u0156\u0005-"+
		"\u0000\u0000\u0156\u015b\u0003\u0014\n\u0000\u0157\u0158\u0005/\u0000"+
		"\u0000\u0158\u015a\u0003\u0014\n\u0000\u0159\u0157\u0001\u0000\u0000\u0000"+
		"\u015a\u015d\u0001\u0000\u0000\u0000\u015b\u0159\u0001\u0000\u0000\u0000"+
		"\u015b\u015c\u0001\u0000\u0000\u0000\u015c\u015e\u0001\u0000\u0000\u0000"+
		"\u015d\u015b\u0001\u0000\u0000\u0000\u015e\u015f\u0005.\u0000\u0000\u015f"+
		"\u0161\u0001\u0000\u0000\u0000\u0160\u0153\u0001\u0000\u0000\u0000\u0160"+
		"\u0155\u0001\u0000\u0000\u0000\u01615\u0001\u0000\u0000\u0000\u0162\u0163"+
		"\u0005:\u0000\u0000\u0163\u0165\u0005)\u0000\u0000\u0164\u0166\u0003\u0014"+
		"\n\u0000\u0165\u0164\u0001\u0000\u0000\u0000\u0165\u0166\u0001\u0000\u0000"+
		"\u0000\u0166\u016b\u0001\u0000\u0000\u0000\u0167\u0168\u0005/\u0000\u0000"+
		"\u0168\u016a\u0003\u0014\n\u0000\u0169\u0167\u0001\u0000\u0000\u0000\u016a"+
		"\u016d\u0001\u0000\u0000\u0000\u016b\u0169\u0001\u0000\u0000\u0000\u016b"+
		"\u016c\u0001\u0000\u0000\u0000\u016c\u016e\u0001\u0000\u0000\u0000\u016d"+
		"\u016b\u0001\u0000\u0000\u0000\u016e\u0171\u0005*\u0000\u0000\u016f\u0171"+
		"\u0005:\u0000\u0000\u0170\u0162\u0001\u0000\u0000\u0000\u0170\u016f\u0001"+
		"\u0000\u0000\u0000\u01717\u0001\u0000\u0000\u0000\u0172\u0173\u0005\u0007"+
		"\u0000\u0000\u0173\u0174\u0003\u0014\n\u0000\u0174\u0175\u0005\b\u0000"+
		"\u0000\u0175\u017d\u0003\u0006\u0003\u0000\u0176\u0177\u0005\u000b\u0000"+
		"\u0000\u0177\u0178\u0003\u0014\n\u0000\u0178\u0179\u0005\b\u0000\u0000"+
		"\u0179\u017a\u0003\u0006\u0003\u0000\u017a\u017c\u0001\u0000\u0000\u0000"+
		"\u017b\u0176\u0001\u0000\u0000\u0000\u017c\u017f\u0001\u0000\u0000\u0000"+
		"\u017d\u017b\u0001\u0000\u0000\u0000\u017d\u017e\u0001\u0000\u0000\u0000"+
		"\u017e\u0182\u0001\u0000\u0000\u0000\u017f\u017d\u0001\u0000\u0000\u0000"+
		"\u0180\u0181\u0005\t\u0000\u0000\u0181\u0183\u0003\u0006\u0003\u0000\u0182"+
		"\u0180\u0001\u0000\u0000\u0000\u0182\u0183\u0001\u0000\u0000\u0000\u0183"+
		"\u0184\u0001\u0000\u0000\u0000\u0184\u0185\u0005\n\u0000\u0000\u01859"+
		"\u0001\u0000\u0000\u0000\u0186\u0187\u0005\u000f\u0000\u0000\u0187\u0188"+
		"\u0003\u0012\t\u0000\u0188\u0189\u0005\u0001\u0000\u0000\u0189\u018a\u0003"+
		"\u0014\n\u0000\u018a\u018b\u0005\u0010\u0000\u0000\u018b\u018c\u0003\u0014"+
		"\n\u0000\u018c;\u0001\u0000\u0000\u0000\u018d\u018e\u0005\f\u0000\u0000"+
		"\u018e\u018f\u0003\u0014\n\u0000\u018f\u0191\u0005\r\u0000\u0000\u0190"+
		"\u0192\u0003>\u001f\u0000\u0191\u0190\u0001\u0000\u0000\u0000\u0192\u0193"+
		"\u0001\u0000\u0000\u0000\u0193\u0191\u0001\u0000\u0000\u0000\u0193\u0194"+
		"\u0001\u0000\u0000\u0000\u0194\u0195\u0001\u0000\u0000\u0000\u0195\u0196"+
		"\u0005\u000e\u0000\u0000\u0196=\u0001\u0000\u0000\u0000\u0197\u0198\u0003"+
		"\u0012\t\u0000\u0198\u0199\u00052\u0000\u0000\u0199\u01a1\u0003\u0014"+
		"\n\u0000\u019a\u019b\u0005\u0003\u0000\u0000\u019b\u019c\u0003\u0012\t"+
		"\u0000\u019c\u019d\u00052\u0000\u0000\u019d\u019e\u0003\u0014\n\u0000"+
		"\u019e\u01a0\u0001\u0000\u0000\u0000\u019f\u019a\u0001\u0000\u0000\u0000"+
		"\u01a0\u01a3\u0001\u0000\u0000\u0000\u01a1\u019f\u0001\u0000\u0000\u0000"+
		"\u01a1\u01a2\u0001\u0000\u0000\u0000\u01a2?\u0001\u0000\u0000\u0000\u01a3"+
		"\u01a1\u0001\u0000\u0000\u0000\u01a4\u01a8\u0003B!\u0000\u01a5\u01a8\u0003"+
		"D\"\u0000\u01a6\u01a8\u0003F#\u0000\u01a7\u01a4\u0001\u0000\u0000\u0000"+
		"\u01a7\u01a5\u0001\u0000\u0000\u0000\u01a7\u01a6\u0001\u0000\u0000\u0000"+
		"\u01a8A\u0001\u0000\u0000\u0000\u01a9\u01aa\u0005\u0011\u0000\u0000\u01aa"+
		"\u01ab\u0003\u0016\u000b\u0000\u01ab\u01ac\u0005\u0012\u0000\u0000\u01ac"+
		"\u01ad\u0003\u0006\u0003\u0000\u01ad\u01ae\u0005\u0013\u0000\u0000\u01ae"+
		"C\u0001\u0000\u0000\u0000\u01af\u01b0\u0005\u0012\u0000\u0000\u01b0\u01b1"+
		"\u0003\u0006\u0003\u0000\u01b1\u01b2\u0005\u0011\u0000\u0000\u01b2\u01b3"+
		"\u0003\u0016\u000b\u0000\u01b3\u01b4\u0005\u0013\u0000\u0000\u01b4E\u0001"+
		"\u0000\u0000\u0000\u01b5\u01b7\u0005\u0014\u0000\u0000\u01b6\u01b8\u0003"+
		"H$\u0000\u01b7\u01b6\u0001\u0000\u0000\u0000\u01b7\u01b8\u0001\u0000\u0000"+
		"\u0000\u01b8\u01b9\u0001\u0000\u0000\u0000\u01b9\u01bb\u0005/\u0000\u0000"+
		"\u01ba\u01bc\u0003\u0014\n\u0000\u01bb\u01ba\u0001\u0000\u0000\u0000\u01bb"+
		"\u01bc\u0001\u0000\u0000\u0000\u01bc\u01bd\u0001\u0000\u0000\u0000\u01bd"+
		"\u01bf\u0005/\u0000\u0000\u01be\u01c0\u0003J%\u0000\u01bf\u01be\u0001"+
		"\u0000\u0000\u0000\u01bf\u01c0\u0001\u0000\u0000\u0000\u01c0\u01c1\u0001"+
		"\u0000\u0000\u0000\u01c1\u01c2\u0005\u0012\u0000\u0000\u01c2\u01c3\u0003"+
		"\u0006\u0003\u0000\u01c3\u01c4\u0005\u0013\u0000\u0000\u01c4G\u0001\u0000"+
		"\u0000\u0000\u01c5\u01c6\u0003\u0006\u0003\u0000\u01c6I\u0001\u0000\u0000"+
		"\u0000\u01c7\u01c8\u0003\u0018\f\u0000\u01c8K\u0001\u0000\u0000\u0000"+
		"\u01c9\u01ca\u0005\u0006\u0000\u0000\u01ca\u01cc\u0005)\u0000\u0000\u01cb"+
		"\u01cd\u0003\u0010\b\u0000\u01cc\u01cb\u0001\u0000\u0000\u0000\u01cc\u01cd"+
		"\u0001\u0000\u0000\u0000\u01cd\u01ce\u0001\u0000\u0000\u0000\u01ce\u01cf"+
		"\u0005*\u0000\u0000\u01cf\u01d0\u0005-\u0000\u0000\u01d0\u01d1\u0003\u0006"+
		"\u0003\u0000\u01d1\u01d2\u0005.\u0000\u0000\u01d2M\u0001\u0000\u0000\u0000"+
		"\u01d3\u01d8\u0003\u0014\n\u0000\u01d4\u01d5\u0005/\u0000\u0000\u01d5"+
		"\u01d7\u0003\u0014\n\u0000\u01d6\u01d4\u0001\u0000\u0000\u0000\u01d7\u01da"+
		"\u0001\u0000\u0000\u0000\u01d8\u01d6\u0001\u0000\u0000\u0000\u01d8\u01d9"+
		"\u0001\u0000\u0000\u0000\u01d9O\u0001\u0000\u0000\u0000\u01da\u01d8\u0001"+
		"\u0000\u0000\u00001S\\gkptx\u0080\u0084\u0089\u008f\u0096\u009d\u00ae"+
		"\u00b4\u00b9\u00c6\u00cd\u00d7\u00dd\u00e2\u00e9\u00f1\u00f9\u0101\u0109"+
		"\u0111\u0115\u011f\u012a\u012c\u013e\u014c\u0151\u015b\u0160\u0165\u016b"+
		"\u0170\u017d\u0182\u0193\u01a1\u01a7\u01b7\u01bb\u01bf\u01cc\u01d8";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}