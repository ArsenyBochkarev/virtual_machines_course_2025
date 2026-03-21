// Generated from language/src/main/java/com/oracle/truffle/lama/parser/Lama.g4 by ANTLR 4.13.2
package com.oracle.truffle.lama.parser;
import org.antlr.v4.runtime.tree.ParseTreeVisitor;

/**
 * This interface defines a complete generic visitor for a parse tree produced
 * by {@link LamaParser}.
 *
 * @param <T> The return type of the visit operation. Use {@link Void} for
 * operations with no return type.
 */
public interface LamaVisitor<T> extends ParseTreeVisitor<T> {
	/**
	 * Visit a parse tree produced by {@link LamaParser#program}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitProgram(LamaParser.ProgramContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#topScope}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitTopScope(LamaParser.TopScopeContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#importStatement}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitImportStatement(LamaParser.ImportStatementContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#scopeExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitScopeExpression(LamaParser.ScopeExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#definition}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDefinition(LamaParser.DefinitionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#varDefinition}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitVarDefinition(LamaParser.VarDefinitionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#varInit}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitVarInit(LamaParser.VarInitContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#funDefinition}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitFunDefinition(LamaParser.FunDefinitionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#patternList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitPatternList(LamaParser.PatternListContext ctx);
	/**
	 * Visit a parse tree produced by the {@code listPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitListPattern(LamaParser.ListPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code parenPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitParenPattern(LamaParser.ParenPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code truePattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitTruePattern(LamaParser.TruePatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code decimalPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDecimalPattern(LamaParser.DecimalPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code sharpStrPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSharpStrPattern(LamaParser.SharpStrPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code sexpPatternNoArgs}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSexpPatternNoArgs(LamaParser.SexpPatternNoArgsContext ctx);
	/**
	 * Visit a parse tree produced by the {@code wildcardPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitWildcardPattern(LamaParser.WildcardPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code aliasPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAliasPattern(LamaParser.AliasPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code sharpSexpPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSharpSexpPattern(LamaParser.SharpSexpPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code sharpFunPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSharpFunPattern(LamaParser.SharpFunPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code varPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitVarPattern(LamaParser.VarPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code charPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitCharPattern(LamaParser.CharPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code consPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitConsPattern(LamaParser.ConsPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code stringPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitStringPattern(LamaParser.StringPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code sharpBoxPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSharpBoxPattern(LamaParser.SharpBoxPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code falsePattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitFalsePattern(LamaParser.FalsePatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code sharpValPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSharpValPattern(LamaParser.SharpValPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code sharpArrayPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSharpArrayPattern(LamaParser.SharpArrayPatternContext ctx);
	/**
	 * Visit a parse tree produced by the {@code sexpPatternWithArgs}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSexpPatternWithArgs(LamaParser.SexpPatternWithArgsContext ctx);
	/**
	 * Visit a parse tree produced by the {@code arrayPattern}
	 * labeled alternative in {@link LamaParser#pattern}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitArrayPattern(LamaParser.ArrayPatternContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#expression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitExpression(LamaParser.ExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#sequenceExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSequenceExpression(LamaParser.SequenceExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#assignExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAssignExpression(LamaParser.AssignExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#consExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitConsExpression(LamaParser.ConsExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#logicalOrExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLogicalOrExpression(LamaParser.LogicalOrExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#logicalAndExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLogicalAndExpression(LamaParser.LogicalAndExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#equalityExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitEqualityExpression(LamaParser.EqualityExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#relationalExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitRelationalExpression(LamaParser.RelationalExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#additiveExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitAdditiveExpression(LamaParser.AdditiveExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#multiplicativeExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitMultiplicativeExpression(LamaParser.MultiplicativeExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#prefixExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitPrefixExpression(LamaParser.PrefixExpressionContext ctx);
	/**
	 * Visit a parse tree produced by the {@code callSuffix}
	 * labeled alternative in {@link LamaParser#postfixExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitCallSuffix(LamaParser.CallSuffixContext ctx);
	/**
	 * Visit a parse tree produced by the {@code dotSuffix}
	 * labeled alternative in {@link LamaParser#postfixExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDotSuffix(LamaParser.DotSuffixContext ctx);
	/**
	 * Visit a parse tree produced by the {@code basePrimary}
	 * labeled alternative in {@link LamaParser#postfixExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitBasePrimary(LamaParser.BasePrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code indexSuffix}
	 * labeled alternative in {@link LamaParser#postfixExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitIndexSuffix(LamaParser.IndexSuffixContext ctx);
	/**
	 * Visit a parse tree produced by the {@code litPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLitPrimary(LamaParser.LitPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code sexpPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSexpPrimary(LamaParser.SexpPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code idPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitIdPrimary(LamaParser.IdPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code parenPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitParenPrimary(LamaParser.ParenPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code arrayPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitArrayPrimary(LamaParser.ArrayPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code listPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitListPrimary(LamaParser.ListPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code ifPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitIfPrimary(LamaParser.IfPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code letPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLetPrimary(LamaParser.LetPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code casePrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitCasePrimary(LamaParser.CasePrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code loopPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLoopPrimary(LamaParser.LoopPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code skipPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSkipPrimary(LamaParser.SkipPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by the {@code lambdaPrimary}
	 * labeled alternative in {@link LamaParser#primary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLambdaPrimary(LamaParser.LambdaPrimaryContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#literal}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLiteral(LamaParser.LiteralContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#identifier}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitIdentifier(LamaParser.IdentifierContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#arrayLiteral}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitArrayLiteral(LamaParser.ArrayLiteralContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#listLiteral}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitListLiteral(LamaParser.ListLiteralContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#sexp}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSexp(LamaParser.SexpContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#ifExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitIfExpression(LamaParser.IfExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#letExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLetExpression(LamaParser.LetExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#caseExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitCaseExpression(LamaParser.CaseExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#caseBranch}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitCaseBranch(LamaParser.CaseBranchContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#loopExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLoopExpression(LamaParser.LoopExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#whileLoop}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitWhileLoop(LamaParser.WhileLoopContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#doWhileLoop}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitDoWhileLoop(LamaParser.DoWhileLoopContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#forLoop}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitForLoop(LamaParser.ForLoopContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#forInit}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitForInit(LamaParser.ForInitContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#forStep}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitForStep(LamaParser.ForStepContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#lambdaExpression}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLambdaExpression(LamaParser.LambdaExpressionContext ctx);
	/**
	 * Visit a parse tree produced by {@link LamaParser#argumentList}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitArgumentList(LamaParser.ArgumentListContext ctx);
}