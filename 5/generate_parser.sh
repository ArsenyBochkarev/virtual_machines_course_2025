#!/usr/bin/env bash

if [ ! -f "antlr-4.13.2-complete.jar" ]; then
  curl -O https://www.antlr.org/download/antlr-4.13.2-complete.jar
fi
$JAVA_HOME/bin/java -cp antlr-4.13.2-complete.jar org.antlr.v4.Tool -package com.oracle.truffle.lama.parser -no-listener -visitor language/src/main/java/com/oracle/truffle/lama/parser/Lama.g4
