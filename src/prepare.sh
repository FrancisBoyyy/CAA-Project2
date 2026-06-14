#!/bin/bash

clear

echo "==> Preparing"

echo ""
echo "-------------------------------------------------"
echo ""

echo "==> Removing all compiled classes (if existent)."
find . -name "*.class" -delete
echo "==> Success."

echo ""
echo "-------------------------------------------------"
echo ""

echo "==> Compiling all sources..."

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    SEP=";"
else
    SEP=":"
fi

CP=".${SEP}lib/*"

find . -name "*.java" > sources.txt
javac -cp "$CP" @sources.txt || exit 1
rm sources.txt
echo "==> Compilation successful."

echo ""
echo "-------------------------------------------------"
echo ""

echo "==> Ready to Deploy."