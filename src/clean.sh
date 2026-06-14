#!/bin/bash

clear

echo "==> Cleaning"

echo ""
echo "-------------------------------------------------"
echo ""

echo "==> Removing all compiled classes (if existent)."
find . -name "*.class" -delete
echo "==> Success."

echo ""
echo "-------------------------------------------------"
echo ""

echo "==> Removing all persistent storage (if existent)."
rm -rf ./client/index/*
echo "==> Success."

echo ""
echo "-------------------------------------------------"
echo ""

echo "==> Clean Completed."