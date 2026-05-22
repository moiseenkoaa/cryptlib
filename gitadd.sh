#!/bin/sh

git add *.h *.cpp *.nasm des/*.h des/*.c des/*.cpp sha256/*.h sha256/*.cpp
git add gitadd.sh
git add CryptLib.vcxproj CryptLib.vcxproj.filters Makefile Licence.txt

if [ x"$1" = "x" ]; then
    #echo 'git commit -m "Comment"'
    #echo 'git push origin master'
    git commit -m '~' && git push origin main
else
    git commit -m "$1" && git push origin main
fi
