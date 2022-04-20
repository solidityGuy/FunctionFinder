# FunctionFinder
Small C++ program to find a size of a function in bytes.

This is useful because the old method of finding a functions size and location, that is, subtracting a naked function positioned "in front" of another, as of the latest Windows versions, produces undefined behaviour.

With this program you can inject naked functions into other programs and therefore infect binarys. The author of this program achieved success in this, however ASLR (security mechanism for binary files) prevents jumping back from the code cave to the original entry point (oEP).

Therefore, the goal of this program is simply as a general experiment and to aid PE file injection, and it has success in changing entry points to a predetermined point in the file, but jumping back does not work - in other words - PE file infection in this manner does not work anymore, and requires extra measures to counter ASLR.

Requirements:
1. Understanding of COM programming - you must install the COM interface in your registry, or the program will abort upon execution.

Usage:
1. After the COM interface is setup and the DIA SDK is installed, use pdbreader to analyze the Symbol Table of a determined .exe file. You must currently edit the code to do so, but you can pass the name of the file as an argument with small edits.
2. Analyze the output of the program and find your shellcode function (you should have a function written in shellcode inside the .exe file analyzed, and all strings should be defined inside the .text section using _emit/db().
3. Insert the correct file offset and size in bytes in injector.cpp. You should make a copy of your .exe file, so myprogram2.exe, for example. The program will do the rest and grab the function from your .exe and insert it into the .exe you passed in argv[1].

Credits to dTm at 0x00sec for making the injector program.
