So basically I parse the output of objdump -d

On windows machines with msys, I cross compile with clang for arm64 and instead of objdump use llvm-objdump, that is until I got a real apple machine.

You need to have swipl in your path.

Basically compile your test programs with -c

gcc -c add.c -O0 {-O1 if you dont want to have fun}

And then

objdump -d add.o | swipl -q a64zdcmp.pl


Also yeah, .pl filename makes all editors think its a perl program. This makes me want to write a perl program which is a prolog program too. I think its possible, given how glorious perl is supposed to be.
