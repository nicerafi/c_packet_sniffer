ATTENTION! 

Sometimes when running "../build/idsniff" for the first time will lead to a core dumped error but after recompiling or re-running the
code it will seem to fix itself.
 
I've only been able to recreate the error twice by running the code on a fresh VM or on the CS241 VM on the DCS machines for the first time.
I haven't been able to recreate the error any other way, such as typing "make clean" to remove the build files so I'm not sure what causes 
the error.

So if the code fails spontaneously first try this may be the issue.

ALSO -
If you force verbose mode in analysis.c it analyses 1000's of background packets, however if it isn't enabled 
it doesn't seem to analyse nearly as many, so basically done force verbose mode in the code.

Cheers!

Mohammed Rafi