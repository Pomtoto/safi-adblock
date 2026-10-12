# Safi has no reflection, JNI or dynamic class loading, so shrinking is safe.
# Class names are kept on purpose: the local crash log and bug reports are only useful
# if the stack traces are readable.
-dontobfuscate
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
