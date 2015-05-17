How to test DLL injection ?

-Modify the process to hook in the DLLInjector.cpp file (MUST BE 32 bits)
-Build
-Copy ExampleDLL.dll in Greenkit/Debug, execute DLLInjector.exe (with admin rights)
-It'll create a temp.txt file in C:// with text in it if it worked
