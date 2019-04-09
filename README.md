# AL5-Cross-Platform-PE-File-IO
A Cross-Platform PE File Read/Write program using Allegro 5

# Setup guide
## Build requirements
* C/C++ Compiler.
* Allegro 5+

## Prototype PE file
* peprototype.gf is a pre-existing PE file that contains one resource, that you may edit to state your copyright woes.

## WritePEBmp usage:
```
To run WritePEBmp, feed it the following parameters: [pe file] [bitmap file] [id].
For example : WritePEBmp gfx025.gf 115.bmp 115
```
## ReadPEBmp usage:
```
To run ReadPEBmp, feed it the following parameters: [pe file] [id].
For example : WritePEBmp gfx025.gf 115
```

You may and can easily modify the program to search and loop through every bitmap in containing folder.
For example, through a simple script or through actually editing the source.

This project is released under MIT licence. See LICENCE file for more info.

Copyright © Matias Persson.
