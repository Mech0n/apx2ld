# A System for Reversing Schneider PLC

A system to restore a real PLC run logic from the apx file which can be dropped from UMAS protocol.

### feature

- locate x86 bytecode from apx file
- restore a PLC run logic from the bytecode
- ~~visualization~~

### Usage

```
pipenv install
pipenv shell
...
```

### TODO

- 1. ~~module for finding variables -> flags~~
- 2. ~~save all reg' value -> set reg~~
- 3. add features in CodeRun:
    - ~~find variables~~
    - ~~mapping the variables and variables in LDExchangeFile~~
    - ~~find fBD~~
    - ~~add FBD in ladder logic tree~~
    - ~~add Multiple input FBD in ladder logic tree~~
    - support CTUD
- 4. visualization
- 5. ~~parse apx file~~
    - ~~split PK~~
    - ~~split zlib~~

### shortcut

- Each rung of ladder language need and only one coil at the far right. 
