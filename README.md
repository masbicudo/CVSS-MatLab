
CVSS for MatLab
===============

This package contains MatLab classes to manipulate **CVSS 2** and **CVSS 3**.
You can load a CVSS string into an instance of a CVSS class, and call
methods to calculate the *base score*, the *temporal score* and the *environmental score*.
It is also possible to manipulate a CVSS instance to add or change values.

Example
-------

```
c = CVSS2.Parse_Metrics_String('AV:N/AC:L/Au:N/C:N/I:N/A:C');
s = c.Base_Score;

btc = c.Fill_Parse('E:U/RL:OF/RC:UC');  % best temporal parameters
bts = c.Temporal_Score;                 % get the best temporal score

Au = c.Au; % getting one of the CVSS parameters value (not the string)
```

Optimizations
-------------

CVSS for MatLab was optimized by using the MatLab profiler to indicate slow methods.
The slowest ones were refactored by reducing the number of loops,
and even one of them was replaced by an equivalent C coded function: `strsplit.c`.
You will need to run `mex strsplit.c` before running to compile it.

More can be optimized, it's a work in progress.

Tests
-----

You can trust this package.
More and more tests will be added so that bugs stay away from the code.

Helping
-------

Helping this project grow is easy.
Just fork it, do what you want to do, and create a pull request.

Don't forget to follow these rules to maintain the quality:
- create test cases for the code (if needed)
- add documentation (if needed)
- comment the code, in english, please
- add your name bellow (and current occupation if you wish)

Contributors
------------

Daniel S. Menasche - professor and researcher at UFRJ
Matheus Martins - graduation student at UFRJ
Miguel Angelo (masbicudo) - graduation student at UFRJ

License
-------

[Apache 2.0 License](LICENSE)
