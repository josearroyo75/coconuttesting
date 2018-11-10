import datetime
import email.utils
import sys

d = datetime.datetime(*email.utils.parsedate(' '.join(sys.argv[1:]))[0:6])
print(d.isoformat())
