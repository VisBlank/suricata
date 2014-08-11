f = open('long-insert.sql', 'w+')

# create table only include primary key
f.write('CREATE TABLE emp (empno NUMBER(4) constraint E_PK primary key);\n')

i = 0
while i < 256:
    f.write('INSERT INTO emp VALUES(%d);\n' % i)
    i += 1

f.write('DROP TABLE emp;\n')

f.close()
