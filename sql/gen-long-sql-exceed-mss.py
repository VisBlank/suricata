import sys

f = open(sys.argv[1], 'w+')

f.write('''
CREATE TABLE employee (
    employee_id INTEGER,
    manager_id INTEGER,
    first_name VARCHAR(4048) NOT NULL,
    last_name VARCHAR(4048) NOT NULL,
    home_addr VARCHAR(4048) NOT NULL,
    title VARCHAR(256),
);\n''')

long_first_name = ''
long_last_name = ''
long_home_addr = ''

idx = 0
while idx < 2048:
    long_first_name = long_first_name + 'ffffffff';
    long_last_name = long_last_name + 'llllllll';
    long_home_addr += 'hhhhhhhh';
    idx += 8

ceo = ''
idx = 0
while idx < 53:
    ceo += 'O'
    idx += 1

fmt = "insert into employee(employee_id,manager_id,first_name,last_name,home_addr,title) values(1,0,'%s','%s','%s','%s');"

sql = fmt % (long_first_name, long_last_name, long_home_addr, ceo)
f.write(sql)
print(len(sql))

f.write('\nDROP TABLE employee;\n')

f.close()
