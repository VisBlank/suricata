f = open('long-sql.sql', 'w+')

# create table only include primary key
f.write('''
CREATE TABLE employee (
    employee_id INTEGER,
    manager_id INTEGER,
    first_name VARCHAR2(256) NOT NULL,
    last_name VARCHAR2(256) NOT NULL,
    home_addr VARCHAR2(256) NOT NULL,
    title VARCHAR2(256),
    salary NUMBER(6, 0)
);\n''')

long_first_name = ''
long_last_name = ''
long_home_addr = ''

idx = 0
while idx < 28:
    long_first_name = long_first_name + 'f';
    long_last_name = long_last_name + 'l';
    long_home_addr += 'h';
    idx += 1

ceo = ''
idx = 0
while idx < 53:
    ceo += 'O'
    idx += 1

fmt = "insert into employee(employee_id,manager_id,first_name,last_name,home_addr,title,salary) values(1,0,'%s','%s','%s','%s',800000);"

sql = fmt % (long_first_name, long_last_name, long_home_addr, ceo)
f.write(sql)
print(len(sql))

f.write('\nDROP TABLE employee;\n')

f.close()
