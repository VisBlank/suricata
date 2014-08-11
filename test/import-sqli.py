import os, sys, time, subprocess

def run_cmd(cmd):
    ret = 0
    try:
        ret = subprocess.call(cmd, shell=True) # disable shell prompt
        if ret < 0:
        # should we fetch the error message of the cmd?
            return {'ret' : ret, 'err' : ''}
        else:
            return {'ret' : ret, 'err' : str(None)}
    except OSError as e:
        return {'ret' : ret, 'err' : str(e)}

for f in os.listdir(sys.argv[1]):
    log = open('sqli-input', 'w+')

    if str.find(f, 'sqli') != -1:
        #lines = open('%s/%s' % (sys.argv[1], f), 'r')
        with open('%s/%s' % (sys.argv[1], f), 'r') as f_in:
                lines = filter(None, (line.rstrip() for line in f_in))

        print 'test sqli in file: %s' % f

        for l in lines:
            if l[:1] == '#':
                continue

            l = l.replace('"', '\"')
            cmd = './libinjection-demo sql "%s"' % l
            print cmd
            ret = run_cmd(cmd)
            if ret['ret'] == 1:
                log.write('[sqli] %s\n' % l)
            elif ret['ret'] == 0:
                log.write('[benign] %s\n' % l)
            else:
                print ret

            time.sleep(1)

        f_in.close()
