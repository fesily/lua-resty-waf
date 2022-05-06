#!/usr/bin/env python3

import os
import sys
import re

def replace(oldstr, newstr, infile, dryrun=False):
    '''
    Sed-like Replace function..
    Usage: pysed.replace(<Old string>, <Replacement String>, <Text File>)
    Example: pysed.replace('xyz', 'XYZ', '/path/to/file.txt')
    Example 'DRYRUN': pysed.replace('xyz', 'XYZ', '/path/to/file.txt', dryrun=True) #This will dump the output to STDOUT instead of changing the input file.
    '''
    linelist = []
    with open(infile) as f:
        for item in f:
            newitem = re.sub(oldstr, newstr, item)
            linelist.append(newitem)
    if dryrun == False:
        with open(infile, "w") as f:
            f.truncate()
            for line in linelist: f.writelines(line)
    elif dryrun == True:
        #for line in linelist: print(line, end='')
        pass
    else:
        exit("Unknown option specified to 'dryrun' argument, Usage: dryrun=<True|False>.")

def rmlinematch(oldstr, infile, dryrun=False):
    '''
    Sed-like line deletion function based on given string..
    Usage: pysed.rmlinematch(<Unwanted string>, <Text File>)
    Example: pysed.rmlinematch('xyz', '/path/to/file.txt')
    Example 'DRYRUN': pysed.rmlinematch('xyz', '/path/to/file.txt', dryrun=True) #This will dump the output to STDOUT instead of changing the input file.
    '''
    linelist = []
    with open(infile) as f:
        for item in f:
            rmitem = re.match(r'.*{}'.format(oldstr), item)
            if type(rmitem) == type(None): linelist.append(item)
    if dryrun == False:
        with open(infile, "w") as f:
            f.truncate()
            for line in linelist: f.writelines(line)
    elif dryrun == True:
        for line in linelist: print(line, end='')
    else:
        exit("Unknown option specified to 'dryrun' argument, Usage: dryrun=<True|False>.")

def rmlinenumber(linenumber, infile, dryrun=False):
    '''
    Sed-like line deletion function based on given line number..
    Usage: pysed.rmlinenumber(<Unwanted Line Number>, <Text File>)
    Example: pysed.rmlinenumber(10, '/path/to/file.txt')
    Example 'DRYRUN': pysed.rmlinenumber(10, '/path/to/file.txt', dryrun=True) #This will dump the output to STDOUT instead of changing the input file.
    '''
    linelist = []
    linecounter = 0
    if type(linenumber) != type(linecounter): exit("'linenumber' argument must be an integer.")
    with open(infile) as f:
        for item in f:
            linecounter = linecounter + 1
            if linecounter != linenumber: linelist.append(item)
    if dryrun == False:
        with open(infile, "w") as f:
            f.truncate()
            for line in linelist: f.writelines(line)
    elif dryrun == True:
        for line in linelist: print(line, end='')
    else:
        exit("Unknown option specified to 'dryrun' argument, Usage: dryrun=<True|False>.")
        
if __name__ == '__main__':
    if len(sys.argv) >1 and sys.argv[1] == 'clean':
        replace(infile="./lib/resty/waf.lua", oldstr="if self\._debug == true then ngx\.log\(.*?'] ', (.*)\) end",newstr = r'''--_LOG_\1''')
        for root,dirs,files in os.walk("./lib/resty/waf/"):
            for name in files:
               replace(infile=os.path.join(root,name),oldstr="if waf\._debug == true then ngx\.log\(.*?'\] ', (.*)\) end",newstr=r'''--_LOG_\1''')
    else:
        replace(infile="./lib/resty/waf.lua", oldstr='--_LOG_(.*)',newstr = r'''if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', \1) end''')
        for root,dirs,files in os.walk("./lib/resty/waf/"):
            for name in files:
                replace(infile=os.path.join(root,name),oldstr='--_LOG_(.*)',newstr=r'''if waf._debug == true then ngx.log(waf._debug_log_level, '[', waf.transaction_id, '] ', \1) end''')