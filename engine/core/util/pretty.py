# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/util/pretty.py
# Author : Hoon
# 
# ====================== Comments ======================
#

def make_pretty( dictionary, exceptions=[] ):
    longest_key = 0
    for k in dictionary.keys():
        len_key = len(k)
        if len_key > longest_key: longest_key = len_key

    return '\n'.join( [ r'{} : {}'.format(f"\t{k:<{longest_key}}", v) for k, v in dictionary.items() if k not in exceptions ] )