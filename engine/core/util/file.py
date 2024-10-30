# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/util/dir.py
# Author : Hoon
# 
# ====================== Comments ======================
#

from os     import makedirs, path, remove
from shutil import rmtree

def rmdir( dirname ):
    if path.isdir( dirname ):
        rmtree( dirname )

def mkdir( dirname ):
    if not path.isdir( dirname ):
        makedirs( dirname )

def rmfile( filename ):
    if  ( path.exists( filename ) )\
    and ( path.isfile( filename ) ):
        remove( filename )