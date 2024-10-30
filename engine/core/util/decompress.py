# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/util/decompress.py
# Author : Hoon
# 
# ====================== Comments ======================
#

from os  import listdir, path
from bz2 import BZ2File

# Engine Libraries
from engine.core.util.file import rmfile

def decompress_bz2files( directory, extract_path ):
    try:
        for filename in listdir( directory ):
            
            if filename.endswith( '.bz2' ):

                with BZ2File( path.join( directory, filename )                    , 'rb' ) as i\
                   , open   ( path.join( extract_path, filename.rstrip( '.bz2' ) ), 'wb' ) as o:
                    o.write( i.read() )

    except:
        raise

    else:
        for filename in listdir( directory ):
            if filename.endswith( '.bz2' ):
                rmfile( path.join( directory, filename ) )