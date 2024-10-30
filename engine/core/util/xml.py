# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/util/cpe.py
# Author : Hoon
# 
# ====================== Comments ======================
#

from pickle    import dump  as pkl_dump
from xmltodict import parse as xmltodict_parse

# Engine Libraries
from engine.core.config.default import ENCODING
from engine.core.util.file      import rmfile

def xml_to_pkl( file, remove_old=False ):

   try:
      with open( file, 'r', encoding=ENCODING ) as i, open( f"{ file }.pkl", 'wb' ) as o:
         pkl_dump( xmltodict_parse( i.read() ), o )
      
   except:
      raise

   else:
      if remove_old:
         rmfile( file )
