# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/util/http.py
# Author : Hoon
# 
# ====================== Comments ======================
#

from time     import sleep
from os.path  import join     as path_join
from os.path  import getsize  as path_getsize
from os.path  import basename as path_basename
from requests import get      as requests_get
from requests import post     as requests_post
from pickle   import dump     as pkl_dump
from json     import dump     as json_dump

# Engine Libraries
from engine.core.config.default import ENCODING
from engine.core.util.file      import rmfile
        
def download_file( uri, savepath ):
    print( f'[+] Downloading from { uri }', end=' ' )
        
    file  = path_join( savepath, path_basename( uri ) )

    if ( r := requests_get( uri ) ).status_code != 200:
        print( '[PASS]' )
        rmfile( file )
        return False
            
    with open( file, 'wb' ) as f:
        f.write( r.content )
            
    if path_getsize( file ) <= 0:
        print( '[PASS]' )
        rmfile( file )
        return False
        
    print( '[DONE]' )
    return True
    
def http_request(
      url     : str
    , params  : dict = None
    , headers : dict = { 'Content-Type' : 'application/json' }
    , retry   : int  = 3
    , file    : str  = None
    , method  : str  = 'GET'
):
    method = method.upper()
    
    if   method == 'GET' : request = requests_get
    elif method == 'POST': request = requests_post

    params = '&'.join( [ f'{ k }' if v is None else f'{ k }={ v }' for k, v in params.items() ] )

    for _ in range( retry ):
        response = request(
              url     = url
            , params  = params
            , headers = headers
        )

        if response.status_code != 200:
            sleep( 30 )
            continue
        
        if file:
            
            if file.endswith( '.json' ):
                with open( file, 'w', encoding=ENCODING ) as f:
                    json_dump( response.json(), f, default=str, indent=4 )

            else:
                with open( file, 'wb' ) as f:
                    pkl_dump( response.json(), f )

            return True
        
        else:
            return response

    raise( f"HTTP { method }: { url }{ params } [{ response.status_code }]" )

def parse_headers( headers, fieldname ):
    
    if headers:
        return str( s.split( ';' )[ 0 ] if ';' in s else s ) \
            if  ( fieldname in headers._store            )   \
            and ( s := headers._store[ fieldname ][ 1 ]  )   \
            else ''

    else:
        return ''
