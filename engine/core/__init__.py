# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/__init__.py
# Author : Hoon
# 

# Python Libraries
from datetime import datetime
from json     import load  as json_load
from json     import dump  as json_dump
from json     import dumps as json_dumps

# Engine Libraries
from engine.core.util           import check_patchlist, get_system_rpmlist
from engine.core.src            import REDHAT
from engine.core.config.default import SRC_PATH, DATEFORMAT, ENCODING

def show_version( dataset_file, logger ):
    try:
        with open( dataset_file, 'r', encoding=ENCODING ) as f:
            logger.echo( json_load( f )[ '@created_at' ] )

    except FileNotFoundError:
        logger.error( f"No such file or directory: { dataset_file }"  )
        return 1
    
    else:
        return 0

def rebuild_dataset( dataset_file, logger ):
    ######################################################################################################################################################
    # REDHAT
    ######################################################################################################################################################
    try:
        with open( dataset_file, 'w', encoding=ENCODING ) as f:
            json_dump( {
                  '@created_at' : datetime.now().strftime( DATEFORMAT )
                , **REDHAT(
                      src_path             = SRC_PATH
                    , remove_old_workplace = True
                    , download_src_files   = True
                    , logger               = logger
                )()
            }, f, default=str, indent=4 )
    
    except:
        logger.error( 'Dataset rebuild failed' )
        return 1
    
    else:
        logger.info( 'done' )
        return 0
        
def cve_scan( dataset_file, logger ):
    try:
        logger.echo( 
            json_dumps( 
                  check_patchlist( dataset_file, get_system_rpmlist() )
                , indent=4
            )
        )
    
    except:
        logger.error( 'Scan Failed' )
        return 1
    
    else:
        return 0