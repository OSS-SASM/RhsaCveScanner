# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/__main__.py
# Author : Hoon
# 
# ====================== Comments ======================
#  

from os.path  import abspath
from argparse import ArgumentParser, RawTextHelpFormatter, SUPPRESS
from sys      import exit as sys_exit

# Engine Libraries
from engine import MODULE, VERSION, ASCII_ART, ENCODING
from engine import Logger, show_version, rebuild_dataset, cve_scan, make_pretty, traceback_message

#####################################################################################################################################################################
# 실행 인자값 파싱
#####################################################################################################################################################################
def parse_args():
    parser = ArgumentParser( 
          add_help        = False
        , formatter_class = RawTextHelpFormatter
        , description     = f"{ ASCII_ART }\n{ MODULE } v{ VERSION }"
    )

    generalGrp = parser.add_argument_group( 'General Commands' )
    generalGrp.add_argument( '-h', '--help'   , help="Show this help message", action='help'                        )
    generalGrp.add_argument( '-v', '--version', help="Show program's version", action='version'   , version=VERSION )
    generalGrp.add_argument( "-d", "--debug"  , help="Enable debug mode"     , action="store_true", default=False   )
    
    datasetManagementGrp = parser.add_argument_group( 'Commands' ).add_mutually_exclusive_group( required=True )
    datasetManagementGrp.add_argument( '-V', '--dataset-version', help='Show the date when dataset created', dest='commands', action='append_const', const='show_version'    )
    datasetManagementGrp.add_argument( '-R', '--dataset-rebuild', help='Rebuild dataset from RHSA OVALs'   , dest='commands', action='append_const', const='rebuild_dataset' )
    datasetManagementGrp.add_argument( '-C', '--cve-scan'       , help='Scanning CVEs with rpm packages'   , dest='commands', action='append_const', const='cve_scan'        )
    
    positional_group = parser.add_argument_group( 'Dataset File' )
    positional_group.add_argument( "dataset", help=SUPPRESS, type=str )
    
    return { 
        k : list( dict.fromkeys( v if v else {} ) )
            if   k == 'commands'
            else v 
        for k, v in vars( parser.parse_args() ).items()
    }

if __name__=='__main__':
    ############################################################################################################################################
    # Parse arguments
    ############################################################################################################################################
    args              = parse_args()
    args[ 'dataset' ] = abspath( args[ 'dataset' ] )
    
    ############################################################################################################################################
    # Logger
    ############################################################################################################################################
    logger = Logger(
          name       = MODULE
        , encoding   = ENCODING
        , colored    = True
        , debug_mode = args[ 'debug' ]
    )
    
    logger.debug( make_pretty( args ) )
    
    try:
        exitcode = 0
        ############################################################################################################################################
        # [ -V, --dataset-version ]: 데이터셋 생성 날짜 확인 모드,
        #   dataset 파일이 생성된 날짜를 출력한다.
        #
        # [ -R, --dataset-rebuild ]: 데이터셋 리빌드 모드,
        #   Redhat RHSA Oval 파일들을 내려받아 가공하여 dataset파일을 생성한다.
        #
        # [ -C, --check-cve ]: CVE 진단 모드
        #   rhsa oval 파일들에서 추출한 dataset파일을 기반으로 이 시스템의 cve 취약점을 점검한다.
        ############################################################################################################################################
        if   'show_version'    in args[ 'commands' ]: exitcode = show_version   ( args[ 'dataset' ], logger )
        elif 'rebuild_dataset' in args[ 'commands' ]: exitcode = rebuild_dataset( args[ 'dataset' ], logger )
        elif 'cve_scan'        in args[ 'commands' ]: exitcode = cve_scan       ( args[ 'dataset' ], logger )
    
    except:
        exitcode = 2
        logger.debug( f'Unexpected error occured: [\n\t{ traceback_message() }\n]' )
    
    sys_exit( exitcode )
        
