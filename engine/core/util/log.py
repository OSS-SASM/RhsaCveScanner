# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/util/log.py
# Author : Hoon
# 
# ====================== Comments ======================
#

from time    import time
from sys     import stdout
from psutil  import Process
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL
from logging import getLogger, Formatter, StreamHandler

# Module Libraries
from engine.core.config.default import ENCODING

STYLE = {
      'END'       : '\033[0m'

    , 'BOLD'      : ';1'
    , 'ITALIC'    : ';3'
    , 'UNDERLINE' : ';4'
    , 'BLINK'     : ';5'
    , 'BLINK2'    : ';6'
    , 'SELECTED'  : ';7'

    , 'BLACK'     : '90'
    , 'RED'       : '91'
    , 'GREEN'     : '92'
    , 'YELLOW'    : '93'
    , 'BLUE'      : '94'
    , 'MAGENTA'   : '95'
    , 'CYAN'      : '96'
    , 'WHITE'     : '97'
}

LOGLEVEL = {
      'SUCCESS'  : 0
    , 'INFO'     : 1
    , 'WARNING'  : 2
    , 'FAIL'     : 3
    , 'ERROR'    : 4
    , 'REJECTED' : 5
    , 'REDIRECT' : 6
    , 'ABORTED'  : 7
    , 'DEBUG'    : 9
}

class Logger:

    @classmethod
    def __init__(
          cls
        , name
        , encoding   = ENCODING
        , colored    = False
        , debug_mode = False
    ):
        cls.name       = name
        cls.encoding   = encoding
        cls.colored    = colored
        cls.debug_mode = debug_mode

        ############################################################################################
        # 모듈 logger
        ############################################################################################
        cls.logger = getLogger( cls.name )

        ############################################################################################
        # 모듈 logger 표준 출력 스트림 핸들러
        ############################################################################################
        cls.streamHandler = StreamHandler( stdout )
        
        ############################################################################################
        # if colered: log level에 따라 다른 색상으로 출력
        # else      : log_level과 상관 없이 같은 색상으로 출력
        ############################################################################################
        cls.streamHandler.setFormatter( 
            cls.LogFormatter( 
                  colored = cls.colored
                , fmt     = '%(msg)s'
                , datefmt = '%Y-%m-%d %H:%M:%S'
            )
        )

        ############################################################################################
        # 디버그 모드인 경우
        ############################################################################################
        if cls.debug_mode: 
            cls.logger.setLevel( DEBUG )
            
            ##############################################################
            # import된 라이브러리들 중,
            # Warning 메세지를 출력하는 경우,
            # logging 모듈로 리다이렉션
            ##############################################################
            from logging import captureWarnings
            captureWarnings( True )

            ##############################################################
            # 파이썬 Warning logger
            ##############################################################
            cls.warnings_logger = getLogger( "py.warnings" )
            cls.warnings_logger.setLevel( WARNING )

            ##############################################################
            # 파이썬 Warning logger 표준 출력 스트림 핸들러
            ##############################################################
            cls.warningStreamHandler = StreamHandler( stdout )
            
            ##############################################################
            # if colered: log level에 따라 다른 색상으로 출력
            # else      : log_level과 상관 없이 같은 색상으로 출력
            ##############################################################
            cls.warningStreamHandler.setFormatter( 
                cls.LogFormatter( 
                      colored = cls.colored
                    , fmt     = '%(message)s'
                    , datefmt = '%Y-%m-%d %H:%M:%S'
                )
            )

            cls.warnings_logger.addHandler( cls.warningStreamHandler )

        ############################################################################################
        # 디버그 모드가 아닌 경우
        ############################################################################################
        else:
            cls.logger.setLevel( INFO )

            ##############################################################
            # import된 라이브러리들 중,
            # Warning 메세지를 출력하는 경우 이를 무시
            ##############################################################
            from warnings import filterwarnings
            filterwarnings( "ignore" )
        
        cls.logger.addHandler( cls.streamHandler )

        cls.debug   = cls.logger.debug
        cls.info    = cls.logger.info
        cls.success = cls.logger.info
        cls.warning = cls.logger.warning
        cls.fail    = cls.logger.error
        cls.error   = cls.logger.critical
    
    ##############################################################
    # 로그 메세지 출력 메소드
    ##############################################################
    @classmethod
    def echo(
          cls
        , msg   : str
        , tag   : str      = None
        , level : LOGLEVEL = None
        , file  : str      = stdout
        , **kwargs
    ):
        if   level == LOGLEVEL[ 'INFO'    ]: msg = f"\033[{ STYLE[ 'WHITE'  ] }m{ '[INFO] '    if not tag else f'[{ tag }] ' }{ STYLE[ 'END' ] }{ msg }"
        elif level == LOGLEVEL[ 'SUCCESS' ]: msg = f"\033[{ STYLE[ 'GREEN'  ] }m{ '[SUCCESS] ' if not tag else f'[{ tag }] ' }{ STYLE[ 'END' ] }{ msg }"
        elif level == LOGLEVEL[ 'WARNING' ]: msg = f"\033[{ STYLE[ 'YELLOW' ] }m{ '[WARNING] ' if not tag else f'[{ tag }] ' }{ STYLE[ 'END' ] }{ msg }"
        elif level == LOGLEVEL[ 'FAIL'    ]: msg = f"\033[{ STYLE[ 'RED'    ] }m{ '[FAIL] '    if not tag else f'[{ tag }] ' }{ STYLE[ 'END' ] }{ msg }"
        elif level == LOGLEVEL[ 'ERROR'   ]: msg = f"\033[{ STYLE[ 'RED'    ] }m{ '[ERROR] '   if not tag else f'[{ tag }] ' }{ STYLE[ 'END' ] }{ msg }"
        elif level == LOGLEVEL[ 'DEBUG'   ]: msg = f"\033[{ STYLE[ 'GREEN'  ] }m{ '[DEBUG] '   if not tag else f'[{ tag }] ' }{ STYLE[ 'END' ] }{ msg }"
        else:
            msg = "{tag}{msg}".format(
                  tag = f"\033[{ STYLE[ 'WHITE' ] }{ STYLE[ 'SELECTED' ] }m{ tag }{ STYLE[ 'END' ] } " if tag else ''
                , msg = f"\033[{ STYLE[ 'WHITE' ]                        }m{ msg }{ STYLE[ 'END' ] }"  if tag else msg
            )

        print( msg, file=file, **kwargs ) if not cls.debug_mode else None

    #########################################################################
    # 로그 종류별 메시지 포맷 클래스
    #########################################################################
    class LogFormatter( Formatter ):

        def __init__(
              cls
            , colored = False
            , fmt     = '%(msg)s'
            , datefmt = '%Y-%m-%d %H:%M:%S'
        ):
            ############################################################
            # 부모클래스의 __init__() 함수를 참조한다.
            ############################################################
            super().__init__(
                  fmt     = fmt
                , datefmt = datefmt
            )

            ############################################################
            # 로그메세지 포맷 정의
            ############################################################
            TIMESTAMP  = '%(asctime)s.%(msecs)02d'
            MODULENAME = '%(name)s'
            LINENO     = '%(lineno)s'
            FUNCNAME   = '%(funcName)s'
            MESSAGE    = fmt

            if colored:
                cls.d_fmt = f"\033[{ STYLE[ 'GREEN'  ] }m{ '[DEBUG]'   }{ STYLE[ 'END' ] }{ TIMESTAMP } { MODULENAME }, line { LINENO } in { FUNCNAME } - \033[{ STYLE[ 'GREEN'  ] }m{ MESSAGE }{ STYLE[ 'END' ] }"
                cls.i_fmt = f"\033[{ STYLE[ 'WHITE'  ] }m{ '[INFO]'    }{ STYLE[ 'END' ] }{ TIMESTAMP } { MODULENAME }, line { LINENO } in { FUNCNAME } - \033[{ STYLE[ 'WHITE'  ] }m{ MESSAGE }{ STYLE[ 'END' ] }"
                cls.w_fmt = f"\033[{ STYLE[ 'YELLOW' ] }m{ '[WARNING]' }{ STYLE[ 'END' ] }{ TIMESTAMP } { MODULENAME }, line { LINENO } in { FUNCNAME } - \033[{ STYLE[ 'YELLOW' ] }m{ MESSAGE }{ STYLE[ 'END' ] }"
                cls.f_fmt = f"\033[{ STYLE[ 'RED'    ] }m{ '[FAIL]'    }{ STYLE[ 'END' ] }{ TIMESTAMP } { MODULENAME }, line { LINENO } in { FUNCNAME } - \033[{ STYLE[ 'RED'    ] }m{ MESSAGE }{ STYLE[ 'END' ] }"
                cls.e_fmt = f"\033[{ STYLE[ 'RED'    ] }m{ '[ERROR]'   }{ STYLE[ 'END' ] }{ TIMESTAMP } { MODULENAME }, line { LINENO } in { FUNCNAME } - \033[{ STYLE[ 'RED'    ] }m{ MESSAGE }{ STYLE[ 'END' ] }"

            else:
                cls.d_fmt = f"{ '[DEBUG]'   } { TIMESTAMP } { MODULENAME }.{ LINENO } { FUNCNAME } - { MESSAGE }"
                cls.i_fmt = f"{ '[INFO]'    } { TIMESTAMP } { MODULENAME }.{ LINENO } { FUNCNAME } - { MESSAGE }"
                cls.w_fmt = f"{ '[WARNING]' } { TIMESTAMP } { MODULENAME }.{ LINENO } { FUNCNAME } - { MESSAGE }"
                cls.f_fmt = f"{ '[FAIL]'    } { TIMESTAMP } { MODULENAME }.{ LINENO } { FUNCNAME } - { MESSAGE }"
                cls.e_fmt = f"{ '[ERROR]'   } { TIMESTAMP } { MODULENAME }.{ LINENO } { FUNCNAME } - { MESSAGE }"

        def format( cls, record ):
            fmt_origin = cls._style._fmt

            if   record.levelno == DEBUG   : cls._style._fmt = cls.d_fmt
            elif record.levelno == INFO    : cls._style._fmt = cls.i_fmt
            elif record.levelno == WARNING : cls._style._fmt = cls.w_fmt
            elif record.levelno == ERROR   : cls._style._fmt = cls.f_fmt
            elif record.levelno == CRITICAL: cls._style._fmt = cls.e_fmt

            result          = Formatter.format( cls, record )
            cls._style._fmt = fmt_origin

            return result
        
def elapsed( original_fn ):
    
    def wrapper( *args, **kwargs ):
        start_time = time()
        result     = original_fn( *args, **kwargs )
        end_time   = time()
        
        print( f"### WorkingTime[ { original_fn.__name__ }() ]: { end_time - start_time } sec ###" )

        return result
    
    return wrapper

def get_memory_usage( pid ):
    if   ( rss := Process( pid ).memory_info().rss ) < ( 1024      ): return f"{ round( rss / 2      , 3 ) } B"
    elif ( rss                                     ) < ( 1024 ** 2 ): return f"{ round( rss / 2 ** 10, 3 ) } KB"
    elif ( rss                                     ) < ( 1024 ** 3 ): return f"{ round( rss / 2 ** 20, 3 ) } MB"
    elif ( rss                                     ) < ( 1024 ** 4 ): return f"{ round( rss / 2 ** 30, 3 ) } GB"