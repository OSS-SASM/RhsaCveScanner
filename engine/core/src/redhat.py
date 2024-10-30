# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/src/redhat.py
# Author : Hoon
# 
# ====================== Comments ======================
#

from os        import listdir
from os.path   import basename as path_basename
from os.path   import abspath  as path_abspath
from os.path   import join     as path_join
from pickle    import load     as pkl_load
from requests  import get      as requests_get
from re        import findall  as re_findall
from re        import IGNORECASE
from cvss      import CVSS2, CVSS3

# Engine Library
from engine.core.util import mkdir, rmdir
from engine.core.util import merge
from engine.core.util import download_file
from engine.core.util import decompress_bz2files
from engine.core.util import xml_to_pkl
from engine.core.util import ifelse

class REDHAT:
    def __init__(
          self
        , src_path
        , remove_old_workplace = True
        , download_src_files   = True
        , logger               = None
    ):
        ################################################################################################################################################################################
        # Logger
        ################################################################################################################################################################################
        self.logger = logger
        
        ################################################################################################################################################################################
        # Workplace directory
        ################################################################################################################################################################################
        self.src_path = path_abspath( path_join( src_path, 'REDHAT' ) )

        ################################################################################################################################################################################
        # Remove old workplace directory
        ################################################################################################################################################################################
        if remove_old_workplace:
            rmdir( path_abspath( path_join( self.src_path, 'oval_v2' ) ) )
        
        ################################################################################################################################################################################
        # Create workplace directory
        ################################################################################################################################################################################
        mkdir( path_abspath( path_join( self.src_path, 'oval_v2' ) ) )
        
        ################################################################################################################################################################################
        # Retrieve & get latest cpes, cpematch, cves datas from NVD
        ################################################################################################################################################################################
        if download_src_files:

            for url in [ _[ 'resourceUrl' ] for _ in requests_get( "https://access.redhat.com/hydra/rest/securitydata/oval/ovalstreams.json" ).json() ]:
                
                self.logger.info( f'Download oval from "{ url }"' )
                
                if download_file( uri=url, savepath=self.src_path ):
                    
                    self.logger.info( f'''Decompress file "{ path_join( self.src_path, 'oval_v2', path_basename( url ) ) }"''' )
                    
                    decompress_bz2files( self.src_path, extract_path=path_join( self.src_path, 'oval_v2' ) )
                    
                    self.logger.info( f'''Convert xml to pkl "{ path_join( self.src_path, 'oval_v2', path_basename( url ) ).rstrip( '.bz2' ) }"''' )
                    
                    xml_to_pkl( 
                        path_join( 
                              self.src_path
                            , 'oval_v2'
                            , path_basename( url ).rstrip( '.bz2' ) 
                        )
                    , remove_old=True )
        
    def __call__( self ):
        return self.extract()
    
    def extract( self ):
        parsed = {}
        
        ################################################################################################################################################################################
        # REDHAT OVAL v2 xml files
        ################################################################################################################################################################################
        for oval_ver in [ 'oval_v2' ]:

            for oval in listdir( directory := path_join( self.src_path, oval_ver ) ):

                self.logger.info( f"Extracting data from { oval }" )

                ###############################################################################################################################################################
                # retrieve oval definitions
                ###############################################################################################################################################################
                with open( path_join( directory, oval ), 'rb' ) as f:
                    oval_definitions = ifelse(
                          _condition = isinstance( ( oval_definitions := pkl_load( f )[ 'oval_definitions' ][ 'definitions' ][ 'definition' ] ), list )
                        , _istrue    =               oval_definitions
                        , _else      =             [ oval_definitions ]
                    )

                merge(
                      parsed
                    , self._extract_data_from_rhsa_oval( oval_definitions )
                )

        return parsed

    def _extract_data_from_rhsa_oval( self, oval_definitions ):
        CVE_DETAIL_BY_ID = {}
        CRITERIA         = {}

        for definition in oval_definitions:
            
            ###############################################################################################################################################################
            # advisory 정보에 CVE 취약점 내용이 없는 경우 제외
            ###############################################################################################################################################################
            if 'cve' not in ( advisory := definition[ 'metadata' ][ 'advisory' ] ):
                continue
            
            ###############################################################################################################################################################
            # CVE
            ###############################################################################################################################################################
            for cve in ( cveList := ifelse(
                  _condition = isinstance( advisory[ 'cve' ], list )
                , _istrue    =             advisory[ 'cve' ]
                , _else      =           [ advisory[ 'cve' ] ]
            ) ):

                CVE_DETAIL_BY_ID[ cve[ '#text' ] ] = self._parse_cvemeta( {
                      **cve
                    , 'title'       : definition[ 'metadata' ][ 'title'       ]
                    , 'description' : definition[ 'metadata' ][ 'description' ]
                    , 'from'        : advisory  [ '@from'    ]
                } )

            ###############################################################################################################################################################
            # 권장 설치 버전 기준 ( 해당 버전 보다 낮은 경우, 노출될 수 있는 취약점 정보가 매핑됨 )
            ###############################################################################################################################################################
            merge(
                  CRITERIA
                , self._recursive_criteria(
                      parent  = definition[ 'criteria' ]
                    , cveList = [ c[ '#text' ] for c in cveList ]
                  )
            )
                
        return {
              'cve'      : CVE_DETAIL_BY_ID
            , 'criteria' : { 'rpm' : CRITERIA }
        }

    def _recursive_criteria( self, parent, cveList ):
        result = {}

        for child in ifelse(
              _condition = isinstance( parent, list )
            , _istrue    =             parent
            , _else      =           [ parent ]
        ):
            
            if 'criteria' in child:
                merge(
                      result
                    , self._recursive_criteria( child[ 'criteria' ], cveList )
                )

            elif 'criterion' in child:

                for criterion in ifelse(
                      _condition = isinstance( child[ 'criterion' ], list )
                    , _istrue    =             child[ 'criterion' ]
                    , _else      =           [ child[ 'criterion' ] ]
                ):
                    if 'is earlier than' not in criterion[ '@comment' ]: continue
                    else                                               : comment = criterion[ '@comment' ].split()

                    rpm          = '-'.join( [ comment[ 0 ], comment[ -1 ] ] ).lower()
                    rpm_name     = rpm.split( ':' )[ 0 ].rsplit( '-', 1 )[ 0 ] if ':' in rpm else rpm.split( '.' )[ 0 ].rsplit( '-', 1 )[ 0 ]
                    rpm_version  = rpm[ len( rpm_name ) + 1: ]
                    
                    rhel_version = 'el' + rpm_version.split( 'el' )[ 1 ].split( '.'       )[ 0 ] if 'el'     in rpm_version else '-'
                    epoch        =        rpm_version.split( ':'  )[ 0 ]                         if ':'      in rpm_version else '-'
                    version      =        rpm_version.split( ':'  )[ 1 ].split( '-'       )[ 0 ] if ':'      in rpm_version else rpm_version.split( '-' )[ 0 ]
                    release      =        rpm_version.split( '-'  )[ 1 ].split( '.centos' )[ 0 ] if 'centos' in rpm_version else rpm_version.split( '-' )[ 1 ]

                    merge(
                          result
                        , { rhel_version: { rpm_name: { epoch: { version: { release: {
                              'rpm' : rpm
                            , 'cve' : cveList
                        } } } } } }
                    )

        return result
    
    def _parse_cvemeta( self, data ):
        result = {
            'redhat' : {
                'rhsa' : {
                      'title'       : data[ 'title'       ]
                    , 'description' : data[ 'description' ]
                }
            }
        }

        #################################################################################################################################################################
        # REFERENCE
        #################################################################################################################################################################
        if '@href' in data:
            result[ 'redhat' ][ 'rhsa' ][ 'reference' ] = data[ '@href' ]

        #################################################################################################################################################################
        # IMPACT
        #################################################################################################################################################################
        if '@impact' in data:
            result[ 'redhat' ][ 'rhsa' ][ 'impact' ] = data[ '@impact' ]

        #################################################################################################################################################################
        # CWE
        #################################################################################################################################################################
        if '@cwe' in data:
            result[ 'redhat' ][ 'rhsa' ][ 'cwe' ] = [ f"CWE-{ no }"
                for no in list( set( re_findall(
                      r'\b[^a-z0-9]*CWE[^\da-z]*(\d+)[^\d\w]?\b'
                    , data[ '@cwe' ]
                    , IGNORECASE
                ) ) )
            ]

        #################################################################################################################################################################
        # CVSS
        #################################################################################################################################################################
        if '@cvss2' in data:
            merge(
                  result[ 'redhat' ][ 'rhsa' ]
                , {
                    'cvss' : {
                        '2.0' : {
                              'source'              :                                            data[ 'from'   ]
                            , 'vectorString'        : ( vectorString :=   '/'.join( ( splited := data[ '@cvss2' ].split( '/' ) )[ 1: ] ) )
                            , 'baseScore'           : ( baseScore    := round( float( splited[ 0 ]                             ), 1    ) )
                            , 'temporalScore'       : round( float( this.temporal_score if ( this := CVSS2( vectorString ) ).temporal_score else '0.0' ), 1 )
                            , 'exploitabilityScore' : round( float(                                                                              '0.0' ), 1 )
                            , 'impactScore'         : round( float(                                                                              '0.0' ), 1 )
                            , 'baseSeverity'        : (
                                'HIGH'   if ( baseScore > 6.9 ) else
                                'MEDIUM' if ( baseScore > 3.9 ) else
                                'LOW'    if ( baseScore > 0   ) else
                                'NONE'
                            )
                        }
                    }
                }
            )
        
        if '@cvss3' in data:
            merge(
                  result[ 'redhat' ][ 'rhsa' ]
                , {
                    'cvss' : {
                        '3.0' : {
                              'source'              :                                            data[ 'from'   ]
                            , 'vectorString'        : ( vectorString :=   '/'.join( ( splited := data[ '@cvss3' ].split( '/' ) )[ 1: ] ) )
                            , 'baseScore'           : ( baseScore    := round( float( splited[ 0 ]                             ), 1    ) )
                            , 'temporalScore'       : round( float( this.temporal_score if ( this := CVSS3( vectorString ) ).temporal_score else '0.0' ), 1 )
                            , 'exploitabilityScore' : round( float( this.esc            if ( this                          ).esc            else '0.0' ), 1 )
                            , 'impactScore'         : round( float( this.isc            if ( this                          ).isc            else '0.0' ), 1 )
                            , 'baseSeverity'        : (
                                'CRITICAL' if ( baseScore > 8.9 ) else
                                'HIGH'     if ( baseScore > 6.9 ) else
                                'MEDIUM'   if ( baseScore > 3.9 ) else
                                'LOW'      if ( baseScore > 0   ) else
                                'NONE'
                            )
                        }
                    }
                }
            )

        return result
