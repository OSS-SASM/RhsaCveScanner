# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/src/redhat.py
# Author : Hoon
# 
# ====================== Comments ======================
# CPE Description
# cpe:2.3: {part} : {vendor} : {product} : {version} : {update} : {edition} : {language} : {sw_edition} : {target_sw} : {target_hw} : {other}
#            └ h = hardware
#            └ o = operating system
#            └ a = application

from os        import listdir
from os.path   import basename as path_basename
from os.path   import abspath  as path_abspath
from os.path   import join     as path_join
from pickle    import load     as pkl_load
from requests  import get      as requests_get
from re        import search   as re_search
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
        # Download security advisory datas from redhat.com
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
            
            cveList = ifelse(
                  _condition = isinstance( advisory[ 'cve' ], list )
                , _istrue    =             advisory[ 'cve' ]
                , _else      =           [ advisory[ 'cve' ] ]
            )
            
            ###############################################################################################################################################################
            # 취약한 버전의 패키지가 어떠한 RHEL 배포판 버전 위에서 동작할 때, 영향이 있는지 확인하고
            # 해당 정보가 확인되는 경우에만 파싱
            ###############################################################################################################################################################
            if (
                    ( 'OR'                                         == definition[ 'criteria' ][ '@operator' ]               )
                and ( 'Red Hat Enterprise Linux must be installed' == definition[ 'criteria' ][ 'criterion' ][ '@comment' ] )
                and ( distro :=  self._find_affected_version_of_rhel( definition[ 'criteria' ] )                            )
            ):
                ################################################################################################################
                # 권장 설치 버전 기준 ( 해당 버전 보다 낮은 경우, 노출될 수 있는 취약점 정보가 매핑됨 )
                ################################################################################################################
                merge(
                      CRITERIA
                    , ( rpmlist := {
                            distro
                          : self._recursive_criteria(
                                parent  = definition[ 'criteria' ][ 'criteria' ]
                              , cveList = [ c[ '#text' ] for c in cveList ]
                          )  
                      } )
                )
            
            ###############################################################################################################################################################
            # CVE
            ###############################################################################################################################################################
            for cve in cveList:

                if cve[ '#text' ] not in CVE_DETAIL_BY_ID:
                    CVE_DETAIL_BY_ID[ cve[ '#text' ] ] = {}
                    
                CVE_DETAIL_BY_ID[ cve[ '#text' ] ] = merge(
                      CVE_DETAIL_BY_ID[ cve[ '#text' ] ]
                    , self._parse_cvemeta( {
                            **cve
                          , 'severity'    : advisory  [ 'severity' ]
                          , 'from'        : advisory  [ '@from'    ]
                          , 'remediation' : rpmlist
                          , 'reference'   : ifelse(
                                _condition = isinstance( definition[ 'metadata' ][ 'reference' ], list )
                              , _istrue    =             definition[ 'metadata' ][ 'reference' ]
                              , _else      =           [ definition[ 'metadata' ][ 'reference' ] ]
                            )
                          , 'bugzilla'    : [ bugzilla for bugzilla in (
                                ifelse(
                                      _condition = isinstance( advisory[ 'bugzilla' ], list )
                                    , _istrue    =             advisory[ 'bugzilla' ]
                                    , _else      =           [ advisory[ 'bugzilla' ] ]
                                ) if 'bugzilla' in advisory else []
                            ) if cve[ '#text' ] in bugzilla[ '#text' ] ]
                      } )
                )
                
        return {
              'cve'      : CVE_DETAIL_BY_ID
            , 'criteria' : { 'rpm' : CRITERIA }
        }

    def _find_affected_version_of_rhel( self, parent ):
        distro = None
        
        for child in ifelse(
              _condition = isinstance( parent, list )
            , _istrue    =             parent
            , _else      =           [ parent ]
        ):
            if  ( 'criteria' in child                                                      )\
            and ( distro     := self._find_affected_version_of_rhel( child[ 'criteria' ] ) ):
                return distro
                
            if 'criterion' in child:
                
                for criterion in ifelse(
                      _condition = isinstance( child[ 'criterion' ], list )
                    , _istrue    =             child[ 'criterion' ]
                    , _else      =           [ child[ 'criterion' ] ]
                ):
                
                    if ( m :=
                        re_search(
                              r'Red\ Hat\ Enterprise\ Linux\ (\d+)\ is\ installed'
                            , criterion[ '@comment' ]
                            , IGNORECASE
                        )
                    ):
                        return f'el{ m.group( 1 ) }'
        
        return distro
    
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

            if 'criterion' in child:

                for criterion in ifelse(
                      _condition = isinstance( child[ 'criterion' ], list )
                    , _istrue    =             child[ 'criterion' ]
                    , _else      =           [ child[ 'criterion' ] ]
                ):
                    
                    if 'is earlier than' not in criterion[ '@comment' ]:
                        continue
                    
                    name    = ( splited := criterion[ '@comment' ].lower().split() )[  0 ]
                    version = ( splited                                            )[ -1 ] if ':' in splited[ -1 ] else f'0:{ splited[ -1 ] }'
                    
                    e = ( splited := version     .split( ':' ) )[ 0 ]
                    v = ( splited := splited[ 1 ].split( '-' ) )[ 0 ]
                    r = ( splited                              )[ 1 ] if '-' in version else '-'

                    merge(
                          result
                        , { name: { e: { v: { r: {
                              'rpm' : ifelse(
                                    _condition = ( e == '0' )
                                  , _istrue    = f"{ name }-{ v }{ '-' + r if r != '-' else '' }"
                                  , _else      = f"{ name }-{ version }"
                              )
                            , 'cve' : cveList
                        } } } } }
                    )

        return result
    
    def _parse_cvemeta( self, data ):
        PARSED = {
            'redhat' : {
                'rhsa' : {
                      'severity' : data[ 'severity' ]
                }
            }
        }
            
        #################################################################################################################################################################
        # REFERENCE
        #################################################################################################################################################################
        if '@href' in data:
            merge(
                  PARSED[ 'redhat' ][ 'rhsa' ]
                , { 'reference' : [ data[ '@href' ] ] }   
            )
            
        if  (            data[ 'bugzilla' ] )\
        and ( '@href' in data[ 'bugzilla' ] ):
            merge(
                  PARSED[ 'redhat' ][ 'rhsa' ]
                , { 'reference' : [ data[ 'bugzilla' ][ '@href' ] ] }   
            )
            
        for r in data[ 'reference' ]:
            if 'CVE' != r[ '@source' ]:
                merge(
                      PARSED[ 'redhat' ][ 'rhsa' ]
                    , { 'reference' : [ r[ '@ref_url' ] ] }   
                )   

        #################################################################################################################################################################
        # IMPACT
        #################################################################################################################################################################
        if '@impact' in data:
            PARSED[ 'redhat' ][ 'rhsa' ][ 'impact' ] = data[ '@impact' ]

        #################################################################################################################################################################
        # CWE
        #################################################################################################################################################################
        if '@cwe' in data:
            PARSED[ 'redhat' ][ 'rhsa' ][ 'cwe' ] = [ f"CWE-{ no }"
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
                  PARSED[ 'redhat' ][ 'rhsa' ]
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
                  PARSED[ 'redhat' ][ 'rhsa' ]
                , {
                    'cvss' : {
                        ( splited := data[ '@cvss3' ].split( '/' ) )[ 1 ].lstrip( 'CVSS:' ) : {
                              'source'              : data[ 'from' ]
                            , 'vectorString'        : ( vectorString :=     '/'.join( splited[ 1: ] )      )
                            , 'baseScore'           : ( baseScore    := round( float( splited[ 0  ] ), 1 ) )
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

        return PARSED
