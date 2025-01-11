# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/util/inspector.py
# Author : Hoon
# 
# ====================== Comments ======================
#

from os   import popen
from re   import compile as re_compile
from json import load    as json_load

# Engine Libraries
from engine.core.config.default import ENCODING
from engine.core.util           import ifelse

def merge( a, b ):
    
    for key in b:
    
        if key in a:
    
            if a[ key ] == b[ key ]:
                pass

            elif isinstance( a[ key ], dict )\
            and  isinstance( b[ key ], dict ):
                merge( a[ key ], b[ key ] )

            elif isinstance( a[ key ], set )\
            and  isinstance( b[ key ], set ):
                a[ key ].update( b[ key ] ); list( a[ key ] )
            
            elif isinstance( a[ key ], list )\
            and  isinstance( b[ key ], list ):
                a[ key ] = list( set( a[ key ] + b[ key ] ) )
                
            elif isinstance( a[ key ], set  )\
            and  isinstance( b[ key ], list ):
                a[ key ].update( set( b[ key ] ) ); list( a[ key ] )
                
            elif isinstance( a[ key ], list )\
            and  isinstance( b[ key ], set  ):
                set( a[ key ] ).update( b[ key ] ); list( a[ key ] )
            
            elif ( a[ key ] == None            )\
            and  ( isinstance( b[ key ], str ) ):
                a[ key ] = b[ key ]

            elif type( a[ key ] ) == type( b[ key ] ):
                a[ key ] = b[ key ]

        else:
            a[ key ] = b[ key ]

    return a

def my_rpm( distro, rpm ):
    rpm = rpm.lower()
    
    name    = ( splited := rpm.split( '|' ) )[  0 ]
    version = ( splited                     )[ -1 ] if ':' in splited[ -1 ] else f"0:{ splited[ -1 ] }"
        
    e = ( splited := version     .split( ':' ) )[ 0 ]
    v = ( splited := splited[ 1 ].split( '-' ) )[ 0 ]
    r = ( splited                              )[ 1 ] if '-' in version else '-'
    
    return { distro: { name: { e: { v: { r: { 
        'rpm': ifelse(
              _condition = ( e == '0' )
            , _istrue    = f"{ name }-{ v }-{ r }"
            , _else      = f"{ name }-{ e }:{ v }-{ r }"
        )
    } } } } } }

def get_system_rpmlist( installedList=[] ):
    distro = None
    
    my_system_rpmlist = {}

    for rpm_string in popen( '/usr/bin/rpm -qa --queryformat "%{N}|%{EPOCHNUM}:%{V}-%{R}\n"' ).read().strip().split( '\n' ) if not installedList else installedList:
      
        if (
               ( rpm_string == ''                  )
            or ( rpm_string.startswith( 'kernel' ) )
        ):
            continue
        
        elif rpm_string.startswith( 'rocky-release' ):
            distro = f"el{ rpm_string.split( '.el' )[ 1 ][ 0 ] }"

        merge(
              my_system_rpmlist
            , my_rpm(
                  distro
                , rpm_string
            )
        )
    
    return my_system_rpmlist

def version_compare( a, b ):
    class Vercmp( object ):
        R_NONALNUMTILDE = re_compile( br"^([^a-zA-Z0-9~]*)(.*)$" )
        R_NUM           = re_compile( br"^([\d]+)(.*)$"          )
        R_ALPHA         = re_compile( br"^([a-zA-Z]+)(.*)$"      )

        @classmethod
        def compare( cls, first, second ):
            first  = first.encode( "ascii", "ignore" )
            second = second.encode( "ascii", "ignore" )
         
            while first or second:
                m1              = cls.R_NONALNUMTILDE.match( first )
                m2              = cls.R_NONALNUMTILDE.match( second )
                m1_head, first  = m1.group( 1 ), m1.group( 2 )
                m2_head, second = m2.group( 1 ), m2.group( 2 )
            
                # Ignore junk at the beginning
                if m1_head or m2_head:
                    continue

                # handle the tilde separator, it sorts before everything else
                if first.startswith( b'~' ):
               
                    if not second.startswith( b'~' ):
                        return -1
               
                    first, second = first[ 1: ], second[ 1: ]
                    continue
               
                if second.startswith( b'~' ):
                    return 1

                # If we ran to the end of either, we are finished with the loop
                if not first or not second:
                    break

                # grab first completely alpha or completely numeric segment
                if ( m1 := cls.R_NUM.match( first ) ):
                    m2 = cls.R_NUM.match( second )

                    # numeric segments are always newer than alpha segments
                    if not m2:
                        return 1

                    isnum = True

                else:
                    m1 = cls.R_ALPHA.match( first  )
                    m2 = cls.R_ALPHA.match( second )
               
                    isnum = False

                # this cannot happen, as we previously tested to make sure that
                # the first string has a non-null segment
                if not m1:
                    return -1   # arbitrary
            
                if not m2:
                    return 1 if isnum else -1

                m1_head, first  = m1.group( 1 ), m1.group( 2 )
                m2_head, second = m2.group( 1 ), m2.group( 2 )

                # throw away any leading zeros - it's a number, right?
                if isnum:
                    m1_head = m1_head.lstrip( b'0' )
                    m2_head = m2_head.lstrip( b'0' )

                    # whichever number has more digits wins
                    m1hlen = len( m1_head )
                    m2hlen = len( m2_head )
               
                    if m1hlen < m2hlen: return -1
                    if m1hlen > m2hlen: return  1

                if m1_head < m2_head: return -1  # Same number of chars
                if m1_head > m2_head: return  1  # Both segments equal
            
                continue

            m1len = len( first  )
            m2len = len( second )

            if m1len == m2len == 0:
                return 0
         
            if m1len != 0:
                return 1

            return -1
    
    def _rpmvercmp( s1, s2 ):
        return Vercmp.compare( s1, s2 )
   
    def _compare_values( s1, s2 ):
        if   s1 == s2: return 0
        elif s1 != s2: return _rpmvercmp( s1, s2 )

    e1, v1, r1 = a
    e2, v2, r2 = b

    if     ( rc := _compare_values( e1, e2 ) ) == 0:
        if ( rc := _compare_values( v1, v2 ) ) == 0:
             rc  = _compare_values( r1, r2 )

    return int( rc )

def get_latest_version( pkgname, versions ):
    target = versions[ 0 ] if ':' in versions[ 0 ] else f"0:{ versions[ 0 ] }"
    latest = (
          ( splited := target      .split( ':' ) )[ 0 ]
        , ( splited := splited[ 1 ].split( '-' ) )[ 0 ]
        , ( splited                              )[ 1 ] if '-' in target else '-'
    )
    
    for version in versions:
        target = version if ':' in version else f"0:{ version }"
        target = (
              ( splited := target      .split( ':' ) )[ 0 ]
            , ( splited := splited[ 1 ].split( '-' ) )[ 0 ]
            , ( splited                              )[ 1 ] if '-' in target else '-'
        )
        
        if -1 == version_compare( latest, target ):
            latest = target
    
    e, v, r = latest
    
    return f"{ pkgname }-{ v }-{ r }" if '0' == e else f"{ pkgname }-{ e }:{ v }-{ r }"

def check_patchlist( dataset_file, system_rpmlist ):
    def _inspection( r, p ):
        result         = []
        installed_list = []
        patch_list     = []

        for         e1 in r:
            for     v1 in r[ e1 ]:
                for r1 in r[ e1 ][ v1 ]:
                    installed_list.append( ( e1, v1, r1 ) )

        for         e2 in p:
            for     v2 in p[ e2 ]:
                for r2 in p[ e2 ][ v2 ]:
                    patch_list.append( ( e2, v2, r2 ) )

        for     pat in patch_list:
            for ins in installed_list:
            
                if version_compare( ins, pat ) > -1:
                    continue

                else:
                    e1, v1, r1 = ins
                    e2, v2, r2 = pat
                    result.append( {
                          '_installed' : r[ e1 ][ v1 ][ r1 ][ 'rpm' ]
                        , '_patch'     : p[ e2 ][ v2 ][ r2 ][ 'rpm' ]
                        , 'cve'        : p[ e2 ][ v2 ][ r2 ][ 'cve' ]
                    } )
      
        return result
   
    #######################################################################
    with open( dataset_file, 'r', encoding=ENCODING ) as f:
        jsonContent = json_load( f )
    
    patchlist = jsonContent[ 'criteria' ][ 'rpm' ]
    cvedict   = jsonContent[ 'cve'      ]
    
    result = {}
    p      = patchlist
    r      = system_rpmlist
   
    for     rhv in r:
        for rpm in r[ rhv ]:

            try:
                p[ rhv ][ rpm ]

            except KeyError:
                continue

            else:
                for vul in _inspection( r[ rhv ][ rpm ], p[ rhv ][ rpm ] ):
                    merge(
                          result
                        , {
                              rpm : { 
                                    '_installed' :   vul[ '_installed' ]
                                  , '_vulnfixed' : [ vul[ '_patch'     ] ]
                                  , 'cve'        :   vul[ 'cve'        ]
                              }
                          }
                    )
    
                if rpm in result:
                    result[ rpm ][ '_vulnfixed' ] = get_latest_version(
                          pkgname  =                 rpm
                        , versions = [ _.lstrip( f'{ rpm }-' ) for _ in set( result[ rpm ][ '_vulnfixed' ] ) ]
                    )

                    result[ rpm ][ 'cve' ] = { cveID : cvedict[ cveID ] for cveID in set( result[ rpm ][ 'cve' ] ) }
                
    return result
