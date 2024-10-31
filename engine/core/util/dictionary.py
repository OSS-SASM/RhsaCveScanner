# -*- coding: utf-8 -*-
# 
# Script : rhsaCveScanner/engine/core/util/dictionary.py
# Author : Hoon
# 
# ====================== Comments ======================
#

def make_pretty( dictionary, exceptions=[] ):
    longest_key = 0
    for k in dictionary.keys():
        len_key = len(k)
        if len_key > longest_key: longest_key = len_key

    return '\n'.join( [ r'{} : {}'.format(f"\t{k:<{longest_key}}", v) for k, v in sorted( dictionary.items() ) if k not in exceptions ] )

#######################################################
# dictionary 합치는 함수 ( 합쳐진 결과가 a에 저장된다 )
# value 값은 list 형태로 이어붙인다
#######################################################
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
                try             : a[ key ] = list( set( a[ key ] + b[ key ] ) )
                except TypeError: a[ key ] = [ merge( _a, _b ) for _a in a[ key ] for _b in b[ key ] ]
                
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

def sort_dictionary(item):
    dic = {}
    for k, v in sorted( item.items() ):
        if isinstance( v, dict ):
            dic[k] = sort_dictionary( v )

        elif isinstance( v, set  ):
            dic[k] = list( sorted(v) )

        elif isinstance( v, list ): 
            try             : dic[k] = list( set( sorted(v) ) )
            except TypeError: dic[k] = v

        else: 
            dic[k] = v

    return dic
