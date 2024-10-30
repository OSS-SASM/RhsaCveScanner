<h1> Redhat RHSA OVAL 기반의 취약점 진단 방법 </h1>

<h2> What is RHSA? </h2>

RHSA는 "Red Hat Security Advisory"의 약자로, Red Hat에서 제공하는 보안 공지입니다.
RHSA는 Red Hat Enterprise Linux (RHEL) 및 Red Hat 제품에서 발견된 보안 취약점, 버그 수정 및 중요한 업데이트에 대한 정보를 포함하고 있습니다.

#### RHSA는 다음과 같은 주요 정보를 제공합니다:

> `취약점에 대한 상세 설명`
- 발견된 취약점의 유형과 영향을 설명합니다.

> `취약점의 심각도`
- 보통, 중요, 긴급 등의 등급으로 구분하여 보안 패치를 얼마나 신속하게 적용해야 할지 안내합니다.

> `업데이트 및 패치 방법`
- 취약점을 해결하기 위해 설치해야 하는 패치나 패키지 버전을 제공합니다.

> `CVE 정보`
- 해당 취약점이 CVE(Common Vulnerabilities and Exposures)에 등록된 경우, 관련 CVE 번호를 포함하여 다른 보안 정보와 연계할 수 있도록 합니다.

#### RHSA는 Red Hat 제품을 사용하는 환경에서 최신 보안 패치를 확인하고 적용하는 데 매우 중요합니다.

<h2> What is OVAL? </h2>

OVAL은 취약점과 관련된 정보를 표현하기 위해 사용되는 XML 기반 언어로, 시스템에서 취약점을 자동으로 감지하고 평가할 수 있도록 표준화된 형식을 제공합니다. 

### RHSA OVAL 파일은 다음과 같은 역할을 합니다:

> `자동 취약점 진단:`
- OVAL 파일을 통해 보안 도구가 Red Hat 시스템에서 해당 보안 권고와 관련된 취약점이 존재하는지 자동으로 검사할 수 있습니다.

> `일관성 있는 평가:`
- OVAL의 표준화된 구조 덕분에 보안 솔루션 간에 일관된 취약점 평가를 수행할 수 있습니다.

> `보안 자동화 지원:`
- 보안 팀이 시스템 보안을 관리하는 데 필요한 시간을 줄여주며, 효율적으로 취약점을 탐지하고 대응할 수 있도록 합니다.

#### RHSA OVAL은 Red Hat에서 제공하는 보안 공지를 OVAL(Open Vulnerability and Assessment Language) 형식으로 제공하는 파일입니다. 

#### 이 파일은 Red Hat Enterprise Linux와 관련된 보안 솔루션에서 많이 사용되며, 관리자는 이 파일을 통해 RHSA에서 제공하는 취약점과 관련된 정보를 시스템에 자동으로 적용할 수 있습니다.

#
### 본문에서는 Red Hat에서 배포하는 최신 RHSA OVAL 파일들을 내려받아 하나의 단일 데이터셋 파일로 병합하고 이를 활용하여 Red Hat 계열 리눅스( RHEL, Rocky, CentOS 등 ) 시스템의 CVE 취약점 진단까지 가능한 도구를 소개합니다.
#

<h1> rhsaCveScanner </h1>

"rhsaCveScanner"는 Python으로 작성된 레드햇 계열 리눅스 패키지 취약점 진단 도구 입니다.

#### rhsaCveScanner는 아래와 같은 환경 에서 개발되었습니다.
```
<REDHAT-LINUX>
 OSNAME              Rocky Linux
 OSVERSION           9.2 (Blue Onyx)
 KERNELNAME          Linux
 KERNELVERSION       5.14.0-284.30.1.el9_2.x86_64
 KERNELBITS          64
 ARCHITECTURE        x86_64
 LASTPATCHED         2023-09-20

<PYTHON>
 VERSION             3.9.16
```

#### rhsaCveScanner는 아래와 Python 라이브러리를 사용합니다.
```
cvss==3.2
requests==2.31.0
xmltodict==0.12.0
```

<h2> 사용 방법 </h2>

```
# python3 rhsaCveScanner -h
usage: rhsaCveScanner [-h] [-v] [-d] (-V | -R | -C)

                                               *
                                              **             *   *        
                                              *                 *         
                                        * *   *              *            
                                          **  **              **          
                                              **              *        *  
                                                **           *    *  **   
                                                  ***      ***   * ***    
                                                      ************        
                                                            ****          
                                                        **********        
                                                         ***********      
                                                          ******* *****   
                                                          ****************
                                                         ***** ***********
                                                        *****  *****      
       ****                          ****             ******  ****        
    *********         ***          ********     ****  ****** *****        
    **               *****        **            ***** ***** *****         
    ***             ***  **       ***           ****** ***  *****         
     *******        **   ***       *******      **  **  *  **  **         
          ****     **     **            ****    ***  **   **   **         
            **    ***********             ***   ****  ** ***   **         
    **     ***   ***       ***    **      **    ***** *****    **         
    ********     **         ***    ********  *  *****  ***     **         
                                           ***  ******                    
           **                        *******************                  
            *******************************************                   
             *************************    **************                  
            ***************                ****   ********                
        ***********  ******                ****       ******              
       *********     *****                 ***           ***              
       ****         *****                  ***           ***              
      ***           *****                  ***          **                
     ***             ****                  **          **                 
    ***                ***                 **         **                  
    **                   **                *        ***                   
   **                     ***             **      ***                     
  ***                       **            **                              
 ***                         **           **                              
**                             **         **                              
                                *          **

rhsaCveScanner v1.0.0

General Commands:
  -h, --help            Show this help message
  -v, --version         Show program's version
  -d, --debug           Enable debug mode

Commands:
  -V, --dataset-version
                        Show the date when dataset created
  -R, --dataset-rebuild
                        Rebuild dataset from RHSA OVALs
  -C, --cve-scan        Scanning CVEs with rpm packages
```

> `-V --dataset-version`
- dataset 파일의 생성날짜를 출력합니다.


> `-R, --dataset-rebuild`
- 최신 Redhat RHSA OVAL 파일을 모두 다운받아 가공하여 단일 파일로 병합합니다.

> `-C, --cve-scan`
- dataset 파일 기준으로 로컬 시스템( 레드햇 계열 리눅스만 가능 )에 설치된 RPM 패키지들에 대한 취약점을 진단합니다.


사용자는 먼저 `-R` 옵션을 통해 최신의 RHSA 데이터셋을 확보해야 합니다.
만약, 기존에 생성했었던 데이터셋 파일이 존재한다면 해당 데이터셋 파일을 통해 바로 진단을 수행( `-C`옵션으로 진단 시작 )하여도 가능하지만
데이터셋의 생성 날짜( `-V` 옵션으로 확인가능 ) 이후로 발견된 CVE 취약점들에 대한 진단은 누락되므로 최신의 데이터셋을 생성하시는 것을 권장합니다.

<h2> 진단 결과 샘플 </h2>

```
# python3 rhsaCveScanner -C ./dataset.json
{
    "el9": {
        "libssh-config": {
            "_installed": "libssh-config-0:0.10.4-8.el9",
            "_vulnfixed": "libssh-config-0:0.10.4-13.el9",
            "cve": [
                "CVE-2023-2283",
                "CVE-2023-6918",
                "CVE-2023-6004",
                "CVE-2023-1667"
            ]
        },
        "glib2": {
            "_installed": "glib2-0:2.68.4-6.el9",
            "_vulnfixed": "glib2-0:2.68.4-11.el9",
            "cve": [
                "CVE-2023-29499",
                "CVE-2023-32611",
                "CVE-2023-32665"
            ]
        }
    },
    "el9_1": {
        "kernel-core": {
            "_installed": "kernel-core-0:5.14.0-162.6.1.el9_1",
            "_vulnfixed": "kernel-core-0:5.14.0-162.23.1.el9_1",
            "cve": [
                "CVE-2022-2964",
                "CVE-2022-4744",
                "CVE-2022-4379",
                "CVE-2022-4269",
                "CVE-2022-30594",
                "CVE-2023-0266",
                "CVE-2022-2959",
                "CVE-2022-4378",
                "CVE-2023-0179",
                "CVE-2023-0386",
                "CVE-2022-4139",
                "CVE-2022-43945",
                "CVE-2022-2873",
                "CVE-2022-3564",
                "CVE-2022-3077"
            ]
        }
    },
    "el9_2": {
        "openssl-devel": {
            "_installed": "openssl-devel-1:3.0.7-17.el9_2",
            "_vulnfixed": "openssl-devel-1:3.0.7-18.el9_2",
            "cve": [
                "CVE-2023-5363"
            ]
        }
    }
}

```

위 내용은 결과로써 출력된 내용이며 각 필드의 의미는 다음과 같습니다.

- `_installed`는 로컬 시스템에 설치된 패키지의 실제 버전을 의미합니다.
- `cve`는 해당 버전에 대하여 알려진 취약점에 대한 CVE-ID를 의미합니다.
- `_vulnfixed`는 `cve`에 명시된 취약점들을 회피하기 위해 Redhat에서 권고하는 안전한 버전입니다.


###


<h1> 마치며... </h1>

위 연구를 통해 RHSA를 활용하면 레드햇 계열 리눅스 시스템에 대한 CVE 취약점 진단을 자동화할 수 있다는 사실을 알게되었습니다.

추후에는 Filebeat 혹은 Ansible을 활용하여 `다수의 점검 대상 자산`으로 부터 설치된 RPM 패키지 목록을 수집하고 이를 진단 서버로 전송하여 중앙에서 다수의 시스템을 자동진단하는 시스템을 구축하는 것을 목표로 추가적인 연구를 진행할 예정입니다.

또한 Redhat뿐 아니라 다른 벤더사들 또한 보안 권고 데이터를 공개하고 있습니다.

`Microsoft`
- MSRC (Microsoft Security Response Center)

`Debian`
- DSA (Debian Security Advisory)

`Canonical( Ubuntu )`
- USN (Ubuntu Security Notices)


위 보안 권고 데이터들 또한 OVAL 혹은 CVRF 등과 같은 표준화된 보안 데이터 표현 방식을 채택하고 있습니다.
추가적인 연구를 통하여 레드햇 계열의 시스템 이외에도 더 다양한 시스템에 대한 자동 취약점 진단이 가능하도록 연구할 계획입니다.
