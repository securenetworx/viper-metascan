# viper-metascan

[![Build Status](https://travis-ci.org/securenetworx/viper-metascan.svg?branch=master)](https://travis-ci.org/securenetworx/viper-metascan)

Metadefender Core (Metascan v.4) analysis module for Viper malware analysis framework

## Configure

Metascan server IP and (if needed) username and password configured in the ms4.py. 

## Usage

```
viper > ms4 -h
usage: ms4 [-h] [-f] [-e] [-l] [--listworkflows] [-w WORKFLOW [WORKFLOW ...]]

Metadefender Core (Metascan v4) analysis module. (c) 2016 Secure Networx Ltd.

optional arguments:
  -h, --help            show this help message and exit
  -f, --find            Analyze all found items
  -e, --engines         List engines
  -l, --license         List licenses
  --listworkflows       List workflows
  -w WORKFLOW [WORKFLOW ...], --workflow WORKFLOW [WORKFLOW ...]
                        Use selected workflow
```

## Single file analysis:

```
viper 3725630036655b1bf9c9b6f0b555d663.doc >
[*] Session opened on /home/shark/viper/projects/fireeye/binaries/d/3/1/d/d31d4ccced028f11703b88cd0c610fc6b706892d7376d2a26124ab34fbea57f9
viper 3725630036655b1bf9c9b6f0b555d663.doc >ms4
+3725630036655b1bf9c9b6f0b555d663.doc-----------------+---------------------+
| Engine      | Threat                                | Def. time           |
+-------------+---------------------------------------+---------------------+
| Cyren       | W97M/Downloader.DX                    | 2016-02-20 10:03:00 |
| ESET        | VBA/TrojanDownloader.Agent.API trojan | 2016-02-20 00:00:00 |
| ClamAV      |                                       | 2016-02-20 10:37:07 |
| Bitdefender | Trojan.Doc.Downloader.IW              | 2016-02-20 10:43:21 |
| Agnitum     |                                       | 2016-02-17 10:34:38 |
| Avira       | W2000M/Donoff.AF                      | 2016-02-20 00:00:00 |
| ThreatTrack |                                       | 2016-02-20 05:20:13 |
| Ikarus      | Trojan-Downloader.VBA.Agent           | 2016-02-20 09:08:12 |
| K7          |                                       | 2016-02-20 00:00:00 |
+-------------+---------------------------------------+---------------------+
+Summary-------------------------------+----------------------------------+--------+
| Filename                             | md5                              | status |
+--------------------------------------+----------------------------------+--------+
| 3725630036655b1bf9c9b6f0b555d663.doc | 3725630036655b1bf9c9b6f0b555d663 | 5/9    |
+--------------------------------------+----------------------------------+--------+
viper 3725630036655b1bf9c9b6f0b555d663.doc >
```

## Multiple file analysis

```
viper > find tag 20160126
+---+--------------------------------------+--------------------------+----------------------------------+----------+
| # | Name                                 | Mime                     | MD5                              | Tags     |
+---+--------------------------------------+--------------------------+----------------------------------+----------+
| 1 | 3725630036655b1bf9c9b6f0b555d663.doc | application/msword       | 3725630036655b1bf9c9b6f0b555d663 | 20160126 |
| 2 | dfa925d1e0ecc10a22f18a75e42c8679.rtf | text/rtf                 | dfa925d1e0ecc10a22f18a75e42c8679 | 20160126 |
| 3 | 040d71e5124a073e78ed6bcd4eeedd7e.xls | application/vnd.ms-excel | 040d71e5124a073e78ed6bcd4eeedd7e | 20160126 |
+---+--------------------------------------+--------------------------+----------------------------------+----------+
viper >ms4 -f
+3725630036655b1bf9c9b6f0b555d663.doc-----------------+---------------------+
| Engine      | Threat                                | Def. time           |
+-------------+---------------------------------------+---------------------+
| Cyren       | W97M/Downloader.DX                    | 2016-02-20 10:03:00 |
| ESET        | VBA/TrojanDownloader.Agent.API trojan | 2016-02-20 00:00:00 |
| ClamAV      |                                       | 2016-02-20 10:37:07 |
| Bitdefender | Trojan.Doc.Downloader.IW              | 2016-02-20 10:43:21 |
| Agnitum     |                                       | 2016-02-17 10:34:38 |
| Avira       | W2000M/Donoff.AF                      | 2016-02-20 00:00:00 |
| ThreatTrack |                                       | 2016-02-20 05:20:13 |
| Ikarus      | Trojan-Downloader.VBA.Agent           | 2016-02-20 09:08:12 |
| K7          |                                       | 2016-02-20 00:00:00 |
+-------------+---------------------------------------+---------------------+
+dfa925d1e0ecc10a22f18a75e42c8679.rtf----+---------------------+
| Engine      | Threat                   | Def. time           |
+-------------+--------------------------+---------------------+
| Cyren       | W32/Dridex.KJQX-7819     | 2016-02-20 10:03:00 |
| ESET        |                          | 2016-02-20 00:00:00 |
| ClamAV      |                          | 2016-02-20 10:37:07 |
| Bitdefender | Trojan.GenericKD.2999814 | 2016-02-20 10:43:21 |
| Agnitum     |                          | 2016-02-17 10:34:38 |
| Avira       | TR/Crypt.Xpack.417467    | 2016-02-20 00:00:00 |
| ThreatTrack |                          | 2016-02-20 05:20:13 |
| Ikarus      | Trojan.Crypt.XPACK       | 2016-02-20 09:08:12 |
| K7          |                          | 2016-02-20 00:00:00 |
+-------------+--------------------------+---------------------+
+040d71e5124a073e78ed6bcd4eeedd7e.xls-----------------+---------------------+
| Engine      | Threat                                | Def. time           |
+-------------+---------------------------------------+---------------------+
| Cyren       | X97M/Downldr.AL.gen                   | 2016-02-20 10:03:00 |
| ESET        | VBA/TrojanDownloader.Agent.APB trojan | 2016-02-20 00:00:00 |
| ClamAV      |                                       | 2016-02-20 10:37:07 |
| Bitdefender | W97M.Downloader.APV                   | 2016-02-20 10:43:21 |
| Agnitum     |                                       | 2016-02-17 10:34:38 |
| Avira       | X2000M/Adnel.AD                       | 2016-02-20 00:00:00 |
| ThreatTrack |                                       | 2016-02-20 05:20:13 |
| Ikarus      | Trojan-Downloader.VBA.Agent           | 2016-02-20 09:08:12 |
| K7          |                                       | 2016-02-20 00:00:00 |
+-------------+---------------------------------------+---------------------+
+Summary-------------------------------+----------------------------------+--------+
| Filename                             | md5                              | status |
+--------------------------------------+----------------------------------+--------+
| 3725630036655b1bf9c9b6f0b555d663.doc | 3725630036655b1bf9c9b6f0b555d663 | 5/9    |
| dfa925d1e0ecc10a22f18a75e42c8679.rtf | dfa925d1e0ecc10a22f18a75e42c8679 | 4/9    |
| 040d71e5124a073e78ed6bcd4eeedd7e.xls | 040d71e5124a073e78ed6bcd4eeedd7e | 5/9    |
+--------------------------------------+----------------------------------+--------+
viper > 
```
