# viper-metascan
Metadefender Core (Metascan v.4) analysis module for Viper malware analysis framework

viper > ms -h<br/>
usage: ms [-h] [-f] [-e] [-l] [--listworkflows] [-w WORKFLOW [WORKFLOW ...]]<br/>
<br/>
Metadefender Core (Metascan v4) analysis module. (c) 2016 Secure Networx Ltd.<br/>
<br/>
optional arguments:<br/>
  -h, --help            show this help message and exit<br/>
  -f, --find            Analyze all found items<br/>
  -e, --engines         List engines<br/>
  -l, --license         List licenses<br/>
  --listworkflows       List workflows<br/>
  -w WORKFLOW [WORKFLOW ...], --workflow WORKFLOW [WORKFLOW ...]<br/>
                        Use selected workflow<br/>

Single file analysis:<br />
<br />
viper 3725630036655b1bf9c9b6f0b555d663.doc > <br />
[*] Session opened on /home/shark/viper/projects/fireeye/binaries/d/3/1/d/d31d4ccced028f11703b88cd0c610fc6b706892d7376d2a26124ab34fbea57f9<br />
viper 3725630036655b1bf9c9b6f0b555d663.doc > ms<br />
+3725630036655b1bf9c9b6f0b555d663.doc-----------------+---------------------+<br />
| Engine      | Threat                                | Def. time           |<br />
+-------------+---------------------------------------+---------------------+<br />
| Cyren       | W97M/Downloader.DX                    | 2016-02-20 10:03:00 |<br />
| ESET        | VBA/TrojanDownloader.Agent.API trojan | 2016-02-20 00:00:00 |<br />
| ClamAV      |                                       | 2016-02-20 10:37:07 |<br />
| Bitdefender | Trojan.Doc.Downloader.IW              | 2016-02-20 10:43:21 |<br />
| Agnitum     |                                       | 2016-02-17 10:34:38 |<br />
| Avira       | W2000M/Donoff.AF                      | 2016-02-20 00:00:00 |<br />
| ThreatTrack |                                       | 2016-02-20 05:20:13 |<br />
| Ikarus      | Trojan-Downloader.VBA.Agent           | 2016-02-20 09:08:12 |<br />
| K7          |                                       | 2016-02-20 00:00:00 |<br />
+-------------+---------------------------------------+---------------------+<br />
<br />
+Summary-------------------------------+----------------------------------+--------+<br />
| Filename                             | md5                              | status |<br />
+--------------------------------------+----------------------------------+--------+<br />
| 3725630036655b1bf9c9b6f0b555d663.doc | 3725630036655b1bf9c9b6f0b555d663 | 5/9    |<br />
+--------------------------------------+----------------------------------+--------+<br />
viper 3725630036655b1bf9c9b6f0b555d663.doc > <br />
