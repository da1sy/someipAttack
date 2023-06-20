环境需求：
python>=3.6
radamsa

使用方法：
```
├── config.ini                              | 配置文件:主要修改服务IP和端口、以及要fuzz的字段
├── exploit.py                              | 运行脚本:sudo python3 exploit.py
├── fields.json                             | Fuzz字段:当congfig.ini 文件中设置了fuzz字段后，需要修改该文件中的[启用fuzz的字段]["fuzzing"]["fuzzer"]的fuzz方法，如"radamsa"
├── fuzzer
│   ├── config.py
│   ├── fuzzer.py                           
│   ├── heartbeat.py
│   ├── __init__.py
│   ├── log.py
│   ├── __pycache__
│   │   ├── config.cpython-36.pyc
│   │   ├── fuzzer.cpython-36.pyc
│   │   ├── heartbeat.cpython-36.pyc
│   │   ├── __init__.cpython-36.pyc
│   │   ├── log.cpython-36.pyc
│   │   └── template.cpython-36.pyc
│   └── template.py
├── fuzz.pcapng
└── README.txt
```  
