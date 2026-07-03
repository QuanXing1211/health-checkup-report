#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
路径编解码工具，解决 Windows 命令行中文字符乱码问题。

用法：
    from _path_helper import decode_argv
    decode_argv()  # 在 main() 开头调用，自动解码所有 sys.argv
"""
import base64
import sys

B64_PREFIX = 'B64:'


def decode_arg(arg):
    if arg.startswith(B64_PREFIX):
        try:
            return base64.b64decode(arg[len(B64_PREFIX):]).decode('utf-8')
        except Exception:
            return arg
    return arg


def decode_argv():
    """原地解码 sys.argv 中的所有条目。"""
    for i in range(1, len(sys.argv)):
        sys.argv[i] = decode_arg(sys.argv[i])
