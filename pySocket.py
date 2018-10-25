#!/usr/bin/env python
# -*- coding:utf-8 -*-

import socket
import time
import re
import os

global client
global writefile
global oldlogfile
COMMON_FLAG = 0
RECV_FLAG = 1
SEND_FLAG = 2

def mkdir(path):
    # 去除首位空格
    path=path.strip()
    # 去除尾部 \ 符号
    path=path.rstrip("\\")
 
    # 判断路径是否存在
    # 存在     True
    # 不存在   False
    isExists=os.path.exists(path)
 
    # 判断结果
    if not isExists:
        # 如果不存在则创建目录
        # 创建目录操作函数
        os.makedirs(path) 
 
        print path + u' 创建成功'
        return True
    else:
        # 如果目录存在则不创建，并提示目录已存在
        print path + u' 目录已存在'
        return False
def GetCurTime():
    CurTime = time.strftime('%Y-%m-%d %H-%M-%S', time.localtime(time.time()))
    return CurTime

def IsReqMkLogFile(oldlog):
    global writefile
    global oldlogfile
    
    filesize = 0L
    filesize = os.path.getsize('logs\\'+oldlog)

    kb = float(filesize)/1024
    if kb >= 1024*100:
        curTime = GetCurTime()
        fileName = curTime + '.txt'
        writefile.close()
        writefile = open(unicode('logs\\' + fileName),'w+')
        oldlogfile = fileName
        
def CheckSendStr(sendStr):
    bRet = True
    if len(sendStr)%2 != 0:
        return False
    for i in range(len(sendStr)):
        if (sendStr[i] >= '0' and sendStr[i] <= '9') or (sendStr[i] >= 'A' and sendStr[i] <= 'Z'):
            continue
        else:
            bRet = False
            break
    return bRet

def writeLog(logString, RorS=0, IsPrint=False):
    '''
    logString: string to be Printed
    RorS:  0,1,2
           0 is common info
           1 is sending info
           2 is recving info
    '''
    global writefile
    global oldlogfile
    
    logString = logString.upper()
    logString = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", logString)
    
    writeTime = GetCurTime()
    if RorS == 0:
        logStr = (writeTime + '  <---->  ' + logString + '\n')
    elif RorS == RECV_FLAG:
        logStr = (writeTime + '  Recv->  ' + logString + '\n')
    elif RorS == SEND_FLAG:
        logStr = (writeTime + '  Send->  ' + logString + '\n')
    if IsPrint:
        print logStr,
        writefile.writelines(logStr)
    else:
        writefile.writelines(logStr)

    #print oldlogfile
    IsReqMkLogFile(oldlogfile)
    
def toHexString(bytes=[], format=0):
    """Returns an hex string representing bytes

        bytes:  a list of bytes to stringify, e.g. [59, 22, 148, 32, 2, 1, 0, 0, 13]
        format: a logical OR of
                COMMA: add a comma between bytes
                HEX: add the 0x chars before bytes
                UPPERCASE: use 0X before bytes (need HEX)
                PACK: remove blanks

        example:
        bytes = [ 0x3B, 0x65, 0x00, 0x00, 0x9C, 0x11, 0x01, 0x01, 0x03 ]

        toHexString(bytes) returns  3B 65 00 00 9C 11 01 01 03

        toHexString(bytes, COMMA) returns  3B, 65, 00, 00, 9C, 11, 01, 01, 03
        toHexString(bytes, HEX) returns  0x3B 0x65 0x00 0x00 0x9C 0x11 0x01 0x01 0x03
        toHexString(bytes, HEX | COMMA) returns  0x3B, 0x65, 0x00, 0x00, 0x9C, 0x11, 0x01, 0x01, 0x03

        toHexString(bytes, PACK) returns  3B6500009C11010103

        toHexString(bytes, HEX | UPPERCASE) returns  0X3B 0X65 0X00 0X00 0X9C 0X11 0X01 0X01 0X03
        toHexString(bytes, HEX | UPPERCASE | COMMA) returns  0X3B, 0X65, 0X00, 0X00, 0X9C, 0X11, 0X01, 0X01, 0X03
    """

    from string import rstrip

    for byte in tuple(bytes):
        pass

    if type(bytes) is not list:
        raise TypeError, 'not a list of bytes'

    if bytes == None or bytes == []:
        return ""
    else:
        pformat = "%-0.2X"
        if COMMA & format:
            pformat = pformat + ","
        pformat = pformat + " "
        if PACK & format:
            pformat = rstrip(pformat)
        if HEX & format:
            if UPPERCASE & format:
                pformat = "0X" + pformat
            else:
                pformat = "0x" + pformat
        return rstrip(rstrip(reduce(lambda a, b: a + pformat % ((b + 256) % 256), [""] + bytes)), ',')


def toBytes(bytestring):
    """Returns a list of bytes from a byte string

       bytestring: a byte string of the format \"3B 65 00 00 9C 11 01 01 03\" or \"3B6500009C11010103\" or \"3B6500   009C1101  0103\"
    """
    from struct import unpack
    import re
    packedstring = ''.join(re.split('\W+', bytestring))
    try:
        return reduce(lambda x, y: x + [int(y, 16)], unpack('2s' * (len(packedstring) / 2), packedstring), [])
    except:
        raise TypeError, '不是字节码的字符串'
    
def InitSocket():
    ipstr = socket.gethostbyname(socket.gethostname())
    print u'当前主机IP:'+ipstr
    global client
    try: 
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip_port = ('127.0.0.1', 6005)
        #ip_port = (ipstr, 6005)
        client.settimeout(2)
        client.connect(ip_port)
    except:
        writeLog('InitSocket失败，出现异常！\n')
        client.close()
        #writefile.close()
def SendData(sendStr):
    sendStr = sendStr.upper()
    if not CheckSendStr(sendStr):
        print u'发送数据长度 或 值不正确，请检查！'
        return False
    client.send(sendStr.decode('hex'))

    writeLog(sendStr, SEND_FLAG)

def RecvData():
    recvStr = client.recv(1024)
    writeLog(recvStr.encode('hex'), RECV_FLAG)
    return recvStr
    
def main():
    global writefile
    global oldlogfile
    curTime = GetCurTime()
    fileName = curTime + '.txt'
    mkdir('logs')
    writefile = open(unicode('logs\\' + fileName),'w+')
    oldlogfile = fileName
    
    InitSocket()
    nCurCount = 0
    # 通信循环
    while 1:
        nCurCount += 1
        try:
            # 发消息
            print u'第{}次测试'.format(nCurCount)+',,',
            writeLog('第{}次测试开始'.format(nCurCount))
            if(nCurCount % 10 == 0):
                print '\n'
            readfile  = open(unicode(u'UID指令数据.txt'),'r')
            line = 'start'
            while line:
                line = readfile.readline()
                line = line.replace(' ', '')
                #print line,len(line)
                if not line:
                    continue
                SendData(line[0:len(line)-1])
                recvdata = RecvData()

            #readfile.seek(0)
            readfile.close()
            writeLog('第{}次测试结束'.format(nCurCount))
            '''
            #sendStr = input('>>: ').strip()
            SendData('1234')    
            # 收消息
            RecvData()
            '''
        except:
            client.close()
            InitSocket()
            print u'第{}次测试过程出现异常'.format(nCurCount)+',,'
            writeLog('第{}次测试过程出现异常'.format(nCurCount))
            pass

if __name__ == '__main__':
    main()

