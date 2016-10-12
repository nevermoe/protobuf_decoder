# -*- coding: utf-8 -*-
import sys
import struct
import json
import traceback

strings = []

def GetWireFormat(data):
    wire_type = data & 0x7
    field_number = (data & 0xF8) >> 3
    return (wire_type, field_number)

#return (num, newStart, success)
def RetrieveInt(data, start, end):
    pos = 0
    byteList = []
    while True:
        if start+pos >= end:
            return (None, None, False)
        oneByte = ord(data[start+pos])
        byteList.append(oneByte & 0x7F)
        pos = pos + 1
        if oneByte & 0x80 == 0x0:
            break;

    newStart = start + pos

    index = len(byteList) - 1
    num = 0
    while index >= 0:
        num = (num << 0x7) + byteList[index]
        index = index - 1
    return (num, newStart, True)

def ParseData(data, start, end, messages, depth = 0):
    global strings
    #print strings
    ordinary = 0
    while start < end:
        (wire_type, field_number) = GetWireFormat(ord(data[start]))

        if wire_type == 0x00:#Varint
            #pos = 0
            #byteList = []
            #while True:
            #    #print start, pos
            #    if start+1+pos >= end:
            #        return False
            #    oneByte = ord(data[start+1+pos])
            #    byteList.append(oneByte & 0x7F)
            #    pos = pos + 1
            #    if oneByte & 0x80 == 0x0:
            #        break;

            #start = start + 1 + pos

            #index = len(byteList) - 1
            #num = 0
            #while index >= 0:
            #    num = (num << 0x7) + byteList[index]
            #    index = index - 1
            (num, start, success) = RetrieveInt(data, start+1, end)
            if success == False:
                return False

            if depth != 0:
                strings.append('\t'*depth)
            strings.append("(%d) Varint: %d\n" % (field_number, num))
            messages['%02d:%02d:Varint' % (field_number,ordinary)] = num
            ordinary  = ordinary + 1

        elif wire_type == 0x01:#64-bit
            num = 0
            pos = 7
            while pos >= 0:
                num = (num << 8) + ord(data[start+1+pos])
                pos = pos - 1

            start = start + 9
            try:
                floatNum = struct.unpack('d',struct.pack('q',int(hex(num),16)))
                floatNum = floatNum[0]
            except:
                floatNum = None
                
            if depth != 0:
                strings.append('\t'*depth)
            if floatNum != None:
                strings.append("(%d) 64-bit: 0x%x / %f\n" % (field_number, num, floatNum))
                messages['%02d:%02d:64-bit' % (field_number,ordinary)] = floatNum
            else:
                strings.append("(%d) 64-bit: 0x%x\n" % (field_number, num))
                messages['%02d:%02d:64-bit' % (field_number,ordinary)] = num


            ordinary = ordinary + 1

            
        elif wire_type == 0x02:#Length-delimited
            curStrIndex = len(strings)
            (stringLen, start, success) = RetrieveInt(data, start+1, end)
            if success == False:
                return False
            #stringLen = ord(data[start+1])
            if depth != 0:
                strings.append('\t'*depth)
            strings.append("(%d) embedded message:\n" % field_number)
            messages['%02d:%02d:embedded message' % (field_number, ordinary)] = {}
            ret = ParseData(data, start, start+stringLen, messages['%02d:%02d:embedded message' % (field_number, ordinary)], depth+1)
            #print '%d:%d:embedded message' % (field_number, ordinary)
            if ret == False:
                strings = strings[0:curStrIndex]    #pop failed result
                #print 'pop: %d:%d:embedded message' % (field_number, ordinary)
                messages.pop('%02d:%02d:embedded message' % (field_number, ordinary), None)
                #print messages
                if depth != 0:
                    strings.append('\t'*depth)
                try:
                    #print data[start+2:start+2+stringLen]
                    #data[start+2:start+2+stringLen].decode('utf-8').encode('utf-8')
                    #strings.append("(%d) string: %s\n" % (field_number, data[start+2:start+2+stringLen]))
                    #messages['%d:%d:string' % (field_number, ordinary)] = data[start+2:start+2+stringLen]
                    #print data[start:start+stringLen]
                    data[start:start+stringLen].decode('utf-8').encode('utf-8')
                    strings.append("(%d) string: %s\n" % (field_number, data[start:start+stringLen]))
                    messages['%02d:%02d:string' % (field_number, ordinary)] = data[start:start+stringLen]
                except:
                    #print traceback.format_exc()
                    #hexStr = ['0x%x' % ord(x) for x in data[start+2:start+2+stringLen]]
                    #hexStr = ':'.join(hexStr)
                    #strings.append("(%d) bytes: %s\n" % (field_number, hexStr))
                    #messages['%d:%d:bytes' % (field_number, ordinary)] = hexStr
                    #print traceback.format_exc()
                    hexStr = ['0x%x' % ord(x) for x in data[start:start+stringLen]]
                    hexStr = ':'.join(hexStr)
                    strings.append("(%d) bytes: %s\n" % (field_number, hexStr))
                    messages['%02d:%02d:bytes' % (field_number, ordinary)] = hexStr

            ordinary = ordinary + 1
            #start = start+2+stringLen
            start = start+stringLen

        elif wire_type == 0x05:#32-bit
            num = 0
            pos = 3
            while pos >= 0:
                num = (num << 8) + ord(data[start+1+pos])
                pos = pos - 1

            start = start + 5
            try:
                floatNum = struct.unpack('f',struct.pack('i',int(hex(num),16)))
                floatNum = floatNum[0]
            except:
                floatNum = None

                
            if depth != 0:
                strings.append('\t'*depth)
            if floatNum != None:
                strings.append("(%d) 32-bit: 0x%x / %f\n" % (field_number, num, floatNum))
                messages['%02d:%02d:32-bit' % (field_number,ordinary)] = floatNum
            else:
                strings.append("(%d) 32-bit: 0x%x\n" % (field_number, num))
                messages['%02d:%02d:32-bit' % (field_number,ordinary)] = num 

            ordinary = ordinary + 1


        else:#a real string
            #strings = strings[0:-1]#pop 'embedded message'
            #(wire_type, field_number) = GetWireFormat(ord(data[start-2]))
            #strings.append("(%d) string: %s\n" % (field_number, data[start:end]))
            #messages['%d:%d:string' % (field_number,ordinary)] = data[start:end]
            #start = end
            return False

    return True

def ParseProto(fileName):
    data = open(fileName, "rb").read()
    size = len(data)

    messages = {}
    ParseData(data, 0, size, messages)

    return messages

def GenValueList(value):
    valueList = []
    while value > 0:
        oneByte = (value & 0x7F)
        value = (value >> 0x7)
        if value > 0:
            oneByte |= 0x80
        valueList.append(oneByte)
    
    return valueList


def WriteValue(value, output):
    byteWritten = 0
    while value > 0:
        oneByte = (value & 0x7F)
        value = (value >> 0x7)
        if value > 0:
            oneByte |= 0x80
        output.append(oneByte)
        byteWritten += 1
    
    return byteWritten

def WriteVarint(field_number, value, output):
    byteWritten = 0
    wireFormat = (field_number << 3) | 0x00
    output.append(wireFormat)
    byteWritten += 1
    while value > 0:
        oneByte = (value & 0x7F)
        value = (value >> 0x7)
        if value > 0:
            oneByte |= 0x80
        output.append(oneByte)
        byteWritten += 1
    
    return byteWritten

def Write64bitFloat(field_number, value, output):
    byteWritten = 0
    wireFormat = (field_number << 3) | 0x01
    output.append(wireFormat)
    byteWritten += 1
    
    bytesStr = struct.pack('d', value).encode('hex')
    n = 2
    bytesList = [bytesStr[i:i+n] for i in range(0, len(bytesStr), n)]
    #i = len(bytesList) - 1
    #while i >= 0:
    #    output.append(int(bytesList[i],16))
    #    byteWritten += 1
    #    i -= 1
    for i in range(0,len(bytesList)):
        output.append(int(bytesList[i],16))
        byteWritten += 1

    return byteWritten

def Write64bit(field_number, value, output):
    byteWritten = 0
    wireFormat = (field_number << 3) | 0x01
    output.append(wireFormat)
    byteWritten += 1
    
    for i in range(0,8):
        output.append(value & 0xFF)
        value = (value >> 8)
        byteWritten += 1

    return byteWritten

def Write32bitFloat(field_number, value, output):
    byteWritten = 0
    wireFormat = (field_number << 3) | 0x05
    output.append(wireFormat)
    byteWritten += 1
    
    bytesStr = struct.pack('f', value).encode('hex')
    n = 2
    bytesList = [bytesStr[i:i+n] for i in range(0, len(bytesStr), n)]
    #i = len(bytesList) - 1
    #while i >= 0:
    #    output.append(int(bytesList[i],16))
    #    byteWritten += 1
    #    i -= 1
    for i in range(0,len(bytesList)):
        output.append(int(bytesList[i],16))
        byteWritten += 1


    return byteWritten

def Write32bit(field_number, value, output):
    byteWritten = 0
    wireFormat = (field_number << 3) | 0x05
    output.append(wireFormat)
    byteWritten += 1
    
    for i in range(0,4):
        output.append(value & 0xFF)
        value = (value >> 8)
        byteWritten += 1

    return byteWritten

def ReEncode(messages, output):
    byteWritten = 0
    for key in sorted(messages.iterkeys()):
        keyList = key.split(':')
        field_number = int(keyList[0])
        wire_type = keyList[2]
        value = messages[key]

        if wire_type == 'Varint':
            byteWritten += WriteVarint(field_number, value, output)
        elif wire_type == '32-bit':
            if type(value) == type(float(1.0)):
                byteWritten += Write32bitFloat(field_number, value, output)
            else:
                byteWritten += Write32bit(field_number, value, output)
        elif wire_type == '64-bit':
            if type(value) == type(float(1.0)):
                byteWritten += Write64bitFloat(field_number, value, output)
            else:
                byteWritten += Write64bit(field_number, value, output)
        elif wire_type == 'embedded message':
            wireFormat = (field_number << 3) | 0x02 
            output.append(wireFormat)
            #output.append(0x00)#dummy number
            index = len(output)
            byteWritten += 1
            tmpByteWritten = ReEncode(messages[key], output)
            valueList = GenValueList(tmpByteWritten)
            listLen = len(valueList)
            for i in range(0,listLen):
                output.insert(index, valueList[i])
                index += 1
            #output[index] = tmpByteWritten
            #print "output:", output
            byteWritten += tmpByteWritten + listLen
        elif wire_type == 'string':
            wireFormat = (field_number << 3) | 0x02 
            output.append(wireFormat)
            byteWritten += 1

            bytesStr = [int(elem.encode("hex"),16) for elem in messages[key]]

            byteWritten += WriteValue(len(bytesStr),output)
            #print "len(bytesStr): %d" % len(bytesStr)
            #print "byteWritten: %d" % byteWritten
            #print "output:", output

            output.extend(bytesStr)
            byteWritten += len(bytesStr)
        elif wire_type == 'bytes':
            wireFormat = (field_number << 3) | 0x02 
            output.append(wireFormat)
            byteWritten += 1

            bytesStr = [int(byte,16) for byte in messages[key].split(':')]
            byteWritten += WriteValue(len(bytesStr),output)

            #print "len(bytesStr): %d" % len(bytesStr)
            #print "byteWritten: %d" % byteWritten
            #print "output:", output

            output.extend(bytesStr)
            byteWritten += len(bytesStr)
            

    return byteWritten
    

def SaveModification(messages, fileName):
    output = list()
    ReEncode(messages, output)
    f = open(fileName, 'wb')
    f.write(bytearray(output))
    f.close()
    

if __name__ == "__main__":
    if sys.argv[1] == "dec":
        messages = ParseProto('tmp.pb')

        f = open('tmp.json', 'wb')
        json.dump(messages, f, indent=4, sort_keys=True)
        f.close()

        f = open('tmp.json', 'r')
        parsedJson = json.load(f)
        #print json.dumps(parsedJson, indent=4, sort_keys=True)
        for str in strings:
            try:
                print str,
            except:
                pass
        f.close()

    elif sys.argv[1] == "enc":

        f = open('tmp.json', 'r')
        messages = json.load(f)
        f.close()

        SaveModification(messages, "tmp.pb")

    else:
        messages = ParseProto(sys.argv[1])

        for str in strings:
            try:
                print str,
            except:
                pass

        f = open('tmp.json', 'wb')
        print json.dumps(messages, indent=4, sort_keys=True)
        f.close()
        SaveModification(messages, "modified")

