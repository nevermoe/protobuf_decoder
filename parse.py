import sys
import struct

strings = []

def GetWireFormat(data):
    wire_type = data & 0x7
    field_number = (data & 0xF8) >> 3
    return (wire_type, field_number)

def ParseData(data, start, end, depth = 0):
    global strings
    curStrIndex = len(strings)
    #print strings
    while start < end:
        (wire_type, field_number) = GetWireFormat(ord(data[start]))

        if wire_type == 0x00:#Varint
            pos = 0
            byteList = []
            while True:
                #print start, pos
                if start+1+pos >= end:
                    return False
                oneByte = ord(data[start+1+pos])
                byteList.append(oneByte & 0x7F)
                pos = pos + 1
                if oneByte & 0x80 == 0x0:
                    break;

            start = start + 1 + pos

            index = len(byteList) - 1
            num = 0
            while index >= 0:
                num = (num << 0x7) + byteList[index]
                index = index - 1

            if depth != 0:
                strings.append('\t'*depth)
            strings.append("(%d) Varint: %d\n" % (field_number, num))

        elif wire_type == 0x01:#64-bit
            num = 0
            pos = 7
            while pos >= 0:
                num = (num << 8) + ord(data[start+1+pos])
                pos = pos - 1

            start = start + 9
            floatNum = struct.unpack('d',struct.pack('q',int(hex(num),16)))
            floatNum = floatNum[0]
                
            if depth != 0:
                strings.append('\t'*depth)
            strings.append("(%d) 64-bit: 0x%x / %f\n" % (field_number, num, floatNum))
            
        
        elif wire_type == 0x02:#Length-delimited
            stringLen = ord(data[start+1])
            if depth != 0:
                strings.append('\t'*depth)
            strings.append("(%d) embedded message:\n" % field_number)
            ret = ParseData(data, start+2, start+2+stringLen, depth+1)
            if ret == False:
                strings = strings[0:curStrIndex]    #pop failed result
                if depth != 0:
                    strings.append('\t'*depth)
                strings.append("(%d) string: %s\n" % (field_number, data[start+2:start+2+stringLen]))

            start = start+2+stringLen

        elif wire_type == 0x05:#32-bit
            num = 0
            pos = 3
            while pos >= 0:
                num = (num << 8) + ord(data[start+1+pos])
                pos = pos - 1

            start = start + 5
            floatNum = struct.unpack('f',struct.pack('i',int(hex(num),16)))
            floatNum = floatNum[0]
                
            if depth != 0:
                strings.append('\t'*depth)
            strings.append("(%d) 32-bit: 0x%x / %f\n" % (field_number, num, floatNum))


        else:#a real string
            strings = strings[0:-1]#pop 'embedded message'
            (wire_type, field_number) = GetWireFormat(ord(data[start-2]))
            strings.append("(%d) string: %s\n" % (field_number, data[start:end]))
            start = end

    return True

def ParseProto(fileName):
    data = open(fileName, "rb").read()
    size = len(data)

    ParseData(data, 0, size)
    for str in strings:
        print str,
    

if __name__ == "__main__":
    ParseProto(sys.argv[1])

