# -*- coding: utf-8 -*-
#! /usr/bin/python

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from java.io import PrintWriter
import sys
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec
from javax.crypto.spec import IvParameterSpec
from java.util import Base64
import traceback
import subprocess
import base64
import array
import ast
import json

#sys.path.append('/usr/local/lib/python2.7/site-packages')
#sys.path.append('/Library/Python/2.7/site-packages')
import codecs

from parse import ParseProto, SaveModification


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()
        # keep a reference to our callbacks object
        self.callbacks = callbacks
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)      
        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Protobuf Editor")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

        return
    
    def createNewInstance(self, controller, editable):
        
        # create a new instance of our custom editor tab
        return ProtobufHelperTab(self, controller, editable)
        

# 
# class implementing IMessageEditorTab
#

class ProtobufHelperTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.editable = editable
        self.controller = controller

        # create an instance of Burp's text editor, to display our deserialized data
        self.txtInput = extender.callbacks.createTextEditor()
        self.txtInput.setEditable(editable)

        self.httpHeaders = None
        self.body = None
        self.content = None
        self.currentMessage = None

        return

    def getTabCaption(self):
        return "Protobuf"
        
    def getUiComponent(self):
        return self.txtInput.getComponent()
    
    def isEnabled(self, content, isRequest):

        return True

    def isModified(self):
        return self.txtInput.isTextModified()

    def getSelectedData(self):
        return self.txtInput.getSelectedText()

    def setMessage(self, content, isRequest):

        self.currentMessage = content

        if (content is None):
            # clear our display
            self.txtInput.setText(None)
            self.txtInput.setEditable(False)

        try:
            res = self.extender.helpers.analyzeResponse(content)
            self.httpHeaders = res.getHeaders() #remember headers

            data = content[res.getBodyOffset():]

            f = open('tmp.pb', 'wb')
            f.write(bytearray(data))
            f.close()

            parsedJson = ParseProto('tmp.pb')
            new_body = json.dumps(parsedJson, indent=4, sort_keys=True, ensure_ascii=False, encoding='utf-8')
            new_req = self.extender.helpers.buildHttpMessage(self.httpHeaders,new_body)
            self.txtInput.setText(new_req)
            self.txtInput.setEditable(True)
        except:
            print(traceback.format_exc())
        return

    def getMessage(self):

        if (self.txtInput.isTextModified()):

            try:
                content = self.txtInput.getText()
                res = self.extender.helpers.analyzeResponse(content)
                self.httpHeaders = res.getHeaders()  # remember headers

                body = content[res.getBodyOffset():]

                f = codecs.open('tmp.json', 'w', 'utf-8')
                jsonFormat = json.loads(body.tostring(), encoding='utf-8')
                json.dump(jsonFormat, f, indent=4, sort_keys = True, ensure_ascii=False, encoding='utf-8')
                f.close()

                f = codecs.open('tmp.json', 'r', 'utf-8')
                messages = json.load(f, encoding='utf-8')
                f.close()
                # 现在的函数处理的数据，如果没有经过文件中转就会出错
                SaveModification(messages, "tmp.pb")

                f = open('tmp.pb', 'rb')
                message = f.read()
                f.close()
                content = self.extender.helpers.buildHttpMessage(self.httpHeaders, message)
            except:
                print(traceback.format_exc())
            return content

        else:
            return self.currentMessage

