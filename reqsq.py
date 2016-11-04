from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import ITab
from burp import IMessageEditorController
from burp import IContextMenuFactory
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from burp import IHttpRequestResponse

import java.awt.Component;
import java.io.OutputStream;
from java.util import List, ArrayList;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JMenuItem;
from javax.swing import JTable;
from javax.swing import JScrollPane;
from javax.swing.table import AbstractTableModel;
from threading import Lock

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, IIntruderPayloadGeneratorFactory, AbstractTableModel, IHttpRequestResponse):
    #strange callback registration function
    def registerExtenderCallbacks(self, callbacks):
        
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        #self.context = None


        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane2 =JSplitPane(JSplitPane.HORIZONTAL_SPLIT)

        # Table of RequestLists
        requestTable = TableOne(self)
        scrollPane = JScrollPane(requestTable)
        self._splitpane.setLeftComponent(scrollPane)

        # Request List
        self._reqstack = ArrayList()
        self._lock = Lock()

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)

        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(requestTable) 
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        # Extention Name and Info
        callbacks.setExtensionName("ReqSquared")
        callbacks.registerContextMenuFactory(self)

        # Initialize tab
        callbacks.addSuiteTab(self)

        # IntruderPayloadGeneratorFactory
        #callbacks.registerIntruderPayloadGeneratorFactory(self)

        return


    ### Extend ITab functions ###
    def getTabCaption(self):
        return "ReqSquared"

    def getUiComponent(self):
        return self._splitpane


    ### Implement Context Menu Factory functions ###
    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to ReqSquared", actionPerformed=self.grabRequest))
        return menu_list
    

    ### Request handling functions ###
    def grabRequest(self, event):
        http_traffic = self.context.getSelectedMessages()
        if (http_traffic != None and len(http_traffic) > 0):
            for t in http_traffic:
                self._reqstack.add(t)
        self.loadReqs()
        return
    
    def loadReqs(self):
        for r in self._reqstack:
            self._lock.acquire()
            row = self._reqstack.size()
            self.fireTableRowsInserted(row, row)
            self._lock.release()

    ### Extend the AbstractTableModel ###
    def getRowCount(self):
        try:
            return self._reqstack.size()
        except:
            return 0

    def getColumnCount(self):
        return 1

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Requests"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._reqstack.get(rowIndex)
        item = self._helpers.analyzeRequest(logEntry).getUrl()
        if columnIndex == 0:
            return item
        return "error: @ getValueAt(self, rowIndex, conlumnIndex)"


    ### implement IMessageEditorController functions ###
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()


#                                        #
# extend JTable to handle cell selection #
#                                        #       _
    
class TableOne(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return
    
    def changeSelection(self, row, col, toggle, extend):
        # show the log entry for the selected row
        logEntry = self._extender._reqstack.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._DisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
        return



    