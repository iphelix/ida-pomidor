#!/usr/bin/env python
#
# IDA Pomidor is a productivity tool that encourages regular timed breaks.

IDAPOMIDOR_VERSION = "1.0"

# Copyright (C) 2014 Peter Kacherginsky
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without 
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Python Libraries
import os
import sys
from datetime import datetime, timedelta

# IDA libraries
import idaapi
import idautils
import idc
from idaapi import Form, Choose2, plugin_t

# PySide
try:
    from PySide import QtCore, QtGui
except ImportError:
    print "[idapomidor] Failed to import PySide library."
    print "             Please install the library and try again."
    sys.exit(1)

###############################################################################
# Embeddable history view of previous tasks
class PomidorView(Choose2):
    """
    Chooser class to display security characteristics of loaded modules.
    """
    def __init__(self, pomidor, embedded = False):

        self.pomidor = pomidor

        Choose2.__init__(self,
                         "IDA Pomidor",
                         [ ["Time",     14 | Choose2.CHCOL_PLAIN],
                           ["Duration",  5 | Choose2.CHCOL_PLAIN], 
                           ["Activity", 10 | Choose2.CHCOL_PLAIN], 
                         ],
                         embedded = embedded)

        self.icon = 47

        # Items for display and corresponding data
        # NOTE: Could become desynchronized, so to avoid this
        #       refresh the view after each change.
        self.items = []

        # Initialize/Refresh the view
        self.refreshitems()

    def show(self):
        # Attempt to open the view
        if self.Show() < 0: return False

        return True

    def refreshitems(self):
        self.items = []

        for (t, d, p) in self.pomidor.pomidors:
            self.items.append( [t.strftime("%Y-%m-%d %H:%M"), "%d" % (d/60), p])
 
    def OnSelectLine(self, n):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetIcon(self, n):

        if not len(self.items) > 0:
            return -1

        pomidor_type = self.items[n][2]

        if   pomidor_type == "Pomidor":     return 61 # green
        elif pomidor_type == "Short break": return 60 # yellow
        else:                               return 59 # red

    def OnClose(self):
        pass

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.refreshitems()
        return n

    def OnActivate(self):
        self.refreshitems()

###############################################################################
# Pomidor timer which contains the timer and embedded history view
class PomidorForm(Form):

    def __init__(self, pomidor):

        self.pomidor = pomidor

        Form.__init__(self, 
r"""BUTTON YES* NONE
BUTTON NO NONE
BUTTON CANCEL NONE
IDA Pomidor
{FormChangeCb}
          {imgPomidor}  
<Pomidor:{iButtonPomidor}> <Short Break:{iButtonShortBreak}> <Long Break:{iButtonLongBreak}>
   {strTime}
<Pomidor Log:{cEChooser}>
""", {
                'imgPomidor'      : Form.StringLabel(""),
                'FormChangeCb'    : Form.FormChangeCb(self.OnFormChange),
                'cEChooser'       : Form.EmbeddedChooserControl(self.pomidor.pomidorView, swidth=50),

                'strTime'         : Form.StringLabel(""),

                'iButtonPomidor'   : Form.ButtonInput(self.OnButtonPomidor, swidth=16),
                'iButtonShortBreak': Form.ButtonInput(self.OnButtonShortBreak, swidth=16),
                'iButtonLongBreak' : Form.ButtonInput(self.OnButtonLongBreak, swidth=16),
            })

        self.Compile()

    def OnButtonPomidor(self, code=0):
        self.pomidor.timer_start("Pomidor")

    def OnButtonShortBreak(self, code=0):
        self.pomidor.timer_start("Short break")

    def OnButtonLongBreak(self, code=0):
        self.pomidor.timer_start("Long break")

    def OnFormChange(self, fid):

        # Form initialization
        if fid == -1:

            # Fill the top image
            self.SetControlValue(self.imgPomidor, "<img src='%s'>" % os.path.join(self.pomidor.path, "pomidor.png") )

            # Set current time, possibly resuming an existing timer
            self.setTime(self.pomidor.duration)

        # Form OK pressed
        elif fid == -2:
            pass

        return 1

    def setTime(self, duration):

        # Convert time offset to the form where we could
        # iterate over each digit in a list [H0,M1,M0,S1,S0]
        time_str = "0%s" % timedelta(seconds = self.pomidor.duration_stop - duration)
        time_str = time_str.replace(':','')

        ctrl_str = ""

        for i, t in enumerate(time_str):
            t = int(t)

            if i != 0 and not i % 2:
                ctrl_str += "<img src='%s'>" % os.path.join(self.pomidor.path, "separator.png")

            ctrl_str += "<img src='%s'>" %  os.path.join(self.pomidor.path, "flipper%d%d.png" % (t, 2) )

        self.SetControlValue( self.strTime, ctrl_str )

###############################################################################
# Plugin manager
class PomidorManager():

    def __init__(self):

        self.addmenu_item_ctxs = list()
        self.path = idaapi.idadir( os.path.join("plugins","idapomidor","images") )

        self.pomidors = list()

        # Initialize the timer
        # NOTE: QTimer is a lot more stable compared to idaapi.register_timer()
        #       unfortunately this requires PySide installation.
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.timer_callback)

        self.qapp = QtCore.QCoreApplication.instance()

        self.pomidorForm = None
        self.pomidorView = PomidorView(self, embedded=True)

        self.interval = 1000

        self.duration = 0
        self.duration_stop = 0
        self.duration_settings = {"Pomidor": 25*60, "Short break": 5*60, "Long break": 15*60}

        self.update = 0

        self.t = None

    #--------------------------------------------------------------------------
    # Menu Items
    #--------------------------------------------------------------------------
    def add_menu_item_helper(self, menupath, name, hotkey, flags, pyfunc, args):

        # add menu item and report on errors
        addmenu_item_ctx = idaapi.add_menu_item(menupath, name, hotkey, flags, pyfunc, args)
        if addmenu_item_ctx is None:
            return 1
        else:
            self.addmenu_item_ctxs.append(addmenu_item_ctx)
            return 0

    def add_menu_items(self):

        if self.add_menu_item_helper("Help/About program..", "IDA Pomidor", "", 1, self.show_pomidor, None): return 1

        return 0

    def del_menu_items(self):
        for addmenu_item_ctx in self.addmenu_item_ctxs:
            idaapi.del_menu_item(addmenu_item_ctx)

    # Show Form
    def show_pomidor(self):
        self.pomidorForm = PomidorForm(self)
        ok = self.pomidorForm.Execute()
        self.pomidorForm.Free()
        self.pomidorForm = None

    def timer_start(self,type):

        # Stop the previous active timer
        if self.timer.isActive():
            self.timer.stop()

        # Set timer duration
        self.duration = 0
        self.duration_stop = self.duration_settings[type]

        # Insert the new task into the chooser and update the view
        self.pomidors.insert(0, (datetime.now(), self.duration_stop, type))
        self.pomidorView.refreshitems()
        self.pomidorForm.RefreshField(self.pomidorForm.cEChooser)

        # Start the timer
        self.timer.start(1000)

    def timer_callback(self):

        if self.duration < self.duration_stop:
            self.duration += self.interval / 1000

            # Update the UI timer if it is visible
            if self.pomidorForm:
                self.pomidorForm.setTime(self.duration)

        else:
            print "[idapomidor] Timer expired after %d minutes." % (self.duration/60)
            self.timer.stop()
            self.qapp.beep()

            ## Open the dialog if it's not already opened
            if not self.pomidorForm:
                self.show_pomidor()

###############################################################################
# Plugin
###############################################################################
class idapomidor_t(plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "IDA productivity tool that encourages regular breaks."
    help = "IDA productivity tool that encourages regular breaks."
    wanted_name = "IDA Pomidor"
    wanted_hotkey = ""

    def init(self):  
        global idapomidor_manager

        # Check if already initialized
        if not 'idapomidor_manager' in globals():

            idapomidor_manager = PomidorManager()
            if idapomidor_manager.add_menu_items():
                print "Failed to initialize IDA Pomidor."
                idapomidor_manager.del_menu_items()
                del idapomidor_manager
                return idaapi.PLUGIN_SKIP
            else:
                print("Initialized IDA Pomidor  v%s (c) Peter Kacherginsky <iphelix@thesprawl.org>" % IDAPOMIDOR_VERSION)
            
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        global idapomidor_manager
        idapomidor_manager.show_pomidor()

    def term(self):
        pass
        

def PLUGIN_ENTRY():
    return idapomidor_t()

###############################################################################
# Script / Testing
###############################################################################

def idapomidor_main():

    global idapomidor_manager

    if 'idapomidor_manager' in globals():
        idapomidor_manager.del_menu_items()
        del idapomidor_manager

    idapomidor_manager = PomidorManager()
    idapomidor_manager.add_menu_items()
    idapomidor_manager.show_pomidor()

if __name__ == '__main__':
    #idapomidor_main()
    pass