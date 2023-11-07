import _thread
from tkinter import *
from scapy.all import *
from tkinter.ttk import Treeview
import tkinter as tk
import json

FrameType = set()
PacketType = set()
ProtocolType = set()


class EntryStructure:
    def __init__(self, frame, packet, transport, src, dst, details):
        self.Frame = frame
        self.Packet = packet
        self.Transport = transport
        self.Src = src
        self.Dst = dst
        self.details = json.dumps(details, indent=4)

    def GetList(self):
        return [self.Frame, self.Packet, self.Transport, self.Src, self.Dst]


class FilterFrame:
    def __init__(self, root):
        self.__root = root
        self.__Frame = None

        self.__frame_stringvar = StringVar()
        self.__frame_dropdown = None

        self.__packet_stringvar = StringVar()
        self.__packet_dropdown = None

        self.__protocol_stringvar = StringVar()
        self.__protocol_dropdown = None
        self.__Frame = Frame(self.__root)
        self.__Frame.grid(row=0, column=0, sticky="n")
        self.Build()

    def Build(self):
        def UpdateFrameType(args):
            self.__frame_stringvar.set(args)

        def UpdatePacketType(args):
            self.__packet_stringvar.set(args)

        def UpdateProtocolType(args):
            self.__protocol_stringvar.set(args)

        self.__frame_stringvar.set("Frame")
        self.__frame_dropdown = OptionMenu(self.__Frame, self.__frame_stringvar, "", *list(FrameType),
                                           command=UpdateFrameType)
        self.__frame_dropdown.grid(row=0, column=0)
        self.__packet_stringvar.set("Packet")
        self.__packet_dropdown = OptionMenu(self.__Frame, self.__packet_stringvar, "", *list(PacketType),
                                            command=UpdatePacketType)
        self.__packet_dropdown.grid(row=0, column=1)
        self.__protocol_stringvar.set("protocol")
        self.__protocol_dropdown = OptionMenu(self.__Frame, self.__protocol_stringvar, "", *list(ProtocolType),
                                              command=UpdateProtocolType)
        self.__protocol_dropdown.grid(row=0, column=2)

    def AddFrameType(self, val):
        self.__frame_dropdown['menu'].add_command(label=val, command=tk._setit(self.__frame_stringvar, val))

    def AddPacketType(self, val):
        self.__packet_dropdown['menu'].add_command(label=val, command=tk._setit(self.__packet_stringvar, val))

    def AddProtocolType(self, val):
        self.__protocol_dropdown['menu'].add_command(label=val, command=tk._setit(self.__protocol_stringvar, val))


class Details:
    def __init__(self, root):
        self.__root = root
        self.__Frame = Frame(root)
        self.__Frame.grid(row=2, column=0, sticky="ew")
        self.__Text = Text(self.__Frame)
        self.__Text.grid(row=0, column=0)

    def AddDetatils(self, Text):
        self.__Text.delete('1.0', END)
        self.__Text.insert(tk.END, Text)


class Table:
    def __init__(self, root):
        self.__data = []
        self.__root = root
        self.__frame = Frame(self.__root)
        self.__frame.grid(row=1, column=0, sticky="nsew")
        self.__Scrollbar = Scrollbar(self.__frame)
        self.__Scrollbar.pack(side=RIGHT, fill='y')
        self.__View = Treeview(self.__frame, yscrollcommand=self.__Scrollbar.set)
        self.__View.pack(fill='both')

        self.__Scrollbar.config(command=self.__View.yview)
        self.__View["column"] = ["Frame", "Packet", "Transport", "Src", "Dst"]

        self.__View.column("#0", width=0, stretch=NO)
        self.__View.column("Frame", anchor=CENTER, width=80)
        self.__View.column("Packet", anchor=CENTER, width=80)
        self.__View.column("Transport", anchor=CENTER, width=80)
        self.__View.column("Src", anchor=CENTER, width=80)
        self.__View.column("Dst", anchor=CENTER, width=80)

        self.__View.heading("#0", text="", anchor=CENTER)
        self.__View.heading("Frame", text="Frame", anchor=CENTER)
        self.__View.heading("Packet", text="Packet", anchor=CENTER)
        self.__View.heading("Transport", text="Transport", anchor=CENTER)
        self.__View.heading("Src", text="Src", anchor=CENTER)
        self.__View.heading("Dst", text="Dst", anchor=CENTER)

        self.__Text = Details(self.__root)
        self.__filter: EntryStructure | None = None
        self.__i = 0

        def item_selected(event):
            print(self.__View.selection())
            self.__Text.AddDetatils(self.__data[int(self.__View.selection()[0])].details)

        self.__View.bind('<<TreeviewSelect>>', item_selected)

    def build(self, data):
        if self.__filter is not None:
            if (((self.__filter.Dst is not None and data.Dst in self.__filter.Dst) or
                 self.__filter.Dst is None) and
                    ((self.__filter.Src is not None and data.Src in self.__filter.Src) or
                     self.__filter.Src is None) and
                    ((self.__filter.Transport is not None and self.__data[
                        self.__i].Transport in self.__filter.Transport)
                     or self.__filter.Transport is None) and
                    ((self.__filter.Packet is not None and data.Packet in self.__filter.Packet) or
                     self.__filter.Packet is None) and
                    ((self.__filter.Frame is not None and data.Frame in self.__filter.Frame) or
                     self.__filter.Frame is None)):
                self.__View.insert(parent='', index='end', iid=str(self.__i), text='',
                                   values=tuple(data.GetList()))
                self.__i += 1
        else:
            self.__View.insert(parent='', index='end', iid=str(self.__i), text='',
                               values=tuple(data.GetList()), open=True)
            self.__i += 1

    def Rebuild(self):
        self.__i = 0
        for i in range(len(self.__data)):
            self.build(data=self.__data[i])

    def SetFilter(self, params):
        self.__filter = params

    def Insert(self, data: EntryStructure):
        self.__data.append(data)
        self.build(data)


def RequestFiller(table, filter):
    def Process(data):
        lines = data.split('\n')
        Out = {}
        Name = "None"
        Order = []
        Temp = {}
        for line in lines:
            if line.startswith('###'):
                Out[Name] = Temp
                Temp = {}
                Order.append(Name)
                Name = line.replace("#", "").replace("[", "").replace("]", "").replace(" ", "")
            else:
                try:
                    Temp1 = line.split("=")
                    Temp[Temp1[0].strip()] = Temp1[1]
                except IndexError:
                    pass
        Out.pop("None")
        Order.pop(0)
        return Order, Out

    def callback(packets):
        for packet in packets:
            Order, resp = Process(packet.show(dump=True))
            print(resp)
            if len(Order) == 1:
                if Order[0] not in FrameType:
                    # filter.AddFrameType(Order[0])
                    pass
                FrameType.add(Order[0])
                table.Insert(EntryStructure(Order[0], '-', '-', '', '', resp))
            if len(Order) == 2:
                if Order[1] not in PacketType:
                    # filter.AddPacketType(Order[1])
                    pass
                PacketType.add(Order[1])
                try:
                    table.Insert(
                        EntryStructure(Order[0], Order[1], '-', resp[Order[1]]['src'], resp[Order[1]]['dst'], resp))
                except KeyError:
                    table.Insert(
                        EntryStructure(Order[0], Order[1], '-', resp[Order[1]]['psrc'], resp[Order[1]]['pdst'], resp))
            if len(Order) == 3:
                if Order[2] not in ProtocolType:
                    # filter.AddProtocolType(Order[2])
                    pass
                ProtocolType.add(Order[2])
                try:
                    table.Insert(
                        EntryStructure(Order[0], Order[1], Order[2], resp[Order[1]]['src'], resp[Order[1]]['dst'],
                                       resp))
                except KeyError:
                    table.Insert(
                        EntryStructure(Order[0], Order[1], '-', resp[Order[1]]['psrc'], resp[Order[1]]['pdst'], resp))


    sniff(prn=callback, count=0)


ws = Tk()
ws.title('Packet Tracker')
# ws.attributes('-fullscreen', True)
ws.columnconfigure(0, weight=1)
ws.rowconfigure(2, weight=0)
# fil = FilterFrame(ws)
tb = Table(ws)
_thread.start_new_thread(RequestFiller, (tb, None))
ws.mainloop()
