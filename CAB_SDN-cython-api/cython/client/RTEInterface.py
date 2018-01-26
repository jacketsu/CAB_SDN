#
# Copyright (C) 2015-2017,  Netronome Systems, Inc.  All rights reserved.
#

import os, sys, struct, pprint, threading
from urlparse import urlparse
from contextlib import contextmanager

from thrift.transport import TTransport, TZlibTransport, TSocket
from thrift.protocol import TBinaryProtocol

import os, sys

from sdk6_rte import RunTimeEnvironment
from sdk6_rte.ttypes import *

class RTEError(Exception): pass
class RTECommError(RTEError): pass
class RTEReturnError(RTEError): pass

RTE_RETURN_CODES = [
    'SUCCESS',
    'ERROR',          # error reason string provided
    'ARGINVALID',     # invalid argument
    'IOERROR',        # platform IO error
    'MEMORYERROR',    # memory allocation error
    'FILEIOERROR',    # file IO error
    'NOTLOADED',      # firmware not loaded
    'HWINCOMPATIBLE', # platform doesn't support operation
]

class NullCtx():
    def __enter__(*args): pass
    def __exit__(*exc_info): pass    
    
# decorator to transform non SUCCESS RteReturn values to exceptions
def RteReturnHandler(err_msg=None):
    def _RteReturnHandler(func):
        def __RteReturnHandler(*args, **kwargs):
            try:
                rte_ret = func(*args, **kwargs)
            except TException, err:
                raise RTECommError, "Communication failure with RPC server: %s"%str(err)
            else:
                if rte_ret.value != RteReturnValue.SUCCESS:
                    error = err_msg
                    if err_msg is None:
                        error = 'Error in %s'%func.func_name
                    reason = ''
                    if rte_ret.reason:
                        reason = ': %s'%rte_ret.reason
                    raise RTEReturnError, '%s: %s%s'%(RTE_RETURN_CODES[rte_ret.value], error, reason)
        return __RteReturnHandler
    return _RteReturnHandler

        
# decorator to catch thrift communication failures
def RPC(func):
    def _RPC(self, *args, **kwargs):
        with self.rte.THRIFT_API_LOCK:
            try:
                return func(self, *args, **kwargs)
            except TException, err:
                raise RTECommError, "Communication failure with RPC server: %s"%str(err)
    return _RPC
    

class RTEModule(object):
    def __init__(self, rte):
        self.rte = rte

class Design(RTEModule):
    @RPC
    def Load(self, elf_fw, pif_design, pif_config):
        with open(elf_fw, "rb") as f:
            elf_fw_data = f.read()
    
        pif_design_data = ""
        if pif_design:
            with open(pif_design, "rb") as f:
                pif_design_data = f.read()
    
        pif_config_data = ""
        if pif_config:
            with open(pif_config, "rb") as f:
                pif_config_data = f.read()

        self.rte.client.design_unload()

        self.rte.client.design_load(DesignLoadArgs(
            nfpfw=elf_fw_data, 
            pif_design_json=pif_design_data, 
            pif_config_json=pif_config_data,
        ))

        return True, ''

    @RPC
    def Unload(self):
        self.rte.client.design_unload()

    @RPC
    def ConfigReload(self, pif_config):
        with open(pif_config, "rb") as f:
            self.rte.client.design_reconfig(f.read())

    @RPC
    def LoadStatus(self):
        return self.rte.client.design_load_status()
        
class Counters(RTEModule):
    def ExtractRteValue(self, rv):
        return rv.intval if rv.type == RteValueType.Int64 else int(rv.stringval)

    @RPC
    def ListP4Counters(self):
        return [cntr for cntr in self.rte.client.p4_counter_list_all()]

    @RPC
    def GetP4Counter(self, counter):
        if isinstance(counter, (int, long)):
            counterId = counter
        elif isinstance(counter, basestring):
            counterId = self.GetP4CounterByName(self, counter).id
        elif isinstance(counter, P4CounterDesc):
            counterId = counter.id
        else:
            raise RTEError, "Unexpected counter parameter type %s"%type(counter)

        counterReturn = self.rte.client.p4_counter_retrieve(counterId)
        if counterReturn.count != -1:
            return struct.unpack('%sQ'%(counterReturn.count/8), counterReturn.data)
        else:
            return ()

    def GetP4Counters(self):
        return [(counter, self.GetP4Counter(counter)) for counter in self.ListP4Counters()]

    def GetP4CounterByName(self, counter_name):
        for counter in self.ListP4Counters():
            if counter.name == counter_name:
                return counter
        raise RTEError, "Counter '%s' not found"%counter_name

    @RPC
    def ClearP4Counter(self, counter):
        if isinstance(counter, int):
            counterId = counter
        elif isinstance(counter, str):
            counterId = self.GetP4CounterByName(counter).id
        elif isinstance(counter, P4CounterDesc):
            counterId = counter.id
        else:
            raise RTEError, "Unexpected counter parameter type %s"%type(counter)
        
        self.rte.client.p4_counter_clear(counterId)

    @RPC
    def ClearAllP4Counters(self):
        self.rte.client.p4_counter_clear_all()
        
    @RPC
    def GetSystemCounters(self):
        sysCounters = self.rte.client.sys_counter_retrieve_all()
        for sc in sysCounters:
            # replace rte values with real ints
            sc.value = self.ExtractRteValue(sc.value)
        return sysCounters

    @RPC
    def ClearAllSysCounters(self):
        self.rte.client.sys_counter_clear_all()

class Tables(RTEModule):
    def GetTableByName(self, table_name):
        for table in self.List():
            if table.tbl_name == table_name:
                return table
        raise RTEError, "Table '%s' not found"%table_name

    def ResolveToTableId(self, tbl_id):
        if isinstance(tbl_id, int):
            return tbl_id
        elif isinstance(tbl_id, basestring):
            return self.GetTableByName(tbl_id).tbl_id
        else:
            raise RTEError, 'Unsupported table name type: %s'%type(tbl_id)

    @RPC
    def AddRule(self, tbl_id, rule_name, default_rule, match, actions, priority = None):
        tbl_entry = TableEntry()
        tbl_entry.rule_name = rule_name
        tbl_entry.default_rule = default_rule
        tbl_entry.match = match
        tbl_entry.actions = actions
        if priority != None:
            tbl_entry.priority = priority
        self.rte.client.table_entry_add(self.ResolveToTableId(tbl_id), tbl_entry)

    @RPC
    def EditRule(self, tbl_id, rule_name, default_rule, match, actions, priority = None):
        tbl_entry = TableEntry()
        tbl_entry.rule_name = rule_name
        tbl_entry.default_rule = default_rule
        tbl_entry.match = match
        tbl_entry.actions = actions
        if priority != None:
            tbl_entry.priority = priority
        self.rte.client.table_entry_edit(self.ResolveToTableId(tbl_id), tbl_entry)

    @RPC
    def DeleteRule(self, tbl_id, rule_name, default_rule, match, actions):
        tbl_entry = TableEntry()
        tbl_entry.rule_name = rule_name
        tbl_entry.default_rule = default_rule
        tbl_entry.match = match
        tbl_entry.actions = actions
        self.rte.client.table_entry_delete(self.ResolveToTableId(tbl_id), tbl_entry)

    @RPC
    def List(self):
        return self.rte.client.table_list_all()
    
    @RPC
    def ListRules(self, tbl_id):
        return self.rte.client.table_retrieve(self.ResolveToTableId(tbl_id))

    @RPC
    def GetVersion(self):
        return self.rte.client.table_version_get()

class Registers(RTEModule):
    @RPC
    def List(self):
        return self.rte.client.register_list_all()
    
    def GetRegisterByName(self, register_name):
        for reg in self.List():
            if reg.name == register_name:
                return reg
        raise RTEError, "Register '%s' not found"%register_name

    def ResolveToRegisterArrayArg(self, register, index, count):
        reg = None
        if isinstance(register, int):
            reg_id = register
        elif isinstance(register, str):
            reg = self.GetRegisterByName(register)
            reg_id = reg.id
        else:
            raise RTEError, "Unhandled register parameter type: %s"%type(register)

        if count == -1:
            if reg is None:
                reg = self.GetRegisterByName(register)
            count = reg.count
        return RegisterArrayArg(reg_id=reg_id, index=index, count=count)
            
    @RPC
    def Get(self, register, index=0, count=1):
        return self.rte.client.register_retrieve(self.ResolveToRegisterArrayArg(register, index, count))
            
    @RPC
    def Clear(self, register, index=0, count=1):
        self.rte.client.register_clear(self.ResolveToRegisterArrayArg(register, index, count))

    @RPC
    def Set(self, register, values, index=0, count=1):
        self.rte.client.register_set(self.ResolveToRegisterArrayArg(register, index, count), values)

    @RPC
    def SetField(self, register, field_id, value, index=0, count=1):
        self.rte.client.register_field_set(self.ResolveToRegisterArrayArg(register, index, count), field_id, value)

class Meters(RTEModule):
    @RPC
    def List(self):
        return self.rte.client.meter_list_all()
            
    @RPC
    def GetConfig(self, meter_id):
        return self.rte.client.meter_config_get(meter_id)

    @RPC
    def SetConfig(self, meter_id, configs):
        ops = [MeterCfg(cfg['rate'], cfg['burst'], cfg['off'], cfg['cnt']) for cfg in configs] 
        self.rte.client.meter_config_set(meter_id, ops)

class Digests(RTEModule):
    @RPC
    def List(self):
        return self.rte.client.digest_list_all()
    
    @RPC
    def Register(self, digest_id):
        return self.rte.client.digest_register(digest_id)        

    @RPC
    def Deregister(self, digest_regid):
        return self.rte.client.digest_deregister(digest_regid)        
    
    @RPC
    def Get(self, digest_handle):
        return self.rte.client.digest_retrieve(digest_handle)        

class Multicast(RTEModule):
    @RPC
    def List(self):
        return self.rte.client.mcast_config_get_all()
    
    @RPC
    def SetConfig(self, group_id, ports):
        cfg = McastCfgEntry(group_id, len(ports), ports)
        self.rte.client.mcast_config_set(cfg)

class System(RTEModule):
    @RPC
    def Shutdown(self):
        return self.rte.client.sys_shutdown()

    @RPC
    def Ping(self):
        return self.rte.client.sys_ping()
    
    @RPC
    def Echo(self, echo_msg):
        return self.rte.client.sys_echo(echo_msg)

    @RPC
    def GetVersion(self):
        return self.rte.client.sys_version_get()

    @RPC
    def GetLogLevel(self):
        return self.rte.client.sys_log_level_get()

    @RPC
    def SetLogLevel(self, level):
        self.rte.client.sys_log_level_set(level)

    @RPC
    def GetPortInfo(self):
        return self.rte.client.port_info_retrieve()
    

class DebugCtl(RTEModule):
    @RPC
    def Execute(self, debug_id, debug_data):
        res = self.rte.client.debugctl(debug_id, debug_data)
        if res.return_value == -1:
            raise RTEError, "Error encountered during debugctl '%s'"%debug_id
        return res.return_data
    
    def SetRuleBreakpoint(self, table_name, rule_name, enable):
        self.Execute('netro_rule_bpt', 'table %s rule %s enabled %s'%(table_name, rule_name, int(enable)))
        
    def GetRuleBreakpoint(self, table_name, rule_name):
        res = self.Execute('netro_rule_bpt', 'table %s rule %s'%(table_name, rule_name))
        name, val = res.split(None, 1)
        assert name=='enabled'
        return bool(int(val))

    def SetMacConfig(self, nbi0_config, nbi1_config):
        for (conf_id, conf_json) in (('nbi_mac8_json', nbi0_config), 
                                     ('nbi_mac9_json', nbi1_config)):
            if conf_json:
                with open(conf_json, "rb") as f:
                    self.Execute(conf_id, f.read())

class ParserValueSets(RTEModule):
    @RPC
    def List(self):
        return self.rte.client.parser_value_set_list_all()
    @RPC
    def Clear(self, pvs_id):
        self.rte.client.parser_value_set_clear(pvs_id)
    @RPC
    def Add(self, pvs_id, pvs_entries):
        pvs_value_entries = []
        for e in pvs_entries:
            pvs_value_entries.append(ParserValueSetEntry(value=e[0], mask=e[1]))
        self.rte.client.parser_value_set_add(pvs_id, pvs_value_entries)
    @RPC
    def Retrieve(self, pvs_id):
        return self.rte.client.parser_value_set_retrieve(pvs_id)


class RTEInterfaceConnection(object):
    def __init__(self):
        self.transport = None

        self.Design = Design(self)
        self.Counters = Counters(self)
        self.Tables = Tables(self)
        self.ParserValueSets = ParserValueSets(self)
        self.Registers = Registers(self)
        self.Meters = Meters(self)
        self.Digests = Digests(self)
        self.Multicast = Multicast(self)
        self.DebugCtl = DebugCtl(self)
        self.System = System(self)

    def Connect(self, host, port, use_zlib=True, serialise_api=False):
        self.transport = TTransport.TBufferedTransport(TSocket.TSocket(host, port))
        if use_zlib:
            self.transport = TZlibTransport.TZlibTransport(self.transport)
        self.client = RunTimeEnvironment.Client(TBinaryProtocol.TBinaryProtocol(self.transport))
        
        # post apply decorators
        self.client.design_load = RteReturnHandler('Loading firmware failed')(self.client.design_load)
        self.client.design_unload = RteReturnHandler('Unloading firmware failed')(self.client.design_unload)
        self.client.design_reconfig = RteReturnHandler('Reload of user config failed')(self.client.design_reconfig)
        self.client.sys_log_level_set = RteReturnHandler('Set log level failed')(self.client.sys_log_level_set)
        self.client.table_entry_add = RteReturnHandler('Adding table entry failed')(self.client.table_entry_add)
        self.client.table_entry_edit = RteReturnHandler('Editing table entry failed')(self.client.table_entry_edit)
        self.client.table_entry_delete = RteReturnHandler('Deleting table entry failed')(self.client.table_entry_delete)
        self.client.p4_counter_clear = RteReturnHandler('P4 counter clear failed')(self.client.p4_counter_clear)
        self.client.p4_counter_clear_all = RteReturnHandler('P4 counter clear allfailed')(self.client.p4_counter_clear_all)
        self.client.sys_counter_clear_all = RteReturnHandler('System counter clear all failed')(self.client.sys_counter_clear_all)
        self.client.register_clear = RteReturnHandler('Register clear failed')(self.client.register_clear)
        self.client.register_field_set = RteReturnHandler('Register field set failed')(self.client.register_field_set)
        self.client.register_set = RteReturnHandler('Register set failed')(self.client.register_set)
        self.client.mcast_config_set = RteReturnHandler('Multicast config set failed')(self.client.mcast_config_set)
        self.client.meter_config_set = RteReturnHandler('Meter config set failed')(self.client.meter_config_set)
        self.client.digest_deregister = RteReturnHandler('Digest deregister failed')(self.client.digest_deregister)
        self.client.parser_value_set_add = RteReturnHandler('Parser value set add failed')(self.client.parser_value_set_add)
        self.client.parser_value_set_clear = RteReturnHandler('Parser value set clear failed')(self.client.parser_value_set_clear)
        
        try:
            self.transport.open()
        except TException, err:
            raise RTECommError, "Communication failure with RPC server: %s"%str(err)

        self.THRIFT_API_LOCK = threading.Lock() if serialise_api else NullCtx()
        
        # test the connection
        self.System.Ping()

    def Disconnect(self):
        if self.transport is not None:
            self.transport.close()
            self.transport = None
                
    @contextmanager    
    def ConnectCtx(self, host, port, use_zlib=True, serialise_api=False):
        try:
            self.Connect(host, port, use_zlib, serialise_api)
            yield self
        finally:
            self.Disconnect()

    def Shutdown(self):
        self.System.Shutdown()
        self.Disconnect()

RTEInterface = RTEInterfaceConnection()
