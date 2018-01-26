#import p4libinit

import os, sys, argparse, pprint, collections, time, traceback

VERSION = '0.2.3'
DESCRIPTION = 'RTE command line interface'

try:
    from nfp_pif_gen import __repo_version__
    VERSION += '-'+__repo_version__.HASH
except ImportError, err:
    VERSION += '-devel'
        
def main():
    try:
        # running from tools
        from nfp_pif_rte.RTEInterface import RTEInterface
    except ImportError, err:
        # running inplace
        from RTEInterface import RTEInterface

    def _parse_slice_fmt(expr):
        name = start = count = None
        if '[' in expr and ']' in expr:
            name, start = expr.split('[', 1)
            if ':' in start:
                start, end = start.split(':', 1)
                start = int(start)
                count = int(end[:-1]) - start
            else:
                start = int(start[:-1])
                count = 1
        else:
            name = expr
        return name, start, count

    def rte_cmd(func):
        def _rte_cmd(args):
            with RTEInterface.ConnectCtx(args.rte_host, args.rte_port, not args.rte_no_zlib):
                return func(args)
        return _rte_cmd

    @rte_cmd
    def rte_version(args):
        print RTEInterface.System.GetVersion()

    @rte_cmd
    def rte_status(args):
        print RTEInterface.Design.LoadStatus()

    @rte_cmd
    def design_load(args):
        RTEInterface.Design.Load(args.firmware_file, args.pif_design, args.pif_config)

    @rte_cmd
    def design_unload(args):
        RTEInterface.Design.Unload()
    
    @rte_cmd
    def design_config_reload(args):
        RTEInterface.Design.ConfigReload(args.pif_config)

    @rte_cmd
    def counters(args):
        if args.counter_cmd == 'list':
            pprint.pprint(RTEInterface.Counters.ListP4Counters())
        elif args.counter_cmd == 'list-system':
            pprint.pprint(RTEInterface.Counters.GetSystemCounters())
        elif args.counter_cmd == 'clear-all':
            RTEInterface.Counters.ClearAllP4Counters()
            print "All P4 counters cleared"
        elif args.counter_cmd == 'clear-all-system':
            RTEInterface.Counters.ClearAllSysCounters()
            print "All system counters cleared"
        else:
            if not args.counter_name: raise Exception, 'counter name is required'
            counter_id = RTEInterface.Counters.GetP4CounterByName(args.counter_name).id
            if args.counter_cmd == 'clear':
                RTEInterface.Counters.ClearP4Counter(counter_id)
                print "P4 counter %s cleared" % args.counter_name
            elif args.counter_cmd == 'get':
                values = RTEInterface.Counters.GetP4Counter(counter_id)
                if args.counter_index == None:
                    print values
                else:
                    if args.counter_index < 0 or args.counter_index >= len(values):
                        raise Exception, 'invalid index'
                    print values[args.counter_index]


    @rte_cmd
    def tables(args):
        if args.table_cmd == 'list':    
            pprint.pprint(RTEInterface.Tables.List())
        else:
            if not args.tbl_name and args.tbl_id == -1: raise Exception, 'table name/id is required'
            tbl_id = args.tbl_id if args.tbl_id != -1 else args.tbl_name
            if args.table_cmd == 'list-rules':    
                pprint.pprint(RTEInterface.Tables.ListRules(tbl_id))
            else:
                if not args.rule_name: raise Exception, 'rule name is required'
                if not args.match:
                    if not args.default_rule:
                        raise Exception, 'match is required'
                if not args.action: raise Exception, 'action is required'
                if args.table_cmd == 'add':
                    RTEInterface.Tables.AddRule(tbl_id, args.rule_name, 
                        args.default_rule, args.match, args.action, priority=args.priority)
                    print "Rule %s added to table %s" % (args.rule_name, tbl_id)        
                elif args.table_cmd == 'edit':
                    RTEInterface.Tables.EditRule(tbl_id, args.rule_name, 
                        args.default_rule, args.match, args.action, priority=args.priority)
                    print "Rule %s in table %s edited" % (args.rule_name, tbl_id)        
                elif args.table_cmd == 'delete':    
                    RTEInterface.Tables.DeleteRule(tbl_id, args.rule_name, 
                        args.default_rule, args.match, args.action)
                    print "Rule %s in table %s deleted" % (args.rule_name, tbl_id)        

    @rte_cmd
    def registers(args):
        if args.register_cmd == 'list':
            pprint.pprint(RTEInterface.Registers.List())
        else:
            if not args.register_name: raise Exception, 'register name is required'
            
            name, start, end = _parse_slice_fmt(args.register_name)
            args_rn = args.register_name if name is None else name
            args_index = args.index if start is None else start
            args_count = args.count if end is None and start is None else end
            if args_index is None: raise Exception, 'register index required'
            if args_count is None: raise Exception, 'register count required'

            if args.register_cmd == 'get':
                pprint.pprint(RTEInterface.Registers.Get(args_rn, args_index, args_count))
            elif args.register_cmd == 'clear':
                RTEInterface.Registers.Clear(args_rn, args_index, args_count)
                print "Register %s cleared" % args.register_name
            elif args.register_cmd == 'set':
                if not args.values: raise Exception, 'register values are required'
                RTEInterface.Registers.Set(args_rn, args.values, args_index, args_count)
                print "Register %s set to %s" % (args.register_name, args.values)
            elif args.register_cmd == 'set-field':
                if args.field_id == -1: raise Exception, 'register field id is required'
                if not args.field_value: raise Exception, 'register field value is required'
                RTEInterface.Registers.SetField(args_rn, args.field_id, args.field_value, args_index, args_count)
                print "Register %s field %s set to %s" % (args.register_name, args.field_id, args.field_value)
        
    @rte_cmd
    def meters(args):
        if args.meter_cmd == 'list':
            pprint.pprint(RTEInterface.Meters.List())
        else:
            if args.meter_id == -1: raise Exception, 'meter id is required'
            if args.meter_cmd == 'get':
                pprint.pprint(RTEInterface.Meters.GetConfig(args.meter_id))
            elif args.meter_cmd == 'set':
                ops_str = args.meter_configs.split(",")
                ops = []
                for o_str in ops_str:
                    off_cnt, rate_burst = o_str.split('=')
                    off, cnt = off_cnt.split(':')
                    rate, burst = rate_burst.split(':')
                    mtrcfg = {'rate': float(rate), 
                              'burst': int(burst, 0), 
                              'off': int(off, 0),
                              'cnt': int(cnt, 0)}
                    ops.append(mtrcfg)
                RTEInterface.Meters.SetConfig(args.meter_id, ops)
                print "Configured meter"
    
    @rte_cmd
    def digests(args):
        if args.digest_cmd == 'list':
            pprint.pprint(RTEInterface.Digests.List())
        elif args.digest_cmd == 'poll':
            # grab all the digest info
            digests = RTEInterface.Digests.List()
        
            # a map for associating registration handle with digest data
            digest_map = collections.OrderedDict()
        
            # register for each digest
            for d in digests:
                # get the digest registration handle
                dh = RTEInterface.Digests.Register(d.id)
                if dh < 0:
                    raise Exception, "Failed to register for digest %s" % d.name
        
                # associate the registration handle with the digest data
                digest_map[dh] = {'desc' : d, 'count' : 0}
        
            print "polling for digests events"
            # okay now periodically retrieve and dump the digest data
            try:
                while 1:
                    for dh, dgdata in digest_map.items():
                        values = RTEInterface.Digests.Get(dh)
        
                        if len(values) == 0: # no data
                            continue
        
                        fldcnt = len(dgdata['desc'].fields)
                        if len(values) % fldcnt != 0:
                            raise Exception, "Invalid field layout from digest %s" % dgdata['desc'].name
                        
                        for i in range(len(values) / fldcnt):
                            print "digest %s (P4 ID %d, P4 fieldlist %s)[%d] {" % (
                                    dgdata['desc'].name,
                                    dgdata['desc'].app_id,
                                    dgdata['desc'].field_list_name,
                                    dgdata['count'])
        
                            for flddesc, fielddata in zip(dgdata['desc'].fields, values[fldcnt * i:fldcnt * (i + 1)]):
                                print "    %s : %s" % (flddesc.name, fielddata)
                            print "}\n"
        
                            dgdata['count'] += 1
        
                    time.sleep(2)
            except KeyboardInterrupt: # exit on control-c
                pass

    @rte_cmd
    def parser_value_sets(args):
        pvs_list = RTEInterface.ParserValueSets.List()

        # build up an name->ID map
        id_map = {}
        for s in pvs_list:
            id_map[s.pvs_name] = s.pvs_id
            # allow the ID to be the name too
            id_map[str(s.pvs_id)] = s.pvs_id

        if args.pvs_cmd == 'list':
            pprint.pprint(pvs_list)
        elif args.pvs_cmd == 'retrieve':
            if args.pvs_id == None: raise Exception, 'parser value set ID is required'

            if args.pvs_id not in id_map:
                raise Exception, 'invalid parser value set ID'

            pprint.pprint(RTEInterface.ParserValueSets.Retrieve(id_map[args.pvs_id]))
        elif args.pvs_cmd == 'clear': 
            if args.pvs_id == None: raise Exception, 'parser value set ID is required'

            if args.pvs_id not in id_map:
                raise Exception, 'invalid parser value set ID'
            
            RTEInterface.ParserValueSets.Clear(id_map[args.pvs_id])
            print "cleared parser value set %s" % args.pvs_id
        elif args.pvs_cmd == 'add': 
            if args.pvs_id == None: raise Exception, 'parser value set ID is required'

            if args.pvs_id not in id_map:
                raise Exception, 'invalid parser value set ID'

            if args.pvs_entries == None:
                raise Exception, 'parser value set entries are required'

            pvs_entries_spl = args.pvs_entries.split(',')

            pvs_entries_list = []
            for spl in pvs_entries_spl:
                vals = spl.split(':')
                if len(vals) > 2:
                    raise Exception, 'invalid parser value set entry ' + spl

                if len(vals) == 1 and len(vals[0].strip()) == 0:
                    continue
                value = vals[0].strip()
                if len(vals) > 1:
                    mask = vals[1].strip()
                else:
                    mask = None

                try:
                    val = long(value, 0)
                    if mask:
                        val = long(mask, 0)
                except:
                    raise Exception, 'invalid parser value set entry ' + spl

                pvs_entries_list.append((value, mask))

            if len(pvs_entries_list) == 0:
                raise Exception, 'must supply at least one valid entry'

            RTEInterface.ParserValueSets.Add(id_map[args.pvs_id], pvs_entries_list)
            print "added %d entries to parser value set %s" % (len(pvs_entries_list), args.pvs_id)

        
    @rte_cmd
    def multicast(args):
        if args.mcast_cmd == 'ports':
            pprint.pprint(RTEInterface.System.GetPortInfo())
        elif args.mcast_cmd == 'list':
            pprint.pprint(RTEInterface.Multicast.List())
        elif args.mcast_cmd == 'set':
            if args.group_id == -1: raise Exception, 'group id is required'

            # convert a list of comma seperated items into ports
            # we can use the port token notation
            ports = []
            ports_info = RTEInterface.System.PortInfo()
            ports_map = collections.OrderedDict()
            for pi in ports_info:
                ports_map[pi.token] = pi.id

            for tok in args.ports.split(","):
                if tok in ports_map:
                    # use the string if possible
                    ports.append(ports_map[tok])
                    continue
                ports.append(int(tok))

            RTEInterface.Multicast.SetConfig(args.group_id, ports)                    
            print "Configured multicast group %d" % grp
        
    @rte_cmd
    def debugctl(args):
        if args.debugctl_cmd == 'exec':
            if not args.debug_id: raise Exception, 'debug_id is required'
            if not args.debug_data: raise Exception, 'debug_data is required'
            print RTEInterface.DebugCtl.Execute(debug_id, debug_data)
        elif args.debugctl_cmd == 'get-rule-break':
            if not args.table_name: raise Exception, 'table_name is required'
            if not args.rule_name: raise Exception, 'rule_name is required'
            print RTEInterface.DebugCtl.GetRuleBreakpoint(args.table_name, args.rule_name)
        elif args.debugctl_cmd == 'set-rule-break':
            if not args.table_name: raise Exception, 'table_name is required'
            if not args.rule_name: raise Exception, 'rule_name is required'
            RTEInterface.DebugCtl.SetRuleBreakpoint(args.table_name, args.rule_name, args.enable)
            print 'Rule breakpoint %s at table: %s, rule: %s'%(
                'set' if args.enable else 'cleared', args.table_name, args.rule_name)

    
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog='Copyright (C) 2016 Netronome Systems, Inc.  All rights reserved.')
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('-r', '--rte-host', dest='rte_host', type=str, default='localhost',
                        help='rte host, default localhost')
    parser.add_argument('-p', '--rte-port', dest='rte_port', type=int, default=20206,
                        help='rte port, default 20206')
    parser.add_argument('-n', '--rte-no-zlib', dest='rte_no_zlib', action='store_true',
                        help="don't use zlib for buffer transport")
    parser.add_argument('--debug-script', dest='debug_script', action='store_true',
                        help=argparse.SUPPRESS)

    subparsers = parser.add_subparsers(help='rte client commands')    
    load_design_parser = subparsers.add_parser('design-load', help='load a pif design')
    load_design_parser.add_argument('-f', '--firmware-file', dest='firmware_file', required=True,
                                    help='firmware file')
    load_design_parser.add_argument('-p', '--pif-design', dest='pif_design', default='',
                                    help='pif design json file')
    load_design_parser.add_argument('-c', '--user-config', dest='pif_config', default='',
                                    help='user config json rules file')
    load_design_parser.set_defaults(func=design_load)

    rte_version_parser = subparsers.add_parser('version', help='get the remote version number')
    rte_version_parser.set_defaults(func=rte_version)

    rte_status_parser = subparsers.add_parser('status', help='get the remote load status')
    rte_status_parser.set_defaults(func=rte_status)

    unload_design_parser = subparsers.add_parser('design-unload', help='unload a pif design')
    unload_design_parser.set_defaults(func=design_unload)

    config_reload_parser = subparsers.add_parser('config-reload', help='reload a user config')
    config_reload_parser.add_argument('-c', '--user-config', dest='pif_config', required=True,
                                      help='user config json rules file')
    config_reload_parser.set_defaults(func=design_config_reload)

    counters_parser = subparsers.add_parser('counters', help='counter commands')
    counters_parser.add_argument('counter_cmd', 
                                 choices=('list', 'list-system', 'clear', 'clear-all',
                                          'clear-all-system', 'get'), 
                                 help='counter command')
    counters_parser.add_argument('-c', '--counter', dest='counter_name', default='',
                                 help='counter name')
    counters_parser.add_argument('-i', '--index', dest='counter_index', default=None,
                                 type=int,
                                 help='counter index')
    counters_parser.set_defaults(func=counters)
        
    tables_parser = subparsers.add_parser('tables', help='table commands')
    tables_parser.add_argument('table_cmd', 
                               choices=('list', 'list-rules', 'add', 'edit', 'delete'), 
                               help='table command')
    tables_parser.add_argument('-t', '--table-name', dest='tbl_name', default='', type=str,
                               help="name of command target table")
    tables_parser.add_argument('-i', '--table-id', dest='tbl_id', default=-1, type=int,
                               help="name of command target table id")
    tables_parser.add_argument('-r', '--rule', dest='rule_name', default='', type=str,
                               help="name of command target rule")
    tables_parser.add_argument('-d', '--default-rule', dest='default_rule', action='store_true',
                               help="flag to set whether rule is target table default rule")
    tables_parser.add_argument('-m', '--match', dest='match', default='', type=str,
                               help="matchfields in JSON format for entry commands")
    tables_parser.add_argument('-a', '--action', dest='action', default='', type=str,
                               help="actions in JSON format for entry commands")    
    tables_parser.add_argument('-p', '--priority', dest='priority', default=None, type=int,
                               help="optional priority for rule")    
    tables_parser.set_defaults(func=tables)

    registers_parser = subparsers.add_parser('registers', help='register commands')
    registers_parser.add_argument('register_cmd', 
                                  choices=('list', 'get', 'clear', 'set', 'set-field'), 
                                  help='register command')
    registers_parser.add_argument('-r', '--register', dest='register_name', default='', type=str,
                                  help="register name")
    registers_parser.add_argument('-i', '--index', dest='index', default=0, type=int,
                                  help="index to start from, default 0")
    registers_parser.add_argument('-c', '--count', dest='count', default=-1, type=int,
                                  help="number of entries to read, default -1 (all)")
    registers_parser.add_argument('-s', '--values', dest='values', nargs='+', default=[],
                                  help="values to set (in hex format)")
    registers_parser.add_argument('-v', '--field-value', dest='field_value', default='', type=str,
                                  help="field value to set (in hex format)")
    registers_parser.add_argument('-f', '--field-id', dest='field_id', default=-1, type=int,
                                  help="field id to set")
                                  
    registers_parser.set_defaults(func=registers)

    meters_parser = subparsers.add_parser('meters', help='meter commands')
    meters_parser.add_argument('meter_cmd', 
                               choices=('list', 'get', 'set'), 
                                  help='meter command')
    meters_parser.add_argument('-m', '--meter-id', dest='meter_id', default=-1, type=int,
                               help="meter id")
    meters_parser.add_argument('-c', '--meter-configs', dest='meter_configs', default='', type=str,
                               help="meter configs, in the format: off0:cnt0=rate0:burst0,offN:cntN=rateN:burstN")
    meters_parser.set_defaults(func=meters)

    digests_parser = subparsers.add_parser('digests', help='digest commands')
    digests_parser.add_argument('digest_cmd', 
                                choices=('list', 'poll'), 
                                help='digest command')
    digests_parser.set_defaults(func=digests)

    pvs_parser = subparsers.add_parser('parser_value_sets', help='parser_value_sets commands')
    pvs_parser.add_argument('pvs_cmd', 
                            choices=('list', 'add', 'clear', 'retrieve'), 
                            help='parser_value_sets command')
    pvs_parser.add_argument('-p', '--parser-value-set-id', dest='pvs_id', default=None, type=str,
                            help="value set id")
    pvs_parser.add_argument('-e', '--parser-value-set-entries', dest='pvs_entries', default=None, type=str,
                            help="parser value set entries to load: comma seperated list <val>[:mask],<val>[:mask],...")
    pvs_parser.set_defaults(func=parser_value_sets)

    mcast_parser = subparsers.add_parser('multicast', help='multicast commands')
    mcast_parser.add_argument('mcast_cmd', 
                              choices=('ports', 'list', 'set'), 
                              help='multicast command')
    mcast_parser.add_argument('-g', '--group-id', dest='group_id', default=-1, type=int,
                               help="group id")
    mcast_parser.add_argument('-p', '--ports', dest='ports', default='', type=str,
                               help="ports, in the format: port0,port1...")
    mcast_parser.set_defaults(func=multicast)

    debugctl_parser = subparsers.add_parser('debugctl', help=argparse.SUPPRESS)
    debugctl_parser.add_argument('debugctl_cmd', type=str,
                              choices=('exec', 'get-rule-break', 'set-rule-break'), 
                              help=argparse.SUPPRESS)
    debugctl_parser.add_argument('-i', '--debug-id', dest='debug_id', default='', type=str,
                               help=argparse.SUPPRESS)
    debugctl_parser.add_argument('-d', '--debug-data', dest='debug_data', default='', type=str,
                               help=argparse.SUPPRESS)
    debugctl_parser.add_argument('-t', '--table-name', dest='table_name', default='', type=str,
                               help=argparse.SUPPRESS)
    debugctl_parser.add_argument('-r', '--rule-name', dest='rule_name', default='', type=str,
                               help=argparse.SUPPRESS)
    debugctl_parser.add_argument('-e', '--enable', dest='enable', default=True, type=bool,
                               help=argparse.SUPPRESS)
    debugctl_parser.set_defaults(func=debugctl)

    args = parser.parse_args()   
    try:
        args.func(args)

    except Exception, err:
        if args.debug_script:
            print >> sys.stderr, traceback.format_exc()
        else:
            print >> sys.stderr, "error: %s"%str(err)
        sys.exit(1)


if __name__ == '__main__':
    main()
