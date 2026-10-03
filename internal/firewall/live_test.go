package firewall

import "testing"

func TestParseLiveRules(t *testing.T) {
	output := `Chain IPTUI_DNAT (1 references)
num   pkts bytes target     prot opt in     out     source               destination
1       42  2520 DNAT       6    --  ens3   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:25565 to:10.66.0.2:25565
2        0     0 DNAT       17   --  ens3   *       0.0.0.0/0            0.0.0.0/0            udp dpt:25565 to:10.66.0.2:25565
3     1.2K   73K DNAT       tcp  --  ens3   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8080 to:10.66.0.3:80
`
	table, ok := ParseLiveRules(output)
	if !ok || table.Chain != "IPTUI_DNAT" || len(table.Entries) != 3 {
		t.Fatalf("parsed %+v, ok %v", table, ok)
	}
	first := table.Entries[0]
	if first.Number != 1 || first.Protocol != "tcp" || first.PublicPort != "25565" || first.ForwardTo != "10.66.0.2:25565" || first.In != "ens3" || !first.Active || first.Extra != "" {
		t.Fatalf("first row: %+v", first)
	}
	if second := table.Entries[1]; second.Protocol != "udp" || second.Active {
		t.Fatalf("second row: %+v", second)
	}
	if third := table.Entries[2]; third.Packets != "1.2K" || third.Bytes != "73K" || third.Protocol != "tcp" || third.ForwardTo != "10.66.0.3:80" {
		t.Fatalf("older iptables prints names, and counters may be abbreviated: %+v", third)
	}

	empty, ok := ParseLiveRules("Chain IPTUI_DNAT (1 references)\nnum   pkts bytes target     prot opt in     out     source               destination\n")
	if !ok || len(empty.Entries) != 0 {
		t.Fatalf("an empty chain should parse to no rows: %+v %v", empty, ok)
	}
	if _, ok := ParseLiveRules("iptables: No chain/target/match by that name."); ok {
		t.Fatal("an error message is not a listing")
	}
}
