package main

import (
	"errors"
	"github.com/cloudflare/gortr/prefixfile"
	"net"
)

type PrefixFilter struct {
	Equals       bool
	LessSpecific bool
	MoreSpecific bool

	Begin  net.IP
	End    net.IP
	Prefix net.IPNet
}

func GetIPBroadcast(ipnet net.IPNet) net.IP {
	br := make([]byte, len(ipnet.IP))
	for i := 0; i < len(ipnet.IP); i++ {
		br[i] = ipnet.IP[i] | (^ipnet.Mask[i])
	}
	return net.IP(br)
}

func MatchResource(v prefixfile.ROAJson, args map[string]interface{}) (bool, error) {
	prefixFilter, err := CreatePrefixFilterFromArgs(args)
	var add bool
	if err == nil {
		cidr := v.GetPrefix()
		add = prefixFilter.CompareToPrefix(*cidr)
		if add == true {
			return add, nil
		}

	}
	return add, err
}

func CreatePrefixFilterFromArgs(args map[string]interface{}) (*PrefixFilter, error) {
	prefixMap := args["prefixFilters"].(map[string]interface{})
	if prefixMap["prefix"] == nil {
		return nil, errors.New("Specify a prefix")
	}
	equals := prefixMap["equal"].(bool)
	lessSpecific := prefixMap["lessSpecific"].(bool)
	moreSpecific := prefixMap["moreSpecific"].(bool)

	_, cidrQ, err := net.ParseCIDR(prefixMap["prefix"].(string))

	if err != nil {
		return nil, err
	}

	begin := cidrQ.IP.To16()
	end := GetIPBroadcast(*cidrQ).To16()

	obj := &PrefixFilter{
		Equals:       equals,
		LessSpecific: lessSpecific,
		MoreSpecific: moreSpecific,

		Begin:  begin,
		End:    end,
		Prefix: *cidrQ,
	}
	return obj, nil
}

func (pf *PrefixFilter) CompareToPrefix(input net.IPNet) bool {
	inputBegin := input.IP
	inputEnd := GetIPBroadcast(input)

	inputBegin = inputBegin.To16()
	inputEnd = inputEnd.To16()
	if pf.LessSpecific && input.Contains(pf.Begin) && input.Contains(pf.End) {
		return true
	}
	if pf.MoreSpecific && pf.Prefix.Contains(inputBegin) && pf.Prefix.Contains(inputEnd) {
		return true
	}
	if pf.Equals && inputBegin.Equal(pf.Begin) && inputEnd.Equal(pf.End) {
		return true
	}
	return false
}
