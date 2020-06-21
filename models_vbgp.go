package main

import (
	"github.com/graphql-go/graphql"
	"net"
)

var (
	BGPObject *graphql.Object
)

type BGPOVResult struct {
	Prefix string
	ASN    uint32
	OV     OVResult
}

func (r *BGPOVResult) GetPrefix() *net.IPNet {
	_, prefix, _ := net.ParseCIDR(r.Prefix)
	return prefix
}

func init() {
	BGPFields := graphql.Fields{
		"asn": &graphql.Field{
			Type: graphql.Float,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				output := p.Source.(*BGPOVResult)
				return output.ASN, nil
			},
			Description: "The ASN of the route",
		},
		"prefix": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				output := p.Source.(*BGPOVResult)
				return output.Prefix, nil
			},
			Description: "The IP prefix of the route",
		},
		// Note: due to the need of having a defined ValidationObject,
		// we need to init() models_validation.go first.
		// this is why this file is called vbgp.go and not bgp.go
		"validation": &graphql.Field{
			Type: ValidationObject,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				output := p.Source.(*BGPOVResult).OV
				return output, nil
			},
			Description: "Validation information",
		},
	}

	BGPObject = graphql.NewObject(graphql.ObjectConfig{
		Name:   "BGP",
		Fields: BGPFields,
	})

	Fields["bgp"] = &graphql.Field{
		Description: "Check status of the routing table",
		Type:        graphql.NewList(BGPObject),
		Args: graphql.FieldConfigArgument{
			"prefixFilters": &graphql.ArgumentConfig{
				Type:        PrefixInput,
				Description: "Filter on prefix",
			},
			"asn": &graphql.ArgumentConfig{
				Type:        graphql.Float,
				Description: "Filter on ASN",
			},
			"status": &graphql.ArgumentConfig{
				Type:        OVStateEnum,
				Description: "Validation status",
			},
			"limit": &graphql.ArgumentConfig{
				Type:        graphql.Int,
				Description: "Limit number of results",
			},
			"offset": &graphql.ArgumentConfig{
				Type:        graphql.Int,
				Description: "Offset results",
			},
		},
	}

}
