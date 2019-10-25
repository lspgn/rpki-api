package main

import (
	"github.com/cloudflare/cfrpki/ov"
	"github.com/cloudflare/gortr/prefixfile"
	"github.com/graphql-go/graphql"
)

var (
	OVStateEnum = graphql.NewEnum(graphql.EnumConfig{
		Name: "validation",
		Values: graphql.EnumValueConfigMap{
			"NotFound": &graphql.EnumValueConfig{Value: ov.STATE_UNKNOWN},
			"Invalid":  &graphql.EnumValueConfig{Value: ov.STATE_INVALID},
			"Valid":    &graphql.EnumValueConfig{Value: ov.STATE_VALID},
		},
		Description: "Validation state",
	})
)

type OVResult struct {
	State    int
	Covering []*prefixfile.ROAJson
}

var (
	ValidationObject *graphql.Object
)

func init() {
	ValidationFields := graphql.Fields{
		"state": &graphql.Field{
			Type: OVStateEnum,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				output := p.Source.(OVResult)
				return output.State, nil
			},
			Description: "List of files in the manifest",
		},
		"covering": &graphql.Field{
			Type: graphql.NewList(RoaItemObject),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				output := p.Source.(OVResult)
				return output.Covering, nil
			},
		},
	}

	ValidationObject = graphql.NewObject(graphql.ObjectConfig{
		Name:   "Validation",
		Fields: ValidationFields,
	})

	Fields["validation"] = &graphql.Field{
		Description: "Check status of validation",
		Type:        ValidationObject,
		Args: graphql.FieldConfigArgument{
			"prefix": &graphql.ArgumentConfig{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "Filter on prefix",
			},
			"asn": &graphql.ArgumentConfig{
				Type:        graphql.NewNonNull(graphql.Float),
				Description: "Filter on ASN",
			},
		},
	}

}
