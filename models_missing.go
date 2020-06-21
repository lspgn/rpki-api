package main

import (
	"github.com/graphql-go/graphql"
)

func init() {
	Fields["missing"] = &graphql.Field{
		Description: "ROAs existing but not covering",
		Type:        graphql.NewList(RoaItemObject),
		Args:        ROAsArgs,
	}

}
