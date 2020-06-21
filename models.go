package main

import (
	"errors"
	"fmt"
	"github.com/cloudflare/gortr/prefixfile"
	"github.com/graphql-go/graphql"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	graphqlRequestDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "graphql_query_duration",
			Help:       "Time to complete a query",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"field"},
	)
	graphqlRequestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "graphql_query_count",
			Help: "Count of queries",
		},
		[]string{"field"},
	)

	RoaItemObject *graphql.Object
	ROAsArgs      graphql.FieldConfigArgument
	PrefixInput   = graphql.NewInputObject(graphql.InputObjectConfig{
		Name: "PrefixArgs",
		Fields: graphql.InputObjectConfigFieldMap{
			"prefix": &graphql.InputObjectFieldConfig{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "Prefix (eg: 10.0.0.0/24)",
			},
			"lessSpecific": &graphql.InputObjectFieldConfig{
				Type:         graphql.Boolean,
				Description:  "The resource must contain the prefix",
				DefaultValue: false,
			},
			"moreSpecific": &graphql.InputObjectFieldConfig{
				Type:         graphql.Boolean,
				Description:  "The resource must be contained in the prefix",
				DefaultValue: false,
			},
			"equal": &graphql.InputObjectFieldConfig{
				Type:         graphql.Boolean,
				Description:  "The resource is equal to the prefix",
				DefaultValue: true,
			},
		},
	})
	Fields = graphql.Fields{}
)

func AppendFields(origin graphql.Fields, fields graphql.Fields) {
	for k, v := range fields {
		origin[k] = v
	}
}

func init() {
	ROAItemFields := graphql.Fields{
		"asn": &graphql.Field{
			Type: graphql.Float,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				output := p.Source.(*prefixfile.ROAJson)
				return output.GetASN(), nil
			},
			Description: "The ASN of the ROA",
		},
		"prefix": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				output := p.Source.(*prefixfile.ROAJson)
				return output.GetPrefix().String(), nil
			},
			Description: "The IP prefix of the ROA",
		},
		"maxLength": &graphql.Field{
			Type: graphql.Int,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				output := p.Source.(*prefixfile.ROAJson)
				return output.GetMaxLen(), nil
			},
			Description: "The maximum length of the prefix of the ROA",
		},
		"ta": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				output := p.Source.(*prefixfile.ROAJson)
				return output.TA, nil
			},
			Description: "The trust anchor of the ROA",
		},
	}
	RoaItemObject = graphql.NewObject(graphql.ObjectConfig{
		Name:   "RoaItem",
		Fields: ROAItemFields,
	})

	ROAsArgs = graphql.FieldConfigArgument{
		"prefixFilters": &graphql.ArgumentConfig{
			Type:        PrefixInput,
			Description: "Filter on prefix",
		},
		"ta": &graphql.ArgumentConfig{
			Type:        graphql.String,
			Description: "Filter on Trust Anchor",
		},
		"asn": &graphql.ArgumentConfig{
			Type:        graphql.Float,
			Description: "Filter on ASN",
		},
		"limit": &graphql.ArgumentConfig{
			Type:        graphql.Int,
			Description: "Limit number of results",
		},
		"offset": &graphql.ArgumentConfig{
			Type:        graphql.Int,
			Description: "Offset results",
		},
	}

	Fields["roas"] = &graphql.Field{
		Description: "List currently valid ROAs",
		Type:        graphql.NewList(RoaItemObject),
		Args:        ROAsArgs,
	}
}

func init() {
	prometheus.MustRegister(graphqlRequestDuration)
	prometheus.MustRegister(graphqlRequestCount)
}

func ErrorLogger(f graphql.FieldResolveFn, log Logger) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		result, err := f(p)
		if err != nil {
			log.Errorf("%v: %+v", p.Context.Value("request.uuid"), err)

			err = errors.New(fmt.Sprintf("There was an error during the request %v", p.Context.Value("request.uuid")))
		}
		return result, err
	}
}

func Wrapper(f graphql.FieldResolveFn, log Logger) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		label := p.Info.FieldName
		graphqlRequestCount.WithLabelValues(label).Inc()
		start := time.Now().UTC()
		result, err := f(p)
		end := time.Now().UTC()
		dur := end.Sub(start)
		graphqlRequestDuration.WithLabelValues(label).Observe(float64(dur.Nanoseconds()))
		log.Debugf("%v: %v with args %v, %v with error: %v. Duration: %v.",
			p.Context.Value("request.uuid"), label, p.Args, p.Info.VariableValues, err, dur)
		return result, err
	}
}

type Logger interface {
	Debugf(string, ...interface{})
	Debug(...interface{})
	Printf(string, ...interface{})
	Print(...interface{})
	Errorf(string, ...interface{})
	Error(...interface{})
	Warnf(string, ...interface{})
	Warn(...interface{})
	Infof(string, ...interface{})
	Info(...interface{})
}

func InitSchema(schemaConfig graphql.SchemaConfig, log Logger) (*graphql.Schema, error) {
	for _, f := range schemaConfig.Query.Fields() {
		r := f.Resolve
		f.Resolve = Wrapper(ErrorLogger(r, log), log)
	}

	schema, err := graphql.NewSchema(schemaConfig)
	if err != nil {
		return nil, err
	}
	return &schema, nil
}
